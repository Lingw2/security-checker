"""Run オーケストレータ (設計書 §3).

パイプライン全体を 1 つの Run として扱い、run_id で全出力を紐づける。
`run_scan` は Scanner → Normalizer → Policy → Report、
`run_review` はそこに Context Builder → Reviewer → Aggregator を挟む。
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from security_checker import __version__
from security_checker.aggregate.findings import build_findings
from security_checker.aggregate.judge import anonymize, apply_judgement, needs_judge
from security_checker.aggregate.registry import build_aggregator
from security_checker.config.schema import BudgetConfig, Config, ReviewerConfig
from security_checker.context.builder import ContextBuilder
from security_checker.context.facts import collect_repo_facts
from security_checker.errors import ConfigError
from security_checker.github.pr import DiffScope
from security_checker.ids import new_run_id
from security_checker.language import resolve_language
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import (
    Coverage,
    Report,
    ReportWarning,
    ReviewerRun,
    ScannerRun,
    SuppressedCandidate,
    TargetInfo,
    count_by_severity,
    count_by_status,
    utcnow,
)
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import Usage, VerdictStatus
from security_checker.observability import logging as log
from security_checker.observability.cost import PriceTable
from security_checker.observability.trace import TraceWriter
from security_checker.policy.engine import PolicyDecision, evaluate
from security_checker.policy.score import compute_score
from security_checker.policy.suppress import (
    SuppressionRules,
    apply_suppressions,
)
from security_checker.providers.base import LLMProvider
from security_checker.providers.registry import build_provider
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import (
    ReviewerRuntime,
    ReviewScheduler,
    ScheduleResult,
    build_runtime,
)
from security_checker.scanners.base import ScanContext, Scanner, ScanResult, Target
from security_checker.scanners.registry import build_scanners
from security_checker.scanners.untrusted import prepare_overrides, residual_warnings


@dataclass
class RunOutcome:
    """1 回の実行の成果物一式."""

    report: Report
    decision: PolicyDecision
    output_dir: Path
    results: list[ScanResult] = field(default_factory=list)


def _log_finish(report: Report, decision: PolicyDecision) -> None:
    log.event(
        "run.finish",
        level="info" if not decision.failed else "warn",
        exit_code=int(decision.exit_code),
        mode=report.target.mode,
        candidates=len(report.candidates),
        suppressed=len(report.suppressed),
        outside_diff=len(report.outside_diff),
        findings=report.finding_counts or None,
        score=report.score.value,
        reasons=decision.reasons,
    )


def resolve_output_dir(config: Config, base: Path) -> Path:
    """出力先を決める. 相対指定は呼び出し元のカレントディレクトリ基準."""
    configured = Path(config.output.dir).expanduser()
    return configured if configured.is_absolute() else (base / configured)


def _coverage(runs: list[ScannerRun], candidates: list[Candidate], *, reviewed: int) -> Coverage:
    return Coverage(
        scanners_total=len(runs),
        scanners_ok=sum(1 for run in runs if run.status is ScanStatus.OK),
        scanners_skipped=sum(1 for run in runs if run.status is ScanStatus.SKIPPED),
        scanners_failed=sum(1 for run in runs if run.status is ScanStatus.FAILED),
        candidates_total=len(candidates),
        candidates_reviewed=reviewed,
    )


def _sort_key(candidate: Candidate) -> tuple[int, str, str, int]:
    severity = candidate.severity_reported or Severity.INFO
    location = candidate.location
    return (
        -severity.order,
        candidate.scanner,
        location.path if location else "",
        location.start_line if location else 0,
    )


def dedupe_and_sort(results: list[ScanResult]) -> list[Candidate]:
    """スキャナ横断で同じ指摘を 1 件にまとめ、重大度順に並べる.

    候補 ID はスキャナ名を含むので、ID では重複を見つけられない。文字どおり同じ ID のほかに、
    依存の脆弱性だけは内容で突き合わせる (osv と trivy の vuln は同じものを報告する)。
    """
    seen: set[str] = set()
    merged: list[Candidate] = []
    for result in results:
        for candidate in result.candidates:
            if candidate.id in seen:
                continue
            seen.add(candidate.id)
            merged.append(candidate)
    return sorted(_merge_dependency_duplicates(merged), key=_sort_key)


def _advisory_ids(candidate: Candidate) -> set[str]:
    return {candidate.rule_id.upper(), *(cve.upper() for cve in candidate.cve)}


def _merge_dependency_duplicates(candidates: list[Candidate]) -> list[Candidate]:
    """同じ manifest の同じ版で、CVE か別名が重なる依存の候補を 1 件にまとめる.

    ecosystem は比べない。スキャナごとに表記が違う (PyPI と pip など) うえ、manifest で決まる。
    先に報告したスキャナの候補を残し、ID を保つ。重大度は厳しいほうを採る。
    """
    kept: list[Candidate] = []
    groups: dict[tuple[str, str | None, str | None], list[int]] = {}
    for candidate in candidates:
        package = candidate.package
        if candidate.category is not Category.DEPENDENCY or package is None:
            kept.append(candidate)
            continue
        key = (package.name.lower(), package.version, package.manifest)
        duplicate = next(
            (
                index
                for index in groups.get(key, [])
                if kept[index].scanner != candidate.scanner
                and _advisory_ids(kept[index]) & _advisory_ids(candidate)
            ),
            None,
        )
        if duplicate is None:
            groups.setdefault(key, []).append(len(kept))
            kept.append(candidate)
        else:
            kept[duplicate] = _merge_candidates(kept[duplicate], candidate)
    return kept


def _merge_candidates(first: Candidate, other: Candidate) -> Candidate:
    severities = [c.severity_reported for c in (first, other) if c.severity_reported is not None]
    return first.model_copy(
        update={
            "severity_reported": max(severities, default=None),
            "cve": list(dict.fromkeys([*first.cve, *other.cve])),
            "cwe": list(dict.fromkeys([*first.cwe, *other.cwe])),
            "references": list(dict.fromkeys([*first.references, *other.references])),
            "fix_available": first.fix_available or other.fix_available,
            "also_reported_by": [*first.also_reported_by, other.scanner],
        }
    )


def _suppress(
    candidates: list[Candidate],
    rules: SuppressionRules | None,
    warnings: list[ReportWarning],
) -> tuple[list[Candidate], list[SuppressedCandidate]]:
    """baseline / ignore / 注釈を適用する (§17.2). 警告は warnings に足す."""
    if rules is None:
        return candidates, []
    kept, suppressed, messages = apply_suppressions(candidates, rules)
    warnings.extend(
        ReportWarning(level="warn", source="suppress", message=message)
        for message in [*rules.warnings, *messages]
    )
    return kept, suppressed


def _target_label(root: Path) -> str:
    """レポートに載せる検査対象の名前. 絶対パス (ユーザー名・構成) を残さない (§6.1)."""
    return root.name or root.anchor or "."


def output_relative(path: Path, output_dir: Path) -> str:
    """出力先からの相対パス. 外にあるもの (指定で出力先を分けた場合) はそのまま."""
    try:
        return path.resolve().relative_to(output_dir.resolve()).as_posix()
    except ValueError:
        return str(path)


def _scope(
    candidates: list[Candidate], root: Path, diff: DiffScope | None
) -> tuple[list[Candidate], list[Candidate], TargetInfo]:
    """diff モードなら変更に関係する候補だけに絞る (§7.4)."""
    if diff is None:
        return candidates, [], TargetInfo(root=_target_label(root), mode="full")
    inside, outside = diff.split(candidates)
    target = TargetInfo(
        root=_target_label(root),
        mode="diff",
        changed_files=len(diff.changed_files),
        base=diff.base,
    )
    return inside, outside, target


async def _run_one(
    scanner: Scanner,
    target: Target,
    ctx: ScanContext,
    semaphore: asyncio.Semaphore,
) -> ScanResult:
    async with semaphore:
        try:
            return await scanner.scan(target, ctx)
        except Exception as exc:  # 1 つの失敗で全体を落とさない (§20.2)
            return ScanResult(
                scanner=scanner.name,
                category=scanner.category,
                status=ScanStatus.FAILED,
                reason=f"内部エラー: {exc}",
            )


async def _execute_scanners(
    config: Config,
    root: Path,
    raw_dir: Path,
    scanners: Sequence[Scanner] | None,
    extra_warnings: Sequence[str] = (),
    *,
    untrusted_target: bool = False,
) -> tuple[list[ScanResult], list[ScannerRun], list[ReportWarning]]:
    """スキャナを並列実行し、結果・サマリ・警告に整形する."""
    # 設定由来の警告を先頭に置く。「設定したのに効かない」は実行前から確定しているため。
    warnings: list[ReportWarning] = [
        ReportWarning(level="warn", source="config", message=message) for message in extra_warnings
    ]
    if scanners is None:
        resolved, warnings_text = build_scanners(config)
    else:
        resolved, warnings_text = list(scanners), []
    warnings.extend(
        ReportWarning(level="warn", source="config", message=message) for message in warnings_text
    )

    target = Target(root=root)
    semaphore = asyncio.Semaphore(config.concurrency.scanners)
    # 信用できない検査対象では、スキャナ自身の設定も対象の外から渡す (#43)
    with tempfile.TemporaryDirectory(prefix="security-checker-untrusted-") as overrides_dir:
        ctx = ScanContext(
            raw_dir=raw_dir,
            exclude=list(config.target.exclude),
            untrusted=prepare_overrides(Path(overrides_dir)) if untrusted_target else None,
        )
        if untrusted_target:
            warnings.extend(
                ReportWarning(level="warn", source="untrusted-target", message=message)
                for message in residual_warnings(root)
            )
        results = list(
            await asyncio.gather(
                *(_run_one(scanner, target, ctx, semaphore) for scanner in resolved)
            )
        )

    runs: list[ScannerRun] = []
    for result in results:
        log.event(
            "scanner.finish",
            level="error" if result.status is ScanStatus.FAILED else "info",
            scanner=result.scanner,
            status=result.status.value,
            candidates=len(result.candidates),
            duration_ms=result.duration_ms,
            exit_code=result.exit_code,
            reason=result.reason,
        )
        runs.append(
            ScannerRun(
                scanner=result.scanner,
                category=result.category,
                status=result.status,
                candidate_count=len(result.candidates),
                duration_ms=result.duration_ms,
                exit_code=result.exit_code,
                version=result.version,
                reason=result.reason,
                stderr_excerpt=result.stderr_excerpt,
                raw_path=output_relative(result.raw_path, raw_dir.parent)
                if result.raw_path
                else None,
                parse_warnings=result.parse_warnings,
                unavailable=result.unavailable,
            )
        )
        if result.status is ScanStatus.FAILED:
            warnings.append(
                ReportWarning(
                    level="error",
                    source=result.scanner,
                    message=result.reason or f"{result.scanner} が失敗しました",
                )
            )
        elif result.status is ScanStatus.SKIPPED:
            warnings.append(
                ReportWarning(
                    level="warn",
                    source=result.scanner,
                    message=result.reason or f"{result.scanner} をスキップしました",
                )
            )
        warnings.extend(
            ReportWarning(level="warn", source=result.scanner, message=parse_warning)
            for parse_warning in result.parse_warnings
        )
    return results, runs, warnings


async def run_scan(
    config: Config,
    root: Path,
    *,
    base_dir: Path | None = None,
    run_id: str | None = None,
    scanners: Sequence[Scanner] | None = None,
    extra_warnings: Sequence[str] = (),
    diff: DiffScope | None = None,
    suppression: SuppressionRules | None = None,
) -> RunOutcome:
    """スキャンを実行してレポートとポリシー判定を返す (LLM は使わない).

    `scanners` を渡すと registry の解決を飛ばす (テストと将来の埋め込み用途)。
    `extra_warnings` は設定層で判明した警告 (未実装項目の指定など)。
    """
    started_at = utcnow()
    identifier = run_id or new_run_id()
    log.set_run_id(identifier)
    output_dir = resolve_output_dir(config, base_dir or Path.cwd())
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    results, runs, warnings = await _execute_scanners(
        config,
        root,
        raw_dir,
        scanners,
        extra_warnings,
        untrusted_target=suppression is not None and suppression.untrusted_target,
    )
    active, suppressed = _suppress(dedupe_and_sort(results), suppression, warnings)
    candidates, outside, target = _scope(active, root, diff)
    score = compute_score(candidates, runs)
    coverage = _coverage(runs, candidates, reviewed=0)

    report = Report(
        tool_version=__version__,
        run_id=identifier,
        started_at=started_at,
        finished_at=utcnow(),
        target=target,
        scanners=runs,
        candidates=candidates,
        outside_diff=outside,
        suppressed=suppressed,
        findings=[],
        coverage=coverage,
        score=score,
        warnings=warnings,
        severity_counts=count_by_severity(candidates),
    )
    decision = evaluate(report, config.policy)
    _log_finish(report, decision)
    return RunOutcome(report=report, decision=decision, output_dir=output_dir, results=results)


@dataclass
class ReviewerSetup:
    """設定から組み立てた Reviewer 一式."""

    runtimes: list[ReviewerRuntime] = field(default_factory=list)
    providers: list[LLMProvider] = field(default_factory=list)
    configs: dict[str, ReviewerConfig] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def smallest_input_limit(setup: ReviewerSetup) -> int | None:
    """Reviewer のうち最も小さい入力の上限 (§8.3). 全 Reviewer に同じ依頼を送るため."""
    limits = [
        runtime.reviewer.provider.capabilities.max_context_tokens
        - runtime.reviewer.max_output_tokens
        for runtime in setup.runtimes
    ]
    return min(limits, default=None)


def build_reviewers(
    config: Config,
    *,
    price_table: PriceTable | None = None,
    environ: dict[str, str] | None = None,
) -> ReviewerSetup:
    """設定の reviewers から Provider と Reviewer を作る (§9, §22)."""
    setup = ReviewerSetup()
    table = price_table or PriceTable()
    language = resolve_language(config.output.language, environ)
    for reviewer_config in config.reviewers:
        provider = build_provider(reviewer_config, environ=environ, warnings=setup.warnings)
        output_limit = provider.capabilities.max_output_tokens
        max_output_tokens = min(reviewer_config.max_output_tokens, output_limit)
        if max_output_tokens < reviewer_config.max_output_tokens:
            setup.warnings.append(
                f"reviewer '{reviewer_config.name}': max_output_tokens "
                f"({reviewer_config.max_output_tokens}) がモデルの出力上限 ({output_limit}) を"
                f"超えるため {output_limit} で送ります。上限が違うなら "
                "capabilities.max_output_tokens を指定してください"
            )
        reviewer = Reviewer(
            reviewer_config.name,
            provider,
            weight=reviewer_config.weight,
            max_output_tokens=max_output_tokens,
            timeout_s=float(reviewer_config.timeout_s),
            seed=reviewer_config.seed,
            # process transport はトークンを実測できないため、価格表があっても
            # 金額を出さない。推測した数字を出すより cost: unknown が正しい (§9.7)。
            price=None
            if reviewer_config.transport == "process"
            else table.lookup(reviewer_config.model or ""),
            save_prompts=config.output.save_prompts,
            language=language,
        )
        setup.runtimes.append(
            build_runtime(
                reviewer,
                reviewer_config,
                default_concurrency=config.concurrency.reviews_per_provider,
            )
        )
        setup.providers.append(provider)
        setup.configs[reviewer_config.name] = reviewer_config
    return setup


def build_tasks(
    candidates: list[Candidate],
    root: Path,
    config: Config,
    setup: ReviewerSetup | None = None,
) -> tuple[list[ReviewTask], list[Candidate]]:
    """候補を ReviewTask にする. budget.max_candidates を超えた分は未レビューとして返す.

    `setup` があれば、Reviewer の入力の上限も予算に反映する (§8.3)。
    """
    limit = config.budget.max_candidates
    selected = candidates[:limit]
    overflow = candidates[limit:]
    builder = ContextBuilder(
        root,
        config.context,
        collect_repo_facts(root, config.target.exclude),
        max_input_tokens=smallest_input_limit(setup) if setup is not None else None,
    )
    return [builder.build(candidate) for candidate in selected], overflow


async def run_review(
    config: Config,
    root: Path,
    *,
    base_dir: Path | None = None,
    run_id: str | None = None,
    scanners: Sequence[Scanner] | None = None,
    reviewer_setup: ReviewerSetup | None = None,
    price_table: PriceTable | None = None,
    environ: dict[str, str] | None = None,
    extra_warnings: Sequence[str] = (),
    diff: DiffScope | None = None,
    suppression: SuppressionRules | None = None,
) -> RunOutcome:
    """スキャン → 文脈構築 → LLM レビュー → 集約 → ポリシー判定."""
    started_at = utcnow()
    identifier = run_id or new_run_id()
    log.set_run_id(identifier)
    output_dir = resolve_output_dir(config, base_dir or Path.cwd())
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if not config.reviewers and reviewer_setup is None:
        raise ConfigError(
            "reviewers が設定されていません。security-checker.yml に reviewer を定義するか、"
            "LLM を使わない `security-checker scan` を実行してください"
        )

    results, runs, warnings = await _execute_scanners(
        config,
        root,
        raw_dir,
        scanners,
        extra_warnings,
        untrusted_target=suppression is not None and suppression.untrusted_target,
    )
    active, suppressed = _suppress(dedupe_and_sort(results), suppression, warnings)
    candidates, outside, target = _scope(active, root, diff)

    setup = reviewer_setup or build_reviewers(config, price_table=price_table, environ=environ)
    warnings.extend(
        ReportWarning(level="warn", source="reviewer", message=message)
        for message in setup.warnings
    )
    tasks, overflow = build_tasks(candidates, root, config, setup)
    if overflow:
        warnings.append(
            ReportWarning(
                level="warn",
                source="budget",
                message=(
                    f"候補 {len(candidates)} 件のうち {len(overflow)} 件は "
                    f"budget.max_candidates ({config.budget.max_candidates}) を超えたため"
                    "未レビューです"
                ),
            )
        )

    trace = TraceWriter(output_dir, identifier, enabled=True)
    if config.output.save_prompts:
        warnings.append(
            ReportWarning(
                level="warn",
                source="output",
                message=(
                    "save_prompts が有効です。プロンプト全文が "
                    f"{output_dir} に保存されます。.gitignore への追加を確認してください"
                ),
            )
        )

    try:
        review_pass = await review_and_aggregate(config, setup, tasks, candidates)
    finally:
        # 途中で例外になっても接続 (httpx.AsyncClient) を残さない
        await close_providers(setup)
    schedule = review_pass.schedule
    findings = review_pass.findings
    warnings.extend(
        ReportWarning(level="warn", source="aggregate", message=message)
        for message in review_pass.warnings
    )
    warnings.extend(
        ReportWarning(level="warn", source="review", message=message)
        for message in schedule.warnings
    )
    if schedule.stopped_reason:
        warnings.append(
            ReportWarning(level="warn", source="budget", message=schedule.stopped_reason)
        )

    trace.write_run(
        {
            "run_id": identifier,
            "started_at": started_at,
            # 絶対パスは残さない (§6.1)。ユーザー名やディレクトリ構成が artifact に出る
            "target": root.name,
            "config": config.masked_dump(),
            "scanners": [run.model_dump(mode="json") for run in runs],
            "reviewers": sorted(setup.configs),
            "candidates": len(candidates),
            "reviewed": len(schedule.reviewed_candidate_ids),
        }
    )
    for call_trace in schedule.traces:
        trace.write_call(call_trace)

    score = compute_score(candidates, runs, findings)
    coverage = _coverage(runs, candidates, reviewed=len(schedule.reviewed_candidate_ids))
    report = Report(
        tool_version=__version__,
        run_id=identifier,
        started_at=started_at,
        finished_at=utcnow(),
        target=target,
        scanners=runs,
        reviewers=_reviewer_runs(setup, schedule),
        candidates=candidates,
        outside_diff=outside,
        suppressed=suppressed,
        findings=findings,
        coverage=coverage,
        score=score,
        warnings=warnings,
        severity_counts=count_by_severity(candidates),
        finding_counts=count_by_status(findings),
        usage=schedule.usage,
        stopped_reason=schedule.stopped_reason,
        trace_dir=output_relative(trace.root, output_dir),
    )
    decision = evaluate(report, config.policy)
    _log_finish(report, decision)
    return RunOutcome(report=report, decision=decision, output_dir=output_dir, results=results)


async def close_providers(setup: ReviewerSetup) -> None:
    """Provider をすべて閉じる. 1 つの aclose が失敗しても、残りは閉じる."""
    async with contextlib.AsyncExitStack() as stack:
        for provider in setup.providers:
            stack.push_async_callback(provider.aclose)


@dataclass
class ReviewPass:
    """一次レビュー (+ Judge) と集約の結果."""

    findings: list[Finding]
    schedule: ScheduleResult
    warnings: list[str] = field(default_factory=list)


async def review_and_aggregate(
    config: Config,
    setup: ReviewerSetup,
    tasks: list[ReviewTask],
    candidates: list[Candidate],
) -> ReviewPass:
    """Reviewer で判定し、集約する. strategy: judge なら割れた候補を Judge に回す (§16)."""
    strategy = config.aggregation.strategy
    judge_name = config.aggregation.judge.reviewer if strategy == "judge" else None
    aggregator, warnings = build_aggregator(
        config.aggregation.judge.fallback if judge_name else strategy,
        weights={reviewer.name: reviewer.weight for reviewer in config.reviewers},
    )
    reviewers = [runtime for runtime in setup.runtimes if runtime.name != judge_name]
    judge = next((runtime for runtime in setup.runtimes if runtime.name == judge_name), None)
    if judge_name is not None and not reviewers:
        raise ConfigError(
            "aggregation.strategy: judge には、Judge 以外の Reviewer が少なくとも 1 つ必要です"
        )

    started = time.monotonic()
    schedule = await ReviewScheduler(
        reviewers, budget=config.budget, deadline_s=config.budget.deadline_s
    ).run(tasks)
    findings = build_findings(
        candidates,
        schedule.verdicts,
        aggregator=aggregator,
        aggregation=config.aggregation,
        policy=config.policy,
    )
    if judge is not None:
        remaining_s = config.budget.deadline_s - (time.monotonic() - started)
        findings = await _judge(config, judge, tasks, findings, schedule, warnings, remaining_s)
    return ReviewPass(findings=findings, schedule=schedule, warnings=warnings)


async def _judge(
    config: Config,
    judge: ReviewerRuntime,
    tasks: list[ReviewTask],
    findings: list[Finding],
    schedule: ScheduleResult,
    warnings: list[str],
    deadline_s: float,
) -> list[Finding]:
    """割れた候補を Judge に回し、結果を Finding に反映する. 失敗は fallback のまま残す."""
    targets = {f.candidate.id for f in findings if needs_judge(f, config.aggregation)}
    if not targets:
        return findings

    budget = _remaining_budget(config.budget, schedule.usage)
    if schedule.stopped_reason or budget is None:
        skip_reason = (
            f"一次レビューが停止したため Judge を実行しません: {schedule.stopped_reason}"
            if schedule.stopped_reason
            else "予算を使い切ったため Judge を実行しません"
        )
        warnings.append(skip_reason)
        return [
            apply_judgement(f, None, policy=config.policy, fallback_reason=skip_reason)
            if f.candidate.id in targets
            else f
            for f in findings
        ]

    by_id = {f.candidate.id: f for f in findings}
    # デッドラインは run 全体の上限なので、Judge の段には残り時間だけを渡す
    judged = await ReviewScheduler([judge], budget=budget, deadline_s=max(0.0, deadline_s)).run(
        [task for task in tasks if task.candidate.id in targets],
        opinions={cid: anonymize(cid, by_id[cid].verdicts) for cid in targets},
    )
    # 一次レビューの結果に合流させる (使用量・トレース・Reviewer ごとの呼び出し数)
    schedule.usage = schedule.usage.merge(judged.usage)
    schedule.traces.extend(judged.traces)
    schedule.warnings.extend(judged.warnings)
    schedule.calls += judged.calls
    schedule.disabled_reviewers.update(judged.disabled_reviewers)
    if judged.stopped_reason and not schedule.stopped_reason:
        schedule.stopped_reason = judged.stopped_reason
    for cid, verdicts in judged.verdicts.items():
        schedule.verdicts.setdefault(cid, []).extend(verdicts)

    fallback_reason = judged.stopped_reason or judged.disabled_reviewers.get(judge.name)
    return [
        apply_judgement(
            f,
            next(iter(judged.verdicts.get(f.candidate.id, [])), None),
            policy=config.policy,
            fallback_reason=fallback_reason,
        )
        if f.candidate.id in targets
        else f
        for f in findings
    ]


def _remaining_budget(budget: BudgetConfig, used: Usage) -> BudgetConfig | None:
    """一次レビューで使った分を差し引いた予算. 残りが無ければ None."""
    max_usd = budget.max_usd
    if max_usd is not None and used.estimated_usd is not None:
        max_usd = max_usd - used.estimated_usd
        if max_usd <= 0:
            return None
    max_tokens = budget.max_total_tokens
    if max_tokens is not None:
        max_tokens = max_tokens - used.total_tokens
        if max_tokens <= 0:
            return None
    return budget.model_copy(update={"max_usd": max_usd, "max_total_tokens": max_tokens})


def _reviewer_runs(setup: ReviewerSetup, schedule: ScheduleResult) -> list[ReviewerRun]:
    """Reviewer 単位のサマリ. 無効化された事実もレポートに残す."""
    summaries: list[ReviewerRun] = []
    for runtime in setup.runtimes:
        name = runtime.name
        # SKIPPED は呼ばなかった印 (無効化・停止・rpd 上限) なので、
        # 呼び出し数にも失敗数にも数えない。理由は disabled_reason と stopped_reason に残る
        verdicts = [
            verdict
            for verdict_list in schedule.verdicts.values()
            for verdict in verdict_list
            if verdict.reviewer == name and verdict.status is not VerdictStatus.SKIPPED
        ]
        usage = Usage()
        for verdict in verdicts:
            usage = usage.merge(verdict.usage)
        provider = runtime.reviewer.provider
        summaries.append(
            ReviewerRun(
                name=name,
                model=getattr(provider, "model", None),
                transport=provider.transport,
                dialect=provider.dialect,
                calls=len(verdicts),
                verdicts_ok=sum(1 for v in verdicts if v.status is VerdictStatus.OK),
                verdicts_error=sum(1 for v in verdicts if v.status is not VerdictStatus.OK),
                usage=usage,
                disabled_reason=schedule.disabled_reviewers.get(name),
            )
        )
    return summaries
