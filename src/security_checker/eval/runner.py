"""評価の実行 (設計書 §27.1).

**実行時と同じ経路を通す。** Context Builder → Reviewer → Aggregator → Finding まで
本番と同じコードを使い、評価専用の近道を作らない。近道を作ると、
測っているものが実際の挙動とずれる。

ケースのコードは一時ディレクトリに書き出してから ContextBuilder に渡す。
「スライスの切り出し」まで含めて本番と同じ条件にするため。
"""

from __future__ import annotations

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from security_checker.config.schema import Config
from security_checker.context.builder import ContextBuilder
from security_checker.context.facts import collect_repo_facts
from security_checker.context.slicer import resolve_inside
from security_checker.errors import ConfigError
from security_checker.eval.dataset import Dataset, EvalCase
from security_checker.eval.metrics import CaseOutcome, Metrics, evaluate_outcomes
from security_checker.models.candidate import Candidate
from security_checker.models.finding import Finding
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import VerdictStatus
from security_checker.observability.cost import PriceTable
from security_checker.report import sanitize as md
from security_checker.run import (
    ReviewerSetup,
    build_reviewers,
    close_providers,
    review_and_aggregate,
    smallest_input_limit,
)


class EvalResult(BaseModel):
    """1 回の評価結果. そのまま JSON として保存できる."""

    model_config = ConfigDict(frozen=True)

    dataset: str
    cases: int
    reviewers: list[str] = Field(default_factory=list)
    aggregation: str = "consensus"
    metrics: Metrics = Metrics()
    outcomes: list[CaseOutcome] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


@dataclass
class _Prepared:
    """ケースごとの一時ワークスペースと ReviewTask."""

    tasks: list[ReviewTask] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    by_id: dict[str, EvalCase] = field(default_factory=dict)


def _prepare(dataset: Dataset, config: Config, workspace: Path, setup: ReviewerSetup) -> _Prepared:
    prepared = _Prepared()
    for case in dataset.cases:
        root = workspace / case.id
        target = resolve_inside(root, case.candidate.path)
        if root.resolve().parent != workspace.resolve() or target is None:
            # dataset の検証を通ったうえでの多重の防御. リンクなどで外に出るなら書かない
            raise ConfigError(f"評価ケース {case.id} の書き出し先がワークスペースの外です")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(case.code, encoding="utf-8")

        candidate = case.to_candidate()
        builder = ContextBuilder(
            root,
            config.context,
            collect_repo_facts(root),
            max_input_tokens=smallest_input_limit(setup),
        )
        prepared.tasks.append(builder.build(candidate))
        prepared.candidates.append(candidate)
        prepared.by_id[case.id] = case
    return prepared


async def run_eval(
    dataset: Dataset,
    config: Config,
    *,
    reviewer_setup: ReviewerSetup | None = None,
    price_table: PriceTable | None = None,
    environ: dict[str, str] | None = None,
    workspace: Path | None = None,
) -> EvalResult:
    """データセットの全ケースをレビューし、指標を計算する."""
    if not config.reviewers and reviewer_setup is None:
        raise ConfigError(
            "reviewers が設定されていません。評価には Reviewer が要ります "
            "(security-checker.yml か --config で指定してください)"
        )

    setup = reviewer_setup or build_reviewers(config, price_table=price_table, environ=environ)
    warnings = list(setup.warnings)

    try:
        with tempfile.TemporaryDirectory(prefix="security-checker-eval-") as temporary:
            root = workspace or Path(temporary)
            prepared = _prepare(dataset, config, root, setup)

            review_pass = await review_and_aggregate(
                config, setup, prepared.tasks, prepared.candidates
            )
    finally:
        # 途中で例外になっても接続 (httpx.AsyncClient) を残さない
        await close_providers(setup)

    schedule = review_pass.schedule
    findings = review_pass.findings
    warnings.extend(review_pass.warnings)
    warnings.extend(schedule.warnings)
    if schedule.stopped_reason:
        warnings.append(schedule.stopped_reason)

    outcomes = [_to_outcome(prepared.by_id[finding.candidate.id], finding) for finding in findings]

    return EvalResult(
        dataset=dataset.name,
        cases=len(dataset.cases),
        reviewers=sorted(setup.configs),
        aggregation=config.aggregation.strategy,
        metrics=evaluate_outcomes(outcomes),
        outcomes=outcomes,
        warnings=warnings,
    )


def _to_outcome(case: EvalCase, finding: Finding) -> CaseOutcome:
    """Finding を採点用の形に落とす."""
    latency = sum(verdict.latency_ms for verdict in finding.verdicts)
    # 1 つでも計測できない transport が混ざったら、合計金額は出さない (§24.3)
    cost_known = all(verdict.usage.cost_known for verdict in finding.verdicts)
    usd: float | None = None
    if cost_known:
        usd = sum(verdict.usage.estimated_usd or 0.0 for verdict in finding.verdicts)

    return CaseOutcome(
        case_id=case.id,
        expected_vulnerable=case.ground_truth.vulnerable,
        expected_severity=case.ground_truth.severity,
        expected_cwe=list(case.ground_truth.cwe),
        status=finding.status,
        severity=finding.severity,
        # スキャナの CWE は数えない. 同梱ケースは候補に正解の CWE が付いており、
        # 足すと LLM が何を答えても一致率が 100% になる (#319)
        cwe=list(
            dict.fromkeys(
                cwe
                for verdict in finding.verdicts
                if verdict.status is VerdictStatus.OK and verdict.vulnerable
                for cwe in verdict.cwe
            )
        ),
        confidence=finding.confidence,
        latency_ms=latency,
        usd=usd,
        cost_known=cost_known,
        summary=finding.summary,
    )


def to_markdown(result: EvalResult) -> str:
    """人間が読む比較表 (§27.3). 数字を隠さない."""
    metrics = result.metrics
    lines = [
        f"# 評価結果: {md.text(result.dataset)}",
        "",
        f"- Reviewer: {', '.join(md.code_span(r) for r in result.reviewers) or '(なし)'}",
        f"- 集約戦略: {result.aggregation}",
        f"- ケース数: {metrics.cases} "
        f"(採点外: エラー {metrics.errors} / 未レビュー {metrics.not_reviewed})",
        "",
        "## 指標",
        "",
        "| 指標 | 値 | 位置づけ |",
        "|---|---|---|",
        f"| **Recall (検出率)** | {_pct(metrics.recall)} | "
        "**主指標**。陽性全体のうち自動で検出した割合。保留は検出に数えない |",
        f"| 判定した中での Recall | {_pct(metrics.answered_recall)} | "
        "参考値。保留が増えると上がるので比較に使わない |",
        f"| Precision | {_pct(metrics.precision)} | 副指標。ノイズの少なさ |",
        f"| F1 | {_pct(metrics.f1)} | 総合 |",
        f"| **FP 削減率** | {_pct(metrics.fp_reduction)} | "
        "このツールの価値そのもの。保留した陰性は削減に数えない |",
        f"| **見逃した真陽性** | {metrics.missed_true_positives} 件 | **0 に近いことが必須条件** |",
        f"| review_required 率 | {_pct(metrics.review_required_rate)} | "
        f"高すぎると実用性が下がる (人間に渡した FP {metrics.deferred_negatives} 件) |",
        f"| Severity MAE | {_num(metrics.severity_mae)} | 重大度判定の質 |",
        f"| CWE 一致率 | {_pct(metrics.cwe_match_rate)} | 分類の質 |",
        f"| コスト | {_usd(metrics)} | 実運用可能性 |",
        f"| レイテンシ / 件 | {metrics.mean_latency_ms:.0f} ms | CI 適合性 |",
        "",
        "## 内訳",
        "",
        "| | 脆弱と報告 | 誤検知と判断 | 人間に委ねた |",
        "|---|---|---|---|",
        f"| 正解: 脆弱 | {metrics.true_positives} | **{metrics.false_negatives}** "
        f"| {metrics.deferred_positives} |",
        f"| 正解: 問題なし | {metrics.false_positives} | {metrics.true_negatives} "
        f"| {metrics.deferred_negatives} |",
        "",
    ]

    if metrics.missed_case_ids:
        # 数字だけでなく、必ず実物を列挙する (§27.2)
        lines += ["## 見逃したケース", ""]
        by_id = {outcome.case_id: outcome for outcome in result.outcomes}
        for case_id in metrics.missed_case_ids:
            outcome = by_id[case_id]
            # summary は LLM の出力. report.md・PR コメントと同じ規則で無害化する (#328)
            summary = " ".join(md.text(outcome.summary).split()) or "(要約なし)"
            lines.append(f"- {md.code_span(case_id)} — {summary}")
        lines.append("")

    if result.warnings:
        lines += ["## 警告", ""]
        lines += [f"- {' '.join(md.text(message).split())}" for message in result.warnings]
        lines.append("")

    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _num(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}"


def _usd(metrics: Metrics) -> str:
    if not metrics.cost_known:
        # 測れないものを測ったふりをしない (§24.3)
        return "unknown (価格の分からないモデルか、計測できない transport を含む)"
    if metrics.total_usd is None:
        return "—"
    return f"${metrics.total_usd:.4f}"


def outcomes_by_case(outcomes: Sequence[CaseOutcome]) -> dict[str, CaseOutcome]:
    return {outcome.case_id: outcome for outcome in outcomes}
