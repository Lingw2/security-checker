"""`explain <finding-id>` — その判定に至った全呼び出しを再表示する (設計書 §24.2).

「なぜこの判定になったか」を後から完全に追跡できることが P4 (Auditable) の到達点。
report.json の Finding と、trace/<run_id>/calls/*.json の呼び出し記録を突き合わせる。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate
from security_checker.models.finding import Finding
from security_checker.models.report import Report, SuppressedCandidate


@dataclass
class Explanation:
    candidate: Candidate
    finding: Finding | None = None
    suppressed: SuppressedCandidate | None = None
    outside_diff: bool = False
    calls: list[dict[str, Any]] = field(default_factory=list)
    trace_dir: Path | None = None


def load_report(path: Path) -> Report:
    if not path.is_file():
        raise ConfigError(f"レポートが見つかりません: {path}")
    try:
        return Report.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ConfigError(f"レポートを読めません ({path}): {exc}") from exc


def explain(report: Report, finding_id: str, *, report_path: Path | None = None) -> Explanation:
    """ID (先頭一致可) から候補を引き、判定と呼び出し記録を集める."""
    pool: list[Candidate] = [
        *report.candidates,
        *report.outside_diff,
        *(item.candidate for item in report.suppressed),
    ]
    matches = {c.id: c for c in pool if c.id == finding_id or c.id.startswith(finding_id)}
    if not matches:
        raise ConfigError(f"ID '{finding_id}' の候補はこのレポートにありません")
    if len(matches) > 1 and finding_id not in matches:
        raise ConfigError(
            f"ID '{finding_id}' に一致する候補が複数あります: {', '.join(sorted(matches))}"
        )
    candidate = matches.get(finding_id) or next(iter(matches.values()))

    result = Explanation(candidate=candidate)
    result.finding = next((f for f in report.findings if f.candidate.id == candidate.id), None)
    result.suppressed = next((s for s in report.suppressed if s.candidate.id == candidate.id), None)
    result.outside_diff = any(c.id == candidate.id for c in report.outside_diff)

    trace_dir = _trace_dir(report, report_path)
    result.trace_dir = trace_dir
    if trace_dir is not None:
        for call_path in sorted((trace_dir / "calls").glob("*.json")):
            try:
                call = json.loads(call_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if call.get("candidate_id") == candidate.id:
                call["_file"] = call_path.name
                result.calls.append(call)
    return result


def _trace_dir(report: Report, report_path: Path | None) -> Path | None:
    """trace_dir は出力先からの相対 (古いレポートでは絶対パス). 移したレポートでも見つける."""
    candidates: list[Path] = []
    if report.trace_dir:
        if report_path is not None:
            candidates.append(report_path.parent / report.trace_dir)
        candidates.append(Path(report.trace_dir))
    if report_path is not None:
        candidates.append(report_path.parent / "trace" / report.run_id)
    return next((path for path in candidates if (path / "calls").is_dir()), None)


def render(result: Explanation) -> str:
    """人間向けのテキスト."""
    c = result.candidate
    lines = [
        f"候補 {c.id}",
        f"  {c.scanner}/{c.rule_id}  {c.where}",
        f"  {c.title}",
        f"  スキャナの重大度: {(c.severity_reported.value if c.severity_reported else '-')}",
        f"  {c.message}",
        "",
    ]
    if result.suppressed is not None:
        note = f" ({result.suppressed.note})" if result.suppressed.note else ""
        lines += [f"抑制: {result.suppressed.reason.value}{note}", ""]
    if result.outside_diff:
        lines += ["diff の範囲外のためレビューしていません", ""]
    finding = result.finding
    if finding is not None:
        lines += [
            f"判定: {finding.status.value}  severity {finding.severity.value}  "
            f"confidence {finding.confidence:.2f}  agreement {finding.agreement.value}",
            f"  {finding.summary}",
        ]
        if finding.aggregation is not None:
            agg = finding.aggregation
            lines.append(
                f"  集約: {agg.strategy} ({agg.votes_vulnerable}/{agg.votes_total} が脆弱と判定)"
            )
            judge = agg.detail.get("judge")
            if isinstance(judge, dict):
                lines.append(f"  Judge ({judge.get('reviewer')}): {judge.get('rationale')}")
            elif agg.detail.get("fallback_used"):
                lines.append(f"  Judge は使われませんでした: {agg.detail['fallback_used']}")
        lines.append("")
        for verdict in finding.verdicts:
            lines.append(
                f"- {verdict.reviewer} ({verdict.model}) status={verdict.status.value} "
                f"vulnerable={verdict.vulnerable} severity={verdict.severity.value} "
                f"confidence={verdict.confidence:.2f} fp={verdict.false_positive_probability:.2f}"
            )
            lines.append(f"    {verdict.reasoning}")
            if verdict.attack_path:
                lines.append(f"    攻撃経路: {' → '.join(verdict.attack_path)}")
        lines.append("")

    if result.trace_dir is None:
        lines.append("呼び出し記録 (trace) が見つかりません")
    elif not result.calls:
        lines.append(f"この候補の呼び出し記録はありません ({result.trace_dir})")
    else:
        lines.append(f"呼び出し記録: {len(result.calls)} 件 ({result.trace_dir / 'calls'})")
        for call in result.calls:
            params = call.get("params") or {}
            usage = call.get("usage") or {}
            response = call.get("response") or {}
            lines.append(
                f"- {call.get('_file')} {call.get('reviewer')} ({call.get('model')}) "
                f"attempt={call.get('attempt')} status={call.get('status')} "
                f"{call.get('latency_ms')} ms "
                f"in={usage.get('input_tokens')} out={usage.get('output_tokens')} "
                f"transport={params.get('transport')} structured={params.get('structured_mode')}"
            )
            if call.get("degraded_to"):
                lines.append(f"    構造化出力を {call['degraded_to']} に降格")
            if response.get("error"):
                lines.append(f"    エラー: {response['error']}")
            prompt = call.get("prompt") or {}
            lines.append(f"    prompt sha256: user={str(prompt.get('user_sha256', ''))[:16]}…")
    return "\n".join(lines) + "\n"
