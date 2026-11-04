"""人間が読むレポート (設計書 §18.1 の `report.md`).

`report.json` は完全な機械可読レポートであり、人間が読むことを想定していない。
こちらが人間向けの正面出力で、PR コメントにもそのまま貼れる形にする。

方針:
  - **結論を最初に置く。** 何件あって、通ったか落ちたかを 1 行目で分かるようにする。
  - **review_required を confirmed の直後に置く** (§18.2)。割れた判断こそ人間が見る。
  - **ツールが失敗した事実を隠さない** (§7.2)。0 件と検査不能を見分けられる形にする。
  - 本文 (reasoning など) は LLM の出力そのままで、ここでは訳さない。
    言語は `output.language` で決まる (§18)。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import Report
from security_checker.policy.engine import PolicyDecision
from security_checker.report import sanitize as md

MAX_FINDINGS_PER_SECTION = 20
MAX_CANDIDATE_ROWS = 50
MAX_ATTACK_PATH_STEPS = 8
#: 未レビューの一覧と warn の上限. report.md は Step Summary (1 ステップ 1 MiB) にそのまま載る
MAX_LIST_ITEMS = 50
REDACTED_NOTE = md.REDACTED_NOTE

SEVERITY_MARK = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
    Severity.NONE: "⚪",
}
SCAN_MARK = {ScanStatus.OK: "✅", ScanStatus.SKIPPED: "⏭️", ScanStatus.FAILED: "❌"}

# 表示順と見出し. review_required は confirmed の直後 (§18.2)。
SECTIONS: tuple[tuple[FindingStatus, str], ...] = (
    (FindingStatus.CONFIRMED, "確認された問題"),
    (FindingStatus.REVIEW_REQUIRED, "要人間判断 (判断が割れた / 信頼度が低い)"),
    (FindingStatus.LIKELY, "可能性が高い"),
    (FindingStatus.INCONCLUSIVE, "判定不能"),
    (FindingStatus.ERROR, "レビュー失敗"),
    (FindingStatus.NOT_REVIEWED, "未レビュー"),
)
STATUS_LABELS = {
    FindingStatus.CONFIRMED: "確認",
    FindingStatus.REVIEW_REQUIRED: "要判断",
    FindingStatus.LIKELY: "可能性大",
    FindingStatus.INCONCLUSIVE: "判定不能",
    FindingStatus.ERROR: "失敗",
    FindingStatus.NOT_REVIEWED: "未レビュー",
    FindingStatus.FALSE_POSITIVE: "誤検出",
}


def render_markdown(report: Report, decision: PolicyDecision) -> str:
    """report.md の本文を組み立てる."""
    lines: list[str] = []
    lines += _headline(report, decision)
    lines += _summary(report)
    lines += _warnings(report)
    if report.findings:
        lines += _findings(report)
    elif report.candidates:
        lines += _candidates(report)
    lines += _footer(report)
    return "\n".join(lines).rstrip() + "\n"


def write_markdown(report: Report, decision: PolicyDecision, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.md"
    path.write_text(render_markdown(report, decision), encoding="utf-8")
    return path


# --- 各節 -------------------------------------------------------------------


def _headline(report: Report, decision: PolicyDecision) -> list[str]:
    """1 行目で結論が分かるようにする."""
    mark = "❌" if decision.failed else "✅"
    verdict = "ポリシー違反あり" if decision.failed else "ポリシー違反なし"
    lines = [
        "# セキュリティレビュー結果",
        "",
        f"## {mark} {verdict}",
        "",
    ]
    if decision.reasons:
        lines += [f"- {reason}" for reason in decision.reasons]
        lines.append("")
    return lines


def _summary(report: Report) -> list[str]:
    score = report.score
    partial = " ⚠️ **部分的な検査結果です**" if score.partial else ""
    lines = [
        "| 項目 | 値 |",
        "|---|---|",
        f"| スコア | **{score.value}/100** (rank {score.rank}){partial} |",
        f"| 候補 | {report.coverage.candidates_total} 件 "
        f"(レビュー済み {report.coverage.candidates_reviewed} 件) |",
    ]
    if report.suppression_label:
        lines.append(f"| 抑制 | {report.suppression_label} (レビュー・判定の対象外) |")
    if report.findings:
        counts = report.finding_counts
        breakdown = " / ".join(
            f"{STATUS_LABELS[status]} {counts.get(status.value, 0)}"
            for status, _ in SECTIONS
            if counts.get(status.value, 0)
        )
        false_positives = counts.get(FindingStatus.FALSE_POSITIVE.value, 0)
        if false_positives:
            breakdown = (breakdown + " / " if breakdown else "") + f"誤検出 {false_positives}"
        lines.append(f"| 判定 | {breakdown or 'なし'} |")

    scanners = " ".join(
        f"{SCAN_MARK[run.status]} {run.scanner}"
        + (f" ({run.candidate_count})" if run.status is ScanStatus.OK else "")
        for run in report.scanners
    )
    lines.append(f"| スキャナ | {scanners or '(なし)'} |")

    if report.reviewers:
        reviewers = " / ".join(
            f"`{run.name}` ({run.transport}, {run.calls} 回"
            + (f", 失敗 {run.verdicts_error}" if run.verdicts_error else "")
            + ")"
            for run in report.reviewers
        )
        usage = report.usage
        cost = (
            f"${usage.estimated_usd:.4f}"
            if usage.cost_known and usage.estimated_usd is not None
            else "unknown"
        )
        lines.append(f"| Reviewer | {reviewers} |")
        lines.append(f"| 使用量 | {usage.total_tokens:,} tokens / コスト {cost} |")
    lines.append("")
    return lines


def _warnings(report: Report) -> list[str]:
    """エラーは畳まずに全部出す. 「壊れているのに緑」を作らないため (§7.2).

    warn は件数が膨らみうる (semgrep の parse 警告など) ので上限で切り、残りの件数を書く。
    """
    errors = [w for w in report.warnings if w.level == "error"]
    notices = [w for w in report.warnings if w.level == "warn"]
    if not errors and not notices:
        return []
    lines = ["## 警告", ""]
    lines += [f"- ❌ **{w.source}**: {_flatten(w.message)}" for w in errors]
    lines += [f"- ⚠️ {w.source}: {_flatten(w.message)}" for w in notices[:MAX_LIST_ITEMS]]
    if len(notices) > MAX_LIST_ITEMS:
        lines.append(f"- _ほか {len(notices) - MAX_LIST_ITEMS} 件の警告は `report.json` を参照_")
    lines.append("")
    return lines


def _findings(report: Report) -> list[str]:
    lines: list[str] = []
    shown = 0
    for status, title in SECTIONS:
        group = [f for f in report.findings if f.status is status and f.suppressed is None]
        if not group:
            continue
        lines += [f"## {title} ({len(group)} 件)", ""]
        if status is FindingStatus.NOT_REVIEWED:
            lines += [
                "予算・上限・中断のためレビューされていません。"
                "「問題なし」ではないことに注意してください。",
                "",
            ]
            lines += [
                f"- {md.code_span(f.candidate.where)} {_flatten(f.candidate.title)}"
                for f in group[:MAX_LIST_ITEMS]
            ]
            if len(group) > MAX_LIST_ITEMS:
                lines.append(f"- _ほか {len(group) - MAX_LIST_ITEMS} 件は `report.json` を参照_")
            lines.append("")
            continue
        for finding in group[:MAX_FINDINGS_PER_SECTION]:
            lines += _finding_block(finding)
            shown += 1
        if len(group) > MAX_FINDINGS_PER_SECTION:
            lines += [
                f"_ほか {len(group) - MAX_FINDINGS_PER_SECTION} 件は `report.json` を参照_",
                "",
            ]

    false_positives = sum(1 for f in report.findings if f.status is FindingStatus.FALSE_POSITIVE)
    if shown == 0 and false_positives:
        lines += [
            f"報告対象の問題はありません (誤検出と判定: {false_positives} 件)。",
            "",
        ]
    return lines


def _finding_block(finding: Finding) -> list[str]:
    candidate = finding.candidate
    mark = SEVERITY_MARK[finding.severity]
    heading = f"### {mark} {finding.severity.value.upper()} — {md.code_span(candidate.where)}"
    lines = [heading, ""]

    meta = [f"**確信度** {finding.confidence:.0%}", f"**一致度** {finding.agreement.value}"]
    if finding.cwe:
        meta.insert(0, "**CWE** " + ", ".join(finding.cwe[:3]))
    lines += [" ・ ".join(meta), ""]
    lines += [f"検出元: `{candidate.scanner}` / `{candidate.rule_id}`", ""]

    if candidate.redacted:
        lines += [f"> {REDACTED_NOTE}", ""]

    summary = finding.summary or candidate.message
    if summary:
        lines += [md.text(summary.strip()), ""]

    ok_verdicts = [v for v in finding.verdicts if v.status.value == "ok"]
    if ok_verdicts:
        lines += ["| Reviewer | 判定 | 確信度 |", "|---|---|---|"]
        for verdict in ok_verdicts:
            judgement = f"{verdict.severity.value}" if verdict.vulnerable else "脆弱ではない"
            lines.append(f"| `{verdict.reviewer}` | {judgement} | {verdict.confidence:.0%} |")
        lines.append("")

    for verdict in ok_verdicts:
        if verdict.attack_path:
            path = " → ".join(
                _flatten(step) for step in verdict.attack_path[:MAX_ATTACK_PATH_STEPS]
            )
            lines += [f"**攻撃経路**: {path}", ""]
            break

    for verdict in ok_verdicts:
        if verdict.remediation is not None and verdict.remediation.approach:
            lines += ["**対応方針**", "", md.text(verdict.remediation.approach.strip()), ""]
            if verdict.remediation.example:
                lines += [*md.code_block(verdict.remediation.example.strip()), ""]
            break

    details = [v for v in ok_verdicts if v.reasoning]
    if details:
        lines += ["<details><summary>各 Reviewer の判断理由</summary>", ""]
        for verdict in details:
            lines += [f"**`{verdict.reviewer}`** — {md.text(verdict.reasoning.strip())}", ""]
        lines += ["</details>", ""]

    failed = [v for v in finding.verdicts if v.status.value != "ok"]
    for verdict in failed:
        lines += [f"> ⚠️ `{verdict.reviewer}` は判定できませんでした: {verdict.status.value}", ""]
    return lines


def _candidates(report: Report) -> list[str]:
    """LLM 未実行のとき. スキャナの報告をそのまま出す (判定済みと混同させない)."""
    lines = [
        "## 候補 (スキャナの報告 / LLM 判定前)",
        "",
        "これは**判定結果ではありません**。誤検出が含まれます。",
        "",
        "| 重大度 | スキャナ | ルール | 場所 |",
        "|---|---|---|---|",
    ]
    for candidate in report.candidates[:MAX_CANDIDATE_ROWS]:
        severity = candidate.severity_reported or Severity.INFO
        lines.append(
            f"| {SEVERITY_MARK[severity]} {severity.value} | `{candidate.scanner}` | "
            f"{_flatten(candidate.title)}{' 🔒' if candidate.redacted else ''} | "
            f"{md.code_span(candidate.where)} |"
        )
    if any(c.redacted for c in report.candidates[:MAX_CANDIDATE_ROWS]):
        lines += ["", f"_{REDACTED_NOTE[2:]} (🔒 の候補)_"]
    if len(report.candidates) > MAX_CANDIDATE_ROWS:
        remaining = len(report.candidates) - MAX_CANDIDATE_ROWS
        lines += ["", f"_ほか {remaining} 件は `report.json` を参照_"]
    lines.append("")
    return lines


def _footer(report: Report) -> list[str]:
    lines = [
        "---",
        "",
        f"security-checker v{report.tool_version} / run `{report.run_id}` / "
        f"target `{report.target.root}` ({report.target.label})",
    ]
    if report.stopped_reason:
        lines += ["", f"⚠️ 途中で停止しました: {report.stopped_reason}"]
    if report.trace_dir:
        lines += ["", f"監査証跡: `{report.trace_dir}`"]
    return lines


def _flatten(text: str) -> str:
    """表とリストを壊さないよう、改行とパイプを潰す. 中身は無害化する."""
    return " ".join(md.text(text).split()).replace("|", "\\|")
