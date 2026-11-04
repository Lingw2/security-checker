"""ターミナル出力 (設計書 §18.2).

「ツールが失敗した」ことを最初に、はっきり出す。0 件と検査不能を見分けられない出力にしない。
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import Report
from security_checker.policy.engine import PolicyDecision

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
    Severity.NONE: "dim",
}
STATUS_MARK = {
    ScanStatus.OK: ("✓", "green"),
    ScanStatus.SKIPPED: ("-", "yellow"),
    ScanStatus.FAILED: ("✗", "bold red"),
}
MAX_ROWS = 50
MAX_FINDING_PANELS = 20

# review_required を confirmed の直後に置く。割れた判断こそ人間が見るべきもの (§18.2)。
FINDING_SECTIONS: tuple[tuple[FindingStatus, str, str], ...] = (
    (FindingStatus.CONFIRMED, "CONFIRMED", "bold red"),
    (FindingStatus.REVIEW_REQUIRED, "REVIEW REQUIRED", "bold yellow"),
    (FindingStatus.LIKELY, "LIKELY", "red"),
    (FindingStatus.INCONCLUSIVE, "INCONCLUSIVE", "yellow"),
    (FindingStatus.ERROR, "ERROR", "bold red"),
    (FindingStatus.NOT_REVIEWED, "NOT REVIEWED", "dim"),
)
WARNING_CHARS = 160


def _one_line(message: str, limit: int = WARNING_CHARS) -> str:
    """警告は 1 行に畳む. スキャナは数十行のエラーを吐くことがあり、画面を潰すため."""
    collapsed = " ".join(message.split())
    return collapsed if len(collapsed) <= limit else collapsed[:limit] + " …(全文は report.json)"


def _header(report: Report) -> Text:
    text = Text()
    text.append(f"security-checker v{report.tool_version}", style="bold")
    text.append(f"   run {report.run_id}", style="dim")
    text.append(f"   target: {report.target.root} ({report.target.label})")
    return text


def _scanner_line(report: Report) -> Text:
    text = Text()
    for index, run in enumerate(report.scanners):
        if index:
            text.append("  ")
        mark, style = STATUS_MARK[run.status]
        text.append(f"{run.scanner} ", style="bold")
        text.append(mark, style=style)
        if run.status is ScanStatus.OK:
            text.append(f" {run.candidate_count}")
        elif run.status is ScanStatus.SKIPPED:
            text.append(" skipped", style="yellow")
        else:
            suffix = f" (exit {run.exit_code})" if run.exit_code is not None else ""
            text.append(f" failed{suffix}", style="bold red")
    if not report.scanners:
        text.append("(有効なスキャナがありません)", style="yellow")
    return text


def _candidate_table(report: Report) -> Table:
    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("severity", width=9)
    table.add_column("scanner", width=9)
    table.add_column("rule")
    table.add_column("location", overflow="fold")
    for candidate in report.candidates[:MAX_ROWS]:
        severity = candidate.severity_reported or Severity.INFO
        table.add_row(
            Text(severity.value.upper(), style=SEVERITY_STYLE[severity]),
            # 外部由来の文字列は Text で渡す. str だと `app/[slug]/page.tsx` の [slug] が
            # rich のマークアップとして消える
            Text(candidate.scanner),
            Text(candidate.title + (" (値はマスク済み)" if candidate.redacted else "")),
            Text(candidate.where),
        )
    return table


def _finding_panel(finding: Finding, style: str) -> Panel:
    candidate = finding.candidate
    body = Text()
    body.append(f"{finding.severity.value.upper():<9}", style=SEVERITY_STYLE[finding.severity])
    if finding.cwe:
        body.append(f"{', '.join(finding.cwe[:2]):<12} ", style="cyan")
    body.append(finding.summary or candidate.message[:120])
    body.append(f"\n{candidate.where}", style="dim")
    if candidate.redacted:
        body.append("   値はマスクして保存・送信", style="dim")
    body.append(f"   confidence {finding.confidence:.2f}", style="dim")
    body.append(f"   agreement: {finding.agreement.value}", style="dim")

    verdicts = [v for v in finding.verdicts if v.status.value == "ok"]
    if verdicts:
        body.append("\n")
        body.append(
            "  ".join(
                f"{v.reviewer}: "
                + (f"{v.severity.value} ({v.confidence:.2f})" if v.vulnerable else "not vulnerable")
                for v in verdicts
            ),
            style="dim",
        )
    for verdict in verdicts:
        if verdict.attack_path:
            body.append("\nAttack path: " + " → ".join(verdict.attack_path[:6]), style="dim")
            break
    return Panel(body, border_style=style, title=None)


def _render_findings(console: Console, report: Report) -> None:
    shown = 0
    for status, label, style in FINDING_SECTIONS:
        group = [f for f in report.findings if f.status is status and f.suppressed is None]
        if not group:
            continue
        if status is FindingStatus.NOT_REVIEWED:
            console.print()
            console.print(
                Text(
                    f"  {label}: {len(group)} 件 (予算・上限・中断のため未レビュー)",
                    style=style,
                )
            )
            continue
        console.print()
        console.print(Text(f"┌ {label} ({len(group)})", style=style))
        for finding in group[:MAX_FINDING_PANELS]:
            console.print(_finding_panel(finding, style))
            shown += 1
        if len(group) > MAX_FINDING_PANELS:
            console.print(
                Text(
                    f"  … ほか {len(group) - MAX_FINDING_PANELS} 件は report.json 参照", style="dim"
                )
            )
    false_positives = sum(1 for f in report.findings if f.status is FindingStatus.FALSE_POSITIVE)
    if shown == 0 and false_positives:
        console.print()
        console.print(Text(f"  報告対象なし (false_positive {false_positives} 件)", style="green"))


def _reviewer_line(report: Report) -> Text:
    text = Text()
    for index, run in enumerate(report.reviewers):
        if index:
            text.append("  ")
        text.append(f"{run.name} ", style="bold")
        text.append(f"({run.calls} calls)")
        if run.verdicts_error:
            text.append(f" error {run.verdicts_error}", style="red")
        if run.disabled_reason:
            text.append(" 無効化", style="bold red")
    usage = report.usage
    text.append(f"     tokens: {usage.total_tokens:,}", style="dim")
    if usage.cost_known and usage.estimated_usd is not None:
        text.append(f"  cost: ${usage.estimated_usd:.4f}", style="dim")
    else:
        text.append("  cost: unknown", style="dim")
    return text


def _summary_line(report: Report) -> Text:
    """最下部の件数サマリ. レビュー後は status 別、スキャンのみなら severity 別."""
    summary = Text("  ")
    if report.findings:
        counts = report.finding_counts
        for status, _label, style in FINDING_SECTIONS:
            summary.append(f"{status.value} {counts.get(status.value, 0)}   ", style=style)
        summary.append(
            f"false_positive {counts.get(FindingStatus.FALSE_POSITIVE.value, 0)}", style="dim"
        )
        return summary
    counts = report.severity_counts
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        summary.append(
            f"{severity.value} {counts.get(severity.value, 0)}   ", style=SEVERITY_STYLE[severity]
        )
    return summary


def render(
    report: Report,
    decision: PolicyDecision,
    output_dir: Path,
    console: Console | None = None,
    *,
    details: Path | None = None,
) -> None:
    """レポートを描画する (既定は標準出力).

    `details` は実際に書き出した詳細レポート. None なら案内しない
    (書いていないファイルや前回の古いファイルを指さない)。
    """
    if console is None:
        console = Console()
        if not console.is_terminal:
            console.soft_wrap = True
    console.print()
    console.print(_header(report))
    console.print()

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold", width=11)
    grid.add_column()
    grid.add_row("Scanners", _scanner_line(report))
    if report.findings:
        grid.add_row(
            "Candidates",
            f"{report.coverage.candidates_total} 件 "
            f"(レビュー済み {report.coverage.candidates_reviewed} 件)",
        )
        grid.add_row("Reviewers", _reviewer_line(report))
    else:
        grid.add_row(
            "Candidates", f"{report.coverage.candidates_total} 件 (未レビュー: LLM 未実行)"
        )
    if report.suppression_label:
        grid.add_row("Suppressed", f"{report.suppression_label} レビュー・判定の対象外")
    console.print(grid)

    errors = [w for w in report.warnings if w.level == "error"]
    notices = [w for w in report.warnings if w.level == "warn"]
    for warning in errors:
        console.print(Text(f"  ⚠ {warning.source}: {_one_line(warning.message)}", style="bold red"))
    for warning in notices[:5]:
        console.print(Text(f"  · {warning.source}: {_one_line(warning.message)}", style="yellow"))
    if len(notices) > 5:
        console.print(Text(f"  · ほか {len(notices) - 5} 件の警告 (report.json 参照)", style="dim"))

    if report.findings:
        _render_findings(console, report)
    elif report.candidates:
        console.print()
        console.print(
            Panel(
                _candidate_table(report),
                title="CANDIDATES (スキャナの報告 / LLM 判定前)",
                title_align="left",
                border_style="blue",
            )
        )
        if len(report.candidates) > MAX_ROWS:
            console.print(
                Text(
                    f"  … ほか {len(report.candidates) - MAX_ROWS} 件は report.json 参照",
                    style="dim",
                )
            )
    else:
        console.print()
        console.print(Text("  検出なし", style="green"))

    console.print()
    console.print(_summary_line(report))

    score_text = Text(f"  score {report.score.value}/100  rank {report.score.rank}")
    if report.score.partial:
        score_text.append(f"  (partial: {report.score.partial_reason})", style="yellow")
    console.print(score_text)
    if details is not None:
        console.print(Text(f"  詳細: {details}", style="dim"))

    for reason in decision.reasons:
        console.print(Text(f"  ✗ {reason}", style="bold red"))
    console.print()
