"""PR コメント — sticky サマリと inline コメント (設計書 §21.3).

ノイズ抑制の原則:
  1. `false_positive` は PR に出さない (report.json には残る)。
  2. sticky サマリは**編集して使い回す**。push のたびにコメントを増やさない。
     指摘ゼロなら既存コメントを ✅ に更新し、コメントが無ければ何も投稿しない (既定)。
  3. 同じ fingerprint の inline コメントは**再投稿しない**。
  4. `review_required` は出すが、CI は落とさない (exit code は policy engine が決める)。

本文の大半は LLM の出力であり、レビュー対象のコードに由来する文字列を含みうる
(プロンプトインジェクション §19.4)。マーカーの偽装・メンション・シークレットを
ここで無害化してから GitHub に送る。
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from security_checker.config.schema import GithubConfig
from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import Report
from security_checker.report import sanitize as md

#: 重複したサマリの古いほうに書く本文. マーカーを含めないので、以後は更新の対象にならない
STALE_SUMMARY = (
    "このコメントは古い結果です。最新の結果は、この PR の新しいサマリコメントを見てください。"
)
SUMMARY_MARKER = "<!-- security-checker:summary:v2 -->"
FINDING_MARKER_PREFIX = "<!-- security-checker:finding:"
_FINDING_MARKER_RE = re.compile(r"^<!-- security-checker:finding:([A-Za-z0-9-]+) -->")

MAX_SUMMARY_FINDINGS = 15
#: GitHub のコメント本文の上限は 65,536 文字. 余裕を持って切る
MAX_BODY_CHARS = 60_000

SEVERITY_MARK = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
    Severity.NONE: "⚪",
}

#: inline_min_status の「以上」を決める順位. ここに無い状態は inline にしない
_INLINE_RANK: dict[FindingStatus, int] = {
    FindingStatus.CONFIRMED: 3,
    FindingStatus.LIKELY: 2,
    FindingStatus.REVIEW_REQUIRED: 1,
}

#: サマリに載せる順. review_required は confirmed の直後 (§18.2)
_SUMMARY_ORDER = (
    FindingStatus.CONFIRMED,
    FindingStatus.REVIEW_REQUIRED,
    FindingStatus.LIKELY,
)


# --- 無害化 ------------------------------------------------------------------


def sanitize(text: str) -> str:
    """LLM / スキャナ由来の文字列を PR に載せられる形にする.

    - HTML (コメント・タグ) を無効化する (マーカーの偽装・本文の隠蔽を防ぐ)
    - 画像を無効化し、@メンションを無効化する (レビュー対象のコードから任意の人を呼び出させない)
    - 既知形式のシークレットを伏せる

    規則は `report.md` と共通 (`security_checker.report.sanitize`)。
    """
    return md.text(text)


def _truncate(text: str, limit: int) -> str:
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def _one_line(text: str, limit: int = 300) -> str:
    return _truncate(sanitize(text), limit)


# --- 何を出すか ----------------------------------------------------------------


def visible_findings(report: Report) -> list[Finding]:
    """PR に出す Finding. 誤検出・抑制済み・判定の無いものは出さない."""
    return [
        finding
        for finding in report.findings
        if finding.suppressed is None and finding.status in _SUMMARY_ORDER
    ]


def has_problems(report: Report) -> bool:
    """サマリで「問題あり」として扱うか. 判定前の候補 (scan のみ) も含める."""
    if report.findings:
        return bool(visible_findings(report))
    return bool(report.candidates)


# --- sticky サマリ ---------------------------------------------------------------


def render_summary(report: Report, *, report_url: str | None = None) -> str:
    """sticky サマリコメントの本文. 先頭行は必ずマーカー."""
    lines = [SUMMARY_MARKER, "## 🛡 AI Security Review", ""]
    lines += _counts_line(report)
    lines += _scanner_warnings(report)
    lines.append("")

    if report.findings:
        shown = visible_findings(report)
        if not shown:
            lines += ["✅ 問題は検出されませんでした。", ""]
        ordered = sorted(shown, key=lambda f: (_SUMMARY_ORDER.index(f.status), -f.severity.order))
        for finding in ordered[:MAX_SUMMARY_FINDINGS]:
            lines += ["---", *_summary_block(finding)]
        if len(ordered) > MAX_SUMMARY_FINDINGS:
            lines += [f"_ほか {len(ordered) - MAX_SUMMARY_FINDINGS} 件は full report を参照_", ""]
    elif report.candidates:
        lines += _candidate_table(report)
    else:
        lines += ["✅ 問題は検出されませんでした。", ""]

    lines += ["---", _footer(report, report_url)]
    body = "\n".join(lines).rstrip() + "\n"
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS] + "\n\n_(長すぎるため省略しました。full report を参照)_\n"
    return body


def _counts_line(report: Report) -> list[str]:
    if not report.findings:
        if report.reviewers:
            return [f"候補 {len(report.candidates)} 件"]
        return [f"候補 {len(report.candidates)} 件 (スキャナのみ・LLM による判定なし)"]
    counts = report.finding_counts
    parts = [
        f"**{counts.get('confirmed', 0)} confirmed**",
        f"{counts.get('likely', 0)} likely",
        f"**{counts.get('review_required', 0)} review required**",
        f"{counts.get('false_positive', 0)} false positive (suppressed)",
    ]
    lines = [" · ".join(parts)]
    for status, label in (
        (FindingStatus.NOT_REVIEWED, "未レビュー"),
        (FindingStatus.ERROR, "レビュー失敗"),
        (FindingStatus.INCONCLUSIVE, "判定不能"),
    ):
        if counts.get(status.value):
            lines.append(f"⚠️ {label} {counts[status.value]} 件 (「問題なし」ではありません)")
    reviewers = ", ".join(f"`{run.name}`" for run in report.reviewers)
    strategy = next(
        (f.aggregation.strategy for f in report.findings if f.aggregation is not None), None
    )
    if reviewers:
        lines.append(
            f"Reviewers: {reviewers}" + (f" · Aggregation: {strategy}" if strategy else "")
        )
    if report.target.mode == "diff":
        lines.append(
            f"範囲: `{report.target.base}` との差分 ({report.target.changed_files or 0} ファイル)"
        )
    return [line + "  " for line in lines[:-1]] + lines[-1:]


def _scanner_warnings(report: Report) -> list[str]:
    """壊れた事実を隠さない (§7.2)."""
    return [
        f"⚠️ `{run.scanner}` が失敗したため、この観点の検査は行われていません。"
        for run in report.scanners
        if run.status is ScanStatus.FAILED
    ]


def _summary_block(finding: Finding) -> list[str]:
    candidate = finding.candidate
    cwe = f" · {finding.cwe[0]}" if finding.cwe else ""
    title = _one_line(finding.summary or candidate.title, 120)
    if finding.status is FindingStatus.REVIEW_REQUIRED:
        lines = [
            f"### ❓ REVIEW REQUIRED{cwe} · {title}",
            f"{md.code_span(candidate.where)} · agreement **{finding.agreement.value}**",
            "",
            "判断が分かれました。人間による確認を推奨します。",
        ]
        for verdict in finding.verdicts:
            if verdict.status.value != "ok":
                continue
            judgement = (
                f"脆弱 ({verdict.severity.value}, {verdict.confidence:.2f})"
                if verdict.vulnerable
                else f"脆弱でない ({verdict.confidence:.2f})"
            )
            lines.append(
                f"- `{verdict.reviewer}`: {judgement} — 「{_one_line(verdict.reasoning, 160)}」"
            )
        return [*lines, ""]

    mark = SEVERITY_MARK[finding.severity]
    label = finding.severity.value.upper()
    if finding.status is FindingStatus.LIKELY:
        label += " (likely)"
    lines = [
        f"### {mark} {label}{cwe} · {title}",
        f"{md.code_span(candidate.where)} · confidence **{finding.confidence:.0%}** · "
        f"agreement **{finding.agreement.value}**",
        "",
    ]
    ok = [v for v in finding.verdicts if v.status.value == "ok" and v.vulnerable]
    path = next((v.attack_path for v in ok if v.attack_path), [])
    if path:
        lines += [
            "**Attack path**",
            " → ".join(md.code_span(_truncate(s, 80)) for s in path[:8]),
            "",
        ]
    reasoning = finding.supporting_reasoning
    if reasoning:
        lines += ["**Reason**", _one_line(reasoning, 800), ""]
    remediation = next((v.remediation for v in ok if v.remediation is not None), None)
    if remediation is not None and remediation.approach:
        lines += ["**Remediation**", _one_line(remediation.approach, 600), ""]
    if finding.verdicts:
        lines += [
            "<details><summary>各 Reviewer の判定</summary>",
            "",
            "| Reviewer | vulnerable | severity | confidence | FP prob |",
            "|---|---|---|---|---|",
        ]
        for verdict in finding.verdicts:
            if verdict.status.value != "ok":
                lines.append(f"| `{verdict.reviewer}` | ⚠️ {verdict.status.value} | | | |")
                continue
            lines.append(
                f"| `{verdict.reviewer}` | {'✅' if verdict.vulnerable else '—'} | "
                f"{verdict.severity.value} | {verdict.confidence:.2f} | "
                f"{verdict.false_positive_probability:.2f} |"
            )
        lines += ["</details>", ""]
    return lines


def _candidate_table(report: Report) -> list[str]:
    lines = [
        "これは**判定結果ではありません** (LLM レビューなし)。誤検出が含まれます。",
        "",
        "| 重大度 | スキャナ | ルール | 場所 |",
        "|---|---|---|---|",
    ]
    for candidate in report.candidates[:MAX_SUMMARY_FINDINGS]:
        severity = candidate.severity_reported or Severity.INFO
        lines.append(
            f"| {SEVERITY_MARK[severity]} {severity.value} | `{candidate.scanner}` | "
            f"{_one_line(candidate.title, 80).replace('|', '/')} | "
            f"{md.code_span(candidate.where)} |"
        )
    if len(report.candidates) > MAX_SUMMARY_FINDINGS:
        lines.append(f"\n_ほか {len(report.candidates) - MAX_SUMMARY_FINDINGS} 件_")
    return [*lines, ""]


def _footer(report: Report, report_url: str | None) -> str:
    parts = [
        f"security-checker v{report.tool_version}",
        f"{report.coverage.candidates_total} candidates → "
        f"{report.coverage.candidates_reviewed} reviewed",
    ]
    usage = report.usage
    if usage.cost_known and usage.estimated_usd is not None:
        parts.append(f"${usage.estimated_usd:.4f}")
    if report_url:
        parts.append(f"[full report]({report_url})")
    return "<sub>" + " · ".join(parts) + "</sub>"


# --- inline コメント --------------------------------------------------------------


def finding_marker(finding: Finding) -> str:
    return f"{FINDING_MARKER_PREFIX}{finding.candidate.id} -->"


def existing_finding_ids(bodies: Iterable[str]) -> set[str]:
    """既に投稿した inline コメントの fingerprint. マーカーは本文の先頭にあるものだけ認める."""
    found: set[str] = set()
    for body in bodies:
        match = _FINDING_MARKER_RE.match(body)
        if match:
            found.add(match.group(1))
    return found


def render_inline(finding: Finding) -> str:
    candidate = finding.candidate
    if finding.status is FindingStatus.REVIEW_REQUIRED:
        head = "❓ **REVIEW REQUIRED** — Reviewer の判断が分かれました"
    else:
        head = (
            f"{SEVERITY_MARK[finding.severity]} **{finding.severity.value.upper()}** "
            f"({finding.status.value}, confidence {finding.confidence:.0%})"
        )
    lines = [finding_marker(finding), head, ""]
    lines.append(_one_line(finding.summary or candidate.message, 300))
    reasoning = finding.supporting_reasoning
    if reasoning:
        lines += ["", _one_line(reasoning, 600)]
    remediation = next(
        (v.remediation for v in finding.verdicts if v.remediation is not None and v.vulnerable),
        None,
    )
    if remediation is not None and remediation.approach:
        lines += ["", f"**Remediation**: {_one_line(remediation.approach, 400)}"]
    lines += ["", f"<sub>`{candidate.scanner}/{candidate.rule_id}`</sub>"]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class InlineComment:
    path: str
    line: int
    body: str
    finding_id: str


@dataclass
class InlinePlan:
    comments: list[InlineComment] = field(default_factory=list)
    already_posted: int = 0
    outside_diff: int = 0
    over_limit: int = 0
    #: base 側の変更と重なり、PR の head の行に対応づけられなかった件数
    unmapped: int = 0


def plan_inline(
    report: Report,
    settings: GithubConfig,
    commentable: Mapping[str, Iterable[tuple[int, int]]],
    posted_ids: set[str],
    *,
    to_head: Callable[[str, int], int | None] | None = None,
) -> InlinePlan:
    """inline コメントの投稿計画を立てる (§21.3).

    `commentable` は PR の diff に含まれる新しい側の行範囲 (GitHub は範囲外に付けられない)。
    パスはリポジトリルートから、行番号は PR の head の行番号で数える。
    `to_head` は検査した行番号を head の行番号に直す。base 側の変更と重なって対応の取れない行は
    推測せず `unmapped` に数える。
    """
    plan = InlinePlan()
    if not settings.inline_comments:
        return plan
    threshold = _INLINE_RANK.get(settings.inline_min_status)
    if threshold is None:
        return plan
    ranges = {path: list(spans) for path, spans in commentable.items()}
    targets = sorted(
        (
            f
            for f in visible_findings(report)
            if _INLINE_RANK.get(f.status, 0) >= threshold and f.candidate.location is not None
        ),
        key=lambda f: (-_INLINE_RANK[f.status], -f.severity.order),
    )
    for finding in targets:
        location = finding.candidate.location
        assert location is not None  # noqa: S101 - 上の絞り込みで保証済み
        if finding.candidate.id in posted_ids:
            plan.already_posted += 1
            continue
        path = report.target.repo_prefix + location.path
        line = max(location.end_line, location.start_line, 1)
        start = max(location.start_line, 1)
        if to_head is not None:
            head_start, head_line = to_head(path, start), to_head(path, line)
            if head_start is None or head_line is None:
                plan.unmapped += 1
                continue
            start, line = head_start, head_line
        spans = ranges.get(path, [])
        # 範囲内でいちばん下の行に付ける (複数行の指摘でも、変更行に乗るように)
        anchor = next(
            (
                min(line, hi)
                for lo, hi in sorted(spans, key=lambda s: -s[1])
                if lo <= line and start <= hi
            ),
            None,
        )
        if anchor is None:
            plan.outside_diff += 1
            continue
        if len(plan.comments) >= settings.max_inline_comments:
            plan.over_limit += 1
            continue
        plan.comments.append(
            InlineComment(
                path=path,
                line=anchor,
                body=render_inline(finding),
                finding_id=finding.candidate.id,
            )
        )
    return plan


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def commentable_ranges(patch: str) -> list[tuple[int, int]]:
    """PR files API の `patch` から、新しい側でコメントできる行範囲を取る (文脈行を含む)."""
    spans: list[tuple[int, int]] = []
    for match in _HUNK_RE.finditer(patch):
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        if count > 0:
            spans.append((start, start + count - 1))
    return spans
