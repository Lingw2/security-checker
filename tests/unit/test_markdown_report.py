"""人間向けレポート report.md (設計書 §18.1).

report.json は機械可読用で人間が読む物ではない。こちらが人間向けの正面出力なので、
「結論が最初に来る」「壊れた事実が隠れない」を回帰として押さえる。
"""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.errors import ExitCode
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import (
    Agreement,
    Category,
    FindingStatus,
    ScanStatus,
    Severity,
)
from security_checker.models.finding import Finding
from security_checker.models.report import (
    Coverage,
    Report,
    ReportWarning,
    ReviewerRun,
    ScannerRun,
    Score,
    TargetInfo,
    utcnow,
)
from security_checker.models.verdict import (
    Remediation,
    ReviewVerdict,
    Usage,
    VerdictStatus,
)
from security_checker.policy.engine import PolicyDecision
from security_checker.report.markdown import render_markdown, write_markdown


@pytest.fixture
def candidate() -> Candidate:
    return Candidate(
        id="c1",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.command-injection",
        title="command-injection",
        message="shell=True にユーザー入力が渡ります",
        location=Location(path="src/app.py", start_line=42, end_line=42),
        severity_reported=Severity.HIGH,
    )


def verdict(reviewer: str, **overrides: Any) -> ReviewVerdict:
    payload = {
        "candidate_id": "c1",
        "reviewer": reviewer,
        "model": "m",
        "status": VerdictStatus.OK,
        "vulnerable": True,
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "false_positive_probability": 0.05,
        "reasoning": "ユーザー入力がシェルに連結されています。",
        "attack_path": ["POST /upload", "filename", "subprocess.run"],
        "remediation": Remediation(approach="argv のリストで渡す", example="run([...])"),
        "usage": Usage(input_tokens=100, output_tokens=50),
    }
    payload.update(overrides)
    if not payload["vulnerable"] and "severity" not in overrides:
        payload["severity"] = Severity.NONE
    return ReviewVerdict(**payload)


def make_report(candidate: Candidate, findings: list[Finding], **overrides: Any) -> Report:
    payload = {
        "tool_version": "2.0.0",
        "run_id": "R1",
        "started_at": utcnow(),
        "finished_at": utcnow(),
        "target": TargetInfo(root="/repo", mode="full"),
        "scanners": [
            ScannerRun(
                scanner="semgrep",
                category=Category.SAST,
                status=ScanStatus.OK,
                candidate_count=1,
            )
        ],
        "candidates": [candidate],
        "findings": findings,
        "coverage": Coverage(
            scanners_total=1,
            scanners_ok=1,
            scanners_skipped=0,
            scanners_failed=0,
            candidates_total=1,
            candidates_reviewed=len(findings),
        ),
        "score": Score(value=80, rank="B", partial=False),
    }
    payload.update(overrides)
    return Report(**payload)


def finding(candidate: Candidate, status: FindingStatus, **overrides: Any) -> Finding:
    payload = {
        "candidate": candidate,
        "status": status,
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "agreement": Agreement.HIGH,
        "cwe": ["CWE-78"],
        "summary": "OS コマンドインジェクション",
        "verdicts": [verdict("r1")],
    }
    payload.update(overrides)
    return Finding(**payload)


def test_verdict_comes_first(candidate):
    report = make_report(candidate, [finding(candidate, FindingStatus.CONFIRMED)])
    decision = PolicyDecision(ExitCode.POLICY_VIOLATION, ["high 以上の confirmed が 1 件"])
    body = render_markdown(report, decision)

    head = body.splitlines()[:4]
    assert head[0] == "# セキュリティレビュー結果"
    assert "ポリシー違反あり" in head[2]
    assert "high 以上の confirmed が 1 件" in body


def test_passing_run_says_so_at_the_top(candidate):
    report = make_report(candidate, [finding(candidate, FindingStatus.FALSE_POSITIVE)])
    body = render_markdown(report, PolicyDecision(ExitCode.OK))
    assert "✅ ポリシー違反なし" in body
    assert "誤検出と判定: 1 件" in body


def test_review_required_is_placed_right_after_confirmed(candidate):
    """割れた判断こそ人間が見るべきもの (§18.2)."""
    findings = [
        finding(candidate, FindingStatus.LIKELY),
        finding(candidate, FindingStatus.REVIEW_REQUIRED),
        finding(candidate, FindingStatus.CONFIRMED),
    ]
    body = render_markdown(make_report(candidate, findings), PolicyDecision(ExitCode.OK))
    assert body.index("確認された問題") < body.index("要人間判断") < body.index("可能性が高い")


def test_finding_block_carries_the_reviewer_reasoning(candidate):
    body = render_markdown(
        make_report(candidate, [finding(candidate, FindingStatus.CONFIRMED)]),
        PolicyDecision(ExitCode.OK),
    )
    assert "`src/app.py:42`" in body
    assert "CWE-78" in body
    assert "ユーザー入力がシェルに連結されています。" in body
    assert "POST /upload → filename → subprocess.run" in body
    assert "argv のリストで渡す" in body


def test_scanner_failure_is_visible(candidate):
    """0 件と検査不能を見分けられない出力にしない (§7.2)."""
    report = make_report(
        candidate,
        [],
        scanners=[
            ScannerRun(
                scanner="gitleaks",
                category=Category.SECRET,
                status=ScanStatus.FAILED,
                exit_code=2,
            )
        ],
        warnings=[ReportWarning(level="error", source="gitleaks", message="起動に失敗")],
        score=Score(value=100, rank="A", partial=True, partial_reason="gitleaks 失敗"),
    )
    body = render_markdown(report, PolicyDecision(ExitCode.EXECUTION_ERROR))
    assert "❌ gitleaks" in body
    assert "起動に失敗" in body
    assert "部分的な検査結果です" in body


def test_not_reviewed_is_not_presented_as_safe(candidate):
    report = make_report(candidate, [finding(candidate, FindingStatus.NOT_REVIEWED, verdicts=[])])
    body = render_markdown(report, PolicyDecision(ExitCode.OK))
    assert "「問題なし」ではないことに注意" in body


def test_candidates_are_labelled_as_pre_judgement(candidate):
    """LLM 未実行のとき、スキャナの報告を判定結果と混同させない."""
    body = render_markdown(make_report(candidate, []), PolicyDecision(ExitCode.OK))
    assert "LLM 判定前" in body
    assert "判定結果ではありません" in body


def test_failed_verdict_is_reported_not_hidden(candidate):
    broken = verdict("r2", status=VerdictStatus.PROVIDER_ERROR, vulnerable=False)
    report = make_report(
        candidate,
        [finding(candidate, FindingStatus.CONFIRMED, verdicts=[verdict("r1"), broken])],
    )
    body = render_markdown(report, PolicyDecision(ExitCode.OK))
    assert "`r2` は判定できませんでした" in body


def test_reviewer_and_usage_row(candidate):
    report = make_report(
        candidate,
        [finding(candidate, FindingStatus.CONFIRMED)],
        reviewers=[
            ReviewerRun(name="local-command", transport="process", dialect="text_io", calls=1)
        ],
        usage=Usage(input_tokens=1000, output_tokens=200, cost_known=False),
    )
    body = render_markdown(report, PolicyDecision(ExitCode.OK))
    assert "`local-command` (process, 1 回)" in body
    assert "コスト unknown" in body


def test_pipes_in_text_do_not_break_tables(candidate):
    noisy = candidate.model_copy(update={"title": "a | b | c"})
    body = render_markdown(make_report(noisy, []), PolicyDecision(ExitCode.OK))
    assert r"a \| b \| c" in body


def test_write_markdown_creates_the_file(candidate, tmp_path):
    report = make_report(candidate, [finding(candidate, FindingStatus.CONFIRMED)])
    path = write_markdown(report, PolicyDecision(ExitCode.OK), tmp_path / "out")
    assert path.name == "report.md"
    assert path.read_text(encoding="utf-8").startswith("# セキュリティレビュー結果")
