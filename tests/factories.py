"""レポート系テストで使う組み立て関数.

SARIF・PR コメントなど、Report を入力に取る出力のテストが同じ形のデータを必要とするため、
ここにまとめる。
"""

from __future__ import annotations

from typing import Any

from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Agreement, Category, FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import (
    Coverage,
    Report,
    ScannerRun,
    Score,
    TargetInfo,
    count_by_status,
    utcnow,
)
from security_checker.models.verdict import Remediation, ReviewVerdict, Usage, VerdictStatus


def make_candidate(
    candidate_id: str = "c1",
    *,
    path: str = "src/app.py",
    line: int = 42,
    severity: Severity | None = Severity.HIGH,
    scanner: str = "semgrep",
    rule_id: str = "rules.command-injection",
    **overrides: Any,
) -> Candidate:
    payload: dict[str, Any] = {
        "id": candidate_id,
        "scanner": scanner,
        "category": Category.SAST,
        "rule_id": rule_id,
        "title": "command-injection",
        "message": "shell=True にユーザー入力が渡ります",
        "location": Location(path=path, start_line=line, end_line=line),
        "severity_reported": severity,
        "cwe": ["CWE-78"],
    }
    payload.update(overrides)
    return Candidate(**payload)


def make_verdict(reviewer: str, candidate_id: str = "c1", **overrides: Any) -> ReviewVerdict:
    payload: dict[str, Any] = {
        "candidate_id": candidate_id,
        "reviewer": reviewer,
        "model": "m",
        "status": VerdictStatus.OK,
        "vulnerable": True,
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "false_positive_probability": 0.05,
        "reasoning": "ユーザー入力がシェルに連結されています。",
        "attack_path": ["POST /upload", "filename", "subprocess.run"],
        "remediation": Remediation(approach="argv のリストで渡す"),
        "usage": Usage(input_tokens=100, output_tokens=50),
    }
    payload.update(overrides)
    if not payload["vulnerable"] and "severity" not in overrides:
        payload["severity"] = Severity.NONE  # 「脆弱ではない」の severity は none か info
    return ReviewVerdict(**payload)


def make_finding(candidate: Candidate, status: FindingStatus, **overrides: Any) -> Finding:
    payload: dict[str, Any] = {
        "candidate": candidate,
        "status": status,
        "severity": Severity.HIGH,
        "confidence": 0.9,
        "agreement": Agreement.HIGH,
        "cwe": ["CWE-78"],
        "summary": "OS コマンドインジェクション",
        "verdicts": [make_verdict("r1", candidate.id)],
    }
    payload.update(overrides)
    return Finding(**payload)


def make_report(
    candidates: list[Candidate],
    findings: list[Finding] | None = None,
    *,
    scanners: list[ScannerRun] | None = None,
    **overrides: Any,
) -> Report:
    found = findings or []
    runs = scanners or [ScannerRun(scanner="semgrep", category=Category.SAST, status=ScanStatus.OK)]
    payload: dict[str, Any] = {
        "tool_version": "2.0.0",
        "run_id": "R1",
        "started_at": utcnow(),
        "finished_at": utcnow(),
        "target": TargetInfo(root="/repo", mode="full"),
        "scanners": runs,
        "candidates": candidates,
        "findings": found,
        "coverage": Coverage(
            scanners_total=len(runs),
            scanners_ok=sum(1 for run in runs if run.status is ScanStatus.OK),
            scanners_skipped=sum(1 for run in runs if run.status is ScanStatus.SKIPPED),
            scanners_failed=sum(1 for run in runs if run.status is ScanStatus.FAILED),
            candidates_total=len(candidates),
            candidates_reviewed=len(found),
        ),
        "score": Score(value=80, rank="B", partial=False),
        "finding_counts": count_by_status(found) if found else {},
    }
    payload.update(overrides)
    return Report(**payload)
