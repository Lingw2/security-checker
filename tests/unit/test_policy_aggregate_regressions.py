"""判定・集約・ポリシーの回帰 (#300, #441, #446, #459, #460, #462)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from security_checker.aggregate.findings import _merge_cwe
from security_checker.aggregate.judge import _label
from security_checker.config.schema import PolicyConfig
from security_checker.errors import ExitCode
from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.report import ScannerRun
from security_checker.models.verdict import ReviewJudgement, VerdictStatus
from security_checker.policy.engine import evaluate
from security_checker.policy.ignore import AnnotationReader, parse_ignore_file
from tests.factories import make_candidate, make_finding, make_report, make_verdict


def judgement(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "vulnerable": True,
        "severity": "high",
        "confidence": 0.9,
        "false_positive_probability": 0.1,
        "reasoning": "r",
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    "overrides",
    [{"vulnerable": True, "severity": "none"}, {"vulnerable": False, "severity": "high"}],
)
def test_contradictory_judgements_are_schema_errors(overrides):
    with pytest.raises(ValidationError, match="severity"):
        ReviewJudgement.model_validate(judgement(**overrides))


@pytest.mark.parametrize("severity", ["none", "info"])
def test_not_vulnerable_with_none_or_info_is_accepted(severity):
    ReviewJudgement.model_validate(judgement(vulnerable=False, severity=severity))


def test_empty_ignore_brackets_suppress_nothing_and_warn(tmp_path):
    (tmp_path / "app.py").write_text("x()  # security-checker: ignore[] reason=?\n", "utf-8")
    reader = AnnotationReader(tmp_path)
    assert reader.find(make_candidate(path="app.py", line=1)) is None
    assert any("ignore[*]" in w for w in reader.warnings)


def test_ignore_file_comments_after_tabs_are_stripped():
    ignore, _ = parse_ignore_file("vendor/**\t# 外部のコード\nliteral\\#hash\n")
    assert ignore.path_patterns == ["vendor/**", "literal#hash"]


def test_strict_execution_errors_keep_the_policy_violations_too():
    candidate = make_candidate()
    runs = [ScannerRun(scanner="trivy", category="config", status=ScanStatus.FAILED)]
    report = make_report(
        [candidate], [make_finding(candidate, FindingStatus.CONFIRMED)], scanners=runs
    )
    decision = evaluate(report, PolicyConfig(strict=True, fail_on=Severity.HIGH))
    assert decision.exit_code is ExitCode.EXECUTION_ERROR
    assert "trivy" in decision.reasons[0]
    assert any("high 以上" in reason for reason in decision.reasons[1:])


def test_cwe_comes_only_from_reviewers_that_found_it_vulnerable():
    candidate = make_candidate(cwe=["CWE-78"])
    verdicts = [
        make_verdict("a", cwe=["CWE-89"]),
        make_verdict("b", vulnerable=False, cwe=["CWE-79"]),
        make_verdict("c", status=VerdictStatus.PROVIDER_ERROR, vulnerable=False, cwe=["CWE-22"]),
    ]
    assert _merge_cwe(candidate, verdicts) == ["CWE-78", "CWE-89"]


def test_judge_labels_do_not_repeat_after_26_reviewers():
    labels = [_label(i) for i in range(60)]
    assert len(set(labels)) == 60
    assert labels[:2] == ["A", "B"]
    assert labels[25:28] == ["Z", "AA", "AB"]
