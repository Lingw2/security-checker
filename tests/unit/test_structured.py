"""Structured Output のスキーマ・抽出・修復 (設計書 §10)."""

from __future__ import annotations

import pytest

from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, Severity
from security_checker.models.task import CodeContext, CodeSlice, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import Evidence, ReviewJudgement
from security_checker.review.structured import (
    SchemaViolationError,
    drop_hallucinated_evidence,
    extract_json,
    parse_judgement,
    verdict_schema,
)
from security_checker.testing import verdict_payload


def test_schema_is_inlined_and_hardened():
    schema = verdict_schema()
    serialized = str(schema)
    assert "$defs" not in serialized
    assert "$ref" not in serialized
    assert schema["additionalProperties"] is False
    # strict モードの実装に合わせ、全プロパティを required にする
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["cwe"]["items"]["pattern"] == "^CWE-[0-9]+$"
    assert schema["properties"]["reasoning"]["maxLength"] == 1500
    assert schema["properties"]["evidence"]["items"]["additionalProperties"] is False


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1}',
        '```json\n{"a": 1}\n```',
        '```\n{"a": 1}\n```',
        'ここに説明があります。\n{"a": 1}\nそして後書き。',
        'prefix {"a": 1} suffix',
    ],
)
def test_extract_json_variants(text):
    assert extract_json(text) == {"a": 1}


def test_extract_json_ignores_braces_inside_strings():
    assert extract_json('{"a": "}{"}') == {"a": "}{"}


def test_extract_json_handles_escaped_quotes():
    assert extract_json('{"a": "he said \\"hi\\" }"}') == {"a": 'he said "hi" }'}


@pytest.mark.parametrize("text", ["", "散文だけ", "{壊れた", "[1, 2]"])
def test_extract_json_failure(text):
    assert extract_json(text) is None


def test_parse_judgement_from_text():
    judgement = parse_judgement(
        None, f"```json\n{__import__('json').dumps(verdict_payload())}\n```"
    )
    assert judgement.vulnerable is True
    assert judgement.severity is Severity.HIGH


def test_parse_judgement_reports_validation_errors():
    with pytest.raises(SchemaViolationError) as excinfo:
        parse_judgement({"vulnerable": "yes"}, "raw")
    message = str(excinfo.value)
    assert "vulnerable" in message or "severity" in message
    assert excinfo.value.raw_text == "raw"


def test_parse_judgement_rejects_bad_cwe_format():
    with pytest.raises(SchemaViolationError):
        parse_judgement(verdict_payload(cwe=["78"]), "raw")


def test_parse_judgement_without_json():
    with pytest.raises(SchemaViolationError, match="JSON"):
        parse_judgement(None, "これは JSON ではありません")


def make_task() -> ReviewTask:
    candidate = Candidate(
        id="c1",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="r",
        title="t",
        message="m",
        location=Location(path="src/app.py", start_line=20, end_line=20),
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(
            primary=CodeSlice(path="src/app.py", start_line=10, end_line=30, text="x\n" * 20)
        ),
        repo_facts=RepoFacts(),
        budget=TokenBudget(max_tokens_per_task=8000),
    )


def test_evidence_outside_context_is_dropped():
    """ハルシネーションした位置をレポートに載せない (§11.3)."""
    judgement = ReviewJudgement.model_validate(
        verdict_payload(
            evidence=[
                {"path": "src/app.py", "start_line": 20, "end_line": 20, "note": "ok"},
                {"path": "src/app.py", "start_line": 999, "end_line": 999, "note": "範囲外"},
                {"path": "other/file.py", "start_line": 20, "end_line": 20, "note": "別ファイル"},
            ]
        )
    )
    checked, warnings = drop_hallucinated_evidence(judgement, make_task())

    assert [item.start_line for item in checked.evidence] == [20]
    assert len(warnings) == 2


def test_evidence_within_context_is_kept():
    judgement = ReviewJudgement.model_validate(
        verdict_payload(
            evidence=[
                Evidence(path="src/app.py", start_line=15, end_line=15, note="ok").model_dump()
            ]
        )
    )
    checked, warnings = drop_hallucinated_evidence(judgement, make_task())
    assert len(checked.evidence) == 1
    assert warnings == []


def test_schema_sent_to_the_llm_has_no_internal_descriptions():
    """pydantic の docstring (日本語の内部メモ) をプロンプトに送らない (#290)."""
    import json

    from security_checker.review.structured import verdict_schema

    text = json.dumps(verdict_schema(), ensure_ascii=False)
    assert '"description"' not in text
