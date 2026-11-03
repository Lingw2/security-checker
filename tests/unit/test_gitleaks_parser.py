"""gitleaks パーサとマスキングの回帰テスト (設計書 §19.2, §25.1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_checker.models.enums import Category, Severity
from security_checker.scanners.base import UnparseableOutputError
from security_checker.scanners.gitleaks import parse_gitleaks, redact_raw_entry

ROOT = Path("/repo")
PLAINTEXT_SECRETS = [
    "xoxb-TESTONLY-0000000000-abcdefghijklmnopqrstuvwx",
    "TESTONLY-abcdef0123456789",
]


def test_basic_normalization(raw_fixture):
    candidates, warnings = parse_gitleaks(raw_fixture("gitleaks_basic.json"), ROOT)

    assert warnings == []
    assert len(candidates) == 2
    first = candidates[0]
    assert first.category is Category.SECRET
    assert first.severity_reported is Severity.CRITICAL
    assert first.cwe == ["CWE-798"]
    assert first.redacted is True
    assert first.location is not None
    assert first.location.path == "settings.py"


def test_secret_values_never_appear_anywhere(raw_fixture):
    """検出値がレポートのどこにも現れないこと. これが崩れると二次漏洩になる."""
    candidates, _ = parse_gitleaks(raw_fixture("gitleaks_basic.json"), ROOT)
    serialized = json.dumps([c.model_dump(mode="json") for c in candidates], ensure_ascii=False)

    for secret in PLAINTEXT_SECRETS:
        assert secret not in serialized
    assert "xoxb" in serialized  # 形式が分かる程度の prefix は残す


def test_raw_entry_is_redacted(raw_fixture):
    entry = raw_fixture("gitleaks_basic.json")[0]
    redacted = redact_raw_entry(entry)
    assert redacted["Secret"].startswith("xoxb")
    assert PLAINTEXT_SECRETS[0] not in json.dumps(redacted)
    assert redacted["StartLine"] == 2  # 位置情報は残す


def test_raw_entry_paths_are_relativized():
    entry = {
        "RuleID": "r",
        "File": "/repo/src/settings.py",
        "Fingerprint": "/repo/src/settings.py:r:2",
        "StartLine": 2,
    }
    redacted = redact_raw_entry(entry, ROOT)
    assert redacted["File"] == "src/settings.py"
    assert redacted["Fingerprint"] == "src/settings.py:r:2"


def test_broken_entries_are_reported_not_swallowed(raw_fixture):
    candidates, warnings = parse_gitleaks(
        raw_fixture("gitleaks_broken.json"), ROOT, exclude=["**/vendor/**"]
    )

    rule_ids = [candidate.rule_id for candidate in candidates]
    assert rule_ids == ["no-start-line"]
    # null / RuleID 欠落 / File 欠落 / StartLine 欠落 の 4 件を握り潰さずに報告する
    assert len(warnings) == 4
    assert candidates[0].location is not None
    assert candidates[0].location.start_line == 0


def test_empty_and_missing_payloads():
    assert parse_gitleaks(None, ROOT) == ([], [])
    assert parse_gitleaks([], ROOT) == ([], [])
    with pytest.raises(UnparseableOutputError):
        parse_gitleaks({"配列ではない": True}, ROOT)
