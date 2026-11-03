"""semgrep パーサのゴールデン / 異常系テスト (設計書 §25.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import SemgrepConfig
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.scanners.base import (
    CommandResult,
    ScanContext,
    Target,
    ToolStatus,
    UnparseableOutputError,
)
from security_checker.scanners.semgrep import SemgrepScanner, parse_semgrep

ROOT = Path("/repo")


def test_basic_normalization(raw_fixture):
    candidates, warnings = parse_semgrep(raw_fixture("semgrep_basic.json"), ROOT)

    assert warnings == []
    assert len(candidates) == 2
    first = candidates[0]
    assert first.scanner == "semgrep"
    assert first.category is Category.SAST
    assert first.severity_reported is Severity.HIGH
    assert first.confidence_reported == 0.9
    assert first.cwe == ["CWE-78"]
    assert first.title == "subprocess-injection"
    assert first.location is not None
    assert first.location.path == "app.py"
    assert first.location.start_line == 16
    assert first.references


def test_empty_results(raw_fixture):
    candidates, warnings = parse_semgrep(raw_fixture("semgrep_empty.json"), ROOT)
    assert candidates == []
    assert warnings == []


def test_broken_entries_are_reported_not_swallowed(raw_fixture):
    candidates, warnings = parse_semgrep(
        raw_fixture("semgrep_broken.json"), ROOT, exclude=["**/vendor/**"]
    )

    # 壊れた 2 件は落ちるが、残りは処理を続ける
    rule_ids = [candidate.rule_id for candidate in candidates]
    assert rule_ids == ["rules.no-start-line", "rules.unknown-severity"]
    assert "rules.excluded" not in rule_ids  # exclude が効いている

    joined = " / ".join(warnings)
    assert "results[0]" in joined
    assert "results[1]" in joined
    assert "Rule ファイルの読み込みに失敗しました" in joined


def test_broken_entry_defaults(raw_fixture):
    candidates, _ = parse_semgrep(raw_fixture("semgrep_broken.json"), ROOT)
    by_rule = {candidate.rule_id: candidate for candidate in candidates}

    no_line = by_rule["rules.no-start-line"]
    assert no_line.location is not None
    assert no_line.location.start_line == 0
    assert no_line.cwe == []  # "壊れた形式" からは CWE を取り出せない

    unknown = by_rule["rules.unknown-severity"]
    assert unknown.severity_reported is Severity.LOW  # 未知の severity は最小に倒す
    assert unknown.location is not None
    assert not unknown.location.path.startswith("/")  # 絶対パスを残さない


def test_non_dict_payload_is_flagged():
    with pytest.raises(UnparseableOutputError):
        parse_semgrep(["結果ではない"], ROOT)
    with pytest.raises(UnparseableOutputError, match="results"):
        parse_semgrep({}, ROOT)
    with pytest.raises(UnparseableOutputError, match="results"):
        parse_semgrep({"results": "x"}, ROOT)


async def test_timeout_s_is_not_passed_as_the_per_rule_timeout(tmp_path, monkeypatch):
    """--timeout は 1 ファイル 1 ルールの上限. 全体の上限を渡すと打ち切りが効かなくなる (#178)."""
    captured: dict[str, Any] = {}

    async def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["timeout_s"] = kwargs["timeout_s"]
        kwargs["stdout_path"].write_text('{"results": []}', encoding="utf-8")
        return CommandResult(exit_code=0, stdout=b"", stderr=b"")

    monkeypatch.setattr("security_checker.scanners.semgrep.run_command", fake_run)
    scanner = SemgrepScanner(SemgrepConfig(timeout_s=600))
    monkeypatch.setattr(scanner, "probe", lambda: ToolStatus(available=True, version="1"))
    result = await scanner.scan(Target(root=tmp_path), ScanContext(raw_dir=tmp_path))
    assert result.status is ScanStatus.OK
    assert "--timeout" not in captured["argv"]
    assert captured["timeout_s"] == 600
