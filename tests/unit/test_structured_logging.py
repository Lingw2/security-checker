"""構造化ログ (設計書 §24.1)."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator

import pytest
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.observability import logging as log


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    yield
    log.disable()
    log.set_run_id(None)


def test_json_lines_carry_run_id_and_fields():
    stream = io.StringIO()
    log.configure(fmt="json", stream=stream)
    log.set_run_id("RUN1")
    log.event("review.call", reviewer="alpha", latency_ms=12)
    record = json.loads(stream.getvalue())
    assert record["run_id"] == "RUN1"
    assert record["event"] == "review.call"
    assert record["level"] == "info"
    assert record["reviewer"] == "alpha"
    assert record["ts"].endswith("Z")


def test_text_format_and_level_filter():
    stream = io.StringIO()
    log.configure(fmt="text", level="warn", stream=stream)
    log.event("quiet")
    log.event("loud", level="warn", reason="x")
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert "warn" in lines[0] and "loud reason=x" in lines[0]


def test_secrets_are_masked():
    stream = io.StringIO()
    log.configure(fmt="json", stream=stream)
    secret = "sk-" + "A" * 40
    log.event("provider.error", detail=f"bad key {secret}")
    assert secret not in stream.getvalue()


def test_nothing_is_emitted_unless_enabled(capsys):
    log.disable()
    log.event("silent")
    assert capsys.readouterr().err == ""


def test_cli_log_format_json_writes_events_to_stderr(tmp_path, monkeypatch):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nscanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "-q", "--log-format", "json"])
    assert result.exit_code == 0
    events = [
        json.loads(line)["event"] for line in result.stderr.splitlines() if line.startswith("{")
    ]
    assert events[-1] == "run.finish"
    # 標準出力はレポート用に空けておく
    assert result.stdout.strip() == ""


def test_cli_default_emits_no_logs(tmp_path, monkeypatch):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nscanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["scan", str(tmp_path), "-q"])
    assert "run.finish" not in result.stderr


def test_text_values_with_spaces_or_equals_are_quoted():
    """key=value の区切りを曖昧にしない. 改行でログ行を偽装させない (#663)."""
    stream = io.StringIO()
    log.configure(fmt="text", stream=stream)
    log.event("e", reason="rate limit hit", expr="a=b", plain="ok", forged="x\nfake line", n=3)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    line = lines[0]
    assert 'reason="rate limit hit"' in line
    assert 'expr="a=b"' in line
    assert "plain=ok" in line
    assert 'forged="x\\nfake line"' in line
    assert "n=3" in line
