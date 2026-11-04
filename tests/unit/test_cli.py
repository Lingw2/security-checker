"""CLI の終了コードと出力のテスト."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.errors import ExitCode

runner = CliRunner()


def disabled_scanners_config(tmp_path: Path) -> None:
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nscanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "  osv: { enabled: false }\n",
        encoding="utf-8",
    )


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "security-checker" in result.stdout


def test_scan_writes_report_and_exits_zero(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path)])

    assert result.exit_code == ExitCode.OK
    payload = json.loads(
        (tmp_path / ".security-checker" / "report.json").read_text(encoding="utf-8")
    )
    assert payload["schema_version"] == 1
    assert payload["candidates"] == []
    assert "score 100/100" in result.stdout


def test_scan_respects_output_dir_and_quiet(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "-o", "out", "--quiet"])

    assert result.exit_code == ExitCode.OK
    assert (tmp_path / "out" / "report.json").is_file()
    assert result.stdout.strip() == ""


def test_scan_writes_sarif_when_requested(tmp_path, monkeypatch):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nscanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "  osv: { enabled: false }\n"
        "output:\n  formats: [json, sarif]\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])

    assert result.exit_code == ExitCode.OK
    sarif = json.loads(
        (tmp_path / ".security-checker" / "report.sarif").read_text(encoding="utf-8")
    )
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "security-checker"
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_scan_missing_target_is_config_error(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "nope")])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_scan_invalid_config_is_config_error(tmp_path, monkeypatch):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\npolicy:\n  fail_on: 大変\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "policy.fail_on" in result.stderr


def test_scan_min_score_violation(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--min-score", "101"])
    assert result.exit_code == 2  # typer の引数検証エラー


def test_config_show_outputs_resolved_json(tmp_path):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\npolicy:\n  fail_on: critical\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["config", "show", str(tmp_path)])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["policy"]["fail_on"] == "critical"


def test_config_show_masks_header_values(tmp_path):
    """headers にはトークンを書きうる. config show は Issue に貼られるので値を出さない (#95)."""
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nreviewers:\n  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: https://example.invalid/v1\n    model: m\n"
        "    headers:\n      X-Api-Key: dummy-value-for-repro\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["config", "show", str(tmp_path)])

    assert result.exit_code == 0
    assert "dummy-value-for-repro" not in result.stdout
    assert json.loads(result.stdout)["reviewers"][0]["headers"] == {"X-Api-Key": "****"}


def test_config_show_explain_reports_origin(tmp_path):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\npolicy:\n  fail_on: critical\n", encoding="utf-8"
    )
    result = runner.invoke(
        app, ["config", "show", str(tmp_path), "--preset", "minimal", "--explain"]
    )

    assert result.exit_code == 0
    assert "preset:minimal" in result.stdout
    assert "policy.fail_on" in result.stdout


def test_config_show_rejects_unknown_preset(tmp_path):
    result = runner.invoke(app, ["config", "show", str(tmp_path), "--preset", "no-such"])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def reviewer_config(tmp_path: Path) -> None:
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\n"
        "scanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "reviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://127.0.0.1:9/v1\n    model: m\n",
        encoding="utf-8",
    )


def test_review_without_reviewers_is_config_error(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["review", str(tmp_path)])

    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "reviewers" in result.stderr


def test_review_missing_api_key_names_the_variable(tmp_path, monkeypatch):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\n"
        "scanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "reviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://127.0.0.1:9/v1\n    model: m\n    api_key_env: SC_TEST_KEY\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("SC_TEST_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["review", str(tmp_path)])

    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "SC_TEST_KEY" in result.stderr


def test_review_dry_run_does_not_call_the_provider(tmp_path, monkeypatch):
    """--dry-run は送信前に内容を見せるだけで、外部には出さない (§19.3)."""
    reviewer_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["review", str(tmp_path), "--dry-run"])

    assert result.exit_code == ExitCode.OK
    assert "dry-run" in result.stdout
    assert "推定入力トークン" in result.stdout


def test_scan_diff_mode_needs_a_base(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\ntarget: { mode: diff }\n"
        "scanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--base" in result.stderr


def test_scan_with_base_outside_git_is_an_execution_error(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--base", "main"])
    assert result.exit_code == ExitCode.EXECUTION_ERROR


def test_scan_full_overrides_the_pr_context(tmp_path, monkeypatch):
    disabled_scanners_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    result = runner.invoke(app, ["scan", str(tmp_path), "--full", "--quiet"])
    assert result.exit_code == ExitCode.OK
    payload = json.loads(
        (tmp_path / ".security-checker" / "report.json").read_text(encoding="utf-8")
    )
    assert payload["target"]["mode"] == "full"
    assert payload["warnings"] == []
