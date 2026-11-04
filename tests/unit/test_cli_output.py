"""CLI の表示と、壊れたときの終わり方 (#185〜#227 の回帰).

外部由来の文字列 (パス・コード・スキャナの出力) を rich のマークアップとして読ませないこと、
「0 件」と「検査できなかった」を見分けられること、想定外の例外を exit 1 に見せないことを固定する。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from security_checker import cli
from security_checker.cli import app
from security_checker.errors import ConfigError, ExitCode
from security_checker.models.candidate import Candidate
from security_checker.models.enums import ScanStatus
from security_checker.policy.engine import PolicyDecision
from security_checker.report.terminal import render
from security_checker.testing import FakeScanner
from tests.factories import make_candidate, make_report

runner = CliRunner()


def reviewer_config(tmp_path: Path, extra: str = "") -> None:
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\n"
        "scanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "  osv: { enabled: false }\n"
        "reviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://127.0.0.1:9/v1\n    model: m\n" + extra,
        encoding="utf-8",
    )


def use_scanners(monkeypatch: pytest.MonkeyPatch, *scanners: FakeScanner) -> None:
    monkeypatch.setattr("security_checker.run.build_scanners", lambda config: (list(scanners), []))


def slug_candidate() -> Candidate:
    return make_candidate("c1", path="app/[slug]/page.tsx", line=3, rule_id="rules.[bold]x")


# --- rich のマークアップとして読ませない (#185, #186, #206) ------------------------


def test_dry_run_shows_code_with_brackets_verbatim(tmp_path, monkeypatch):
    reviewer_config(tmp_path)
    (tmp_path / "app" / "[slug]").mkdir(parents=True)
    (tmp_path / "app" / "[slug]" / "page.tsx").write_text(
        "const a = 1;\nconst b = [red]x[/red];\nexec(params.slug);\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    use_scanners(monkeypatch, FakeScanner("semgrep", candidates=[slug_candidate()]))
    result = runner.invoke(app, ["review", str(tmp_path), "--dry-run"])
    assert result.exit_code == ExitCode.OK, result.output
    assert "app/[slug]/page.tsx" in result.stdout
    assert "[red]x[/red]" in result.stdout


def test_terminal_candidate_table_keeps_brackets_in_paths():
    console = Console(record=True, width=200)
    report = make_report([slug_candidate()])
    render(report, PolicyDecision(exit_code=ExitCode.OK), Path("out"), console=console)
    text = console.export_text()
    assert "app/[slug]/page.tsx:3" in text


def test_error_messages_keep_brackets(tmp_path):
    missing = tmp_path / "[nope]"
    result = runner.invoke(app, ["scan", str(missing)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "[nope]" in result.stderr


# --- dry-run / estimate (#187, #189, #191, #215, #216) -----------------------------


def test_dry_run_and_estimate_together_is_a_config_error(tmp_path, monkeypatch):
    reviewer_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["review", str(tmp_path), "--dry-run", "--estimate"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "同時に指定できません" in result.stderr


@pytest.mark.parametrize("flag", ["--dry-run", "--estimate"])
def test_preview_shows_skipped_scanners(tmp_path, monkeypatch, flag):
    reviewer_config(tmp_path)
    monkeypatch.chdir(tmp_path)
    use_scanners(monkeypatch, FakeScanner("trivy", status=ScanStatus.SKIPPED, reason="未導入"))
    result = runner.invoke(app, ["review", str(tmp_path), flag])
    assert result.exit_code == ExitCode.OK, result.output
    assert "trivy" in result.stdout
    assert "未導入" in result.stdout


@pytest.mark.parametrize("flag", ["--dry-run", "--estimate"])
def test_preview_formats_errors_raised_during_the_scan(tmp_path, monkeypatch, flag):
    reviewer_config(tmp_path)
    monkeypatch.chdir(tmp_path)

    def broken(config):
        raise ConfigError("スキャナの設定が壊れています")

    monkeypatch.setattr("security_checker.run.build_scanners", broken)
    result = runner.invoke(app, ["review", str(tmp_path), flag])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "スキャナの設定が壊れています" in result.stderr


def test_dry_run_shows_the_system_prompt_and_its_language(tmp_path, monkeypatch):
    reviewer_config(tmp_path, "output:\n  language: ja\n")
    monkeypatch.chdir(tmp_path)
    use_scanners(monkeypatch)
    result = runner.invoke(app, ["review", str(tmp_path), "--dry-run"])
    assert result.exit_code == ExitCode.OK, result.output
    assert "system (全タスク共通)" in result.stdout
    assert "language: ja" in result.stdout


# --- 存在しないパス・設定の警告 (#214, #227) ---------------------------------------


@pytest.mark.parametrize(
    "args",
    [["config", "show", "{missing}"], ["providers", "check", "--path", "{missing}"]],
)
def test_commands_refuse_a_missing_directory(tmp_path, args):
    missing = str(tmp_path / "nope")
    result = runner.invoke(app, [a.format(missing=missing) for a in args])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "検査対象が見つかりません" in result.stderr


def test_providers_check_shows_config_warnings(tmp_path, monkeypatch):
    reviewer_config(tmp_path, "target:\n  root: sub\n")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["providers", "check", "--path", str(tmp_path), "--no-probe"])
    # 受け付けたが効かない設定を、config show と同じく黙って通さない
    assert "target.root (sub) は使われません" in result.stderr


# --- terminal の案内 (#225) と折り返し (#223) ---------------------------------------


def test_terminal_does_not_point_at_a_report_it_did_not_write(tmp_path, monkeypatch):
    reviewer_config(tmp_path, "output:\n  formats: [terminal]\n")
    monkeypatch.chdir(tmp_path)
    use_scanners(monkeypatch)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.OK, result.output
    assert "詳細:" not in result.stdout


def test_terminal_points_at_the_markdown_report_when_written(tmp_path, monkeypatch):
    reviewer_config(tmp_path, "output:\n  formats: [terminal, json, markdown]\n")
    monkeypatch.chdir(tmp_path)
    use_scanners(monkeypatch)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert "report.md" in result.stdout


def test_non_terminal_output_is_not_wrapped():
    console = cli._console()
    assert not console.is_terminal
    assert console.soft_wrap


# --- 想定外の例外は exit 3 (#207) -----------------------------------------------------


def test_unexpected_exceptions_exit_with_an_execution_error(monkeypatch, capsys):
    def explode() -> None:
        raise NotADirectoryError("出力先がディレクトリではありません")

    monkeypatch.setattr(cli, "app", explode)
    monkeypatch.setattr(sys, "argv", ["security-checker"])
    with pytest.raises(SystemExit) as info:
        cli.main()
    assert info.value.code == ExitCode.EXECUTION_ERROR
    err = capsys.readouterr().err
    assert "NotADirectoryError" in err
    assert "内部エラー" in err
