"""`security-checker init` — 環境検出と設定生成 (設計書 §9.8).

既定の Reviewer は 1 つも持たない。特定のベンダーを標準として押し付けないため。
検出できるものが無くても、コマンドを直接指定すれば設定を生成できる。
"""

from __future__ import annotations

import subprocess

import pytest
import yaml
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import Config
from security_checker.errors import ExitCode
from security_checker.providers.detect import Detection

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_detection(monkeypatch):
    """検出結果は実行環境 (PATH・環境変数) で変わる. テストは環境に依存させない."""
    monkeypatch.setattr("security_checker.cli.detect_all", lambda: [])


@pytest.fixture
def one_detection(monkeypatch):
    detection = Detection(
        transport="process",
        name="detected",
        available=True,
        detail="テスト用",
        config={"name": "detected", "transport": "process", "preset": "detected"},
    )
    monkeypatch.setattr("security_checker.cli.detect_all", lambda: [detection])
    return detection


def test_init_without_presets_generates_nothing_and_says_why(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path)], input="\n")
    assert result.exit_code == ExitCode.OK
    assert not (tmp_path / "security-checker.yml").exists()
    assert "--command" in result.stdout


def test_init_with_a_direct_command_writes_a_usable_config(tmp_path):
    result = runner.invoke(
        app, ["init", str(tmp_path), "--command", "my-cmd --non-interactive --no-tools"]
    )
    assert result.exit_code == ExitCode.OK

    document = (tmp_path / "security-checker.yml").read_text(encoding="utf-8")
    config = Config.model_validate(yaml.safe_load(document))
    reviewer = config.reviewers[0]
    assert reviewer.name == "my-cmd"
    assert reviewer.transport == "process"
    assert reviewer.command == ["my-cmd", "--non-interactive", "--no-tools"]
    # 書き込み能力の無効化が利用者の責任であることを、生成物にも残す (§9.7)
    assert "書き込み能力" in document


def test_init_honours_an_explicit_name(tmp_path):
    runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd -q", "--name", "reviewer-a"])
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["name"] == "reviewer-a"


def test_init_refuses_to_overwrite_without_force(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert (tmp_path / "security-checker.yml").read_text(encoding="utf-8") == "version: 1\n"


def test_init_force_overwrites(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--force"])
    assert result.exit_code == ExitCode.OK
    assert "my-cmd" in (tmp_path / "security-checker.yml").read_text(encoding="utf-8")


def test_init_stdout_does_not_touch_the_filesystem(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--stdout"])
    assert result.exit_code == ExitCode.OK
    assert not (tmp_path / "security-checker.yml").exists()
    assert "my-cmd" in result.stdout


def test_init_rejects_a_missing_directory(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path / "nope"), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_init_local_writes_the_gitignored_overlay(tmp_path):
    """共有設定を残したまま、手元用の Reviewer だけを別ファイルに置く."""
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--local"])

    assert result.exit_code == ExitCode.OK
    assert (tmp_path / "security-checker.yml").read_text(encoding="utf-8") == "version: 1\n"
    payload = yaml.safe_load((tmp_path / "security-checker.local.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["command"] == ["my-cmd"]


def test_init_with_a_command_does_not_prompt_about_detections(tmp_path, one_detection):
    """--command は明示指定. 標準入力が無い場面 (CI) でも止まらないこと."""
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.OK
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert [block["name"] for block in payload["reviewers"]] == ["my-cmd"]


def test_init_yes_adopts_detections_alongside_the_command(tmp_path, one_detection):
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--yes"])
    assert result.exit_code == ExitCode.OK
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert [block["name"] for block in payload["reviewers"]] == ["detected", "my-cmd"]


def test_init_suggests_local_when_the_shared_config_exists(tmp_path):
    (tmp_path / "security-checker.yml").write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--local" in result.stdout + str(result.stderr)


# --- 非対話・--stdout・http の model・名前の重複・.gitignore (#195, #208〜#212) -------


def test_init_without_stdin_stops_with_guidance(tmp_path, one_detection):
    """標準入力が無いと番号を尋ねても答えが返らない. Aborted (exit 1) にしない (#208)."""
    result = runner.invoke(app, ["init", str(tmp_path)], input=None)
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--yes" in result.stderr


def test_init_stdout_writes_only_yaml_to_stdout(tmp_path, one_detection):
    result = runner.invoke(app, ["init", str(tmp_path), "--yes", "--stdout"])
    assert result.exit_code == ExitCode.OK, result.output
    payload = yaml.safe_load(result.stdout)
    assert payload["reviewers"][0]["name"] == "detected"
    assert "環境を検出しています" in result.stderr


@pytest.fixture
def http_detection(monkeypatch):
    detection = Detection(
        transport="http",
        name="openai",
        available=True,
        detail="テスト用",
        config={"name": "openai", "transport": "http", "preset": "openai"},
    )
    monkeypatch.setattr("security_checker.cli.detect_all", lambda: [detection])


def test_init_http_detection_gets_the_given_model(tmp_path, http_detection):
    result = runner.invoke(app, ["init", str(tmp_path), "--yes", "--model", "m-1"])
    assert result.exit_code == ExitCode.OK, result.output
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["model"] == "m-1"


def test_init_http_detection_without_a_model_says_so(tmp_path, http_detection):
    result = runner.invoke(app, ["init", str(tmp_path), "--yes"])
    assert result.exit_code == ExitCode.OK, result.output
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert payload["reviewers"][0]["model"] == "<model-id>"
    assert "書き換えてください" in result.stdout
    # 生成した設定はそのまま読める
    Config.model_validate(payload)


def test_init_command_with_a_detected_name_gets_a_unique_name(tmp_path, one_detection):
    result = runner.invoke(app, ["init", str(tmp_path), "--yes", "--command", "detected --x"])
    assert result.exit_code == ExitCode.OK, result.output
    payload = yaml.safe_load((tmp_path / "security-checker.yml").read_text(encoding="utf-8"))
    assert [block["name"] for block in payload["reviewers"]] == ["detected", "detected-2"]


def test_init_explicit_name_that_collides_is_refused(tmp_path, one_detection):
    result = runner.invoke(
        app, ["init", str(tmp_path), "--yes", "--command", "x", "--name", "detected"]
    )
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "--name" in result.stderr


def test_init_local_warns_when_git_does_not_ignore_it(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    result = runner.invoke(app, ["init", str(tmp_path), "--command", "my-cmd", "--local"])
    assert result.exit_code == ExitCode.OK
    assert "git で無視されていません" in result.stdout
    (tmp_path / ".gitignore").write_text("security-checker.local.yml\n", encoding="utf-8")
    result = runner.invoke(
        app, ["init", str(tmp_path), "--command", "my-cmd", "--local", "--force"]
    )
    assert "コミットされません" in result.stdout


def test_windows_command_keeps_backslashes(monkeypatch):
    from security_checker import cli

    monkeypatch.setattr(cli.os, "name", "nt")
    assert cli._split_command('"C:\\Program Files\\x\\cmd.exe" --flag') == [
        "C:\\Program Files\\x\\cmd.exe",
        "--flag",
    ]
