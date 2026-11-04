"""設定の合成順序と検証のテスト (設計書 §12)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from security_checker.config.loader import (
    PRESET_DIR,
    LoadedConfig,
    available_presets,
    env_overrides,
    load_config,
)
from security_checker.config.schema import Config
from security_checker.errors import ConfigError
from security_checker.models.enums import Severity


def write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "security-checker.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_defaults_without_config_file(tmp_path):
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.HIGH
    assert loaded.config.scanners.semgrep.enabled is True
    assert loaded.config_path is None


def test_config_file_is_discovered(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n")
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.CRITICAL
    assert loaded.origins["policy.fail_on"].startswith("file:")


def test_merge_order_cli_wins_over_env_and_file(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n  min_confidence: 0.9\n")
    loaded = load_config(
        tmp_path,
        environ={"SECURITY_CHECKER__POLICY__FAIL_ON": "medium"},
        cli_overrides={"policy": {"fail_on": "low"}},
    )
    assert loaded.config.policy.fail_on is Severity.LOW
    assert loaded.config.policy.min_confidence == 0.9  # 上書きされていない値は保持
    assert loaded.origins["policy.fail_on"] == "cli"


def test_env_overrides_parse_scalars():
    overrides = env_overrides(
        {
            "SECURITY_CHECKER__POLICY__STRICT": "false",
            "SECURITY_CHECKER__CONCURRENCY__SCANNERS": "8",
            "UNRELATED": "x",
        }
    )
    assert overrides == {"policy": {"strict": False}, "concurrency": {"scanners": 8}}


def test_preset_is_applied_then_overridden_by_file(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  strict: true\n")
    loaded = load_config(tmp_path, preset="minimal", environ={})
    assert loaded.config.policy.fail_on is Severity.CRITICAL  # preset 由来
    assert loaded.config.policy.strict is True  # ファイルが後勝ち
    assert loaded.config.scanners.osv.enabled is False


def test_osv_is_enabled_by_default_and_trivy_is_opt_in():
    """依存の既知脆弱性は、設定を書かなくても検査する (#101)."""
    config = Config()
    assert config.scanners.osv.enabled is True
    assert config.scanners.trivy.enabled is False


def test_all_presets_are_valid(tmp_path):
    assert set(available_presets()) == {"ci", "frugal", "minimal", "thorough"}
    for preset in available_presets():
        load_config(tmp_path, preset=preset, environ={})


def test_unknown_preset(tmp_path):
    with pytest.raises(ConfigError, match="preset"):
        load_config(tmp_path, preset="存在しない", environ={})


def test_plaintext_api_key_is_rejected(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n  - name: r1\n    transport: http\n"
        "    dialect: openai_chat\n    base_url: http://x/v1\n    model: m\n"
        "    api_key: TESTONLY-secret\n",
    )
    with pytest.raises(ConfigError, match="api_key_env"):
        load_config(tmp_path, environ={})


def test_unknown_key_is_rejected(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_onn: high\n")
    with pytest.raises(ConfigError, match="fail_onn"):
        load_config(tmp_path, environ={})


def test_broken_yaml_is_config_error(tmp_path):
    write_config(tmp_path, "version: 1\npolicy: [\n")
    with pytest.raises(ConfigError, match="YAML"):
        load_config(tmp_path, environ={})


def test_transport_is_required(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    model: m\n")
    with pytest.raises(ConfigError, match="transport"):
        load_config(tmp_path, environ={})


def test_http_reviewer_requires_endpoint_fields(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    transport: http\n")
    with pytest.raises(ConfigError, match="dialect"):
        load_config(tmp_path, environ={})


def test_process_reviewer_requires_preset_or_command(tmp_path):
    write_config(tmp_path, "version: 1\nreviewers:\n  - name: r1\n    transport: process\n")
    with pytest.raises(ConfigError, match="preset"):
        load_config(tmp_path, environ={})


def test_duplicate_reviewer_names(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n"
        "  - { name: r1, transport: process, command: [echo] }\n"
        "  - { name: r1, transport: process, command: [echo] }\n",
    )
    with pytest.raises(ConfigError, match="重複"):
        load_config(tmp_path, environ={})


def test_judge_reviewer_must_exist(tmp_path):
    write_config(
        tmp_path,
        "version: 1\nreviewers:\n  - { name: r1, transport: process, command: [echo] }\n"
        "aggregation:\n  strategy: judge\n  judge:\n    reviewer: missing\n",
    )
    with pytest.raises(ConfigError, match="judge"):
        load_config(tmp_path, environ={})


def test_explicit_config_path_must_exist(tmp_path):
    with pytest.raises(ConfigError, match="見つかりません"):
        load_config(tmp_path, config_path=tmp_path / "nope.yml", environ={})


def write_local_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "security-checker.local.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_local_config_is_discovered_and_layered_over_the_shared_one(tmp_path):
    """共有設定に手元用の Reviewer を混ぜずに済ませるための層 (§12)."""
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n")
    write_local_config(
        tmp_path,
        "version: 1\nreviewers:\n  - name: mine\n    transport: process\n    command: ['cmd']\n",
    )
    loaded = load_config(tmp_path, environ={})

    assert [r.name for r in loaded.config.reviewers] == ["mine"]
    # 共有設定の値は残る (置き換えではなく重ね合わせ)
    assert loaded.config.policy.fail_on is Severity.CRITICAL
    assert loaded.origins["reviewers"].startswith("local:")
    assert loaded.local_config_path is not None


def test_local_config_wins_over_the_shared_one(tmp_path):
    write_config(tmp_path, "version: 1\npolicy:\n  fail_on: critical\n")
    write_local_config(tmp_path, "version: 1\npolicy:\n  fail_on: low\n")
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.LOW


def test_env_and_cli_still_win_over_the_local_config(tmp_path):
    write_local_config(tmp_path, "version: 1\npolicy:\n  fail_on: low\n")
    loaded = load_config(
        tmp_path,
        environ={"SECURITY_CHECKER__POLICY__FAIL_ON": "medium"},
    )
    assert loaded.config.policy.fail_on is Severity.MEDIUM


def test_local_config_works_without_a_shared_one(tmp_path):
    write_local_config(tmp_path, "version: 1\npolicy:\n  fail_on: low\n")
    loaded = load_config(tmp_path, environ={})
    assert loaded.config.policy.fail_on is Severity.LOW
    assert loaded.config_path is None
    assert loaded.local_config_path is not None


def test_local_config_also_rejects_plaintext_keys(tmp_path):
    """個人用ファイルでも平文キーは受け付けない (§19.1)."""
    write_local_config(
        tmp_path,
        "version: 1\nreviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: https://x/v1\n    model: m\n    api_key: sk-plaintext\n",
    )
    with pytest.raises(ConfigError, match="平文の api_key"):
        load_config(tmp_path, environ={})


def test_no_local_config_leaves_the_field_empty(tmp_path):
    write_config(tmp_path, "version: 1\n")
    assert load_config(tmp_path, environ={}).local_config_path is None


# --- local 層の reviewers は置き換えず、name で合成する (#173) ---------------------------

_SHARED = """
version: 1
reviewers:
  - {name: team,   transport: http, dialect: openai_chat, base_url: http://x/v1, model: m}
  - {name: judge1, transport: http, dialect: openai_chat, base_url: http://x/v1, model: m}
aggregation:
  strategy: judge
  judge: {reviewer: judge1}
"""


def _load_with_local(tmp_path: Path, local: str) -> LoadedConfig:
    (tmp_path / "security-checker.yml").write_text(_SHARED, encoding="utf-8")
    (tmp_path / "security-checker.local.yml").write_text(local, encoding="utf-8")
    return load_config(tmp_path, environ={})


def test_local_reviewers_are_added_to_the_shared_ones(tmp_path):
    loaded = _load_with_local(
        tmp_path, "version: 1\nreviewers:\n  - {name: mine, transport: process, command: [a]}\n"
    )
    assert [r.name for r in loaded.config.reviewers] == ["team", "judge1", "mine"]


def test_local_reviewer_with_the_same_name_overrides_only_what_it_writes(tmp_path):
    loaded = _load_with_local(tmp_path, "version: 1\nreviewers:\n  - {name: team, model: other}\n")
    team = loaded.config.reviewers[0]
    assert team.model == "other"
    assert team.base_url == "http://x/v1"
    assert len(loaded.config.reviewers) == 2


def test_local_can_disable_a_shared_reviewer(tmp_path):
    loaded = _load_with_local(
        tmp_path, "version: 1\nreviewers:\n  - {name: team, enabled: false}\n"
    )
    assert [r.name for r in loaded.config.reviewers] == ["judge1"]


def test_disabling_the_judge_is_reported_as_a_config_error(tmp_path):
    with pytest.raises(ConfigError, match="judge1"):
        _load_with_local(tmp_path, "version: 1\nreviewers:\n  - {name: judge1, enabled: false}\n")


def test_other_layers_still_replace_the_list(tmp_path):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nreviewers:\n  - {name: a, transport: process, command: [x]}\n",
        encoding="utf-8",
    )
    loaded = load_config(
        tmp_path,
        environ={},
        cli_overrides={"reviewers": [{"name": "b", "transport": "process", "command": ["y"]}]},
    )
    assert [r.name for r in loaded.config.reviewers] == ["b"]


# --- 文字列の項目を YAML で壊さない (#204) ------------------------------------------


def test_env_values_for_string_fields_stay_strings(tmp_path):
    loaded = load_config(
        tmp_path,
        environ={
            "SECURITY_CHECKER__OUTPUT__LANGUAGE": "no",
            "SECURITY_CHECKER__GITHUB__COMMENT_AUTHOR": "12345",
            "SECURITY_CHECKER__POLICY__STRICT": "false",
            "SECURITY_CHECKER__BUDGET__MAX_USD": "2.5",
        },
    )
    assert loaded.config.output.language == "no"
    assert loaded.config.github.comment_author == "12345"
    assert loaded.config.policy.strict is False
    assert loaded.config.budget.max_usd == 2.5


# --- 常に除外するもの (#203) ---------------------------------------------------------


def test_custom_exclude_still_skips_git_and_the_output_directory(tmp_path):
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\ntarget:\n  exclude: ['docs/**']\n", encoding="utf-8"
    )
    exclude = load_config(tmp_path, environ={}).config.target.exclude
    assert exclude[0] == "docs/**"
    assert "**/.git/**" in exclude
    assert "**/.security-checker/**" in exclude
    assert "**/node_modules/**" not in exclude  # 既定は置き換える


# --- preset の名前で presets の外を読ませない (#211) ---------------------------------


def test_a_preset_name_cannot_escape_the_presets_directory(tmp_path):
    (tmp_path / "evil.yml").write_text("version: 1\n", encoding="utf-8")
    try:
        relative = os.path.relpath(tmp_path / "evil", PRESET_DIR)
    except ValueError:  # Windows で一時ディレクトリが別のドライブにある
        pytest.skip("presets と一時ディレクトリが別のドライブにある")
    assert (PRESET_DIR / f"{relative}.yml").is_file()  # 照合しなければ読めてしまう経路
    with pytest.raises(ConfigError, match="存在しません"):
        load_config(tmp_path, preset=str(relative), environ={})
