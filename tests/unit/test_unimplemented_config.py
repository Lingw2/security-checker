"""受け付けたが効かない設定を、黙って無視しない (設計書 P9).

v1 の最大の欠陥は「ツールが失敗しても成功に見える」ことだった。
「設定したのに効かない」も同じ種類の事故なので、同じ強さで扱う。
"""

from __future__ import annotations

import pytest

from security_checker.config.loader import load_config
from security_checker.config.schema import Config
from security_checker.config.unimplemented import unimplemented_warnings


def test_nothing_is_reported_for_the_defaults():
    """既定値のままなら警告は出ない (ノイズにしない)."""
    assert unimplemented_warnings(Config(), {}) == []


def test_sarif_format_is_no_longer_reported():
    """P4 で実装した. 実装済みの項目を警告し続けると、警告そのものが信用されなくなる."""
    config = Config.model_validate({"output": {"formats": ["terminal", "json", "sarif"]}})
    assert unimplemented_warnings(config, {}) == []


def test_baseline_is_no_longer_reported():
    config = Config.model_validate({"policy": {"baseline": ".security-checker-baseline.json"}})
    assert unimplemented_warnings(config, {}) == []


def test_diff_mode_is_no_longer_reported():
    diff = Config.model_validate({"target": {"mode": "diff"}})
    assert unimplemented_warnings(diff, {}) == []


def test_github_section_is_no_longer_reported():
    config = Config()
    assert unimplemented_warnings(config, {"github.comment": "file:security-checker.yml"}) == []


def test_logging_section_is_no_longer_reported():
    assert unimplemented_warnings(Config(), {"logging.format": "cli"}) == []


def test_num_ctx_names_the_reviewer():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "local",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://localhost:11434",
                    "model": "m",
                    "num_ctx": 16384,
                }
            ]
        }
    )
    messages = unimplemented_warnings(config, {})
    assert any("'local'" in message and "num_ctx" in message for message in messages)


def test_ci_preset_does_not_warn_about_sarif(tmp_path):
    loaded = load_config(tmp_path, preset="ci")
    assert "sarif" in loaded.config.output.formats
    assert not any("sarif" in message for message in loaded.warnings)


def test_plain_config_has_no_warnings(tmp_path):
    loaded = load_config(tmp_path)
    assert loaded.warnings == []


def test_target_root_is_reported():
    """検査対象は CLI の引数で決まる. target.root は書いても効かない."""
    config = Config.model_validate({"target": {"root": "src"}})
    messages = unimplemented_warnings(config, {})
    assert any("target.root" in message for message in messages)


def test_max_callers_is_reported_until_callers_are_collected():
    """呼び出し元はまだ集めていない. 増やしても文脈は変わらない (#92)."""
    config = Config.model_validate({"context": {"max_callers": 5}})
    assert any("context.max_callers" in m for m in unimplemented_warnings(config, {}))
    # 0 は実際の挙動 (呼び出し元を渡さない) と一致するので警告しない
    assert unimplemented_warnings(Config.model_validate({"context": {"max_callers": 0}}), {}) == []


def test_bundled_presets_do_not_set_max_callers(tmp_path):
    for preset in ("frugal", "minimal", "thorough"):
        loaded = load_config(tmp_path, preset=preset)
        assert not any("max_callers" in message for message in loaded.warnings), preset


def test_http_only_fields_on_process_transport_are_reported():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "cli",
                    "transport": "process",
                    "command": ["mycmd", "--non-interactive"],
                    "base_url": "https://example.invalid/v1",
                    "api_key_env": "MY_API_KEY",
                    "headers": {"X-Trace": "1"},
                }
            ]
        }
    )
    messages = unimplemented_warnings(config, {})
    for field in ("base_url", "api_key_env", "headers"):
        assert any("'cli'" in message and field in message for message in messages), field


def test_process_only_fields_on_http_transport_are_reported():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "api",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "https://example.invalid/v1",
                    "model": "m",
                    "command": ["mycmd"],
                    "prompt_via": "file",
                }
            ]
        }
    )
    messages = unimplemented_warnings(config, {})
    for field in ("command", "prompt_via"):
        assert any("'api'" in message and field in message for message in messages), field


def test_fields_that_match_the_transport_are_not_reported():
    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "api",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "https://example.invalid/v1",
                    "model": "m",
                    "api_key_env": "MY_API_KEY",
                    "headers": {"X-Trace": "1"},
                },
                {
                    "name": "cli",
                    "transport": "process",
                    "command": ["mycmd"],
                    "prompt_via": "file",
                },
            ]
        }
    )
    assert unimplemented_warnings(config, {}) == []


def test_min_ratio_below_a_majority_is_reported():
    config = Config.model_validate({"aggregation": {"consensus": {"min_ratio": 0.3}}})
    assert any("min_ratio" in warning for warning in unimplemented_warnings(config))
    assert not any("min_ratio" in warning for warning in unimplemented_warnings(Config()))


@pytest.mark.parametrize(
    ("scanner", "argument"),
    [
        ("semgrep", "--sarif"),
        ("semgrep", "--output=x"),
        ("gitleaks", "--report-path"),
        ("trivy", "--format"),
    ],
)
def test_extra_args_that_take_over_the_output_are_reported(scanner, argument):
    config = Config.model_validate({"scanners": {scanner: {"extra_args": [argument]}}})
    assert any("extra_args" in warning for warning in unimplemented_warnings(config))


def test_other_extra_args_are_not_reported():
    config = Config.model_validate({"scanners": {"semgrep": {"extra_args": ["--timeout", "30"]}}})
    assert not any("extra_args" in warning for warning in unimplemented_warnings(config))
