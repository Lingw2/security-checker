"""entry point で登録したスキャナの実行 (設計書 §29.1)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from pydantic import ValidationError

from security_checker.config.schema import Config
from security_checker.errors import ConfigError
from security_checker.models.enums import ScanStatus
from security_checker.run import run_scan
from security_checker.scanners import registry
from security_checker.testing.fakes import FakeScanner

# --- entry point で登録したスキャナを実行する (#174) ------------------------------------


class _PluginScanner(FakeScanner):
    def __init__(self, settings: object) -> None:
        super().__init__("myscan")
        self.settings = settings


def _plugin_entry(load: Any = None) -> Any:
    entry = mock.Mock()
    entry.name = "myscan"
    entry.load = load or (lambda: _PluginScanner)
    return entry


def _no_builtins(**overrides: Any) -> dict[str, Any]:
    return {
        "scanners": {
            "semgrep": {"enabled": False},
            "gitleaks": {"enabled": False},
            "osv": {"enabled": False},
            **overrides,
        }
    }


def test_a_configured_plugin_is_built_and_runs(tmp_path: Path) -> None:
    config = Config.model_validate(_no_builtins(plugins={"myscan": {"timeout_s": 30}}))
    with mock.patch.object(registry, "entry_points", lambda group: [_plugin_entry()]):
        outcome = asyncio.run(run_scan(config, tmp_path))
    assert [run.scanner for run in outcome.report.scanners] == ["myscan"]
    assert outcome.report.scanners[0].status is ScanStatus.OK


def test_an_installed_plugin_does_not_run_or_load_until_configured() -> None:
    load = mock.Mock(side_effect=AssertionError("読み込まれた"))
    config = Config.model_validate(_no_builtins())
    with mock.patch.object(registry, "entry_points", lambda group: [_plugin_entry(load)]):
        scanners, warnings = registry.build_scanners(config)
    assert scanners == []
    assert any("myscan" in warning for warning in warnings)
    load.assert_not_called()


def test_a_disabled_plugin_does_not_run() -> None:
    config = Config.model_validate(_no_builtins(plugins={"myscan": {"enabled": False}}))
    with mock.patch.object(registry, "entry_points", lambda group: [_plugin_entry()]):
        scanners, warnings = registry.build_scanners(config)
    assert scanners == []
    assert warnings == []


def test_an_unknown_plugin_name_is_a_config_error() -> None:
    config = Config.model_validate(_no_builtins(plugins={"typo": {}}))
    with (
        mock.patch.object(registry, "entry_points", lambda group: [_plugin_entry()]),
        pytest.raises(ConfigError, match="typo"),
    ):
        registry.build_scanners(config)


def test_a_plugin_that_fails_to_load_is_a_config_error() -> None:
    def broken() -> Any:
        raise ImportError("no module")

    config = Config.model_validate(_no_builtins(plugins={"myscan": {}}))
    with (
        mock.patch.object(registry, "entry_points", lambda group: [_plugin_entry(broken)]),
        pytest.raises(ConfigError, match="読み込めません"),
    ):
        registry.build_scanners(config)


def test_plugins_cannot_shadow_builtins() -> None:
    with pytest.raises(ValidationError):
        Config.model_validate({"scanners": {"plugins": {"semgrep": {}}}})
