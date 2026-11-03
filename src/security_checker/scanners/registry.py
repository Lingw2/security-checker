"""内蔵 Scanner と entry_points プラグインの解決 (設計書 §29)."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from security_checker.config.schema import Config, ScannerConfig
from security_checker.errors import ConfigError
from security_checker.scanners.base import Scanner
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.osv import OsvScanner
from security_checker.scanners.semgrep import SemgrepScanner
from security_checker.scanners.trivy import TrivyScanner

ENTRY_POINT_GROUP = "security_checker.scanners"

BUILTIN_SCANNERS: dict[str, Callable[[Any], Scanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "osv": OsvScanner,
    "trivy": TrivyScanner,
}


def discover_plugin_scanners() -> dict[str, EntryPoint]:
    """外部パッケージが登録した Scanner を探す. 読み込むのは有効にしたものだけ."""
    return {entry.name: entry for entry in entry_points(group=ENTRY_POINT_GROUP)}


def _load_plugin(entry: EntryPoint) -> Callable[[Any], Scanner]:
    try:
        factory: Callable[[Any], Scanner] = entry.load()
    except Exception as exc:  # プラグイン側の任意の失敗を封じ込める
        raise ConfigError(f"scanner プラグイン '{entry.name}' を読み込めません: {exc}") from exc
    return factory


def build_scanners(config: Config) -> tuple[list[Scanner], list[str]]:
    """設定で有効化されている Scanner を組み立てる.

    プラグインは入れただけでは動かさない。依存に入ったパッケージが黙ってスキャナとして
    動かないよう、`scanners.plugins` に書いたものだけを読み込む (§29.1)。
    """
    plugins = discover_plugin_scanners()
    configured = config.scanners.plugins
    unknown = sorted(set(configured) - set(plugins))
    if unknown:
        raise ConfigError(
            f"scanners.plugins の {', '.join(unknown)} は entry point に登録されていません。"
            f"登録済み: {', '.join(sorted(plugins)) or '(なし)'}"
        )
    warnings = [
        f"scanner プラグイン '{name}' は有効になっていません。"
        f"使うなら scanners.plugins に {name} を書いてください"
        for name in sorted(set(plugins) - set(configured) - set(BUILTIN_SCANNERS))
    ]

    scanners: list[Scanner] = []
    settings: dict[str, ScannerConfig] = config.scanner_settings()
    for name, scanner_settings in settings.items():
        if not scanner_settings.enabled:
            continue
        if name in BUILTIN_SCANNERS:
            scanners.append(BUILTIN_SCANNERS[name](scanner_settings))
        elif name in plugins:
            scanners.append(_load_plugin(plugins[name])(scanner_settings))
        else:
            warnings.append(f"scanner '{name}' は未実装のため無効化しました")
    return scanners, warnings
