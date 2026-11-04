"""設定の探索・合成・検証 (設計書 §12).

合成順序 (後勝ち):
  組み込み既定値 ← preset ← 設定ファイル ← ローカル設定 ← 環境変数 ← CLI フラグ

「ローカル設定」は git 管理しない個人用の上書き層 (`security-checker.local.yml`)。
共有する設定と、手元でだけ使う Reviewer 定義を混ぜないためにある。
"""

from __future__ import annotations

import os
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from security_checker.config.schema import Config
from security_checker.config.unimplemented import unimplemented_warnings
from security_checker.errors import ConfigError

CONFIG_FILENAMES = (
    "security-checker.yml",
    "security-checker.yaml",
    ".security-checker.yml",
    ".security-checker.yaml",
    ".github/security-checker.yml",
)
#: git 管理しない個人用の上書き層. 共有設定より後に適用される (後勝ち).
LOCAL_CONFIG_FILENAMES = (
    "security-checker.local.yml",
    "security-checker.local.yaml",
)
ENV_PREFIX = "SECURITY_CHECKER__"
#: 検査対象のツリーを信用しない (設定を読まない). ENV_PREFIX と衝突しない名前にする
UNTRUSTED_TARGET_ENV = "SECURITY_CHECKER_UNTRUSTED_TARGET"
PRESET_DIR = Path(__file__).parent / "presets"

Layer = str


@dataclass
class LoadedConfig:
    """解決済み設定と、どの層で値が決まったかの記録 (`config show --explain` 用)."""

    config: Config
    origins: dict[str, Layer] = field(default_factory=dict)
    config_path: Path | None = None
    preset: str | None = None
    local_config_path: Path | None = None
    #: 検査対象のツリーを信用しない (SECURITY_CHECKER_UNTRUSTED_TARGET)
    untrusted_target: bool = False
    #: 受け付けたが実装が追いついていない項目の警告 (P9: 黙って無視しない)
    warnings: list[str] = field(default_factory=list)


def find_config_file(root: Path) -> Path | None:
    """対象ディレクトリ配下から設定ファイルを探す."""
    for name in CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def find_local_config_file(root: Path) -> Path | None:
    """個人用の上書き設定を探す. `--config` の指定とは独立に、対象直下だけを見る."""
    for name in LOCAL_CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def available_presets() -> list[str]:
    return sorted(path.stem for path in PRESET_DIR.glob("*.yml"))


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} の YAML を解釈できません: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path} を読み込めません: {exc}") from exc
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} のトップレベルはマッピングである必要があります")
    return raw


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _merge_local_layer(merged: dict[str, Any], local: dict[str, Any]) -> dict[str, Any]:
    """local 層の合成. reviewers だけは置き換えず、name をキーに足す.

    手元用の Reviewer を足しても、チームの Reviewer は残る。同じ名前は項目ごとに上書きする。
    """
    combined = _deep_merge(merged, local)
    shared, personal = merged.get("reviewers"), local.get("reviewers")
    if not isinstance(shared, list) or not isinstance(personal, list):
        return combined
    reviewers = list(shared)
    positions = {
        entry["name"]: index
        for index, entry in enumerate(reviewers)
        if isinstance(entry, dict) and "name" in entry
    }
    for entry in personal:
        index = positions.get(entry.get("name")) if isinstance(entry, dict) else None
        if index is None:
            reviewers.append(entry)
        else:
            reviewers[index] = _deep_merge(reviewers[index], entry)
    combined["reviewers"] = reviewers
    return combined


def _drop_disabled_reviewers(merged: dict[str, Any]) -> dict[str, Any]:
    """`enabled: false` の Reviewer を外す. 残りの検証は、外した後の構成に対して行う."""
    reviewers = merged.get("reviewers")
    if not isinstance(reviewers, list):
        return merged
    kept = [e for e in reviewers if not (isinstance(e, dict) and e.get("enabled") is False)]
    return {**merged, "reviewers": kept}


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = value
    return flat


def env_overrides(environ: dict[str, str] | None = None) -> dict[str, Any]:
    """`SECURITY_CHECKER__POLICY__FAIL_ON=critical` 形式を入れ子 dict に変換する."""
    source = environ if environ is not None else dict(os.environ)
    overrides: dict[str, Any] = {}
    for raw_key, raw_value in source.items():
        if not raw_key.startswith(ENV_PREFIX):
            continue
        parts = [part.lower() for part in raw_key[len(ENV_PREFIX) :].split("__") if part]
        if not parts:
            continue
        value = _env_value(parts, raw_value)
        cursor = overrides
        for part in parts[:-1]:
            nested = cursor.setdefault(part, {})
            if not isinstance(nested, dict):
                nested = {}
                cursor[part] = nested
            cursor = nested
        cursor[parts[-1]] = value
    return overrides


def _env_value(parts: list[str], raw: str) -> Any:
    """環境変数の値を解釈する. 文字列の項目には文字列のまま渡す.

    YAML として読むと `no` が false に、`12345` が int になり、言語コードや
    ユーザー名を壊す。スキーマが文字列を期待する項目では YAML として読まない。
    """
    if _expects_str(parts):
        return raw
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError:
        return raw


def _expects_str(parts: list[str]) -> bool:
    """`Config` のフィールドを辿り、行き着いた先が str (または str | None) か."""
    model: Any = Config
    annotation: Any = None
    for part in parts:
        fields = getattr(model, "model_fields", None)
        if not fields or part not in fields:
            return False
        annotation = fields[part].annotation
        model = _model_in(annotation)
    return _is_str(annotation)


def _model_in(annotation: Any) -> Any:
    """`X | None` の中の BaseModel を取り出す (無ければ None)."""
    candidates = typing.get_args(annotation) or (annotation,)
    for candidate in candidates:
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _is_str(annotation: Any) -> bool:
    if annotation is str:
        return True
    args = [a for a in typing.get_args(annotation) if a is not type(None)]
    origin = typing.get_origin(annotation)
    is_union = origin is typing.Union or isinstance(annotation, types.UnionType)
    return is_union and bool(args) and all(a is str for a in args)


def _reject_plaintext_keys(data: dict[str, Any]) -> None:
    """`api_key:` の平文フィールドはスキーマに存在しない (§19.1). 誤記を明確に伝える."""
    reviewers = data.get("reviewers")
    if not isinstance(reviewers, list):
        return
    for reviewer in reviewers:
        if isinstance(reviewer, dict) and "api_key" in reviewer:
            name = reviewer.get("name", "?")
            raise ConfigError(
                f"reviewer '{name}': 平文の api_key は設定できません。"
                "環境変数名を api_key_env で指定してください (例: api_key_env: MY_API_KEY)"
            )


def load_config(
    root: Path,
    *,
    config_path: Path | None = None,
    preset: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
) -> LoadedConfig:
    """設定を合成して検証する. 失敗時は必ず ConfigError (exit 2).

    環境変数 `SECURITY_CHECKER_UNTRUSTED_TARGET=1` のときは、検査対象のツリーから設定を
    一切読まない (共有設定も local 層も)。fork PR のコードを特権のある文脈で検査するとき、
    PR 側が置いた設定の `command` がシークレット付きで実行されるのを防ぐ (§21.2)。
    """
    source = environ if environ is not None else dict(os.environ)
    untrusted = source.get(UNTRUSTED_TARGET_ENV, "").lower() in ("1", "true", "yes")
    if untrusted:
        if config_path is None:
            raise ConfigError(
                f"{UNTRUSTED_TARGET_ENV} が有効なときは、検査対象の外にある設定ファイルを "
                "--config で明示してください"
            )
        if config_path.resolve().is_relative_to(root.resolve()):
            raise ConfigError(
                f"{UNTRUSTED_TARGET_ENV} が有効なときは、検査対象の中の設定ファイル "
                f"({config_path}) を使えません"
            )

    layers: list[tuple[Layer, dict[str, Any]]] = [("default", Config().model_dump(mode="json"))]

    if preset is not None:
        preset_path = PRESET_DIR / f"{preset}.yml"
        # 名前は同梱の一覧と照合する. `../x` で presets の外の YAML を読ませない
        if preset not in available_presets() or not preset_path.is_file():
            raise ConfigError(
                f"preset '{preset}' は存在しません。利用可能: {', '.join(available_presets())}"
            )
        layers.append((f"preset:{preset}", _read_yaml(preset_path)))

    resolved_path = config_path
    if resolved_path is None:
        resolved_path = find_config_file(root)
    elif not resolved_path.is_file():
        raise ConfigError(f"設定ファイルが見つかりません: {resolved_path}")
    if resolved_path is not None:
        file_data = _read_yaml(resolved_path)
        _reject_plaintext_keys(file_data)
        layers.append((f"file:{resolved_path}", file_data))

    # 共有設定の後に、git 管理しない個人用の層を重ねる。
    # 「手元でだけ使う Reviewer」を共有設定に混ぜずに済ませるための経路。
    local_path = None if untrusted else find_local_config_file(root)
    if local_path is not None:
        local_data = _read_yaml(local_path)
        _reject_plaintext_keys(local_data)
        layers.append((f"local:{local_path}", local_data))

    layers.append(("env", env_overrides(source)))
    layers.append(("cli", cli_overrides or {}))

    merged: dict[str, Any] = {}
    origins: dict[str, Layer] = {}
    for name, data in layers:
        if not data:
            continue
        merged = (
            _merge_local_layer(merged, data)
            if name.startswith("local:")
            else _deep_merge(merged, data)
        )
        for key in _flatten(data):
            origins[key] = name

    try:
        config = Config.model_validate(_drop_disabled_reviewers(merged))
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(exc)) from exc

    return LoadedConfig(
        config=config,
        origins=origins,
        config_path=resolved_path,
        preset=preset,
        local_config_path=local_path,
        untrusted_target=untrusted,
        warnings=unimplemented_warnings(config, origins),
    )


def _format_validation_error(exc: ValidationError) -> str:
    lines = ["設定が不正です:"]
    for error in exc.errors():
        location = ".".join(str(part) for part in error["loc"]) or "(root)"
        lines.append(f"  - {location}: {error['msg']}")
    return "\n".join(lines)
