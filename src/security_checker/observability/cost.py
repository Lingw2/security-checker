"""コスト計測 (設計書 §24.3).

価格表はコードに埋めない (頻繁に変わるため)。未知のモデルは推測せず `cost: unknown` とする。
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from security_checker.errors import ConfigError
from security_checker.models.verdict import Usage

PRICING_FILENAME = "pricing.yml"
PER_TOKENS = 1_000_000


class ModelPrice(BaseModel):
    """100 万トークンあたりの USD."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # 負の単価は予算の判定を壊す (支出が減って見える) ので受け付けない (#453)
    input_per_1m: float = Field(default=0.0, ge=0.0)
    output_per_1m: float = Field(default=0.0, ge=0.0)

    def estimate(self, usage: Usage) -> float:
        return (
            usage.input_tokens * self.input_per_1m + usage.output_tokens * self.output_per_1m
        ) / PER_TOKENS


class PriceTable(BaseModel):
    """モデル名 → 価格. 完全一致で引き、無ければ不明として扱う."""

    model_config = ConfigDict(frozen=True)

    prices: dict[str, ModelPrice] = {}

    def lookup(self, model: str) -> ModelPrice | None:
        return self.prices.get(model)

    def apply(self, usage: Usage, model: str) -> Usage:
        price = self.lookup(model)
        if price is None:
            return usage.model_copy(update={"estimated_usd": None, "cost_known": False})
        return usage.model_copy(update={"estimated_usd": price.estimate(usage), "cost_known": True})


def default_pricing_paths(config_dir: Path | None) -> list[Path]:
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    paths = [root / "security-checker" / PRICING_FILENAME]
    if config_dir is not None:
        paths.insert(0, config_dir / PRICING_FILENAME)
    return paths


def load_price_table(config_dir: Path | None = None, explicit: Path | None = None) -> PriceTable:
    """pricing.yml を読む. 無ければ空表 (= すべて cost unknown)."""
    candidates = [explicit] if explicit is not None else default_pricing_paths(config_dir)
    for path in candidates:
        if path is None or not path.is_file():
            continue
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"{path} を読み込めません: {exc}") from exc
        if not isinstance(raw, dict):
            # リストなどは AttributeError で落ちていた (#452)
            raise ConfigError(
                f"{path}: トップレベルはマッピング (models: ...) である必要があります"
            )
        entries = raw.get("models", raw)
        if not isinstance(entries, dict):
            raise ConfigError(f"{path}: models はマッピングである必要があります")
        try:
            return PriceTable(
                prices={
                    str(name): ModelPrice.model_validate(value) for name, value in entries.items()
                }
            )
        except ValidationError as exc:
            raise ConfigError(f"{path} の価格定義が不正です: {exc}") from exc
    return PriceTable()
