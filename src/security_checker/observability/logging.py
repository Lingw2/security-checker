"""構造化ログ (設計書 §24.1).

  {"ts":"2026-08-30T10:00:00Z","level":"info","run_id":"01JQ...","event":"review.call",
   "reviewer":"alpha","candidate_id":"a1b2c3d4","attempt":1,"latency_ms":2310,"status":"ok"}

- すべての行が run_id を持つ (contextvar で引き回す)。
- 出力先は標準エラー。標準出力はレポート (terminal / JSON) のために空けておく。
- マスキングフィルタ (§19.1) を必ず通す。
- **既定では何も出さない。** `logging.*` か `--log-format` / `--log-level` を指定したときだけ有効。
  既定で出すと、ターミナル出力にログが混ざってノイズになる。
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Literal, TextIO

from security_checker.context.redact import redact_known_patterns

LOGGER_NAME = "security_checker"
_run_id: ContextVar[str | None] = ContextVar("security_checker_run_id", default=None)

LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "error": logging.ERROR,
}

logger = logging.getLogger(LOGGER_NAME)
logger.addHandler(logging.NullHandler())
logger.propagate = False


def set_run_id(run_id: str | None) -> None:
    _run_id.set(run_id)


class _Formatter(logging.Formatter):
    def __init__(self, fmt: Literal["text", "json"]) -> None:
        super().__init__()
        self.fmt = fmt

    def format(self, record: logging.LogRecord) -> str:
        fields: dict[str, Any] = getattr(record, "fields", {})
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "level": "warn" if record.levelname == "WARNING" else record.levelname.lower(),
            "run_id": _run_id.get(),
            "event": record.getMessage(),
            **fields,
        }
        if self.fmt == "json":
            text = json.dumps(payload, ensure_ascii=False, default=str)
        else:
            extras = " ".join(f"{key}={_text_value(value)}" for key, value in fields.items())
            text = f"{payload['ts']} {payload['level']:<5} {payload['event']}" + (
                f" {extras}" if extras else ""
            )
        return redact_known_patterns(text)


def _text_value(value: Any) -> str:
    """text 形式の値. 空白・`=`・引用符・制御文字を含むなら JSON の文字列として引用する.

    そのままだと `reason=rate limit hit` が `reason=rate` と `limit` と `hit` に見え、
    key=value の区切りが曖昧になる (改行はログ行の偽装にもなる)。
    """
    text = value if isinstance(value, str) else str(value)
    if text == "" or any(c.isspace() or c in '="\\' or not c.isprintable() for c in text):
        return json.dumps(text, ensure_ascii=False)
    return text


def configure(
    *,
    level: str = "info",
    fmt: Literal["text", "json"] = "text",
    stream: TextIO | None = None,
) -> logging.Handler:
    """ログを有効にする. 返したハンドラは disable() で外せる (テスト・多重呼び出し用)."""
    disable()
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(_Formatter(fmt))
    handler.set_name("security-checker")
    logger.addHandler(handler)
    logger.setLevel(LEVELS.get(level, logging.INFO))
    return handler


def disable() -> None:
    for handler in list(logger.handlers):
        if handler.get_name() == "security-checker":
            logger.removeHandler(handler)
            handler.close()


def event(name: str, *, level: str = "info", **fields: Any) -> None:
    """1 イベントを記録する. 値は JSON にできるものだけを渡す."""
    logger.log(LEVELS.get(level, logging.INFO), name, extra={"fields": fields})
