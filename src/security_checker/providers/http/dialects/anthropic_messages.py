"""`anthropic_messages` 方言 — `POST {base_url}/v1/messages` (設計書 §9.6).

「Anthropic 社の」ではなく「Messages API という形の」という意味の名前である。
この形を話すエンドポイントであれば、提供元がどこであっても同じアダプタで扱える。

`openai_chat` と互換性がない点が 2 つある。
  1. system がメッセージ配列ではなく独立したフィールドである
  2. JSON Schema を直接指定する仕組みがなく、**ツール呼び出しの強制**で代替する

2 はこの形で構造化出力を得る最も確実な方法で、応答の `content[].input` が
そのまま検証済みの構造化データになる。散文の混入を構造的に排除できる。
"""

from __future__ import annotations

import json
from typing import Any

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import (
    DialectOptions,
    DialectResponse,
    output_limit,
)

#: 構造化出力を受け取るための関数名. 応答の content[].input がそのまま結果になる
TOOL_NAME = "submit_review"
#: この形のバージョン指定ヘッダ. headers 設定で上書きできる
DEFAULT_API_VERSION = "2023-06-01"


class AnthropicMessagesDialect:
    """Messages 形式のリクエスト・レスポンス変換."""

    name = "anthropic_messages"

    def __init__(self, options: DialectOptions | None = None) -> None:
        # この形には文脈長やモデル保持の指定が無いため、受け取っても使わない
        self.options = options or DialectOptions()

    def endpoint(self, base_url: str, model: str) -> str:
        # base_url に /v1 を含めて書く人と含めない人の両方がいる。
        # どちらでも同じ URL になるよう正規化する (二重の /v1 を作らない)。
        trimmed = base_url.rstrip("/")
        if trimmed.endswith("/v1"):
            trimmed = trimmed[: -len("/v1")]
        return f"{trimmed}/v1/messages"

    def headers(self, api_key: str | None) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": DEFAULT_API_VERSION,
        }
        if api_key:
            # この形は Authorization ではなく専用ヘッダで鍵を渡す
            headers["x-api-key"] = api_key
        return headers

    def build_payload(
        self,
        req: CompletionRequest,
        *,
        model: str,
        capabilities: Capabilities,
        mode: StructuredMode,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model,
            "max_tokens": output_limit(req, capabilities),
            "messages": [{"role": "user", "content": req.user}],
        }
        if capabilities.supports_system_role:
            # system はメッセージではなく独立フィールド。この差異をここで吸収する
            payload["system"] = req.system
        else:
            payload["messages"] = [{"role": "user", "content": f"{req.system}\n\n{req.user}"}]
        if capabilities.supports_temperature:
            payload["temperature"] = req.temperature

        if req.json_schema is not None and mode is StructuredMode.JSON_SCHEMA:
            payload["tools"] = [
                {
                    "name": TOOL_NAME,
                    "description": "Submit your security review verdict.",
                    "input_schema": req.json_schema,
                }
            ]
            payload["tool_choice"] = {"type": "tool", "name": TOOL_NAME}
        # json_mode に相当する仕組みはこの形に無い。prompt_only と同じく
        # プロンプト側の指示だけで縛り、抽出と修復は structured.py に任せる。
        return payload

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse:
        content = payload.get("content")
        if not isinstance(content, list):
            raise ProviderResponseError("応答に content がありません")

        texts: list[str] = []
        parsed: dict[str, Any] | None = None
        for block in content:
            if not isinstance(block, dict):
                continue
            kind = block.get("type")
            if kind == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])
            elif kind == "tool_use" and isinstance(block.get("input"), dict):
                # 強制したツール呼び出しの入力が、そのまま検証済みの構造化データ
                parsed = block["input"]

        text = "".join(texts)
        if parsed is not None and not text:
            # 上位 (structured.py) は text からも復元できる必要がある
            text = json.dumps(parsed, ensure_ascii=False)
        if parsed is None and not text:
            raise ProviderResponseError("応答に text も tool_use も含まれていません")

        raw_usage = payload.get("usage")
        usage = Usage()
        if isinstance(raw_usage, dict):
            # input_tokens はキャッシュの読み出し・書き込みを含まない。ほかの方言 (prompt_tokens) と
            # 同じく「送った入力の合計」にそろえ、予算とコストの見積りで数え漏らさない (#667)
            cache_read = _as_int(raw_usage.get("cache_read_input_tokens"))
            cache_write = _as_int(raw_usage.get("cache_creation_input_tokens"))
            usage = Usage(
                input_tokens=_as_int(raw_usage.get("input_tokens")) + cache_read + cache_write,
                output_tokens=_as_int(raw_usage.get("output_tokens")),
                cached_tokens=cache_read,
            )

        model_reported = payload.get("model")
        return DialectResponse(
            text=text,
            parsed=parsed,
            usage=usage,
            finish_reason=str(payload.get("stop_reason") or "stop"),
            model_reported=model_reported if isinstance(model_reported, str) else None,
        )

    def health_payload(self, model: str, capabilities: Capabilities) -> dict[str, Any]:
        return {
            "model": model,
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "ping"}],
        }

    def is_auth_error(self, status: int, body: str) -> bool:
        return False

    def explain_error(self, status: int, body: str) -> str | None:
        """次に取れる行動が分かる場合だけ文章にする (§20.2)."""
        lowered = body.lower()
        if status == 404 and "model" in lowered:
            return (
                "model に指定した ID がこのエンドポイントに存在しません。"
                "設定の model を確認してください"
            )
        if status == 400 and "max_tokens" in lowered:
            return (
                "出力トークンの上限がモデルの許容範囲を超えています。"
                "max_output_tokens を下げてください"
            )
        return None


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0
