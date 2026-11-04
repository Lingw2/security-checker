"""gemini_generate 方言と responseSchema への変換 (設計書 §9.5).

この形は responseSchema が OpenAPI のサブセットで、JSON Schema をそのまま
送ると 400 になる。変換層が「落とすもの」と「保つもの」をここで固定する。
"""

from __future__ import annotations

from typing import Any

import pytest

from security_checker.observability.cost import ModelPrice
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.gemini_generate import (
    GeminiGenerateDialect,
    to_response_schema,
)
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect
from security_checker.review.structured import verdict_schema

SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"vulnerable": {"type": "boolean"}},
    "required": ["vulnerable"],
}


@pytest.fixture
def dialect() -> GeminiGenerateDialect:
    return GeminiGenerateDialect()


def make_request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {
        "system": "system-text",
        "user": "user-text",
        "json_schema": SCHEMA,
        "max_output_tokens": 500,
    }
    payload.update(overrides)
    return CompletionRequest(**payload)


def test_model_appears_in_the_url(dialect: GeminiGenerateDialect) -> None:
    """この形はモデル名を URL に含める (endpoint が model を受け取る理由)."""
    assert (
        dialect.endpoint("https://endpoint.test/v1beta/", "my-model")
        == "https://endpoint.test/v1beta/models/my-model:generateContent"
    )


def test_key_goes_in_a_header_not_the_url(dialect: GeminiGenerateDialect) -> None:
    """URL はログや履歴に残りうるため、鍵をクエリに置かない (§19.1)."""
    assert dialect.headers("k")["x-goog-api-key"] == "k"
    assert "x-goog-api-key" not in dialect.headers(None)


def test_system_is_a_separate_field(dialect: GeminiGenerateDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["systemInstruction"]["parts"][0]["text"] == "system-text"
    assert payload["contents"][0]["parts"][0]["text"] == "user-text"


def test_json_schema_mode_sends_a_converted_schema(dialect: GeminiGenerateDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    generation = payload["generationConfig"]
    assert generation["responseMimeType"] == "application/json"
    # そのままではなく、変換後のものが乗る
    assert "additionalProperties" not in generation["responseSchema"]
    assert generation["responseSchema"]["type"] == "OBJECT"


def test_json_mode_asks_for_json_without_a_schema(dialect: GeminiGenerateDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_MODE
    )
    assert payload["generationConfig"]["responseMimeType"] == "application/json"
    assert "responseSchema" not in payload["generationConfig"]


def test_prompt_only_sends_neither(dialect: GeminiGenerateDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.PROMPT_ONLY
    )
    assert "responseMimeType" not in payload["generationConfig"]


def test_parse_response(dialect: GeminiGenerateDialect) -> None:
    parsed = dialect.parse_response(
        {
            "modelVersion": "m",
            "candidates": [
                {
                    "content": {"parts": [{"text": '{"vulnerable"'}, {"text": ": true}"}]},
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 120,
                "candidatesTokenCount": 30,
                "thoughtsTokenCount": 15,
                "cachedContentTokenCount": 90,
            },
        }
    )
    assert parsed.text == '{"vulnerable": true}'
    assert parsed.usage.input_tokens == 120
    assert parsed.usage.reasoning_tokens == 15
    assert parsed.usage.cached_tokens == 90
    assert parsed.model_reported == "m"


def test_a_blocked_prompt_says_why(dialect: GeminiGenerateDialect) -> None:
    """「何も返らなかった」で終わらせない (§20.2)."""
    with pytest.raises(ProviderResponseError, match="blockReason"):
        dialect.parse_response({"promptFeedback": {"blockReason": "SAFETY"}})


def test_errors_say_what_to_do(dialect: GeminiGenerateDialect) -> None:
    # この形は鍵の不備を 401 ではなく 400 で返すため、認証エラーに見えない
    assert dialect.explain_error(400, "API key not valid. Please pass a valid API key.")
    assert dialect.explain_error(404, "model not found")
    assert dialect.explain_error(400, "something else") is None


# --- スキーマ変換 -----------------------------------------------------------


def test_unsupported_keywords_are_dropped() -> None:
    converted = to_response_schema(
        {
            "type": "object",
            "title": "T",
            "additionalProperties": False,
            "properties": {
                "text": {"type": "string", "maxLength": 120, "pattern": "^x"},
                "score": {"type": "number", "minimum": 0, "maximum": 1},
            },
        }
    )
    assert set(converted) == {"type", "properties"}
    assert converted["properties"]["text"] == {"type": "STRING"}
    # minimum / maximum は responseSchema でも使えるので残す (#298)
    assert converted["properties"]["score"] == {"type": "NUMBER", "minimum": 0, "maximum": 1}


def test_nullable_union_is_folded() -> None:
    converted = to_response_schema(
        {
            "type": "object",
            "properties": {
                "a": {"anyOf": [{"type": "string", "maxLength": 10}, {"type": "null"}]},
                "b": {"type": ["integer", "null"]},
            },
        }
    )
    assert converted["properties"]["a"] == {"type": "STRING", "nullable": True}
    assert converted["properties"]["b"] == {"type": "INTEGER", "nullable": True}


def test_refs_are_expanded() -> None:
    converted = to_response_schema(
        {
            "type": "object",
            "$defs": {"Item": {"type": "object", "properties": {"n": {"type": "integer"}}}},
            "properties": {"items": {"type": "array", "items": {"$ref": "#/$defs/Item"}}},
        }
    )
    assert converted["properties"]["items"]["items"]["properties"]["n"] == {"type": "INTEGER"}


def test_unresolvable_ref_is_an_error() -> None:
    with pytest.raises(ProviderResponseError):
        to_response_schema({"type": "object", "properties": {"x": {"$ref": "#/$defs/Missing"}}})


def test_required_keeps_only_existing_properties() -> None:
    converted = to_response_schema(
        {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "required": ["a", "ghost"],
        }
    )
    assert converted["required"] == ["a"]


def test_the_real_verdict_schema_converts_without_unsupported_keywords() -> None:
    """実際に送るスキーマが変換を通ること (400 の原因を作らない)."""
    converted = to_response_schema(verdict_schema())
    forbidden = {"additionalProperties", "anyOf", "$ref", "$defs", "maxLength", "pattern"}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            assert not (set(node) & forbidden), f"未対応キーワードが残っている: {set(node)}"
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(converted)
    assert converted["type"] == "OBJECT"
    assert "severity" in converted["properties"]


def test_thinking_tokens_are_billed_as_output() -> None:
    """請求額が同じ応答は、方言によらず同じ金額に見積もる (#168)."""
    price = ModelPrice(input_per_1m=1.0, output_per_1m=10.0)
    gemini = GeminiGenerateDialect().parse_response(
        {
            "candidates": [{"content": {"parts": [{"text": "{}"}]}, "finishReason": "STOP"}],
            "usageMetadata": {
                "promptTokenCount": 1000,
                "candidatesTokenCount": 200,
                "thoughtsTokenCount": 3000,
                "totalTokenCount": 4200,
            },
        }
    )
    chat = OpenAIChatDialect().parse_response(
        {
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 3200,
                "completion_tokens_details": {"reasoning_tokens": 3000},
            },
        }
    )
    assert gemini.usage.total_tokens == chat.usage.total_tokens == 4200
    assert gemini.usage.reasoning_tokens == chat.usage.reasoning_tokens == 3000
    assert price.estimate(gemini.usage) == price.estimate(chat.usage)
