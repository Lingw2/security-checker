"""anthropic_messages 方言のリクエスト/レスポンス変換 (設計書 §9.6).

この形は openai_chat と 2 点で互換性がない。
  1. system が独立フィールド
  2. JSON Schema の直接指定が無く、ツール呼び出しの強制で代替する
どちらもテストで固定する。
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.anthropic_messages import (
    TOOL_NAME,
    AnthropicMessagesDialect,
)
from security_checker.providers.http.dialects.base import REASONING_HEADROOM_TOKENS

SCHEMA = {"type": "object", "properties": {"vulnerable": {"type": "boolean"}}}


@pytest.fixture
def dialect() -> AnthropicMessagesDialect:
    return AnthropicMessagesDialect()


def make_request(**overrides: Any) -> CompletionRequest:
    payload: dict[str, Any] = {
        "system": "system-text",
        "user": "user-text",
        "json_schema": SCHEMA,
        "max_output_tokens": 500,
    }
    payload.update(overrides)
    return CompletionRequest(**payload)


def test_endpoint_normalises_a_base_url_with_or_without_v1(
    dialect: AnthropicMessagesDialect,
) -> None:
    """どちらの書き方でも同じ URL になる (二重の /v1 を作らない)."""
    expected = "https://endpoint.test/v1/messages"
    assert dialect.endpoint("https://endpoint.test", "m") == expected
    assert dialect.endpoint("https://endpoint.test/", "m") == expected
    assert dialect.endpoint("https://endpoint.test/v1", "m") == expected
    assert dialect.endpoint("https://endpoint.test/v1/", "m") == expected


def test_headers_use_the_dedicated_key_header(dialect: AnthropicMessagesDialect) -> None:
    headers = dialect.headers("k")
    assert headers["x-api-key"] == "k"
    assert "Authorization" not in headers
    assert headers["anthropic-version"]
    assert "x-api-key" not in dialect.headers(None)


def test_system_is_a_separate_field(dialect: AnthropicMessagesDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["system"] == "system-text"
    assert payload["messages"] == [{"role": "user", "content": "user-text"}]


def test_system_is_folded_when_unsupported(dialect: AnthropicMessagesDialect) -> None:
    capabilities = Capabilities(supports_system_role=False)
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=capabilities, mode=StructuredMode.JSON_SCHEMA
    )
    assert "system" not in payload
    assert "system-text" in payload["messages"][0]["content"]


def test_json_schema_mode_forces_a_tool_call(dialect: AnthropicMessagesDialect) -> None:
    payload = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    assert payload["tools"][0]["input_schema"] == SCHEMA
    assert payload["tool_choice"] == {"type": "tool", "name": TOOL_NAME}


def test_weaker_modes_send_no_tools(dialect: AnthropicMessagesDialect) -> None:
    """json_mode に相当する仕組みが無いので、プロンプト側の指示に任せる."""
    for mode in (StructuredMode.JSON_MODE, StructuredMode.PROMPT_ONLY):
        payload = dialect.build_payload(
            make_request(), model="m", capabilities=Capabilities(), mode=mode
        )
        assert "tools" not in payload
        assert "tool_choice" not in payload


def test_reasoning_models_get_output_headroom(dialect: AnthropicMessagesDialect) -> None:
    """思考トークンで出力予算を食い尽くし、本文が切れるのを防ぐ (§9.6)."""
    plain = dialect.build_payload(
        make_request(), model="m", capabilities=Capabilities(), mode=StructuredMode.JSON_SCHEMA
    )
    thinking = dialect.build_payload(
        make_request(),
        model="m",
        capabilities=Capabilities(reasoning=True),
        mode=StructuredMode.JSON_SCHEMA,
    )
    assert plain["max_tokens"] == 500
    assert thinking["max_tokens"] == 500 + REASONING_HEADROOM_TOKENS


def test_tool_use_block_becomes_parsed_output(dialect: AnthropicMessagesDialect) -> None:
    parsed = dialect.parse_response(
        {
            "model": "m",
            "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "name": TOOL_NAME, "input": {"vulnerable": True}}],
            "usage": {
                "input_tokens": 120,
                "output_tokens": 30,
                "cache_read_input_tokens": 90,
            },
        }
    )
    assert parsed.parsed == {"vulnerable": True}
    # text からも復元できる必要がある (上位は text 経由でも検証する)
    assert json.loads(parsed.text) == {"vulnerable": True}
    # キャッシュから読んだ分も「送った入力」に含める (ほかの方言の prompt_tokens と同じ)
    assert parsed.usage.input_tokens == 120 + 90
    assert parsed.usage.cached_tokens == 90
    assert parsed.finish_reason == "tool_use"


def test_text_blocks_are_concatenated(dialect: AnthropicMessagesDialect) -> None:
    parsed = dialect.parse_response(
        {"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]}
    )
    assert parsed.text == "ab"
    assert parsed.parsed is None


def test_empty_content_is_an_error(dialect: AnthropicMessagesDialect) -> None:
    with pytest.raises(ProviderResponseError):
        dialect.parse_response({"content": []})
    with pytest.raises(ProviderResponseError):
        dialect.parse_response({"stop_reason": "end_turn"})


def test_errors_say_what_to_do(dialect: AnthropicMessagesDialect) -> None:
    assert dialect.explain_error(404, '{"error":{"message":"model not found"}}')
    assert dialect.explain_error(400, "max_tokens is too large")
    assert dialect.explain_error(400, "something else") is None


def test_cache_creation_tokens_are_counted_as_input() -> None:
    """キャッシュへの書き込みも入力として課金される. 数え漏らさない (#667)."""
    dialect = AnthropicMessagesDialect()
    parsed = dialect.parse_response(
        {
            "content": [{"type": "text", "text": "{}"}],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_creation_input_tokens": 1000,
                "cache_read_input_tokens": 0,
            },
        }
    )
    assert parsed.usage.input_tokens == 1010
    assert parsed.usage.cached_tokens == 0
