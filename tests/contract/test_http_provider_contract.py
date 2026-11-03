"""内蔵 http Provider が公開契約テストを通ること (設計書 §25.2)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import respx

from security_checker.providers.base import Capabilities, LLMProvider, StructuredMode
from security_checker.providers.http.dialects.openai_chat import OpenAIChatDialect
from security_checker.providers.http.transport import HttpProvider
from security_checker.testing import ProviderContractTests

BASE_URL = "http://contract.test/v1"


class TestOpenAIChatProviderContract(ProviderContractTests):
    def make_provider(self) -> LLMProvider:
        respx.start()
        respx.post(f"{BASE_URL}/chat/completions").mock(
            return_value=httpx.Response(
                200,
                json={
                    "model": "m",
                    "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 5, "completion_tokens": 1},
                },
            )
        )
        return HttpProvider(
            name="contract",
            dialect=OpenAIChatDialect(),
            base_url=BASE_URL,
            model="m",
            capabilities=Capabilities(structured_output=StructuredMode.JSON_SCHEMA),
            client=httpx.AsyncClient(),
        )

    def make_http_provider(
        self, handler: Callable[[httpx.Request], httpx.Response]
    ) -> LLMProvider | None:
        return HttpProvider(
            name="contract",
            dialect=OpenAIChatDialect(),
            base_url=BASE_URL,
            model="m",
            capabilities=Capabilities(structured_output=StructuredMode.JSON_SCHEMA),
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )

    def teardown_method(self) -> None:
        respx.stop()
