"""テスト用のフェイク実装 (設計書 §25).

外部プラグイン作者にも公開する。実ツール / 実 LLM を叩かずにパイプラインを回すために使う。
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import Any, ClassVar, Literal

from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, ScanStatus
from security_checker.models.verdict import Usage
from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    HealthStatus,
    StructuredMode,
)
from security_checker.scanners.base import ScanContext, ScanResult, Target, ToolStatus


class FakeScanner:
    """あらかじめ決めた結果を返す Scanner."""

    requires: ClassVar[list[str]] = []

    def __init__(
        self,
        name: str = "fake",
        *,
        category: Category = Category.SAST,
        status: ScanStatus = ScanStatus.OK,
        candidates: list[Candidate] | None = None,
        reason: str | None = None,
        exit_code: int | None = 0,
        raises: Exception | None = None,
    ) -> None:
        self.name = name
        self.category = category
        self._status = status
        self._candidates = candidates or []
        self._reason = reason
        self._exit_code = exit_code
        self._raises = raises
        self.calls = 0

    def probe(self) -> ToolStatus:
        return ToolStatus(available=self._status is not ScanStatus.SKIPPED, reason=self._reason)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=self._status,
            candidates=self._candidates if self._status is ScanStatus.OK else [],
            reason=self._reason,
            exit_code=self._exit_code,
        )


class ScriptedProvider:
    """あらかじめ決めた応答 (または例外) を順に返す Provider.

    実 LLM を叩かずにパイプライン全体を回すために使う (設計書 §25)。
    """

    transport: Literal["http", "process"] = "http"

    def __init__(
        self,
        script: Sequence[str | dict[str, Any] | Exception | CompletionResponse],
        *,
        name: str = "fake-reviewer",
        model: str = "fake-model",
        dialect: str = "fake",
        capabilities: Capabilities | None = None,
        usage: Usage | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self.dialect = dialect
        self._script = list(script)
        self._capabilities = capabilities or Capabilities(
            structured_output=StructuredMode.JSON_SCHEMA
        )
        self._usage = usage or Usage(input_tokens=100, output_tokens=50)
        self.requests: list[CompletionRequest] = []
        self.closed = False

    @property
    def capabilities(self) -> Capabilities:
        return self._capabilities

    async def complete(self, req: CompletionRequest) -> CompletionResponse:
        self.requests.append(req)
        if not self._script:
            raise AssertionError("ScriptedProvider: 応答が尽きました")
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, CompletionResponse):
            # finish_reason などを含めて応答をそのまま返したいとき
            return item
        text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
        return CompletionResponse(
            text=text,
            parsed=item if isinstance(item, dict) else None,
            usage=self._usage,
            model_reported=self.model,
        )

    async def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True)

    async def aclose(self) -> None:
        self.closed = True


def verdict_payload(**overrides: Any) -> dict[str, Any]:
    """テスト用の妥当な ReviewJudgement ペイロード."""
    payload: dict[str, Any] = {
        "vulnerable": True,
        "vulnerability_type": "OS Command Injection",
        "cwe": ["CWE-78"],
        "severity": "high",
        "confidence": 0.9,
        "false_positive_probability": 0.05,
        "exploitability": "likely",
        "impact": "任意コマンド実行",
        "attack_vector": "HTTP request body",
        "attack_path": ["POST /upload", "filename", "subprocess.run"],
        "evidence": [],
        "reasoning": "ユーザー入力がシェルに渡っています。",
        "remediation": {"approach": "shell=True をやめる", "example": None, "references": []},
        "needs_more_context": [],
    }
    payload.update(overrides)
    return payload


class SlowProvider(ScriptedProvider):
    """実際の HTTP と同じく I/O で待つ Provider.

    ScriptedProvider は await しないので、各タスクが次のタスクの起動前に最後まで走る。
    予算や無効化が「順番待ちの呼び出し」を止めるかは、これを使わないと確かめられない。
    """

    delay_s = 0.01

    async def complete(self, request: CompletionRequest) -> CompletionResponse:
        await asyncio.sleep(self.delay_s)
        return await super().complete(request)
