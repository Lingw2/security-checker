"""Provider 契約テスト (設計書 §25.2).

外部プラグイン作者は次だけ書けば自作 Provider の適合性を検証できる:

    class TestMyProvider(ProviderContractTests):
        def make_provider(self):
            return MyProvider(...)

HTTP で話す Provider は `make_http_provider` も実装すると、例外の正規化・降格・
内部リトライなしまで検証できる。実装しなければ、その項目は skip になる。
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from security_checker.providers.base import (
    Capabilities,
    CompletionRequest,
    CompletionResponse,
    LLMProvider,
    StructuredMode,
)
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderBadRequestError,
    ProviderRateLimitError,
    ProviderServerError,
    ProviderTimeoutError,
)
from security_checker.providers.process.runner import ProcessProvider


class ProviderContractTests:
    """すべての Provider が満たすべき契約."""

    def make_provider(self) -> LLMProvider:  # pragma: no cover - サブクラスが実装する
        raise NotImplementedError

    def make_http_provider(
        self, handler: Callable[[httpx.Request], httpx.Response]
    ) -> LLMProvider | None:
        """`handler` を偽のエンドポイントとして使う Provider を返す (任意).

        `httpx.MockTransport(handler)` を内部のクライアントに渡す。
        注入できない Provider は None のままでよい。§25.2 の 3・4・6 番が skip になる。
        """
        del handler
        return None

    def ok_response(self) -> httpx.Response:
        """スキーマを満たす正常応答. 方言ごとに形が違うので、必要なら上書きする."""
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "{}"}}], "usage": {"prompt_tokens": 1}}
        )

    def _http_provider(self, handler: Callable[[httpx.Request], httpx.Response]) -> LLMProvider:
        provider = self.make_http_provider(handler)
        if provider is None:
            pytest.skip("make_http_provider が実装されていない (§25.2 の 3・4・6 番)")
        return provider

    def make_request(self, **overrides: Any) -> CompletionRequest:
        payload: dict[str, Any] = {
            "system": "system",
            "user": "user",
            "json_schema": {"type": "object", "properties": {}},
            "max_output_tokens": 128,
            "timeout_s": 5.0,
        }
        payload.update(overrides)
        return CompletionRequest(**payload)

    def test_capabilities_are_valid(self) -> None:
        provider = self.make_provider()
        capabilities = provider.capabilities
        assert isinstance(capabilities, Capabilities)
        assert capabilities.max_context_tokens > 0
        assert capabilities.max_output_tokens > 0
        assert isinstance(capabilities.structured_output, StructuredMode)

    def test_identity_fields(self) -> None:
        provider = self.make_provider()
        assert provider.transport in ("http", "process")
        assert isinstance(provider.dialect, str) and provider.dialect

    @pytest.mark.asyncio
    async def test_complete_returns_response(self) -> None:
        provider = self.make_provider()
        response = await provider.complete(self.make_request())
        assert isinstance(response, CompletionResponse)
        assert isinstance(response.text, str)
        assert response.usage.total_tokens > 0, "usage が埋まっていない"
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_aclose_is_idempotent(self) -> None:
        provider = self.make_provider()
        await provider.aclose()
        await provider.aclose()

    # --- HTTP の失敗の正規化 (§25.2 の 3 番) ------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("status", "error"),
        [
            (401, ProviderAuthError),
            (403, ProviderAuthError),
            (429, ProviderRateLimitError),
            (500, ProviderServerError),
            (503, ProviderServerError),
        ],
    )
    async def test_http_errors_are_normalized(self, status: int, error: type[Exception]) -> None:
        provider = self._http_provider(lambda _: httpx.Response(status, text="error"))
        with pytest.raises(error):
            await provider.complete(self.make_request())
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_rate_limit_carries_retry_after(self) -> None:
        provider = self._http_provider(
            lambda _: httpx.Response(429, text="slow", headers={"Retry-After": "12"})
        )
        with pytest.raises(ProviderRateLimitError) as excinfo:
            await provider.complete(self.make_request())
        assert excinfo.value.retry_after == 12.0
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_a_timeout_is_normalized(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timeout", request=request)

        provider = self._http_provider(handler)
        with pytest.raises(ProviderTimeoutError):
            await provider.complete(self.make_request())
        await provider.aclose()

    # --- 構造化出力の降格 (§25.2 の 4 番) --------------------------------------

    @pytest.mark.asyncio
    async def test_a_rejected_schema_is_degraded(self) -> None:
        """400 なら 1 段降格して送り直し、結果に degraded_to が入る."""
        responses = [httpx.Response(400, text="unsupported schema"), self.ok_response()]
        provider = self._http_provider(lambda _: responses.pop(0))
        if provider.capabilities.structured_output is StructuredMode.PROMPT_ONLY:
            pytest.skip("これ以上降格できない")
        response = await provider.complete(self.make_request())
        assert response.degraded_to is not None
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_other_client_errors_are_not_degraded(self) -> None:
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(404, text="no such model")

        provider = self._http_provider(handler)
        with pytest.raises(ProviderBadRequestError):
            await provider.complete(self.make_request())
        assert len(calls) == 1
        await provider.aclose()

    # --- 内部でリトライしない (§25.2 の 6 番) -----------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [429, 500])
    async def test_no_retry_inside_the_provider(self, status: int) -> None:
        """リトライは scheduler の責務. 内部で繰り返すとバックオフと予算が効かなくなる."""
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return httpx.Response(status, text="error")

        provider = self._http_provider(handler)
        with pytest.raises((ProviderRateLimitError, ProviderServerError)):
            await provider.complete(self.make_request())
        assert len(calls) == 1
        await provider.aclose()


# --- process transport への追加契約 (設計書 §25.2 の 7〜10) --------------------
#
# フィクスチャは実在のコマンドを模したものではなく、§9.7 の契約
# (stdin を読み、stdout にテキストを返し、exit 0 で終わる) だけを満たす最小のスクリプト。
# テストが特定ベンダーの挙動に依存しないようにするための意図的な選択である。

ECHO_SCRIPT = (
    "import json,os,sys;"
    "data=sys.stdin.read();"
    "print(json.dumps({'cwd': os.getcwd(), 'argv': sys.argv[1:], 'stdin_len': len(data)}))"
)

WRITER_SCRIPT = (
    "import json,pathlib,sys;"
    "sys.stdin.read();"
    "pathlib.Path('written-by-reviewer.txt').write_text('x', encoding='utf-8');"
    "print(json.dumps({'wrote': True}))"
)

SPAWNER_SCRIPT = (
    "import pathlib,subprocess,sys,time;"
    "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']);"
    "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8');"
    "time.sleep(120)"
)

#: 親はすぐ終了し、孫だけが stdout を持ったまま残る
EARLY_EXIT_SPAWNER_SCRIPT = (
    "import pathlib,subprocess,sys;"
    "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']);"
    "pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8');"
    "print('{}')"
)

CHILD_REAP_DEADLINE_S = 10.0


def python_command(script: str, *args: str) -> list[str]:
    """契約テスト用の最小コマンドを組み立てる (実行系は現在の Python)."""
    return [sys.executable, "-c", script, *args]


class ProcessProviderContractTests(ProviderContractTests):
    """`process` transport が追加で満たすべき契約 (設計書 §25.2 の 7〜10).

    9 番 (実行後に cwd へファイルが作られていないこと) は
    P3 (No Automatic Modification) を保証する唯一の自動検証である。
    """

    def make_process_provider(self, command: list[str]) -> ProcessProvider:
        """指定した argv で Provider を作る. 別実装はここだけ差し替えればよい."""
        return ProcessProvider(name="contract", command=command, capabilities=Capabilities())

    def make_provider(self) -> LLMProvider:
        return self.make_process_provider(python_command(ECHO_SCRIPT))

    def _echo(self, response: CompletionResponse) -> dict[str, Any]:
        assert response.parsed is not None, "stdout から JSON を抽出できていない"
        return response.parsed

    def test_structured_output_is_prompt_only(self) -> None:
        """stdin/stdout の契約しかないため、スキーマ強制はできない (§9.7)."""
        provider = self.make_provider()
        assert provider.capabilities.structured_output is StructuredMode.PROMPT_ONLY

    @pytest.mark.asyncio
    async def test_prompt_never_reaches_argv(self) -> None:
        """契約 7: シェルを経由せず、プロンプトを引数に埋め込まない."""
        provider = self.make_process_provider(python_command(ECHO_SCRIPT))
        # シェル経由なら副作用を持つ文字列。argv にもシェルにも渡ってはならない。
        prompt = "'; touch /tmp/security-checker-should-not-exist; echo '"
        response = await provider.complete(self.make_request(system="", user=prompt))
        echoed = self._echo(response)
        assert all(prompt not in arg for arg in echoed["argv"])
        assert echoed["stdin_len"] == len(prompt)
        assert not _exists("/tmp/security-checker-should-not-exist")
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_cwd_is_outside_the_repository(self) -> None:
        """契約 8: cwd はレビュー対象リポジトリの外の、毎回作り直す空ディレクトリ."""
        provider = self.make_provider()
        response = await provider.complete(self.make_request())
        assert _is_outside_repository(self._echo(response)["cwd"])
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_no_files_are_created_by_a_well_behaved_command(self) -> None:
        """契約 9 (前半): 何も書かないコマンドでは書込検知が沈黙する."""
        provider = self.make_provider()
        response = await provider.complete(self.make_request())
        assert response.warnings == []
        assert response.trace_response.get("created_paths") == []
        await provider.aclose()

    @pytest.mark.asyncio
    async def test_write_attempt_is_detected(self) -> None:
        """契約 9 (後半): 書き込みを試みるコマンドを検知できる — P3 の実測."""
        provider = self.make_process_provider(python_command(WRITER_SCRIPT))
        response = await provider.complete(self.make_request())
        assert response.trace_response.get("created_paths") == ["written-by-reviewer.txt"]
        assert any("written-by-reviewer.txt" in warning for warning in response.warnings)
        await provider.aclose()

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
    async def test_timeout_reaps_the_process_group(self, tmp_path: Path) -> None:
        """契約 10: タイムアウトで子プロセスが残らない (killpg)."""
        pid_file = tmp_path / "child.pid"
        provider = self.make_process_provider(python_command(SPAWNER_SCRIPT, str(pid_file)))
        with pytest.raises(ProviderTimeoutError):
            await provider.complete(self.make_request(timeout_s=1.5))

        assert _exists(pid_file), "フィクスチャが子プロセスを起動できていない"
        child_pid = int(_read(pid_file))
        deadline = time.monotonic() + CHILD_REAP_DEADLINE_S
        while time.monotonic() < deadline:
            if not _process_alive(child_pid):
                break
            await asyncio.sleep(0.1)
        assert not _process_alive(child_pid), f"孫プロセス {child_pid} が残っている"
        await provider.aclose()

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
    async def test_timeout_reaps_a_grandchild_after_the_parent_exits(self, tmp_path: Path) -> None:
        """契約 10: 親が先に終了しても、stdout を持った孫プロセスが残らない."""
        pid_file = tmp_path / "child.pid"
        provider = self.make_process_provider(
            python_command(EARLY_EXIT_SPAWNER_SCRIPT, str(pid_file))
        )
        with pytest.raises(ProviderTimeoutError):
            await provider.complete(self.make_request(timeout_s=1.5))

        assert _exists(pid_file), "フィクスチャが子プロセスを起動できていない"
        child_pid = int(_read(pid_file))
        deadline = time.monotonic() + CHILD_REAP_DEADLINE_S
        while time.monotonic() < deadline:
            if not _process_alive(child_pid):
                break
            await asyncio.sleep(0.1)
        assert not _process_alive(child_pid), f"孫プロセス {child_pid} が残っている"
        await provider.aclose()


def _is_outside_repository(reported_cwd: str) -> bool:
    cwd = Path(reported_cwd).resolve()
    repository = Path.cwd().resolve()
    return cwd != repository and repository not in cwd.parents


def _exists(path: str | Path) -> bool:
    return Path(path).exists()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # 存在はするが signal を送れない
        return True
    return True
