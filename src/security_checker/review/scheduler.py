"""全 LLM 呼び出しの統括 (設計書 §22, §23).

Provider にはレート制御もリトライも持たせない。ここに集約することで、
Provider ごとの挙動のばらつきを防ぎ、コストと予算の監視を一箇所にまとめる。
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from security_checker.config.schema import BudgetConfig, ReviewerConfig
from security_checker.context.budget import PROMPT_OVERHEAD_TOKENS, estimate_tokens
from security_checker.models.task import ReviewTask
from security_checker.models.verdict import ReviewVerdict, Usage, VerdictStatus
from security_checker.observability import logging as log
from security_checker.observability.quota import QuotaStore, quota_key
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
)
from security_checker.review import prompts
from security_checker.review.prompts import PeerOpinion
from security_checker.review.reviewer import Reviewer, ReviewOutcome, SendCancelledError

#: tpm の見積りでは user プロンプトを実測するので、残りは system の分
SYSTEM_PROMPT_TOKENS = PROMPT_OVERHEAD_TOKENS
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0
BACKOFF_CAP_S = 60.0
CIRCUIT_BREAKER_FAILURES = 5
DEFAULT_DEADLINE_S = 1800.0
#: rate_limit.rpm を書いていない Reviewer の初期値. 429 を受けるまでは絞らない
UNTHROTTLED_RPM = 100_000
#: 429 がこの回数続いたら実効 rpm を下げ (§22.2)、成功がこの回数続いたら戻し始める
THROTTLE_AFTER_RATE_LIMITS = 2
RECOVER_AFTER_SUCCESSES = 5


class RateLimiter:
    """rpm のトークンバケット. 送信直前に 1 リクエスト分を確保する."""

    def __init__(self, rpm: int) -> None:
        self.rpm = rpm
        self.base_rpm = rpm
        self._events: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0] >= 60.0:
                    self._events.popleft()
                if len(self._events) < self.rpm:
                    self._events.append(now)
                    return
                oldest = self._events[0]
                wait_for = 60.0 - (now - oldest)
            await sleep(max(0.05, wait_for))
            async with self._lock:
                # 待った分の枠は空いたものとして扱う
                if self._events and self._events[0] == oldest:
                    self._events.popleft()

    def throttle(self) -> int:
        """実効 rpm を半分に下げる (下限 1). 絞っていなければ直近の実績を起点にする."""
        recent = len(self._events) or 1
        self.rpm = max(1, min(self.rpm, recent) // 2)
        return self.rpm

    def recover(self) -> None:
        self.rpm = min(self.base_rpm, self.rpm * 2)


class TokenLimiter:
    """tpm のスライディングウィンドウ. 送信前に見積もったトークン数を確保する (§22.1).

    1 回で上限を超える依頼は、窓が空になるのを待ってから単独で通す (永久に待たない)。
    """

    def __init__(self, tpm: int) -> None:
        self.tpm = tpm
        self._events: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                while self._events and now - self._events[0][0] >= 60.0:
                    self._events.popleft()
                used = sum(count for _, count in self._events)
                if not self._events or used + tokens <= self.tpm:
                    self._events.append((now, tokens))
                    return
                wait_for = 60.0 - (now - self._events[0][0])
            await asyncio.sleep(max(0.05, wait_for))


@dataclass
class DailyQuota:
    """rpd. 記録はプロセスをまたいで残る (observability/quota.py)."""

    store: QuotaStore
    key: str
    limit: int

    def remaining(self) -> int:
        return self.store.remaining(self.key, self.limit)


@dataclass
class ReviewerRuntime:
    """1 Reviewer 分の実行状態 (並列度・レート・サーキットブレーカ)."""

    reviewer: Reviewer
    semaphore: asyncio.Semaphore
    limiter: RateLimiter | None = None
    consecutive_failures: int = 0
    disabled_reason: str | None = None
    token_limiter: TokenLimiter | None = None
    daily: DailyQuota | None = None
    consecutive_rate_limits: int = 0
    consecutive_successes: int = 0

    @property
    def name(self) -> str:
        return self.reviewer.name


@dataclass
class ScheduleResult:
    """スケジューラの成果. 中断しても部分結果を必ず返す (§20.2)."""

    verdicts: dict[str, list[ReviewVerdict]] = field(default_factory=dict)
    traces: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    reviewed_candidate_ids: set[str] = field(default_factory=set)
    disabled_reviewers: dict[str, str] = field(default_factory=dict)
    stopped_reason: str | None = None
    calls: int = 0


def build_runtime(
    reviewer: Reviewer,
    config: ReviewerConfig,
    *,
    default_concurrency: int,
    quota_store: QuotaStore | None = None,
) -> ReviewerRuntime:
    """設定から実行状態を作る. rate_limit の宣言をスケジューラが尊重する."""
    concurrency = min(config.concurrency, default_concurrency)
    limits = config.rate_limit
    return ReviewerRuntime(
        reviewer=reviewer,
        semaphore=asyncio.Semaphore(max(1, concurrency)),
        limiter=RateLimiter(limits.rpm or UNTHROTTLED_RPM),
        token_limiter=TokenLimiter(limits.tpm) if limits.tpm else None,
        daily=DailyQuota(
            store=quota_store or QuotaStore(),
            key=quota_key(config.name, config.model),
            limit=limits.rpd,
        )
        if limits.rpd
        else None,
    )


def _request_tokens(runtime: ReviewerRuntime, task: ReviewTask) -> int:
    """tpm 用の見積り. 入力は実際のプロンプトから、出力は上限で数える."""
    user = prompts.render_user(task, {})
    return estimate_tokens(user) + SYSTEM_PROMPT_TOKENS + runtime.reviewer.max_output_tokens


class ReviewScheduler:
    """候補 × Reviewer の呼び出しを、レート・並列・予算・時間の制約下で捌く."""

    def __init__(
        self,
        runtimes: list[ReviewerRuntime],
        *,
        budget: BudgetConfig,
        deadline_s: float = DEFAULT_DEADLINE_S,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        self.runtimes = runtimes
        self.budget = budget
        self.deadline_s = deadline_s
        self._sleep: Callable[[float], Awaitable[None]] = sleep or asyncio.sleep
        self._stop = asyncio.Event()
        self._result = ScheduleResult()
        self._lock = asyncio.Lock()
        self._started = time.monotonic()
        #: 送信中の呼び出しの見積り. 使用量は応答が返るまで増えないので、並列分をここで数える
        self._reserved_tokens = 0
        self._reserved_usd = 0.0
        #: 価格の分かる呼び出しの金額の累計 (下限). 合計の usage は 1 件でも価格が分からないと
        #: 金額が不明になるため、予算の判定にはこちらを使う (#311)
        self._known_usd = 0.0
        self._budget_warned = False
        self._opinions: Mapping[str, Sequence[PeerOpinion]] | None = None

    async def run(
        self,
        tasks: list[ReviewTask],
        *,
        opinions: Mapping[str, Sequence[PeerOpinion]] | None = None,
    ) -> ScheduleResult:
        """全候補をレビューする. 予算・デッドライン超過時は部分結果を返す.

        `opinions` (候補 ID → 匿名化した意見) を渡すと、Reviewer は Judge として呼ばれる (§16)。
        """
        self._opinions = opinions
        if not self.runtimes:
            self._result.warnings.append("有効な Reviewer がありません")
            return self._result
        for runtime in self.runtimes:
            if runtime.daily is not None and runtime.daily.remaining() < len(tasks):
                self._result.warnings.append(
                    f"{runtime.name}: 1 日の上限 (rpd {runtime.daily.limit}) の残りが "
                    f"{runtime.daily.remaining()} 回で、候補 {len(tasks)} 件に足りません。"
                    "上限に達した時点でこの Reviewer を止めます"
                )

        await asyncio.gather(
            *(self._review_candidate(runtime, task) for task in tasks for runtime in self.runtimes)
        )
        self._fill_skipped(tasks)
        for runtime in self.runtimes:
            if runtime.daily is not None:
                self._result.warnings.extend(dict.fromkeys(runtime.daily.store.errors))
        return self._result

    # --- 内部 -------------------------------------------------------------

    def _fill_skipped(self, tasks: list[ReviewTask]) -> None:
        """一部の Reviewer だけが判定した候補に、判定しなかった Reviewer の SKIPPED を残す.

        無効化・停止で呼ばなかった Reviewer の verdict が欠けると、集約側は
        「Reviewer が 1 つ」と「残りが失敗した」を区別できない (P9)。
        誰も判定していない候補は not_reviewed として残すため、ここでは足さない。
        """
        for task in tasks:
            verdicts = self._result.verdicts.get(task.candidate.id)
            if not verdicts:
                continue
            seen = {verdict.reviewer for verdict in verdicts}
            for runtime in self.runtimes:
                if runtime.name in seen:
                    continue
                reason = (
                    runtime.disabled_reason
                    or self._result.stopped_reason
                    or "この候補はレビューされませんでした"
                )
                outcome = runtime.reviewer.error_outcome(task, VerdictStatus.SKIPPED, reason)
                verdicts.append(outcome.verdict)

    async def _review_candidate(self, runtime: ReviewerRuntime, task: ReviewTask) -> None:
        outcome = await self._attempt_with_retries(runtime, task)
        if outcome is None:
            return
        verdict = outcome.verdict
        log.event(
            "review.call",
            level="info" if verdict.status is VerdictStatus.OK else "warn",
            reviewer=runtime.name,
            model=verdict.model,
            candidate_id=task.candidate.id,
            judge=self._opinions is not None,
            attempt=verdict.attempt,
            latency_ms=verdict.latency_ms,
            input_tokens=verdict.usage.input_tokens,
            output_tokens=verdict.usage.output_tokens,
            status=verdict.status.value,
        )
        async with self._lock:
            self._result.verdicts.setdefault(task.candidate.id, []).append(outcome.verdict)
            self._result.reviewed_candidate_ids.add(task.candidate.id)
            self._result.warnings.extend(outcome.warnings)
            if outcome.trace:
                self._result.traces.append(outcome.trace)
            self._result.usage = self._result.usage.merge(outcome.verdict.usage)
            if outcome.verdict.usage.cost_known:
                self._known_usd += outcome.verdict.usage.estimated_usd or 0.0
            self._result.calls += 1
        await self._check_budget()

    async def _before_send(self, runtime: ReviewerRuntime, task: ReviewTask) -> tuple[int, float]:
        """提供元への 1 回の送信の直前に呼ぶ. 止めるなら SendCancelledError を投げる.

        順番待ちの間に予算超過や無効化が起きるので、待ったあとにも判定する (§23)。
        確保した見積り (トークン, USD) を返す。呼び出し元が応答のあとで解放する。
        """
        await self._ensure_may_send(runtime)
        if runtime.daily is not None and runtime.daily.remaining() <= 0:
            reason = f"1 日の上限 (rpd {runtime.daily.limit}) に達しました"
            await self._disable(runtime, reason)
            raise SendCancelledError(reason)
        if runtime.limiter is not None:
            await runtime.limiter.acquire(self._sleep)
        tokens = _request_tokens(runtime, task)
        if runtime.token_limiter is not None:
            await runtime.token_limiter.acquire(tokens)
        await self._ensure_may_send(runtime)
        reservation = await self._reserve(runtime, tokens)
        if runtime.daily is not None:
            # 送る前に数える. 失敗した呼び出しも提供元の上限には数えられる
            runtime.daily.store.consume(runtime.daily.key)
        return reservation

    async def _ensure_may_send(self, runtime: ReviewerRuntime) -> None:
        if self._deadline_exceeded():
            await self._stop_run("実行時間の上限に達しました")
        if self._stop.is_set():
            raise SendCancelledError(self._result.stopped_reason or "run が停止しました")
        if runtime.disabled_reason is not None:
            raise SendCancelledError(runtime.disabled_reason)

    async def _reserve(self, runtime: ReviewerRuntime, tokens: int) -> tuple[int, float]:
        """使用量 + 送信中の分 + この呼び出しの見積りが上限を超えるなら、送らずに止める.

        何も使っていないときの 1 回は通す。上限が 1 回分の見積りより小さくても、
        進まないまま止まらないようにするため。見積りは出力の上限で数えるので保守的である。
        """
        usage = self._result.usage
        price = runtime.reviewer.price
        usd = 0.0
        if price is not None:
            output = runtime.reviewer.max_output_tokens
            usd = price.estimate(Usage(input_tokens=max(0, tokens - output), output_tokens=output))
        idle = usage.total_tokens == 0 and self._reserved_tokens == 0
        limit_tokens = self.budget.max_total_tokens
        if (
            not idle
            and limit_tokens is not None
            and usage.total_tokens + self._reserved_tokens + tokens > limit_tokens
        ):
            await self._stop_run(
                f"トークン上限 {limit_tokens} を超える見込みのため止めました "
                f"(実績 {usage.total_tokens}、送信中 {self._reserved_tokens}、次の見積り {tokens})"
            )
        limit_usd = self.budget.max_usd
        if (
            not idle
            and limit_usd is not None
            and price is not None
            and self._known_usd + self._reserved_usd + usd > limit_usd
        ):
            await self._stop_run(f"予算 ${limit_usd} を超える見込みのため止めました")
        if self._stop.is_set():
            raise SendCancelledError(self._result.stopped_reason or "run が停止しました")
        self._reserved_tokens += tokens
        self._reserved_usd += usd
        return tokens, usd

    async def _attempt_with_retries(
        self, runtime: ReviewerRuntime, task: ReviewTask
    ) -> ReviewOutcome | None:
        """None は 1 回も判定できないまま止められたこと. 候補は not_reviewed か SKIPPED になる."""
        last_error = "不明なエラー"
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                async with runtime.semaphore:
                    outcome = await self._review_once(runtime, task)
            except SendCancelledError:
                return None
            except ProviderAuthError as exc:
                # 認証失敗は 1 回で当該 Reviewer を無効化する (§23)
                await self._disable(runtime, str(exc))
                return runtime.reviewer.error_outcome(
                    task, VerdictStatus.PROVIDER_ERROR, str(exc), attempt=attempt
                )
            except ProviderRateLimitError as exc:
                # rate limit はサーキットブレーカに数えない (§23)。壊れているわけではない
                last_error = str(exc)
                await self._on_rate_limit(runtime)
                wait_limit = self._wait_limit()
                if exc.retry_after is not None and exc.retry_after > wait_limit:
                    message = (
                        f"{last_error} (Retry-After {exc.retry_after:.0f}s は"
                        f"待てる上限 {wait_limit:.0f}s を超えるため待ちません)"
                    )
                    return runtime.reviewer.error_outcome(
                        task, VerdictStatus.PROVIDER_ERROR, message, attempt=attempt
                    )
                if attempt == MAX_ATTEMPTS:
                    return runtime.reviewer.error_outcome(
                        task, VerdictStatus.PROVIDER_ERROR, last_error, attempt=attempt
                    )
                await self._sleep(min(_backoff_delay(attempt, exc), wait_limit))
                continue
            except ProviderError as exc:
                last_error = str(exc)
                if not exc.retryable or attempt == MAX_ATTEMPTS:
                    await self._record_failure(runtime, last_error)
                    return runtime.reviewer.error_outcome(
                        task, VerdictStatus.PROVIDER_ERROR, last_error, attempt=attempt
                    )
                await self._sleep(min(_backoff_delay(attempt, exc), self._wait_limit()))
                continue

            runtime.consecutive_rate_limits = 0
            if outcome.verdict.status is VerdictStatus.OK:
                runtime.consecutive_failures = 0
                self._on_success(runtime)
            else:
                await self._record_failure(runtime, outcome.verdict.reasoning)
            return outcome

        return runtime.reviewer.error_outcome(
            task, VerdictStatus.PROVIDER_ERROR, last_error, attempt=MAX_ATTEMPTS
        )

    async def _review_once(self, runtime: ReviewerRuntime, task: ReviewTask) -> ReviewOutcome:
        """1 回のレビュー. 見積りの確保は応答が返った時点で解く (実績は呼び出し元が足す)."""
        reservations: list[tuple[int, float]] = []

        async def before_send() -> None:
            reservations.append(await self._before_send(runtime, task))

        try:
            return await runtime.reviewer.review(
                task,
                opinions=self._opinions.get(task.candidate.id)
                if self._opinions is not None
                else None,
                before_send=before_send,
            )
        finally:
            for tokens, usd in reservations:
                self._reserved_tokens -= tokens
                self._reserved_usd -= usd

    async def _on_rate_limit(self, runtime: ReviewerRuntime) -> None:
        """429 が続くなら実効 rpm を下げる (§22.2). 無料枠で「とりあえず動く」ことを優先する."""
        runtime.consecutive_successes = 0
        runtime.consecutive_rate_limits += 1
        if runtime.limiter is None or runtime.consecutive_rate_limits < THROTTLE_AFTER_RATE_LIMITS:
            return
        rpm = runtime.limiter.throttle()
        async with self._lock:
            message = f"{runtime.name}: 429 が続くため実効 rpm を {rpm} に下げました"
            if message not in self._result.warnings:
                self._result.warnings.append(message)

    def _on_success(self, runtime: ReviewerRuntime) -> None:
        runtime.consecutive_successes += 1
        if runtime.limiter is not None and runtime.consecutive_successes >= RECOVER_AFTER_SUCCESSES:
            runtime.limiter.recover()
            runtime.consecutive_successes = 0

    def _wait_limit(self) -> float:
        """Retry-After やバックオフで待てる上限. 残り時間を超えては待たない (§22.2)."""
        remaining = self.deadline_s - (time.monotonic() - self._started)
        return max(0.0, min(BACKOFF_CAP_S, remaining))

    async def _record_failure(self, runtime: ReviewerRuntime, message: str) -> None:
        runtime.consecutive_failures += 1
        if runtime.consecutive_failures >= CIRCUIT_BREAKER_FAILURES:
            await self._disable(
                runtime,
                f"{CIRCUIT_BREAKER_FAILURES} 回連続で失敗したため無効化しました: {message}",
            )

    async def _disable(self, runtime: ReviewerRuntime, reason: str) -> None:
        if runtime.disabled_reason is not None:
            return
        runtime.disabled_reason = reason
        log.event("reviewer.disabled", level="warn", reviewer=runtime.name, reason=reason)
        async with self._lock:
            self._result.disabled_reviewers[runtime.name] = reason
            self._result.warnings.append(f"{runtime.name}: {reason}")

    async def _check_budget(self) -> None:
        usage = self._result.usage
        if (
            self.budget.max_total_tokens is not None
            and usage.total_tokens > self.budget.max_total_tokens
        ):
            await self._stop_run(
                f"トークン上限 {self.budget.max_total_tokens} を超えました "
                f"(実績 {usage.total_tokens})"
            )
        if self.budget.max_usd is not None and self._known_usd > self.budget.max_usd:
            await self._stop_run(
                f"予算 ${self.budget.max_usd} を超えました "
                f"(価格の分かる呼び出しだけで概算 ${self._known_usd:.4f})"
            )

    async def _stop_run(self, reason: str) -> None:
        if self.budget.on_exceed == "warn_and_continue" and "予算" in reason:
            async with self._lock:
                if not self._budget_warned:
                    self._budget_warned = True
                    self._result.warnings.append(f"{reason} (warn_and_continue のため続行します)")
            return
        if self._stop.is_set():
            return
        self._stop.set()
        async with self._lock:
            self._result.stopped_reason = reason
            self._result.warnings.append(f"{reason}。ここまでの結果を出力します")

    def _deadline_exceeded(self) -> bool:
        return (time.monotonic() - self._started) > self.deadline_s


def _backoff_delay(attempt: int, exc: ProviderError) -> float:
    """指数バックオフ + フルジッター. Retry-After があれば上限の範囲で尊重する (§22.2)."""
    if isinstance(exc, ProviderRateLimitError) and exc.retry_after is not None:
        return max(0.0, exc.retry_after)
    ceiling = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2.0 ** (attempt - 1)))
    jitter: float = random.random()  # noqa: S311 - 暗号用途ではない
    return jitter * ceiling
