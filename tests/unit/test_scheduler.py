"""スケジューラのリトライ・サーキットブレーカ・予算 (設計書 §22, §23)."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from security_checker.config.schema import BudgetConfig, RateLimit, ReviewerConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category
from security_checker.models.task import CodeContext, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import Usage, VerdictStatus
from security_checker.observability.cost import ModelPrice
from security_checker.observability.quota import QuotaStore
from security_checker.providers.errors import (
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderServerError,
)
from security_checker.providers.http.transport import _retry_after
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import (
    CIRCUIT_BREAKER_FAILURES,
    RateLimiter,
    ReviewScheduler,
    build_runtime,
)
from security_checker.testing import ScriptedProvider, SlowProvider, verdict_payload


def make_task(index: int = 0) -> ReviewTask:
    candidate = Candidate(
        id=f"c{index}",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="r",
        title="t",
        message="m",
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(),
        repo_facts=RepoFacts(),
        budget=TokenBudget(max_tokens_per_task=8000),
    )


def make_scheduler(
    script: Sequence[Any],
    *,
    budget: BudgetConfig | None = None,
    rpm: int | None = None,
) -> tuple[ReviewScheduler, Any, ScriptedProvider, list[float]]:
    provider = ScriptedProvider(script)
    reviewer = Reviewer("r1", provider)
    config = ReviewerConfig(
        name="r1",
        transport="http",
        dialect="openai_chat",
        base_url="http://x/v1",
        model="m",
        rate_limit=RateLimit(rpm=rpm),
    )
    runtime = build_runtime(reviewer, config, default_concurrency=4)
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    scheduler = ReviewScheduler([runtime], budget=budget or BudgetConfig(), sleep=fake_sleep)
    return scheduler, runtime, provider, slept


async def test_successful_run_collects_verdicts():
    scheduler, _, provider, _ = make_scheduler([verdict_payload(), verdict_payload()])
    result = await scheduler.run([make_task(0), make_task(1)])

    assert set(result.verdicts) == {"c0", "c1"}
    assert result.calls == 2
    assert result.usage.total_tokens == 300
    assert len(provider.requests) == 2


async def test_retries_transient_errors():
    scheduler, _, provider, slept = make_scheduler([ProviderServerError("500"), verdict_payload()])
    result = await scheduler.run([make_task()])

    assert result.verdicts["c0"][0].status is VerdictStatus.OK
    assert len(provider.requests) == 2
    assert len(slept) == 1  # バックオフが 1 回


async def test_gives_up_after_max_attempts():
    scheduler, _, provider, _ = make_scheduler([ProviderServerError("500")] * 3)
    result = await scheduler.run([make_task()])

    verdict = result.verdicts["c0"][0]
    assert verdict.status is VerdictStatus.PROVIDER_ERROR
    assert len(provider.requests) == 3  # 初回 + 2 リトライ


async def test_rate_limit_error_respects_retry_after():
    scheduler, _, _, slept = make_scheduler(
        [ProviderRateLimitError("429", retry_after=7.5), verdict_payload()]
    )
    await scheduler.run([make_task()])
    assert slept == [7.5]


async def test_auth_error_disables_reviewer_immediately():
    """認証失敗はリトライせず、その Reviewer を run 全体で無効化する (§23)."""
    scheduler, runtime, provider, _ = make_scheduler(
        [ProviderAuthError("401"), verdict_payload(), verdict_payload()]
    )
    result = await scheduler.run([make_task(0), make_task(1), make_task(2)])

    assert runtime.disabled_reason is not None
    assert "r1" in result.disabled_reviewers
    assert len(provider.requests) == 1  # 以降は呼ばない


async def test_circuit_breaker_after_consecutive_failures():
    scheduler, runtime, _, _ = make_scheduler([ProviderServerError("500")] * 30)
    await scheduler.run([make_task(index) for index in range(10)])

    assert runtime.disabled_reason is not None
    assert "連続で失敗" in runtime.disabled_reason


async def test_schema_error_counts_as_failure_but_is_reported():
    scheduler, _, _, _ = make_scheduler(["壊れた応答", "また壊れた応答"])
    result = await scheduler.run([make_task()])

    verdict = result.verdicts["c0"][0]
    assert verdict.status is VerdictStatus.SCHEMA_ERROR
    assert result.calls == 1  # 判定不能でもレポートには残る


async def test_token_budget_stops_run_and_keeps_partial_results():
    budget = BudgetConfig(max_total_tokens=200, max_usd=None)
    scheduler, _, provider, _ = make_scheduler([verdict_payload()] * 5, budget=budget)
    result = await scheduler.run([make_task(index) for index in range(5)])

    assert result.stopped_reason is not None
    assert "トークン上限" in result.stopped_reason
    assert result.verdicts  # 部分結果は捨てない
    assert len(provider.requests) < 5


async def test_disabled_reviewer_leaves_skipped_verdicts():
    """途中で無効化された Reviewer の分も SKIPPED として残す.

    欠けると、集約側が単独 Reviewer と区別できない (#91)。
    """
    _, broken, _, _ = make_scheduler([ProviderAuthError("401")])
    working = build_runtime(
        Reviewer("r2", ScriptedProvider([verdict_payload()] * 3)),
        ReviewerConfig(
            name="r2", transport="http", dialect="openai_chat", base_url="http://x/v1", model="m"
        ),
        default_concurrency=4,
    )
    scheduler = ReviewScheduler([broken, working], budget=BudgetConfig())
    result = await scheduler.run([make_task(index) for index in range(3)])

    for index in range(3):
        verdicts = {v.reviewer: v for v in result.verdicts[f"c{index}"]}
        assert set(verdicts) == {"r1", "r2"}
        assert verdicts["r2"].status is VerdictStatus.OK
        assert verdicts["r1"].status is not VerdictStatus.OK
    assert result.calls == 4  # 足した SKIPPED は呼び出しに数えない


async def test_unreviewed_candidates_get_no_skipped_verdicts():
    """誰も判定していない候補は not_reviewed のまま残すため、SKIPPED を足さない."""
    scheduler, _, _, _ = make_scheduler([ProviderAuthError("401")])
    result = await scheduler.run([make_task(index) for index in range(3)])

    assert set(result.verdicts) == {"c0"}


async def test_no_reviewers_is_reported():
    scheduler = ReviewScheduler([], budget=BudgetConfig())
    result = await scheduler.run([make_task()])
    assert result.verdicts == {}
    assert any("Reviewer" in warning for warning in result.warnings)


async def test_rate_limiter_allows_burst_up_to_rpm():
    limiter = RateLimiter(rpm=3)
    await asyncio.wait_for(asyncio.gather(*(limiter.acquire() for _ in range(3))), timeout=1.0)


async def test_rate_limiter_blocks_beyond_rpm():
    limiter = RateLimiter(rpm=1)
    await limiter.acquire()
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(limiter.acquire(), timeout=0.2)


async def test_usage_is_priced_as_unknown_without_table():
    scheduler, _, _, _ = make_scheduler([verdict_payload()])
    result = await scheduler.run([make_task()])
    assert result.usage.cost_known is False
    assert result.usage == Usage(
        input_tokens=100, output_tokens=50, estimated_usd=None, cost_known=False
    )


# --- 順番待ちの呼び出しも止める (#146) -------------------------------------------


def slow_runtime(
    script: Sequence[Any], *, concurrency: int = 1, price: ModelPrice | None = None
) -> tuple[SlowProvider, Any]:
    provider = SlowProvider(script)
    config = ReviewerConfig(
        name="r1",
        transport="http",
        dialect="openai_chat",
        base_url="http://x/v1",
        model="m",
        concurrency=concurrency,
    )
    reviewer = Reviewer("r1", provider, price=price)
    return provider, build_runtime(reviewer, config, default_concurrency=4)


async def test_token_budget_stops_waiting_calls():
    provider, runtime = slow_runtime([verdict_payload()] * 10)
    result = await ReviewScheduler(
        [runtime], budget=BudgetConfig(max_total_tokens=200, max_usd=None)
    ).run([make_task(i) for i in range(10)])
    assert len(provider.requests) == 1
    assert "トークン上限" in (result.stopped_reason or "")
    assert result.usage.total_tokens == 150


async def test_usd_budget_counts_calls_in_flight():
    """並列に飛んでいる分も見積りに入れる. 応答を待つ間に上限を超えて送らない."""
    price = ModelPrice(input_per_1m=1000.0, output_per_1m=1000.0)
    provider, runtime = slow_runtime([verdict_payload()] * 8, concurrency=4, price=price)
    result = await ReviewScheduler(
        [runtime], budget=BudgetConfig(max_usd=4.0, max_total_tokens=None)
    ).run([make_task(i) for i in range(8)])
    assert len(provider.requests) == 1  # 1 回の見積りは出力上限込みで $3.5 超
    assert "予算" in (result.stopped_reason or "")


async def test_warn_and_continue_warns_once_and_keeps_sending():
    price = ModelPrice(input_per_1m=1000.0, output_per_1m=1000.0)
    provider, runtime = slow_runtime([verdict_payload()] * 4, price=price)
    result = await ReviewScheduler(
        [runtime],
        budget=BudgetConfig(max_usd=0.01, max_total_tokens=None, on_exceed="warn_and_continue"),
    ).run([make_task(i) for i in range(4)])
    assert len(provider.requests) == 4
    assert sum("warn_and_continue" in warning for warning in result.warnings) == 1


async def test_disabling_a_reviewer_stops_its_waiting_calls():
    provider, runtime = slow_runtime([ProviderAuthError("401")] + [verdict_payload()] * 9)
    await ReviewScheduler([runtime], budget=BudgetConfig()).run([make_task(i) for i in range(10)])
    assert len(provider.requests) == 1
    assert runtime.disabled_reason == "401"


async def test_deadline_stops_waiting_calls():
    provider, runtime = slow_runtime([verdict_payload()] * 10)
    result = await ReviewScheduler([runtime], budget=BudgetConfig(), deadline_s=0.015).run(
        [make_task(i) for i in range(10)]
    )
    assert len(provider.requests) < 10
    assert "実行時間" in (result.stopped_reason or "")


async def test_reservations_are_released_after_each_call():
    _, runtime = slow_runtime([verdict_payload()] * 3)
    scheduler = ReviewScheduler([runtime], budget=BudgetConfig())
    await scheduler.run([make_task(i) for i in range(3)])
    assert scheduler._reserved_tokens == 0
    assert scheduler._reserved_usd == 0.0


# --- スキーマ修復の再送もレート制御を通す (#148) ------------------------------------


async def test_schema_repair_counts_against_rpd(tmp_path: Path) -> None:
    store = QuotaStore(tmp_path / "quota.json")
    provider = ScriptedProvider(["broken", verdict_payload()] * 3)
    config = ReviewerConfig(
        name="r1",
        transport="http",
        dialect="openai_chat",
        base_url="http://x/v1",
        model="m",
        rate_limit=RateLimit(rpd=3),
    )
    runtime = build_runtime(
        Reviewer("r1", provider), config, default_concurrency=4, quota_store=store
    )
    result = await ReviewScheduler([runtime], budget=BudgetConfig()).run(
        [make_task(i) for i in range(3)]
    )
    assert len(provider.requests) == 3  # 宣言した上限を超えて送らない
    assert runtime.daily is not None
    assert runtime.daily.remaining() == 0
    # 修復の直前で止まった候補も、使った分とともに残る
    assert any(v[0].status is VerdictStatus.SCHEMA_ERROR for v in result.verdicts.values())


# --- 429 の扱い (#149) ------------------------------------------------------------


async def test_rate_limits_do_not_open_the_circuit_breaker():
    failures = CIRCUIT_BREAKER_FAILURES * 3
    scheduler, runtime, _, _ = make_scheduler([ProviderRateLimitError("429")] * failures)
    await scheduler.run([make_task(i) for i in range(CIRCUIT_BREAKER_FAILURES)])
    assert runtime.disabled_reason is None


async def test_a_long_retry_after_is_not_waited_for():
    scheduler, _, provider, slept = make_scheduler(
        [ProviderRateLimitError("429", retry_after=86400), verdict_payload()]
    )
    result = await scheduler.run([make_task()])
    verdict = result.verdicts["c0"][0]
    assert slept == []
    assert len(provider.requests) == 1
    assert verdict.status is VerdictStatus.PROVIDER_ERROR
    assert "86400" in verdict.reasoning


async def test_consecutive_rate_limits_lower_the_effective_rpm_and_success_restores_it():
    scheduler, runtime, _, _ = make_scheduler(
        [ProviderRateLimitError("429")] * 2 + [verdict_payload()] * 6, rpm=8
    )
    result = await scheduler.run([make_task(i) for i in range(1)])
    assert runtime.limiter.rpm < 8
    assert any("実効 rpm" in warning for warning in result.warnings)
    lowered = runtime.limiter.rpm
    await scheduler.run([make_task(i) for i in range(1, 6)])
    assert lowered < runtime.limiter.rpm <= 8


async def test_a_reviewer_without_declared_rpm_can_also_be_throttled():
    scheduler, runtime, _, _ = make_scheduler(
        [ProviderRateLimitError("429")] * 2 + [verdict_payload()]
    )
    await scheduler.run([make_task()])
    assert runtime.limiter is not None
    assert runtime.limiter.rpm == 1


def test_retry_after_reads_seconds_and_http_dates():
    def header(value: str) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": value})

    assert _retry_after(header("12")) == 12.0
    later = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    delay = _retry_after(header(later))
    assert delay is not None
    assert 25 <= delay <= 31
    past = format_datetime(datetime.now(UTC) - timedelta(seconds=30), usegmt=True)
    assert _retry_after(header(past)) == 0.0
    assert _retry_after(header("soon")) is None


async def test_usd_budget_still_works_with_an_unpriced_reviewer():
    """価格の分からない Reviewer が混ざっても、分かっている分だけで上限を超えたら止める (#311)."""
    price = ModelPrice(input_per_1m=1000.0, output_per_1m=1000.0)
    priced_provider, priced = slow_runtime([verdict_payload()] * 8, price=price)
    unpriced_provider = SlowProvider([verdict_payload()] * 8)
    unpriced = build_runtime(
        Reviewer("r2", unpriced_provider),
        ReviewerConfig(
            name="r2", transport="http", dialect="openai_chat", base_url="http://x/v1", model="m"
        ),
        default_concurrency=1,
    )
    result = await ReviewScheduler(
        [priced, unpriced], budget=BudgetConfig(max_usd=4.0, max_total_tokens=None)
    ).run([make_task(i) for i in range(8)])
    assert "予算" in (result.stopped_reason or "")
    assert len(priced_provider.requests) < 8
