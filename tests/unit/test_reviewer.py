"""Reviewer の Verdict 生成と修復リトライ (設計書 §10.2, §24)."""

from __future__ import annotations

import json

import pytest

from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, Severity
from security_checker.models.task import CodeContext, CodeSlice, RepoFacts, ReviewTask, TokenBudget
from security_checker.models.verdict import ReviewJudgement, VerdictStatus
from security_checker.observability.cost import ModelPrice
from security_checker.providers.base import Capabilities, StructuredMode
from security_checker.review.reviewer import Reviewer
from security_checker.review.structured import drop_hallucinated_evidence
from security_checker.testing import ScriptedProvider, verdict_payload


def make_task(category: Category = Category.SAST) -> ReviewTask:
    candidate = Candidate(
        id="c1",
        scanner="semgrep",
        category=category,
        rule_id="rules.x",
        title="t",
        message="ユーザー入力がシェルに渡る",
        location=Location(path="src/app.py", start_line=10, end_line=10),
        severity_reported=Severity.HIGH,
        cwe=["CWE-78"],
    )
    return ReviewTask(
        candidate=candidate,
        code_context=CodeContext(
            primary=CodeSlice(
                path="src/app.py", start_line=5, end_line=15, text="\n".join("x" for _ in range(11))
            )
        ),
        repo_facts=RepoFacts(languages=["Python"], frameworks=["flask"]),
        budget=TokenBudget(max_tokens_per_task=8000),
    )


async def test_successful_review_produces_verdict():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider)

    outcome = await reviewer.review(make_task())

    assert outcome.verdict.status is VerdictStatus.OK
    assert outcome.verdict.vulnerable is True
    assert outcome.verdict.severity is Severity.HIGH
    assert outcome.verdict.candidate_id == "c1"
    assert outcome.verdict.reviewer == "r1"
    assert outcome.verdict.usage.input_tokens == 100


async def test_prompt_contains_untrusted_delimiters_and_schema():
    provider = ScriptedProvider([verdict_payload()])
    await Reviewer("r1", provider).review(make_task())

    request = provider.requests[0]
    assert "<<<UNTRUSTED_CODE>>>" in request.user
    assert "UNTRUSTED DATA" in request.system
    assert "src/app.py" in request.user
    assert request.json_schema is not None
    assert request.temperature == 0.0


async def test_repair_retry_recovers_from_broken_json():
    """壊れた応答は 1 回だけ修復を試みる (§10.2)."""
    provider = ScriptedProvider(["これは JSON ではありません", json.dumps(verdict_payload())])
    outcome = await Reviewer("r1", provider).review(make_task())

    assert outcome.verdict.status is VerdictStatus.OK
    assert outcome.verdict.attempt == 2
    assert len(provider.requests) == 2
    assert "不正でした" in provider.requests[1].user


async def test_repair_is_attempted_only_once():
    provider = ScriptedProvider(["壊れています", "まだ壊れています"])
    outcome = await Reviewer("r1", provider).review(make_task())

    assert outcome.verdict.status is VerdictStatus.SCHEMA_ERROR
    assert len(provider.requests) == 2  # 3 回目は呼ばない
    assert outcome.warnings


async def test_usage_is_summed_across_repair():
    provider = ScriptedProvider(["壊れています", json.dumps(verdict_payload())])
    outcome = await Reviewer("r1", provider).review(make_task())
    assert outcome.verdict.usage.input_tokens == 200


async def test_cost_is_unknown_without_price_table():
    provider = ScriptedProvider([verdict_payload()])
    outcome = await Reviewer("r1", provider).review(make_task())
    assert outcome.verdict.usage.cost_known is False
    assert outcome.verdict.usage.estimated_usd is None


async def test_cost_is_computed_with_price():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider, price=ModelPrice(input_per_1m=10.0, output_per_1m=30.0))
    outcome = await reviewer.review(make_task())

    assert outcome.verdict.usage.cost_known is True
    assert outcome.verdict.usage.estimated_usd == (100 * 10.0 + 50 * 30.0) / 1_000_000


async def test_trace_records_hashes_not_prompts_by_default():
    """既定ではプロンプト全文を保存しない (§24.2)."""
    provider = ScriptedProvider([verdict_payload()])
    outcome = await Reviewer("r1", provider).review(make_task())

    prompt = outcome.trace["prompt"]
    assert "system_sha256" in prompt
    assert "system" not in prompt
    assert outcome.trace["status"] == "ok"


async def test_trace_can_include_prompts():
    provider = ScriptedProvider([verdict_payload()])
    reviewer = Reviewer("r1", provider, save_prompts=True)
    outcome = await reviewer.review(make_task())
    assert (
        "<<<UNTRUSTED_CODE>>>"
        in outcome.trace["prompt"]["system"] + outcome.trace["prompt"]["user"]
    )


async def test_out_of_range_evidence_is_dropped():
    payload = verdict_payload(
        evidence=[{"path": "src/app.py", "start_line": 999, "end_line": 999, "note": "範囲外"}]
    )
    outcome = await Reviewer("r1", ScriptedProvider([payload])).review(make_task())

    assert outcome.verdict.evidence == []
    assert any("範囲外" in warning for warning in outcome.warnings)


async def test_error_outcome_is_recorded_not_swallowed():
    reviewer = Reviewer("r1", ScriptedProvider([]))
    outcome = reviewer.error_outcome(make_task(), VerdictStatus.PROVIDER_ERROR, "401 unauthorized")

    assert outcome.verdict.status is VerdictStatus.PROVIDER_ERROR
    assert outcome.verdict.vulnerable is False
    assert "401" in outcome.verdict.reasoning


# --- トレースには実際に送った値を残す (#152) --------------------------------------


@pytest.mark.parametrize("supports_seed", [True, False])
@pytest.mark.parametrize("supports_temperature", [True, False])
async def test_trace_records_what_was_actually_sent(supports_seed, supports_temperature):
    provider = ScriptedProvider(
        [verdict_payload()],
        capabilities=Capabilities(
            structured_output=StructuredMode.JSON_SCHEMA,
            supports_seed=supports_seed,
            supports_temperature=supports_temperature,
        ),
    )
    outcome = await Reviewer("r1", provider, seed=42).review(make_task())
    params = outcome.trace["params"]
    assert params["seed"] == provider.requests[0].seed
    assert params["seed"] == (42 if supports_seed else None)
    assert params["seed_configured"] == 42
    assert params["temperature"] == (0.0 if supports_temperature else None)


# --- evidence の検証 (#151) ----------------------------------------------------------


def _judgement(*evidence: tuple[str, int, int]) -> ReviewJudgement:
    return ReviewJudgement.model_validate(
        {
            "vulnerable": True,
            "severity": "high",
            "confidence": 0.9,
            "false_positive_probability": 0.1,
            "reasoning": "r",
            "evidence": [
                {"path": path, "start_line": start, "end_line": end, "note": "n"}
                for path, start, end in evidence
            ],
        }
    )


def _task_with_primary() -> ReviewTask:
    primary = CodeSlice(path="app.py", start_line=10, end_line=20, text="x", label="primary")
    return make_task().model_copy(update={"code_context": CodeContext(primary=primary)})


@pytest.mark.parametrize(
    "item",
    [
        ("lib/myapp.py", 12, 12),
        ("/etc/app.py", 15, 15),
        ("app.py", 20, 9999),
        ("app.py", 18, 3),
        ("app.py", 5, 12),
    ],
)
def test_evidence_outside_what_was_shown_is_dropped(item):
    kept, warnings = drop_hallucinated_evidence(_judgement(item), _task_with_primary())
    assert kept.evidence == []
    assert warnings


@pytest.mark.parametrize("path", ["app.py", "./app.py"])
def test_evidence_inside_what_was_shown_is_kept(path):
    judgement = _judgement((path, 10, 20))
    kept, warnings = drop_hallucinated_evidence(judgement, _task_with_primary())
    assert kept is judgement
    assert warnings == []


def test_evidence_for_a_candidate_without_code_is_dropped():
    kept, warnings = drop_hallucinated_evidence(_judgement(("uv.lock", 1, 1)), make_task())
    assert kept.evidence == []
    assert warnings


async def test_truncated_output_is_not_repaired_with_the_same_limit():
    """上限で切れた出力に同じ上限で修復を送らない (#665)."""
    from security_checker.providers.base import CompletionResponse

    cut = CompletionResponse(text='{"vulnerable": tr', finish_reason="length")
    provider = ScriptedProvider([cut, verdict_payload()])
    outcome = await Reviewer("r1", provider, max_output_tokens=50).review(make_task())
    assert outcome.verdict.status is VerdictStatus.SCHEMA_ERROR
    assert "max_output_tokens (50)" in outcome.verdict.reasoning
    assert len(provider.requests) == 1


def test_max_output_tokens_is_clamped_to_the_model_limit():
    """モデルの出力上限を Reviewer の希望で引き上げない (#610)."""
    from security_checker.config.schema import Config
    from security_checker.run import build_reviewers

    config = Config.model_validate(
        {
            "reviewers": [
                {
                    "name": "r1",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://127.0.0.1:9/v1",
                    "model": "m",
                    "max_output_tokens": 999_999,
                    "capabilities": {"max_output_tokens": 1024},
                }
            ]
        }
    )
    setup = build_reviewers(config, environ={})
    assert setup.runtimes[0].reviewer.max_output_tokens == 1024
    assert any("1024" in w for w in setup.warnings)


async def test_concurrent_reviews_trace_their_own_prompts():
    """同じ Reviewer を並行して呼んでも、トレースには自分の候補のプロンプトが残る (#315)."""
    import asyncio

    from security_checker.observability.trace import sha256_text
    from security_checker.review import prompts
    from security_checker.review.structured import verdict_schema

    class SlowProvider(ScriptedProvider):
        async def complete(self, req):
            # 1 件目を遅らせ、2 件目のプロンプトが先に設定される順序にする
            await asyncio.sleep(0.05 if "c-slow" in req.user else 0)
            return await super().complete(req)

    provider = SlowProvider([verdict_payload(), verdict_payload()])
    reviewer = Reviewer("r1", provider)
    base = make_task()
    slow = base.model_copy(update={"candidate": base.candidate.model_copy(update={"id": "c-slow"})})
    fast = base.model_copy(update={"candidate": base.candidate.model_copy(update={"id": "c-fast"})})
    outcomes = await asyncio.gather(reviewer.review(slow), reviewer.review(fast))
    schema = verdict_schema()
    for task, outcome in zip((slow, fast), outcomes, strict=True):
        expected = sha256_text(prompts.render_user(task, schema))
        assert outcome.trace is not None
        assert outcome.trace["prompt"]["user_sha256"] == expected


def test_local_ollama_reviewers_cost_zero_and_unpriced_ones_are_warned():
    """ollama_chat は価格表に無ければ 0 (#313). 価格の無い Reviewer は予算の外と警告する (#311)."""
    from security_checker.config.schema import Config
    from security_checker.run import build_reviewers

    config = Config.model_validate(
        {
            "budget": {"max_usd": 1.0},
            "reviewers": [
                {
                    "name": "local",
                    "transport": "http",
                    "dialect": "ollama_chat",
                    "base_url": "http://127.0.0.1:11434",
                    "model": "llama",
                },
                {
                    "name": "remote",
                    "transport": "http",
                    "dialect": "openai_chat",
                    "base_url": "http://127.0.0.1:9/v1",
                    "model": "unknown-model",
                },
            ],
        }
    )
    setup = build_reviewers(config, environ={})
    local, remote = (runtime.reviewer for runtime in setup.runtimes)
    assert local.price is not None and local.price.input_per_1m == 0.0
    assert remote.price is None
    assert any("'remote'" in w and "budget.max_usd" in w for w in setup.warnings)
    assert not any("'local'" in w for w in setup.warnings)
