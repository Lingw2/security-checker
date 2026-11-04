"""Weighted 戦略の表駆動テスト (設計書 §14.2).

重みの用途は「実力差の反映」と「安いモデルの影響を抑える」の 2 つ。
スコアの計算過程は detail に必ず残る (P4)。
"""

from __future__ import annotations

import pytest

from security_checker.aggregate.registry import build_aggregator
from security_checker.aggregate.weighted import CONFIRMED_MARGIN, WeightedAggregator
from security_checker.config.schema import AggregationConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Agreement, Category, FindingStatus, Severity
from security_checker.models.verdict import ReviewVerdict, VerdictStatus

CANDIDATE = Candidate(
    id="c1",
    scanner="semgrep",
    category=Category.SAST,
    rule_id="r",
    title="t",
    message="m",
    severity_reported=Severity.MEDIUM,
)
CFG = AggregationConfig(strategy="weighted")


def verdict(
    reviewer: str = "a",
    *,
    vulnerable: bool = True,
    severity: Severity | None = None,
    confidence: float = 0.9,
    status: VerdictStatus = VerdictStatus.OK,
    needs_more_context: list[str] | None = None,
) -> ReviewVerdict:
    if severity is None:
        severity = Severity.HIGH if vulnerable else Severity.NONE
    return ReviewVerdict(
        candidate_id="c1",
        reviewer=reviewer,
        model="m",
        status=status,
        vulnerable=vulnerable,
        severity=severity,
        confidence=confidence,
        false_positive_probability=0.1,
        reasoning="理由",
        needs_more_context=needs_more_context or [],
    )


def test_registry_resolves_weighted_and_passes_weights():
    aggregator, warnings = build_aggregator("weighted", weights={"a": 2.0})
    assert isinstance(aggregator, WeightedAggregator)
    assert aggregator.weights == {"a": 2.0}
    assert warnings == []


def test_consensus_ignores_weights_without_failing():
    """戦略ごとの分岐を registry に作らないため、どの戦略にも同じものを渡す."""
    aggregator, _ = build_aggregator("consensus", weights={"a": 2.0})
    assert aggregator.name == "consensus"


def test_unanimous_vulnerable_is_confirmed():
    outcome = WeightedAggregator().aggregate(CANDIDATE, [verdict("a"), verdict("b")], CFG)
    assert outcome.status is FindingStatus.CONFIRMED
    assert outcome.detail["score"] == pytest.approx(0.9)
    assert outcome.severity is Severity.HIGH


def test_unanimous_safe_is_false_positive():
    outcome = WeightedAggregator().aggregate(
        CANDIDATE, [verdict("a", vulnerable=False), verdict("b", vulnerable=False)], CFG
    )
    assert outcome.status is FindingStatus.FALSE_POSITIVE
    assert outcome.severity is Severity.NONE
    assert outcome.detail["score"] == pytest.approx(-0.9)


def test_a_split_lands_in_review_required():
    """割れたら無理に 1 つの答えを出さない (§13.1)."""
    outcome = WeightedAggregator().aggregate(
        CANDIDATE, [verdict("a"), verdict("b", vulnerable=False)], CFG
    )
    assert outcome.status is FindingStatus.REVIEW_REQUIRED
    assert outcome.detail["score"] == pytest.approx(0.0)


def test_weight_shifts_the_outcome():
    """重い Reviewer の判定が結果を動かす (これが weighted の存在理由)."""
    verdicts = [verdict("heavy"), verdict("light", vulnerable=False)]
    split = WeightedAggregator().aggregate(CANDIDATE, verdicts, CFG)
    # 既定のしきい値は 0.6。等倍なら 0.0 で割れるが、9:1 なら 0.72 まで上がる
    weighted = WeightedAggregator({"heavy": 9.0, "light": 1.0}).aggregate(CANDIDATE, verdicts, CFG)
    assert split.status is FindingStatus.REVIEW_REQUIRED
    assert weighted.status in (FindingStatus.LIKELY, FindingStatus.CONFIRMED)
    assert weighted.detail["score"] > split.detail["score"]


def test_zero_weight_reviewer_does_not_vote():
    """重み 0 は「参加させるが影響させない」. 黙って無視せず detail に残す."""
    outcome = WeightedAggregator({"muted": 0.0}).aggregate(
        CANDIDATE, [verdict("a"), verdict("muted", vulnerable=False)], CFG
    )
    assert outcome.status is FindingStatus.CONFIRMED
    assert outcome.detail["weights"] == {"a": 1.0, "muted": 0.0}


def test_all_zero_weights_do_not_silently_become_a_verdict():
    outcome = WeightedAggregator({"a": 0.0, "b": 0.0}).aggregate(
        CANDIDATE, [verdict("a"), verdict("b")], CFG
    )
    assert outcome.status is FindingStatus.REVIEW_REQUIRED
    assert "重み" in outcome.summary


def test_threshold_margin_separates_confirmed_from_likely():
    cfg = AggregationConfig(strategy="weighted", weighted={"threshold": 0.6})
    likely = WeightedAggregator().aggregate(
        CANDIDATE, [verdict("a", confidence=0.65), verdict("b", confidence=0.65)], cfg
    )
    confirmed = WeightedAggregator().aggregate(
        CANDIDATE,
        [verdict("a", confidence=0.6 + CONFIRMED_MARGIN + 0.05)],
        cfg,
    )
    assert likely.status is FindingStatus.LIKELY
    assert confirmed.status is FindingStatus.CONFIRMED


def test_errors_only_is_an_error():
    outcome = WeightedAggregator().aggregate(
        CANDIDATE, [verdict("a", status=VerdictStatus.PROVIDER_ERROR)], CFG
    )
    assert outcome.status is FindingStatus.ERROR
    assert outcome.agreement is Agreement.NOT_APPLICABLE


def test_all_reviewers_asking_for_context_is_inconclusive():
    outcome = WeightedAggregator().aggregate(
        CANDIDATE,
        [
            verdict("a", vulnerable=False, needs_more_context=["呼び出し元"]),
            verdict("b", vulnerable=False, needs_more_context=["設定"]),
        ],
        CFG,
    )
    assert outcome.status is FindingStatus.INCONCLUSIVE


def test_single_reviewer_is_not_reported_as_agreement():
    """「1 モデルの合意」を高い一致度として偽装しない (§13.2)."""
    outcome = WeightedAggregator().aggregate(CANDIDATE, [verdict("a")], CFG)
    assert outcome.agreement is Agreement.NOT_APPLICABLE


def test_weighted_mean_severity_uses_the_weights():
    cfg = AggregationConfig(strategy="weighted", consensus={"severity": "weighted_mean"})
    verdicts = [
        verdict("heavy", severity=Severity.CRITICAL),
        verdict("light", severity=Severity.MEDIUM),
    ]
    weighted = WeightedAggregator({"heavy": 5.0, "light": 1.0}).aggregate(CANDIDATE, verdicts, cfg)
    equal = WeightedAggregator().aggregate(CANDIDATE, verdicts, cfg)
    # 等倍なら high に丸まるが、重い側に寄せると critical になる
    assert equal.severity is Severity.HIGH
    assert weighted.severity is Severity.CRITICAL


def test_detail_keeps_the_calculation():
    outcome = WeightedAggregator({"a": 2.0}).aggregate(CANDIDATE, [verdict("a"), verdict("b")], CFG)
    assert outcome.detail["strategy"] == "weighted"
    assert "score" in outcome.detail
    assert "weights" in outcome.detail
    assert "reviewers" in outcome.detail


@pytest.mark.parametrize("failure", [VerdictStatus.PROVIDER_ERROR, VerdictStatus.SKIPPED])
def test_partial_failure_is_not_false_positive(failure):
    """失敗した Reviewer を除いて正規化すると、残った 1 体の判定がそのまま確定してしまう (#91)."""
    outcome = WeightedAggregator().aggregate(
        CANDIDATE,
        [verdict("a", vulnerable=False, confidence=0.9), verdict("b", status=failure)],
        CFG,
    )
    assert outcome.status is FindingStatus.REVIEW_REQUIRED
    assert outcome.detail["mode"] == "partial_reviewers"
