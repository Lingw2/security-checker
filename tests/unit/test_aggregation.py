"""集約戦略の表駆動テスト (設計書 §13-15).

特に「割れたら review_required」を網羅する。
"""

from __future__ import annotations

import pytest

from security_checker.aggregate.agreement import compute_agreement
from security_checker.aggregate.consensus import ConsensusAggregator
from security_checker.aggregate.findings import build_findings
from security_checker.aggregate.weighted import WeightedAggregator
from security_checker.config.schema import AggregationConfig, PolicyConfig
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


@pytest.fixture
def aggregator() -> ConsensusAggregator:
    return ConsensusAggregator()


@pytest.fixture
def cfg() -> AggregationConfig:
    return AggregationConfig()


# --- 単一 Reviewer (§13.2) -------------------------------------------------


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.95, FindingStatus.CONFIRMED),
        (0.8, FindingStatus.CONFIRMED),
        (0.6, FindingStatus.LIKELY),
        (0.5, FindingStatus.LIKELY),
        (0.3, FindingStatus.REVIEW_REQUIRED),
    ],
)
def test_single_reviewer_status_by_confidence(aggregator, cfg, confidence, expected):
    outcome = aggregator.aggregate(CANDIDATE, [verdict(confidence=confidence)], cfg)
    assert outcome.status is expected
    # 「1 モデルの合意」を high agreement と偽装しない
    assert outcome.agreement is Agreement.NOT_APPLICABLE


def test_single_reviewer_not_vulnerable(aggregator, cfg):
    outcome = aggregator.aggregate(CANDIDATE, [verdict(vulnerable=False)], cfg)
    assert outcome.status is FindingStatus.FALSE_POSITIVE
    assert outcome.severity is Severity.NONE


# --- 複数 Reviewer (§14.1) -------------------------------------------------


def test_all_agree_vulnerable_is_confirmed(aggregator, cfg):
    verdicts = [verdict("a"), verdict("b")]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.CONFIRMED
    assert outcome.agreement is Agreement.HIGH
    assert outcome.severity is Severity.HIGH


def test_split_decision_is_review_required(aggregator, cfg):
    """割れたら無理に 1 つの答えを出さない (要件メモ §14 の中核)."""
    verdicts = [verdict("a", vulnerable=True), verdict("b", vulnerable=False)]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.REVIEW_REQUIRED
    assert "分かれ" in outcome.summary


def test_all_agree_not_vulnerable_is_false_positive(aggregator, cfg):
    verdicts = [verdict("a", vulnerable=False), verdict("b", vulnerable=False)]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.FALSE_POSITIVE


def test_moderate_confidence_is_likely(aggregator, cfg):
    verdicts = [verdict("a", confidence=0.6), verdict("b", confidence=0.6)]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.LIKELY


def test_no_valid_verdicts_is_error(aggregator, cfg):
    verdicts = [verdict("a", status=VerdictStatus.PROVIDER_ERROR)]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.ERROR
    assert outcome.detail["valid_verdicts"] == 0


@pytest.mark.parametrize(
    ("survivor", "expected"),
    [
        (verdict("a", vulnerable=False, confidence=0.9), FindingStatus.REVIEW_REQUIRED),
        (verdict("a", confidence=0.95), FindingStatus.LIKELY),
        (verdict("a", confidence=0.3), FindingStatus.REVIEW_REQUIRED),
    ],
)
@pytest.mark.parametrize("failure", [VerdictStatus.PROVIDER_ERROR, VerdictStatus.SKIPPED])
def test_partial_failure_does_not_fall_back_to_single_reviewer(
    aggregator, cfg, survivor, expected, failure
):
    """2 体中 1 体が落ちたら、残った 1 体だけで false_positive / confirmed にしない (#91)."""
    outcome = aggregator.aggregate(CANDIDATE, [survivor, verdict("b", status=failure)], cfg)
    assert outcome.status is expected
    assert outcome.detail["mode"] == "partial_reviewers"
    assert outcome.detail["failed_verdicts"] == 1
    assert set(outcome.detail["reviewers"]) == {"a", "b"}


def test_all_need_more_context_is_inconclusive(aggregator, cfg):
    verdicts = [
        verdict("a", vulnerable=False, needs_more_context=["呼び出し元"]),
        verdict("b", vulnerable=False, needs_more_context=["設定値"]),
    ]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("mode", "expected"),
    [("median", Severity.HIGH), ("max", Severity.CRITICAL), ("weighted_mean", Severity.HIGH)],
)
def test_severity_aggregation_modes(aggregator, mode, expected):
    cfg = AggregationConfig.model_validate({"consensus": {"severity": mode}})
    verdicts = [
        verdict("a", severity=Severity.MEDIUM),
        verdict("b", severity=Severity.HIGH),
        verdict("c", severity=Severity.CRITICAL),
    ]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.severity is expected


def test_detail_records_each_reviewer(aggregator, cfg):
    outcome = aggregator.aggregate(CANDIDATE, [verdict("a"), verdict("b")], cfg)
    assert set(outcome.detail["reviewers"]) == {"a", "b"}
    assert outcome.detail["strategy"] == "consensus"


# --- agreement (§15) -------------------------------------------------------


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([verdict("a")], Agreement.NOT_APPLICABLE),
        ([verdict("a"), verdict("b")], Agreement.HIGH),
        (
            [verdict("a", severity=Severity.CRITICAL), verdict("b", severity=Severity.LOW)],
            Agreement.LOW,
        ),
        ([verdict("a"), verdict("b", vulnerable=False)], Agreement.LOW),
        (
            [verdict("a"), verdict("b"), verdict("c"), verdict("d", vulnerable=False)],
            Agreement.MEDIUM,
        ),
    ],
)
def test_agreement_levels(verdicts, expected):
    assert compute_agreement(verdicts) is expected


def test_low_agreement_caps_confidence(aggregator, cfg):
    verdicts = [
        verdict("a", confidence=0.95),
        verdict("b", confidence=0.95, severity=Severity.LOW),
        verdict("c", confidence=0.95, vulnerable=False),
    ]
    outcome = aggregator.aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.agreement is Agreement.LOW
    assert outcome.confidence <= 0.5


# --- Finding 化 ------------------------------------------------------------


def test_build_findings_marks_unreviewed(aggregator):
    findings = build_findings(
        [CANDIDATE],
        {},
        aggregator=aggregator,
        aggregation=AggregationConfig(),
        policy=PolicyConfig(),
    )
    assert findings[0].status is FindingStatus.NOT_REVIEWED
    assert findings[0].severity is Severity.MEDIUM


def test_min_confidence_downgrades_to_review_required(aggregator):
    findings = build_findings(
        [CANDIDATE],
        {"c1": [verdict("a", confidence=0.55)]},
        aggregator=aggregator,
        aggregation=AggregationConfig(),
        policy=PolicyConfig(min_confidence=0.7),
    )
    assert findings[0].status is FindingStatus.REVIEW_REQUIRED


def test_findings_merge_cwe(aggregator):
    candidate = CANDIDATE.model_copy(update={"cwe": ["CWE-89"]})
    findings = build_findings(
        [candidate],
        {"c1": [verdict("a").model_copy(update={"cwe": ["CWE-78"]})]},
        aggregator=aggregator,
        aggregation=AggregationConfig(),
        policy=PolicyConfig(),
    )
    assert findings[0].cwe == ["CWE-89", "CWE-78"]


def test_headline_prefers_the_vulnerability_type():
    """見出しに数百字の reasoning の断片を置かない."""
    from security_checker.aggregate.consensus import _headline

    typed = verdict().model_copy(update={"vulnerability_type": "OS Command Injection"})
    assert _headline(typed) == "OS Command Injection"


def test_headline_falls_back_to_a_whole_sentence():
    from security_checker.aggregate.consensus import _headline

    reasoning = "これは一文目です。" + "二文目は非常に長い説明が続きます。" * 30
    untyped = verdict().model_copy(update={"vulnerability_type": None, "reasoning": reasoning})
    headline = _headline(untyped)
    assert headline.startswith("これは一文目です。")
    assert headline.endswith("…")  # 文の区切りまで戻して詰めた印


def test_headline_never_cuts_mid_sentence():
    from security_checker.aggregate.consensus import _first_sentence

    text = "あ" * 500
    assert _first_sentence(text, 200).endswith("…")
    assert len(_first_sentence(text, 200)) <= 202


# --- 半々は過半数ではない (#153) ---------------------------------------------


@pytest.mark.parametrize(
    ("votes", "against", "min_votes"),
    [(2, 2, 2), (1, 1, 1)],
)
def test_an_even_split_is_review_required(votes, against, min_votes):
    verdicts = [verdict(f"v{i}") for i in range(votes)] + [
        verdict(f"n{i}", vulnerable=False, severity=Severity.NONE) for i in range(against)
    ]
    cfg = AggregationConfig.model_validate({"consensus": {"min_votes": min_votes}})
    outcome = ConsensusAggregator().aggregate(CANDIDATE, verdicts, cfg)
    assert outcome.status is FindingStatus.REVIEW_REQUIRED


def test_a_strict_majority_is_still_reported():
    verdicts = [
        verdict("a"),
        verdict("b"),
        verdict("c", vulnerable=False, severity=Severity.NONE),
    ]
    outcome = ConsensusAggregator().aggregate(CANDIDATE, verdicts, AggregationConfig())
    assert outcome.status in (FindingStatus.LIKELY, FindingStatus.CONFIRMED)


# --- 重大度の丸めは常に上 (#154) ------------------------------------------------


@pytest.mark.parametrize(
    ("low", "high", "expected"),
    [
        (Severity.INFO, Severity.LOW, Severity.LOW),
        (Severity.LOW, Severity.MEDIUM, Severity.MEDIUM),
        (Severity.MEDIUM, Severity.HIGH, Severity.HIGH),
        (Severity.HIGH, Severity.CRITICAL, Severity.CRITICAL),
    ],
)
@pytest.mark.parametrize("mode", ["median", "weighted_mean"])
@pytest.mark.parametrize("aggregator", [ConsensusAggregator, WeightedAggregator])
def test_severity_ties_round_up_in_every_band(aggregator, mode, low, high, expected):
    cfg = AggregationConfig.model_validate({"consensus": {"severity": mode}})
    verdicts = [verdict("a", severity=low), verdict("b", severity=high)]
    assert aggregator().aggregate(CANDIDATE, verdicts, cfg).severity is expected


def test_consensus_weighted_mean_uses_the_reviewer_weights():
    cfg = AggregationConfig.model_validate({"consensus": {"severity": "weighted_mean"}})
    verdicts = [verdict("a", severity=Severity.CRITICAL), verdict("b", severity=Severity.LOW)]
    aggregator = ConsensusAggregator({"a": 9.0, "b": 1.0})
    assert aggregator.aggregate(CANDIDATE, verdicts, cfg).severity is Severity.CRITICAL


# --- 自信の無い「脆弱ではない」で候補を消さない (#155) -------------------------------


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        (0.2, FindingStatus.REVIEW_REQUIRED),
        (0.79, FindingStatus.REVIEW_REQUIRED),
        (0.8, FindingStatus.FALSE_POSITIVE),
        (0.95, FindingStatus.FALSE_POSITIVE),
    ],
)
def test_not_vulnerable_needs_decisive_confidence(confidence, expected):
    def no(name: str) -> ReviewVerdict:
        return verdict(name, vulnerable=False, severity=Severity.NONE, confidence=confidence)

    multi = ConsensusAggregator().aggregate(CANDIDATE, [no("a"), no("b")], AggregationConfig())
    single = ConsensusAggregator().aggregate(CANDIDATE, [no("a")], AggregationConfig())
    assert multi.status is expected
    assert single.status is expected
    if expected is FindingStatus.REVIEW_REQUIRED:
        # 候補の重大度を残す。none にすると人間が見る優先度が下がる
        assert multi.severity is Severity.MEDIUM
        assert single.severity is Severity.MEDIUM


def test_not_vulnerable_with_a_request_for_context_is_not_dismissed():
    verdicts = [
        verdict("a", vulnerable=False, severity=Severity.NONE),
        verdict("b", vulnerable=False, severity=Severity.NONE, needs_more_context=["呼び出し元"]),
    ]
    outcome = ConsensusAggregator().aggregate(CANDIDATE, verdicts, AggregationConfig())
    assert outcome.status is FindingStatus.REVIEW_REQUIRED


@pytest.mark.parametrize(
    "single",
    [
        verdict("a", confidence=0.9),
        verdict("a", confidence=0.55),
        verdict("a", confidence=0.3),
        verdict("a", vulnerable=False, severity=Severity.NONE, confidence=0.9),
        verdict("a", vulnerable=False, severity=Severity.NONE, confidence=0.3),
        verdict("a", vulnerable=False, severity=Severity.NONE, needs_more_context=["x"]),
    ],
)
def test_a_single_reviewer_gives_the_same_result_in_every_strategy(single):
    consensus = ConsensusAggregator().aggregate(CANDIDATE, [single], AggregationConfig())
    weighted = WeightedAggregator().aggregate(CANDIDATE, [single], AggregationConfig())
    assert (consensus.status, consensus.severity) == (weighted.status, weighted.severity)
