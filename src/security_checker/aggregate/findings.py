"""Candidate + Verdict[] → Finding (設計書 §6.3, §13)."""

from __future__ import annotations

from security_checker.aggregate.base import Aggregator
from security_checker.config.schema import AggregationConfig, PolicyConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import FindingStatus, Severity
from security_checker.models.finding import AggregationDetail, Finding
from security_checker.models.verdict import ReviewVerdict, VerdictStatus


def build_findings(
    candidates: list[Candidate],
    verdicts_by_candidate: dict[str, list[ReviewVerdict]],
    *,
    aggregator: Aggregator,
    aggregation: AggregationConfig,
    policy: PolicyConfig,
) -> list[Finding]:
    """レビュー済み候補は集約し、未レビュー候補は not_reviewed として残す."""
    findings: list[Finding] = []
    for candidate in candidates:
        verdicts = verdicts_by_candidate.get(candidate.id)
        if verdicts is None:
            findings.append(_not_reviewed(candidate))
            continue

        outcome = aggregator.aggregate(candidate, verdicts, aggregation)
        status = outcome.status
        # 信頼度が閾値未満のものは review_required に落とす (§12 policy.min_confidence)
        if (
            status in (FindingStatus.CONFIRMED, FindingStatus.LIKELY)
            and outcome.confidence < policy.min_confidence
        ):
            status = FindingStatus.REVIEW_REQUIRED

        findings.append(
            Finding(
                candidate=candidate,
                verdicts=verdicts,
                status=status,
                severity=outcome.severity,
                confidence=outcome.confidence,
                agreement=outcome.agreement,
                cwe=_merge_cwe(candidate, verdicts),
                summary=outcome.summary,
                aggregation=AggregationDetail(
                    strategy=aggregator.name,
                    votes_vulnerable=sum(
                        1
                        for verdict in verdicts
                        if verdict.status is VerdictStatus.OK and verdict.vulnerable
                    ),
                    votes_total=sum(
                        1 for verdict in verdicts if verdict.status is VerdictStatus.OK
                    ),
                    detail=outcome.detail,
                ),
            )
        )
    return findings


def _not_reviewed(candidate: Candidate) -> Finding:
    """未レビューの候補も黙って消さず、状態を明示して残す (§20.2)."""
    return Finding(
        candidate=candidate,
        verdicts=[],
        status=FindingStatus.NOT_REVIEWED,
        severity=candidate.severity_reported or Severity.INFO,
        confidence=0.0,
        cwe=list(candidate.cwe),
        summary="予算・上限・中断のためレビューされていません。",
    )


def _merge_cwe(candidate: Candidate, verdicts: list[ReviewVerdict]) -> list[str]:
    merged = list(candidate.cwe)
    # 「脆弱ではない」と判定した Reviewer や、失敗した判定の CWE は根拠にならない
    supporting = [v for v in verdicts if v.status is VerdictStatus.OK and v.vulnerable]
    for verdict in supporting:
        for cwe in verdict.cwe:
            if cwe not in merged:
                merged.append(cwe)
    return merged
