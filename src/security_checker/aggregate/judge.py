"""Judge 戦略 (設計書 §16).

    Reviewer A ─┐
    Reviewer B ─┼→  Judge  →  最終判定 + どの論点を採用 / 棄却したか
    Reviewer C ─┘

  1. 匿名化: Judge に渡す意見からモデル名・Reviewer 名を除き `Reviewer A/B/C` にする。
     順序は候補ごとに決まった乱数で並べ替える (再現できるように seed は候補 ID)。
  2. 元の文脈 (コード) も渡す。意見だけでは多数決の言い換えしかできない。
  3. Judge の出力も ReviewVerdict のスキーマ。採否の理由は reasoning に書かせる。
  4. 新しい脆弱性は探させない (プロンプトで縛る)。
  5. Judge が失敗したら fallback 戦略の結果をそのまま使い、その事実を detail に残す。
  6. 既定では判断が割れた候補 (fallback で review_required) だけを Judge に回す。

**見逃しを増やさない方向に倒す。** Judge が「脆弱ではない」と言っても、確信度が
低ければ false_positive にせず review_required のまま残す (主指標は Recall, §27.2)。
"""

from __future__ import annotations

import random
import string
from collections.abc import Sequence
from typing import Any

from security_checker.aggregate.base import DECISIVE_CONFIDENCE
from security_checker.config.schema import AggregationConfig, PolicyConfig
from security_checker.models.enums import FindingStatus, Severity
from security_checker.models.finding import AggregationDetail, Finding
from security_checker.models.verdict import ReviewVerdict, VerdictStatus
from security_checker.review.prompts import PeerOpinion

STRATEGY = "judge"


def _label(index: int) -> str:
    """0 → A, 25 → Z, 26 → AA, 27 → AB … (表計算の列名と同じ). 27 人目から重複させない."""
    letters = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = string.ascii_uppercase[remainder] + letters
    return letters


def anonymize(candidate_id: str, verdicts: Sequence[ReviewVerdict]) -> list[PeerOpinion]:
    """有効な判定だけを、名前を伏せて並べ替える."""
    valid = [verdict for verdict in verdicts if verdict.status is VerdictStatus.OK]
    shuffled = list(valid)
    random.Random(candidate_id).shuffle(shuffled)  # noqa: S311 - 暗号用途ではない
    return [
        PeerOpinion(
            label=f"Reviewer {_label(index)}",
            vulnerable=verdict.vulnerable,
            severity=verdict.severity.value,
            confidence=verdict.confidence,
            false_positive_probability=verdict.false_positive_probability,
            exploitability=verdict.exploitability.value,
            reasoning=verdict.reasoning,
            attack_path=list(verdict.attack_path),
            needs_more_context=list(verdict.needs_more_context),
        )
        for index, verdict in enumerate(shuffled)
    ]


def needs_judge(finding: Finding, cfg: AggregationConfig) -> bool:
    """この Finding を Judge に回すか."""
    valid = [v for v in finding.verdicts if v.status is VerdictStatus.OK]
    if not valid:
        return False  # 評価する意見が無い
    if cfg.judge.only_on_disagreement:
        return finding.status is FindingStatus.REVIEW_REQUIRED
    return finding.status not in (FindingStatus.ERROR, FindingStatus.NOT_REVIEWED)


def apply_judgement(
    finding: Finding,
    judge: ReviewVerdict | None,
    *,
    policy: PolicyConfig,
    fallback_reason: str | None = None,
) -> Finding:
    """Judge の判定で Finding を置き換える. 判定が無ければ fallback の結果を残す."""
    base_detail: dict[str, Any] = {
        "fallback": finding.aggregation.strategy if finding.aggregation else None,
        "fallback_status": finding.status.value,
    }
    if judge is None or judge.status is not VerdictStatus.OK:
        reason = fallback_reason or (judge.reasoning if judge is not None else "Judge 未実行")
        return _with_detail(finding, {**base_detail, "judge": None, "fallback_used": reason})

    if judge.vulnerable:
        status = (
            FindingStatus.CONFIRMED
            if judge.confidence >= DECISIVE_CONFIDENCE
            else FindingStatus.LIKELY
        )
        if judge.confidence < policy.min_confidence:
            status = FindingStatus.REVIEW_REQUIRED
        severity = judge.severity
    elif judge.confidence >= DECISIVE_CONFIDENCE and not judge.needs_more_context:
        status = FindingStatus.FALSE_POSITIVE
        severity = Severity.NONE
    else:
        # 確信の無い「脆弱ではない」で候補を消さない
        status = FindingStatus.REVIEW_REQUIRED
        severity = finding.severity

    detail = {
        **base_detail,
        "judge": {
            "reviewer": judge.reviewer,
            "model": judge.model,
            "vulnerable": judge.vulnerable,
            "severity": judge.severity.value,
            "confidence": judge.confidence,
            "rationale": judge.reasoning,
            "needs_more_context": list(judge.needs_more_context),
        },
    }
    summary = judge.reasoning.split("\n", 1)[0][:200] if judge.reasoning else finding.summary
    return finding.model_copy(
        update={
            "status": status,
            "severity": severity,
            "confidence": judge.confidence,
            "summary": summary,
            "aggregation": _aggregation(finding, detail),
        }
    )


def _aggregation(finding: Finding, detail: dict[str, Any]) -> AggregationDetail:
    base = finding.aggregation
    return AggregationDetail(
        strategy=STRATEGY,
        votes_vulnerable=base.votes_vulnerable if base else 0,
        votes_total=base.votes_total if base else 0,
        detail={**(base.detail if base else {}), **detail},
    )


def _with_detail(finding: Finding, detail: dict[str, Any]) -> Finding:
    return finding.model_copy(update={"aggregation": _aggregation(finding, detail)})
