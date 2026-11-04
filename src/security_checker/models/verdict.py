"""ReviewVerdict — 1 つの LLM の判定 (設計書 §6.2).

P1 時点では生成する経路がまだない (P2 の Reviewer が埋める) が、
LLM に強制する JSON Schema そのものであるため、データモデルとして先に固定する。
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from security_checker.models.enums import Exploitability, Severity


class VerdictStatus(StrEnum):
    """Verdict の生成結果. LLM 由来ではなく実行系が付与する."""

    OK = "ok"
    SCHEMA_ERROR = "schema_error"
    PROVIDER_ERROR = "provider_error"
    SKIPPED = "skipped"


CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[0-9]+$")]


class Usage(BaseModel):
    """トークン使用量. input / output / reasoning / cached を区別して持つ (設計書 §24.3).

    `output_tokens` は請求対象の出力トークン全体で、推論トークンを含む。
    `reasoning_tokens` はその内訳。提供元の数え方の違いは方言が吸収する。
    """

    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    cached_tokens: int = 0
    estimated_usd: float | None = None
    cost_known: bool = True

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def merge(self, other: Usage) -> Usage:
        """複数呼び出しの合算. コストは片方でも不明なら不明として扱う."""
        known = self.cost_known and other.cost_known
        usd: float | None = None
        if known and (self.estimated_usd is not None or other.estimated_usd is not None):
            usd = (self.estimated_usd or 0.0) + (other.estimated_usd or 0.0)
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
            cached_tokens=self.cached_tokens + other.cached_tokens,
            estimated_usd=usd,
            cost_known=known,
        )


class Evidence(BaseModel):
    """判断根拠となったコード位置."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int
    end_line: int
    note: str = Field(max_length=300)


class Remediation(BaseModel):
    """修正方針. 例示のみで、適用は行わない (P3: No Automatic Modification)."""

    model_config = ConfigDict(frozen=True)

    approach: str = Field(max_length=800)
    example: str | None = Field(default=None, max_length=1200)
    references: list[str] = Field(default_factory=list, max_length=5)


class ReviewJudgement(BaseModel):
    """LLM が生成する部分だけを切り出したもの. これが Structured Output の schema になる."""

    model_config = ConfigDict(frozen=True)

    # maxLength / maxItems を全フィールドに置くのは出力トークンの暴走を抑えるため (§10.1)
    vulnerable: bool
    vulnerability_type: str | None = Field(default=None, max_length=120)
    cwe: list[CweId] = Field(default_factory=list, max_length=5)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    false_positive_probability: float = Field(ge=0.0, le=1.0)
    exploitability: Exploitability = Exploitability.UNKNOWN
    impact: str | None = Field(default=None, max_length=600)
    attack_vector: str | None = Field(default=None, max_length=200)
    attack_path: list[str] = Field(default_factory=list, max_length=12)
    evidence: list[Evidence] = Field(default_factory=list, max_length=8)
    reasoning: str = Field(max_length=1500)
    remediation: Remediation | None = None
    needs_more_context: list[str] = Field(default_factory=list, max_length=5)

    @model_validator(mode="after")
    def _severity_matches_the_verdict(self) -> ReviewJudgement:
        """矛盾した判定 (脆弱なのに severity: none など) を通さない. 修復リトライで直させる."""
        if self.vulnerable and self.severity is Severity.NONE:
            raise ValueError(
                "vulnerable: true のときは severity を none 以外 (info / low / medium / high / "
                "critical) にしてください"
            )
        if not self.vulnerable and self.severity not in (Severity.NONE, Severity.INFO):
            raise ValueError("vulnerable: false のときは severity を none か info にしてください")
        return self


class ReviewVerdict(ReviewJudgement):
    """メタ情報 (実行系が付与) + LLM の判定."""

    model_config = ConfigDict(frozen=True)

    candidate_id: str
    reviewer: str
    model: str
    attempt: int = 1
    usage: Usage = Usage()
    latency_ms: int = 0
    status: VerdictStatus = VerdictStatus.OK
