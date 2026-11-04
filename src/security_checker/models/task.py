"""ReviewTask — LLM に渡すもの (設計書 §8.1).

リポジトリ全体は渡さない。候補箇所とその周辺文脈だけを渡す。
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from security_checker.models.candidate import Candidate


class CodeSlice(BaseModel):
    """コードの一部分. 行番号を保持し、プロンプトでは行番号付きで提示する."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int
    end_line: int
    text: str
    label: str = "primary"

    def numbered(self) -> str:
        """行番号付きテキスト. evidence の行番号を正確に返させるために必要 (§11.3)."""
        lines = self.text.splitlines()
        width = len(str(self.start_line + len(lines) - 1))
        return "\n".join(
            f"{self.start_line + offset:>{width}}| {line}" for offset, line in enumerate(lines)
        )


class CodeContext(BaseModel):
    """候補箇所を中心とした文脈."""

    model_config = ConfigDict(frozen=True)

    primary: CodeSlice | None = None
    callers: list[CodeSlice] = Field(default_factory=list)
    related: list[CodeSlice] = Field(default_factory=list)
    file_tree_excerpt: str | None = None
    truncated: bool = False


class RepoFacts(BaseModel):
    """到達可能性の判断材料. これがないと LLM は全てを HIGH と判定しがちになる (§8.1)."""

    model_config = ConfigDict(frozen=True)

    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    has_auth_layer: bool | None = None
    is_public_repo: bool | None = None
    deployment_hints: list[str] = Field(default_factory=list)
    #: MAX_FILES で走査を打ち切った (事実は先頭の一部からしか集めていない)
    truncated: bool = False


class TokenBudget(BaseModel):
    """1 候補あたりの入力予算."""

    model_config = ConfigDict(frozen=True)

    max_tokens_per_task: int
    estimated_input_tokens: int = 0


class ReviewTask(BaseModel):
    """1 候補分のレビュー依頼. 全 Reviewer に完全に同一のものを渡す (§11.4)."""

    model_config = ConfigDict(frozen=True)

    candidate: Candidate
    code_context: CodeContext
    repo_facts: RepoFacts
    budget: TokenBudget
    notes: list[str] = Field(default_factory=list)
