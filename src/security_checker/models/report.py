"""レポートのデータモデル (設計書 §18)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding, SuppressionReason
from security_checker.models.verdict import Usage

SCHEMA_VERSION = 1


class ScannerRun(BaseModel):
    """1 スキャナの実行結果サマリ. status を必ず持つ (設計書 §7.2)."""

    model_config = ConfigDict(frozen=True)

    scanner: str
    category: Category
    status: ScanStatus
    candidate_count: int = 0
    duration_ms: int = 0
    exit_code: int | None = None
    version: str | None = None
    reason: str | None = None
    stderr_excerpt: str | None = None
    raw_path: str | None = None
    parse_warnings: list[str] = Field(default_factory=list)


class SuppressedCandidate(BaseModel):
    """抑制した候補. 消さずに理由付きで残す (設計書 §17.2)."""

    model_config = ConfigDict(frozen=True)

    candidate: Candidate
    reason: SuppressionReason
    #: 注釈の reason= や、一致した ignore の行
    note: str | None = None


class ReportWarning(BaseModel):
    """レポート冒頭に集約される警告 (設計書 §20.2)."""

    model_config = ConfigDict(frozen=True)

    level: Literal["warn", "error"]
    source: str
    message: str


class ReviewerRun(BaseModel):
    """1 Reviewer の実行サマリ. 途中で無効化された事実も残す (設計書 §23)."""

    model_config = ConfigDict(frozen=True)

    name: str
    model: str | None = None
    transport: str = "http"
    dialect: str | None = None
    calls: int = 0
    verdicts_ok: int = 0
    verdicts_error: int = 0
    usage: Usage = Usage()
    disabled_reason: str | None = None


class Coverage(BaseModel):
    """「どこまで検査できたか」. スコアの解釈に必須の情報."""

    model_config = ConfigDict(frozen=True)

    scanners_total: int
    scanners_ok: int
    scanners_skipped: int
    scanners_failed: int
    candidates_total: int
    candidates_reviewed: int = 0


class Score(BaseModel):
    """補助指標としてのスコア (設計書 §17.3)."""

    model_config = ConfigDict(frozen=True)

    value: int = Field(ge=0, le=100)
    rank: Literal["A", "B", "C", "D"]
    partial: bool
    partial_reason: str | None = None
    deductions: dict[str, int] = Field(default_factory=dict)


class TargetInfo(BaseModel):
    """検査対象の記録."""

    model_config = ConfigDict(frozen=True)

    root: str
    mode: Literal["full", "diff"] = "full"
    changed_files: int | None = None
    #: diff モードの比較基準 (例: origin/main)
    base: str | None = None
    #: リポジトリルートから検査対象までの接頭辞 (例: `services/api/`)。
    #: Location.path は検査対象からの相対なので、SARIF と inline コメントでだけ前に付ける
    repo_prefix: str = ""

    @property
    def label(self) -> str:
        """人間向けの検査範囲の表記 (例: `diff mode vs origin/main, 12 files`)."""
        if self.mode == "diff":
            return f"diff mode vs {self.base}, {self.changed_files or 0} files"
        return f"{self.mode} mode"


class Report(BaseModel):
    """機械可読レポート. schema_version を必ず持つ (設計書 §6.4)."""

    model_config = ConfigDict(frozen=True)

    schema_version: int = SCHEMA_VERSION
    tool: str = "security-checker"
    tool_version: str
    run_id: str
    started_at: datetime
    finished_at: datetime
    target: TargetInfo

    scanners: list[ScannerRun] = Field(default_factory=list)
    reviewers: list[ReviewerRun] = Field(default_factory=list)
    candidates: list[Candidate] = Field(default_factory=list)
    #: diff モードで変更に関係しなかった候補. レビューしないが、SARIF では alert を
    #: 閉じないために残す (report/sarif.py)
    outside_diff: list[Candidate] = Field(default_factory=list)
    #: baseline / ignore / 注釈で抑制した候補. レビューもゲートもしない
    suppressed: list[SuppressedCandidate] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    coverage: Coverage
    score: Score
    warnings: list[ReportWarning] = Field(default_factory=list)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    finding_counts: dict[str, int] = Field(default_factory=dict)
    usage: Usage = Usage()
    stopped_reason: str | None = None
    trace_dir: str | None = None

    @property
    def suppression_label(self) -> str | None:
        """抑制の内訳 (例: `3 件 (baseline 2 / ignore 1)`). 無ければ None."""
        if not self.suppressed:
            return None
        labels = {"baseline": "baseline", "ignore_file": "ignore", "inline_annotation": "注釈"}
        counts: dict[str, int] = {}
        for item in self.suppressed:
            counts[item.reason.value] = counts.get(item.reason.value, 0) + 1
        breakdown = " / ".join(f"{labels[key]} {value}" for key, value in counts.items())
        return f"{len(self.suppressed)} 件 ({breakdown})"

    @property
    def has_failed_scanner(self) -> bool:
        return any(run.status is ScanStatus.FAILED for run in self.scanners)

    def dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)


def utcnow() -> datetime:
    return datetime.now(UTC)


def count_by_status(findings: list[Finding]) -> dict[str, int]:
    counts = {status.value: 0 for status in FindingStatus}
    for finding in findings:
        counts[finding.status.value] += 1
    return counts


def count_by_severity(candidates: list[Candidate]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for candidate in candidates:
        key = (candidate.severity_reported or Severity.INFO).value
        counts[key] += 1
    return counts
