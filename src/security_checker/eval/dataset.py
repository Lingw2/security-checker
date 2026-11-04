"""評価用データセットの読み込み (設計書 §26).

1 ケース = 1 YAML ファイル。**スキャナが出した候補 + そのコード + 人手の正解ラベル**を持つ。
スキャナを実際に動かさないのは、評価したいのが「スキャナの検出力」ではなく
「LLM レビューが候補をどう判定するか」だからである。

業務コードや非公開コードをリポジトリに置かないこと (§26.3)。
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, Severity

#: ケースの id はワークスペースのディレクトリ名になる。区切り文字や `..` を通さない
_CASE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


class GroundTruth(BaseModel):
    """人手で付けた正解ラベル."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerable: bool
    cwe: list[str] = Field(default_factory=list)
    severity: Severity = Severity.NONE
    #: なぜその正解なのか. **必須**. ラベルの妥当性を後から検証できないと評価自体が信用できない
    rationale: str

    @field_validator("rationale")
    @classmethod
    def _rationale_is_written(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rationale (なぜその正解なのか) は空にできません")
        return value


class CaseCandidate(BaseModel):
    """スキャナが出したことにする候補 (§26.1)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scanner: str
    rule_id: str
    category: Category = Category.SAST
    message: str = ""
    path: str
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    severity_reported: Severity | None = None
    cwe: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def _path_stays_inside(cls, value: str) -> str:
        """一時ワークスペースの外に書き出させない (配布されたデータセットを回す前提)."""
        windows = PureWindowsPath(value)
        if (
            not value
            or PurePosixPath(value).is_absolute()
            or windows.is_absolute()
            or windows.drive
        ):
            raise ValueError(f"path は相対パスである必要があります: {value!r}")
        if ".." in PurePosixPath(value).parts or ".." in windows.parts:
            raise ValueError(f"path に .. は使えません: {value!r}")
        return value


class EvalCase(BaseModel):
    """1 件の評価ケース."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    source: str = "handmade"
    language: str = "python"
    candidate: CaseCandidate
    #: 文脈込みの実コード. ContextBuilder に通すため、一時ディレクトリに書き出して使う
    code: str
    ground_truth: GroundTruth

    @field_validator("id")
    @classmethod
    def _id_is_a_plain_name(cls, value: str) -> str:
        if not _CASE_ID.fullmatch(value) or value in {".", ".."}:
            raise ValueError(f"id は英数字と . _ - だけで書いてください: {value!r}")
        return value

    def to_candidate(self) -> Candidate:
        """実行時と同じ Candidate に変換する (評価専用の経路を作らない)."""
        spec = self.candidate
        return Candidate(
            id=self.id,
            scanner=spec.scanner,
            category=spec.category,
            rule_id=spec.rule_id,
            title=spec.rule_id,
            message=spec.message,
            location=Location(
                path=spec.path,
                start_line=spec.start_line,
                end_line=spec.end_line or spec.start_line,
            ),
            severity_reported=spec.severity_reported,
            cwe=list(spec.cwe),
        )


class Dataset(BaseModel):
    """ケースの集合. 名前はディレクトリ名."""

    model_config = ConfigDict(frozen=True)

    name: str
    cases: list[EvalCase]

    @property
    def positives(self) -> int:
        return sum(1 for case in self.cases if case.ground_truth.vulnerable)

    @property
    def negatives(self) -> int:
        return len(self.cases) - self.positives


def load_dataset(directory: Path) -> Dataset:
    """`<dir>/cases/*.yaml` を読む. 壊れたケースは黙って飛ばさない (P9)."""
    root = directory.expanduser()
    cases_dir = root / "cases"
    if not cases_dir.is_dir():
        raise ConfigError(f"評価ケースが見つかりません: {cases_dir}")

    cases: list[EvalCase] = []
    seen: set[str] = set()
    for path in sorted([*cases_dir.glob("*.yaml"), *cases_dir.glob("*.yml")]):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"評価ケース {path} を読み込めません: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"評価ケース {path} のトップレベルはマッピングである必要があります")
        raw.setdefault("id", path.stem)
        try:
            case = EvalCase.model_validate(raw)
        except ValidationError as exc:
            raise ConfigError(f"評価ケース {path} が不正です: {exc}") from exc
        if case.id in seen:
            # ID は結果の突合に使う。重複すると集計が静かに壊れる
            raise ConfigError(f"評価ケースの id が重複しています: {case.id} ({path})")
        seen.add(case.id)
        cases.append(case)

    if not cases:
        raise ConfigError(f"評価ケースが 1 件もありません: {cases_dir}")
    return Dataset(name=root.name, cases=cases)
