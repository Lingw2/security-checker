"""Candidate — Scanner 出力の正規化形 (設計書 §6.1)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from security_checker.models.enums import Category, Severity

_COMMENT_RE = re.compile(r"(#|//|--).*$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
_WS_RE = re.compile(r"\s+")


def normalize_snippet(text: str) -> str:
    """安定 ID 用の正規化: コメント除去 → 空白圧縮 → 小文字化."""
    without_comments = _COMMENT_RE.sub(" ", text)
    return _WS_RE.sub(" ", without_comments).strip().lower()


class Location(BaseModel):
    """コード上の位置. path は検査対象からの相対パス (設計書 §6.1)."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = Field(ge=0)
    end_line: int = Field(ge=0)
    snippet: str | None = None

    @field_validator("path")
    @classmethod
    def _reject_absolute(cls, value: str) -> str:
        # v1 はレポートに絶対パスを書き出していた. 型の不変条件として禁止する.
        if value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value):
            raise ValueError(f"location.path は相対パスでなければなりません: {value}")
        return value.replace("\\", "/")


class PackageRef(BaseModel):
    """依存パッケージ参照."""

    model_config = ConfigDict(frozen=True)

    ecosystem: str
    name: str
    version: str | None = None
    manifest: str | None = None

    def as_key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version or '*'}"


class Candidate(BaseModel):
    """スキャナが報告した「機械的な事実」. LLM の判断は一切含まない."""

    model_config = ConfigDict(frozen=True)

    id: str
    scanner: str
    category: Category
    rule_id: str
    title: str
    message: str

    location: Location | None = None
    package: PackageRef | None = None

    severity_reported: Severity | None = None
    confidence_reported: float | None = None
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    fix_available: str | None = None

    raw: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = False
    #: 秘密の値の sha256. baseline の照合だけに使い、実行中のメモリから外へ出さない。
    #: 低エントロピーの値は総当たりで戻せるので、レポートにもログにも載せない (§19.2, ADR 0008)
    secret_digest: str | None = Field(default=None, exclude=True, repr=False)

    @property
    def where(self) -> str:
        """人間向けの位置表記."""
        if self.location is not None:
            return f"{self.location.path}:{self.location.start_line}"
        if self.package is not None:
            return self.package.as_key()
        return "-"


def candidate_id(
    scanner: str,
    rule_id: str,
    path: str,
    fingerprint_source: str,
    occurrence: int = 0,
) -> str:
    """安定 ID (設計書 §6.1).

    行番号を含めない. 無関係な編集で ID が変わると baseline と PR コメントが壊れるため.
    同一ファイル内で同じスニペットが複数ある場合のみ出現順の連番で区別する.
    """
    payload = "\x00".join([scanner, rule_id, path, normalize_snippet(fingerprint_source)])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return digest if occurrence == 0 else f"{digest}-{occurrence}"


class IdFactory:
    """同一 (scanner, rule_id, path, snippet) の重複に出現順の連番を振る (設計書 §6.1)."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str, str, str], int] = {}

    def make(self, scanner: str, rule_id: str, path: str, fingerprint_source: str) -> str:
        key = (scanner, rule_id, path, normalize_snippet(fingerprint_source))
        occurrence = self._seen.get(key, 0)
        self._seen[key] = occurrence + 1
        return candidate_id(scanner, rule_id, path, fingerprint_source, occurrence)
