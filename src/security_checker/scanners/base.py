"""Scanner Interface (設計書 §7).

不変条件 (§7.2):
  - ScanResult.status は必須。`failed` を `ok` と同一に扱うコードパスを作らない。
  - パーサは想定外の JSON 構造を握り潰さず、該当エントリだけを parse_warnings に落として続行する。
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict

from security_checker.config.schema import ScannerConfig
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, ScanStatus
from security_checker.scanners.untrusted import UntrustedOverrides

STDERR_EXCERPT_LIMIT = 2000


class Target(BaseModel):
    """検査対象."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    root: Path
    changed_files: list[str] | None = None
    base_ref: str | None = None


@dataclass
class ScanContext:
    """スキャナ実行時の共有情報."""

    raw_dir: Path
    exclude: list[str] = field(default_factory=list)
    #: 検査対象を信用しないときの、各スキャナに明示的に渡す設定 (#43)。None は信用する
    untrusted: UntrustedOverrides | None = None


class UnparseableOutputError(Exception):
    """出力全体の形が想定と違う. 1 エントリの破損 (parse_warnings) とは分ける.

    これを 0 件の成功として扱うと、何も検査していないのにスコアが満点に見える (§7.2)。
    """


class ToolStatus(BaseModel):
    """外部コマンドの導入状況."""

    model_config = ConfigDict(frozen=True)

    available: bool
    version: str | None = None
    reason: str | None = None


class ScanResult(BaseModel):
    """1 スキャナの実行結果."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    scanner: str
    category: Category
    status: ScanStatus
    candidates: list[Candidate] = []
    stderr_excerpt: str | None = None
    raw_path: Path | None = None
    duration_ms: int = 0
    exit_code: int | None = None
    version: str | None = None
    reason: str | None = None
    parse_warnings: list[str] = []
    #: skipped のうち「入れていない・起動できない」. 対象が無いだけの skip とは区別する
    unavailable: bool = False


class Scanner(Protocol):
    """内蔵 / 外部プラグイン共通の契約."""

    name: str
    category: Category
    requires: ClassVar[list[str]]

    def probe(self) -> ToolStatus: ...

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult: ...


@dataclass
class CommandResult:
    """外部コマンドの実行結果."""

    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


async def run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int,
    stdout_path: Path | None = None,
) -> CommandResult:
    """外部コマンドを shell を介さずに実行する.

    shell=False は設計上の制約 (§9.7): 引数がシェルに解釈される経路を作らない。
    タイムアウト時は子プロセスを確実に殺してから戻る。
    """
    stdout_file = stdout_path.open("wb") if stdout_path is not None else None
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            stdout=stdout_file or asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_s)
        except TimeoutError:
            process.kill()
            await process.wait()
            return CommandResult(exit_code=None, stdout=b"", stderr=b"", timed_out=True)
        return CommandResult(
            exit_code=process.returncode,
            stdout=stdout or b"",
            stderr=stderr or b"",
        )
    finally:
        if stdout_file is not None:
            stdout_file.close()


def probe_command(command: str, version_args: tuple[str, ...] = ("--version",)) -> ToolStatus:
    """コマンドの有無とバージョンを調べる. 失敗しても例外にしない."""
    path = shutil.which(command)
    if path is None:
        return ToolStatus(available=False, reason=f"{command} が見つかりません")
    try:
        completed = subprocess.run(
            [path, *version_args],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ToolStatus(available=True, reason=f"バージョン取得に失敗しました: {exc}")
    output = (completed.stdout or completed.stderr).decode("utf-8", "replace").strip()
    version = output.splitlines()[0] if output else None
    return ToolStatus(available=True, version=version)


def excerpt(data: bytes, limit: int = STDERR_EXCERPT_LIMIT) -> str | None:
    """stderr の先頭を安全に抜き出す."""
    if not data:
        return None
    text = data.decode("utf-8", "replace").strip()
    if not text:
        return None
    return text if len(text) <= limit else text[:limit] + " …(truncated)"


class BaseScanner:
    """内蔵 Scanner の共通実装."""

    name: str = ""
    category: Category = Category.SAST
    requires: ClassVar[list[str]] = []
    install_hint: str = ""

    def __init__(self, settings: ScannerConfig) -> None:
        self.settings = settings

    def probe(self) -> ToolStatus:
        status = probe_command(self.requires[0])
        if not status.available and self.install_hint:
            return status.model_copy(update={"reason": f"{status.reason}。{self.install_hint}"})
        return status

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:  # pragma: no cover
        raise NotImplementedError

    # --- 結果生成のヘルパ ---------------------------------------------------

    def skipped(
        self, reason: str, *, version: str | None = None, unavailable: bool = False
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=ScanStatus.SKIPPED,
            reason=reason,
            version=version,
            unavailable=unavailable,
        )

    def failed(
        self,
        reason: str,
        *,
        exit_code: int | None = None,
        stderr: bytes | str | None = None,
        duration_ms: int = 0,
        version: str | None = None,
        raw_path: Path | None = None,
    ) -> ScanResult:
        stderr_text = excerpt(stderr) if isinstance(stderr, bytes) else stderr
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=ScanStatus.FAILED,
            reason=reason,
            exit_code=exit_code,
            stderr_excerpt=stderr_text,
            duration_ms=duration_ms,
            version=version,
            raw_path=raw_path,
        )

    def ok(
        self,
        candidates: list[Candidate],
        *,
        duration_ms: int,
        exit_code: int | None,
        version: str | None = None,
        raw_path: Path | None = None,
        parse_warnings: list[str] | None = None,
        stderr: bytes | str | None = None,
    ) -> ScanResult:
        stderr_text = excerpt(stderr) if isinstance(stderr, bytes) else stderr
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=ScanStatus.OK,
            candidates=candidates,
            duration_ms=duration_ms,
            exit_code=exit_code,
            version=version,
            raw_path=raw_path,
            parse_warnings=parse_warnings or [],
            stderr_excerpt=stderr_text,
        )


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def relative_path(raw_path: str, root: Path) -> str:
    """スキャナが返したパスをリポジトリルートからの相対パスに正規化する (§6.1)."""
    cleaned = raw_path.replace("\\", "/")
    candidate = Path(cleaned)
    # "/" 始まりは Windows では絶対パスと判定されない (ドライブが無い) が、
    # ルートからのパスなので同じ扱いにする
    if candidate.is_absolute() or cleaned.startswith("/"):
        try:
            cleaned = candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            cleaned = candidate.name
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def as_dict(value: Any) -> dict[str, Any]:
    """JSON の想定外構造を握り潰さないためのヘルパ."""
    return value if isinstance(value, dict) else {}
