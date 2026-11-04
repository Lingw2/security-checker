"""process transport の隔離 (設計書 §9.7).

起動対象は**任意のコマンド**であり、その中にはファイルを書き換える能力を持つものが含まれる。
P3 (No Automatic Modification) は transport の性質によらず守る必要があるため、
対象が何であるかを問わず次を一律に強制する。

1. リポジトリの外で起動する — cwd は毎回作り直す空の一時ディレクトリ。
   リポジトリのパスを指す環境変数 (PWD など) も渡さない
2. シェルを経由しない — argv のリストで起動し、`shell=False` 固定
3. プロンプトは stdin か一時ファイルで渡す — コマンドライン引数に埋め込まない
   (長さ制限・`ps` からの可視性・フラグとしての誤解釈を避ける)
4. 実行後に一時 cwd の差分を検査する — 書き込みは warning と trace に残す。
   検知できるのは一時 cwd の中だけで、絶対パスでの cwd の外への書き込みは検知しない
5. プロセスグループごと kill する — タイムアウトでも正常終了でも子プロセスを残さない
6. 出力は上限つきで読む — 上限を超えた分は読み捨て、メモリに溜めない (#48)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from security_checker.processes import POSIX, terminate
from security_checker.processes import TERM_GRACE_S as TERM_GRACE_S

# プロセスグループの後片付けはスキャナと共通 (security_checker.processes)
CREATED_PATHS_LIMIT = 20
OUTPUT_LIMIT = 200_000
#: メモリに保持する出力のバイト数の上限.
#: UTF-8 は 1 文字最大 4 バイトなので、文字数の上限 (OUTPUT_LIMIT) を必ず満たせる
OUTPUT_BYTE_LIMIT = OUTPUT_LIMIT * 4
_READ_CHUNK = 64 * 1024
TRUNCATED_NOTICE = "\n…(truncated)"

#: 子に渡さない環境変数. 値がリポジトリのパスであり、資格情報ではないもの
REPOSITORY_PATH_VARIABLES = (
    "OLDPWD",
    "INIT_CWD",
    "GITHUB_WORKSPACE",
    "CI_PROJECT_DIR",
    "CI_WORKSPACE",
    "CIRCLE_WORKING_DIRECTORY",
    "BITBUCKET_CLONE_DIR",
    "BUILD_SOURCESDIRECTORY",
    "WORKSPACE",
)

PromptVia = Literal["stdin", "file"]

#: `prompt_via: file` のとき、argv 中のこの文字列が一時ファイルのパスに置換される。
#: 置換対象がなければパスを末尾に追加する。
PROMPT_FILE_PLACEHOLDER = "{prompt_file}"


@dataclass(frozen=True)
class SandboxResult:
    """1 回のサンドボックス実行の結果."""

    exit_code: int | None
    stdout: str
    stderr: str
    argv: tuple[str, ...]
    timed_out: bool = False
    created_paths: tuple[str, ...] = ()
    duration_ms: int = 0


async def run_sandboxed(
    argv: Sequence[str],
    *,
    prompt: str,
    prompt_via: PromptVia = "stdin",
    timeout_s: float = 300.0,
    environ: Mapping[str, str] | None = None,
) -> SandboxResult:
    """コマンドを隔離した一時ディレクトリで実行し、stdout を回収する.

    `environ` を省略すると呼び出し元の環境を引き継ぐ。
    process transport の存在意義は「そのコマンド側の既存ログインを使う」ことなので、
    資格情報を含む環境は落とさない。リポジトリのパスを指す変数だけを除く (§9.7)。
    """
    started = time.monotonic()
    with (
        tempfile.TemporaryDirectory(prefix="sc-cwd-", ignore_cleanup_errors=True) as cwd_name,
        tempfile.TemporaryDirectory(prefix="sc-prompt-", ignore_cleanup_errors=True) as prompt_name,
    ):
        cwd = Path(cwd_name)
        resolved, stdin_data = _prepare_input(argv, prompt, prompt_via, Path(prompt_name))
        process = await asyncio.create_subprocess_exec(
            *resolved,
            cwd=str(cwd),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_child_environment(os.environ if environ is None else environ, cwd),
            # POSIX では新しいセッション = 新しいプロセスグループ。killpg で一掃するために必要。
            start_new_session=POSIX,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                _communicate_capped(process, stdin_data), timeout=timeout_s
            )
            # 1 起動 = 1 判定。stdout を閉じて残った孫プロセスも片づける
            await terminate(process)
        except asyncio.CancelledError:
            # 中断 (Ctrl-C・予算による打ち切り) でも、起動したコマンドを残さない (#219)
            await asyncio.shield(terminate(process))
            raise
        except TimeoutError:
            timed_out = True
            stdout, stderr = _Captured(), _Captured()
            await terminate(process)
            # 止めた後のパイプを EOF まで読み切って閉じる (残すとトランスポートが後片付けされない)
            with contextlib.suppress(TimeoutError, OSError, RuntimeError):
                await asyncio.wait_for(_communicate_capped(process, b""), timeout=TERM_GRACE_S)

        return SandboxResult(
            exit_code=process.returncode,
            stdout=stdout.text(),
            stderr=stderr.text(),
            argv=tuple(resolved),
            timed_out=timed_out,
            created_paths=created_paths(cwd),
            duration_ms=int((time.monotonic() - started) * 1000),
        )


def _child_environment(environ: Mapping[str, str], cwd: Path) -> dict[str, str]:
    """子に渡す環境. Python は cwd= を指定しても PWD を書き換えないので、ここで直す."""
    started_in = os.getcwd()
    child = {
        name: value
        for name, value in environ.items()
        if name not in REPOSITORY_PATH_VARIABLES and value != started_in
    }
    child["PWD"] = str(cwd)
    return child


def _prepare_input(
    argv: Sequence[str],
    prompt: str,
    prompt_via: PromptVia,
    prompt_dir: Path,
) -> tuple[list[str], bytes]:
    """プロンプトの渡し方を決める. どちらの経路でも argv には本文が入らない.

    一時ファイルは cwd の**外**に置く。cwd に置くと、書込検知 (§9.7 の 4) が
    自分自身の書き込みを Reviewer の書き込みとして誤検知する。
    """
    if prompt_via == "stdin":
        return list(argv), prompt.encode("utf-8")

    path = prompt_dir / "prompt.txt"
    path.write_text(prompt, encoding="utf-8")
    if any(PROMPT_FILE_PLACEHOLDER in arg for arg in argv):
        resolved = [arg.replace(PROMPT_FILE_PLACEHOLDER, str(path)) for arg in argv]
    else:
        resolved = [*argv, str(path)]
    return resolved, b""


def created_paths(cwd: Path) -> tuple[str, ...]:
    """実行後の一時 cwd に何が作られたかを見る.

    空で始まったディレクトリなので、残っているものはすべて Reviewer の書き込みである
    (§25.2 の契約テスト 9 番)。絶対パスでこの外に書かれた場合は検知できない。
    """
    found: list[str] = []
    for path in sorted(cwd.rglob("*")):
        suffix = "/" if path.is_dir() else ""
        found.append(path.relative_to(cwd).as_posix() + suffix)
        if len(found) >= CREATED_PATHS_LIMIT:
            break
    return tuple(found)


@dataclass
class _Captured:
    """上限つきで読んだ出力."""

    data: bytes = b""
    overflowed: bool = False

    def text(self) -> str:
        return _decode(self.data, overflowed=self.overflowed)


async def _communicate_capped(
    process: asyncio.subprocess.Process, stdin_data: bytes
) -> tuple[_Captured, _Captured]:
    """`communicate()` と同じく stdin を渡して終了を待つが、出力は上限までしか保持しない.

    `communicate()` は出力を全量メモリに読んでから返すため、出力を止めないコマンドが
    タイムアウトまでメモリを使い続ける。上限を超えた分は読み捨てる (パイプは詰まらせない)。
    """
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise RuntimeError("stdin / stdout / stderr を PIPE で開いていません")
    _, stdout, stderr, _ = await asyncio.gather(
        _write_stdin(process.stdin, stdin_data),
        _read_capped(process.stdout),
        _read_capped(process.stderr),
        process.wait(),
    )
    return stdout, stderr


async def _write_stdin(stream: asyncio.StreamWriter, data: bytes) -> None:
    # 相手が stdin を読まずに終了しても失敗にしない (communicate() と同じ扱い)
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        if data:
            stream.write(data)
            await stream.drain()
    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
        stream.close()
        await stream.wait_closed()


async def _read_capped(stream: asyncio.StreamReader, limit: int = OUTPUT_BYTE_LIMIT) -> _Captured:
    buffer = bytearray()
    overflowed = False
    while chunk := await stream.read(_READ_CHUNK):
        room = limit - len(buffer)
        if room > 0:
            buffer.extend(chunk[:room])
        if len(chunk) > room:
            overflowed = True
    return _Captured(bytes(buffer), overflowed)


def _decode(data: bytes | None, *, overflowed: bool = False) -> str:
    if not data:
        return ""
    text = data.decode("utf-8", "replace")
    if len(text) <= OUTPUT_LIMIT and not overflowed:
        return text
    return text[:OUTPUT_LIMIT] + TRUNCATED_NOTICE
