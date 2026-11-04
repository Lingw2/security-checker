"""process transport の隔離 (設計書 §9.7).

ここで検証しているのは「安全側の性質」であり、機能ではない。
壊れたら P3 (No Automatic Modification) が崩れる。
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import pytest

from security_checker.providers.process.sandbox import (
    OUTPUT_LIMIT,
    PROMPT_FILE_PLACEHOLDER,
    TERM_GRACE_S,
    TRUNCATED_NOTICE,
    _read_capped,
    created_paths,
    run_sandboxed,
)


def python(script: str, *args: str) -> list[str]:
    return [sys.executable, "-c", script, *args]


ECHO_CWD = "import os,sys;sys.stdin.read();print(os.getcwd())"
ECHO_STDIN = "import sys;print(sys.stdin.read(), end='')"
ECHO_ARGV = "import json,sys;sys.stdin.read();print(json.dumps(sys.argv[1:]))"
READ_FILE = (
    "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'), end='')"
)
WRITE_TREE = (
    "import pathlib,sys;"
    "sys.stdin.read();"
    "pathlib.Path('sub').mkdir();"
    "pathlib.Path('sub/out.txt').write_text('x', encoding='utf-8');"
    "print('done')"
)


async def test_stdout_and_exit_code_are_returned():
    result = await run_sandboxed(python(ECHO_STDIN), prompt="hello", timeout_s=30)
    assert result.exit_code == 0
    assert result.stdout == "hello"
    assert result.timed_out is False


def assert_outside_and_cleaned(reported_cwd: str) -> None:
    cwd = Path(reported_cwd.strip()).resolve()
    assert Path.cwd().resolve() not in cwd.parents
    # 実行後に片づけられている (毎回作り直す)
    assert not cwd.exists()


async def test_cwd_is_a_fresh_directory_outside_the_repository():
    result = await run_sandboxed(python(ECHO_CWD), prompt="x", timeout_s=30)
    assert_outside_and_cleaned(result.stdout)


async def test_prompt_is_never_placed_in_argv():
    """引数に入れると ps で他ユーザーに見え、フラグとしても解釈されうる (§9.7 の 3)."""
    prompt = "--not-a-flag; rm -rf /"
    result = await run_sandboxed(python(ECHO_ARGV), prompt=prompt, timeout_s=30)
    assert prompt not in result.stdout
    assert prompt not in " ".join(result.argv)


async def test_prompt_via_file_uses_the_placeholder():
    command = python(READ_FILE, PROMPT_FILE_PLACEHOLDER)
    result = await run_sandboxed(command, prompt="from-file", prompt_via="file", timeout_s=30)
    assert result.stdout == "from-file"
    assert PROMPT_FILE_PLACEHOLDER not in " ".join(result.argv)


async def test_prompt_via_file_appends_the_path_when_no_placeholder():
    result = await run_sandboxed(
        python(READ_FILE), prompt="appended", prompt_via="file", timeout_s=30
    )
    assert result.stdout == "appended"


async def test_prompt_file_is_not_counted_as_a_write():
    """一時ファイルは cwd の外に置く. 自分の書き込みを検知してはいけない."""
    result = await run_sandboxed(python(READ_FILE), prompt="x", prompt_via="file", timeout_s=30)
    assert result.created_paths == ()


async def test_writes_are_detected_including_subdirectories():
    result = await run_sandboxed(python(WRITE_TREE), prompt="x", timeout_s=30)
    assert result.created_paths == ("sub/", "sub/out.txt")


async def test_timeout_marks_the_result_and_does_not_raise():
    result = await run_sandboxed(python("import time;time.sleep(60)"), prompt="x", timeout_s=1.0)
    assert result.timed_out is True
    assert result.stdout == ""


async def test_environment_is_passed_through_by_default():
    """process transport の存在意義は、そのコマンド側の既存ログインを使うこと (§9.7)."""
    script = "import os,sys;sys.stdin.read();print(os.environ.get('SC_TEST_MARKER', ''))"
    os.environ["SC_TEST_MARKER"] = "inherited"
    try:
        result = await run_sandboxed(python(script), prompt="x", timeout_s=30)
    finally:
        del os.environ["SC_TEST_MARKER"]
    assert result.stdout.strip() == "inherited"


async def test_explicit_environment_replaces_the_inherited_one():
    script = "import os,sys;sys.stdin.read();print(os.environ.get('SC_TEST_MARKER', 'absent'))"
    result = await run_sandboxed(
        python(script), prompt="x", timeout_s=30, environ={"PATH": os.environ.get("PATH", "")}
    )
    assert result.stdout.strip() == "absent"


async def test_missing_command_raises_oserror():
    with pytest.raises(OSError):
        await run_sandboxed(["security-checker-no-such-command"], prompt="x", timeout_s=5)


def test_created_paths_reports_relative_posix_paths(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.txt").write_text("x", encoding="utf-8")
    assert created_paths(tmp_path) == ("a/", "a/b.txt")


# --- 出力の上限 (#48) -------------------------------------------------------------


async def test_large_output_is_truncated_with_notice():
    script = f"import sys;sys.stdin.read();sys.stdout.write('x' * {OUTPUT_LIMIT * 5})"
    result = await run_sandboxed(python(script), prompt="p", timeout_s=60)
    assert result.exit_code == 0
    assert result.stdout.endswith(TRUNCATED_NOTICE)
    assert len(result.stdout) == OUTPUT_LIMIT + len(TRUNCATED_NOTICE)


async def test_endless_output_does_not_accumulate_in_memory():
    """出力を止めないコマンドでも、保持するのは上限まで (タイムアウトで止まる)."""
    script = "import sys\nsys.stdin.read()\nwhile True:\n    sys.stdout.write('y' * 65536)\n"
    result = await run_sandboxed(python(script), prompt="p", timeout_s=2)
    assert result.timed_out is True


async def test_read_capped_keeps_only_the_limit_and_flags_overflow():
    reader = asyncio.StreamReader()
    reader.feed_data(b"a" * 10)
    reader.feed_data(b"b" * 10)
    reader.feed_eof()
    captured = await _read_capped(reader, limit=15)
    assert captured.data == b"a" * 10 + b"b" * 5
    assert captured.overflowed is True
    assert captured.text().endswith(TRUNCATED_NOTICE)


async def test_read_capped_within_the_limit_is_untouched():
    reader = asyncio.StreamReader()
    reader.feed_data("日本語".encode())
    reader.feed_eof()
    captured = await _read_capped(reader, limit=1024)
    assert captured.overflowed is False
    assert captured.text() == "日本語"


async def test_command_that_ignores_stdin_is_not_an_error():
    result = await run_sandboxed(python("print('ok')"), prompt="x" * 1_000_000, timeout_s=30)
    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"


# --- リポジトリのパスを環境変数で渡さない (#167) ------------------------------------


async def test_child_does_not_receive_the_repository_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    environ = {
        "PATH": "/usr/bin:/bin",
        "PWD": str(tmp_path),
        "OLDPWD": str(tmp_path),
        "GITHUB_WORKSPACE": str(tmp_path),
        "SOME_DIR": str(tmp_path),
        "GITHUB_TOKEN": "kept",
    }
    script = "import json,os,sys;sys.stdin.read();print(json.dumps(dict(os.environ)))"
    result = await run_sandboxed([sys.executable, "-c", script], prompt="x", environ=environ)
    seen = json.loads(result.stdout)
    assert str(tmp_path) not in seen.values()
    assert "GITHUB_WORKSPACE" not in seen
    assert seen["GITHUB_TOKEN"] == environ["GITHUB_TOKEN"]
    assert seen["PWD"] != str(tmp_path)


# --- 親が先に終了しても孫を残さない (#166) ------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
async def test_grandchild_is_reaped_after_a_normal_exit(tmp_path):
    """stdout を閉じて残る孫も片づける. 1 起動 = 1 判定で、残るプロセスは要らない."""
    pid_file = tmp_path / "pid"
    script = (
        "import pathlib,subprocess,sys;"
        "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL);"
        "pathlib.Path(sys.argv[1]).write_text(str(c.pid));print('ok')"
    )
    result = await run_sandboxed([sys.executable, "-c", script, str(pid_file)], prompt="x")
    assert result.stdout.strip() == "ok"
    assert result.exit_code == 0
    child = int(pid_file.read_text())
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.05)
    os.kill(child, signal.SIGKILL)
    pytest.fail("孫プロセスが残っている")


@pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
async def test_timeout_does_not_wait_extra_when_the_parent_exited_first():
    """孫まで止めるので EOF がすぐ来る. 猶予の 3 秒を使い切らない."""
    script = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);print('{}')"
    )
    result = await run_sandboxed([sys.executable, "-c", script], prompt="x", timeout_s=1.0)
    assert result.timed_out
    # 猶予を使い切ると timeout + TERM_GRACE_S 以上かかる. それ未満なら待っていない.
    # (3000 ms 固定の上限は、負荷の高い CI でインタプリタの起動が遅いと誤って落ちた)
    assert result.duration_ms < (1.0 + TERM_GRACE_S) * 1000


@pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
async def test_cancelling_a_call_stops_the_command_and_its_children(tmp_path):
    """中断 (Ctrl-C・予算の打ち切り) でも起動したコマンドを残さない (#219)."""
    pid_file = tmp_path / "pid"
    script = (
        "import pathlib,subprocess,sys,time;"
        "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(c.pid));time.sleep(60)"
    )
    task = asyncio.create_task(
        run_sandboxed([sys.executable, "-c", script, str(pid_file)], prompt="x", timeout_s=60)
    )
    for _ in range(200):
        if pid_file.exists() and pid_file.read_text():
            break
        await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    child = int(pid_file.read_text())
    for _ in range(100):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.05)
    os.kill(child, signal.SIGKILL)
    pytest.fail("孫プロセスが残っている")
