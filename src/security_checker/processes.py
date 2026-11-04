"""起動した外部プロセスの後片付け (スキャナと process transport で共通).

`start_new_session=True` で起動したプロセスを、孫までプロセスグループごと止める。
親が先に終了していても、グループに残った孫には届ける。
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time

POSIX = os.name == "posix"
TERM_GRACE_S = 3.0
GROUP_POLL_S = 0.05

__all__ = ["GROUP_POLL_S", "POSIX", "TERM_GRACE_S", "terminate"]


async def terminate(process: asyncio.subprocess.Process) -> None:
    """プロセスグループごと片づける. SIGTERM を試してから SIGKILL に上げる.

    親が先に終了していても、グループに残った孫には届ける。判断の基準は
    「親が終了したか」ではなく「グループが空になったか」である。

    Windows には SIGKILL もプロセスグループも無い。`_signal_group` はシグナルによらず
    TerminateProcess (`process.kill()`) で止めるので、動いている間に 1 回だけ試す。
    """
    if not POSIX:
        if process.returncode is None:
            _signal_group(process, signal.SIGTERM)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(process.wait()), timeout=TERM_GRACE_S)
        return
    for signal_number in (signal.SIGTERM, signal.SIGKILL):
        if not _group_alive(process):
            return
        _signal_group(process, signal_number)
        deadline = time.monotonic() + TERM_GRACE_S
        # プロセスグループの終了を知らせる仕組みは OS に無いので、ポーリングする
        while _group_alive(process) and time.monotonic() < deadline:  # noqa: ASYNC110
            await asyncio.sleep(GROUP_POLL_S)


def _group_alive(process: asyncio.subprocess.Process) -> bool:
    """グループに生きているプロセスが残っているか."""
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except OSError:  # PermissionError: 存在はするがシグナルを送れない
        return True
    return True


def _signal_group(process: asyncio.subprocess.Process, signal_number: int) -> None:
    """POSIX ではプロセスグループ全体に、それ以外ではプロセス単体に送る.

    `start_new_session=True` で起動しているので、グループ ID は親の PID と同じ。
    親が回収された後は `getpgid` が失敗するため、PID をそのまま使う。
    """
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        if POSIX:
            os.killpg(process.pid, signal_number)
            return
        process.kill()
