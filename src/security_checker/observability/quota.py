"""日次クォータ (rpd: requests / day) の記録 (設計書 §22.1).

無料枠に多い「1 日 N 回まで」は、プロセスをまたいで数えないと守れない。
`~/.cache/security-checker/quota.json` (XDG_CACHE_HOME を尊重) に Reviewer ごとの
当日の呼び出し回数を保存する。日付は UTC で区切る (提供元のリセット時刻とずれることがある)。

読み・足し・書きはロックファイル (`quota.json.lock`) の排他ロックの中で行い、
同時に走らせた security-checker どうしで数え漏れを起こさない (#450)。
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

QUOTA_FILENAME = "quota.json"
#: 古い日付の記録は残しても役に立たない. 直近の数日分だけ持つ
KEEP_DAYS = 7


def default_quota_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "security-checker" / QUOTA_FILENAME


def _today() -> date:
    return datetime.now(UTC).date()


class QuotaStore:
    """Reviewer ごとの当日の呼び出し回数. 読み書きに失敗しても実行は止めない (警告にする)."""

    def __init__(self, path: Path | None = None, *, today: Callable[[], date] = _today) -> None:
        self.path = path or default_quota_path()
        self._today = today
        self.errors: list[str] = []

    def _load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            self.errors.append(f"クォータの記録 {self.path} を読めません: {exc}")
            return {}
        return data if isinstance(data, dict) else {}

    def used(self, key: str) -> int:
        day = self._load().get(self._today().isoformat(), {})
        value = day.get(key, 0) if isinstance(day, dict) else 0
        return value if isinstance(value, int) else 0

    def remaining(self, key: str, limit: int) -> int:
        return max(0, limit - self.used(key))

    def consume(self, key: str, count: int = 1) -> int:
        """回数を足して保存し、当日の累計を返す. ほかのプロセスとは排他で読み書きする."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.errors.append(f"クォータの記録 {self.path} に書けません: {exc}")
        with _locked(self.path.with_name(self.path.name + ".lock"), self.errors):
            return self._consume_unlocked(key, count)

    def _consume_unlocked(self, key: str, count: int) -> int:
        data = self._load()
        today = self._today().isoformat()
        day = data.get(today)
        if not isinstance(day, dict):
            day = {}
        day[key] = int(day.get(key, 0)) + count
        data[today] = day
        # ISO 形式の日付は文字列順 = 日付順. 新しい KEEP_DAYS 日分だけ残す
        for stale in sorted(data)[:-KEEP_DAYS]:
            data.pop(stale, None)
        try:
            # 一時ファイル名は一意にする (同じ名前だと、ほかのプロセスの書きかけを置き換える)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.path.parent, prefix=".quota-", delete=False
            ) as handle:
                handle.write(json.dumps(data, ensure_ascii=False, indent=2))
            Path(handle.name).replace(self.path)
        except OSError as exc:
            self.errors.append(f"クォータの記録 {self.path} に書けません: {exc}")
        return int(day[key])


@contextlib.contextmanager
def _locked(lock_path: Path, errors: list[str]) -> Iterator[None]:
    """プロセス間の排他ロック. 取れなくても実行は止めない (警告にして続ける)."""
    try:
        handle = lock_path.open("a+b")
    except OSError as exc:
        errors.append(f"クォータのロック {lock_path} を開けません: {exc}")
        yield
        return
    try:
        try:
            _lock(handle.fileno())
        except OSError as exc:
            errors.append(f"クォータのロック {lock_path} を取れません: {exc}")
        yield
    finally:
        with contextlib.suppress(OSError):
            _unlock(handle.fileno())
        handle.close()


if sys.platform == "win32":  # pragma: no cover - Windows でだけ通る
    import msvcrt

    def _lock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def _unlock(fd: int) -> None:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


def quota_key(reviewer: str, model: str | None) -> str:
    """同じモデルでも Reviewer 名が違えば別のキーにする (別アカウントのことがあるため)."""
    return f"{reviewer}:{model or '-'}"
