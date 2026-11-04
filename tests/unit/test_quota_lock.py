"""日次クォータの記録をプロセスをまたいで数え漏らさない (#450)."""

from __future__ import annotations

import multiprocessing
from pathlib import Path

from security_checker.observability.quota import QuotaStore


def _consume_many(path: str, times: int) -> None:
    store = QuotaStore(Path(path))
    for _ in range(times):
        store.consume("r1:m")


def test_parallel_processes_do_not_lose_counts(tmp_path):
    path = tmp_path / "quota.json"
    context = multiprocessing.get_context("spawn")
    workers = [context.Process(target=_consume_many, args=(str(path), 25)) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=60)
        assert worker.exitcode == 0
    assert QuotaStore(path).used("r1:m") == 100
    # 一時ファイルを残さない
    assert not list(tmp_path.glob(".quota-*"))
