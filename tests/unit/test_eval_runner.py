"""評価ランナー: 途中で止まった run は理由を結果に残す (設計書 §27)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from security_checker.config.schema import Config, ReviewerConfig
from security_checker.eval.dataset import load_dataset
from security_checker.eval.runner import run_eval
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup
from security_checker.testing import ScriptedProvider, verdict_payload

VULNERABLE_CASE = """
candidate:
  scanner: semgrep
  rule_id: rules.command-injection
  path: app/upload.py
  start_line: 3
  severity_reported: high
  cwe: ["CWE-78"]
code: |
  import subprocess
  def run(name):
      subprocess.run("ls " + name, shell=True)
ground_truth:
  vulnerable: true
  cwe: ["CWE-78"]
  severity: high
  rationale: name が検証なしでシェルに渡る
"""

SAFE_CASE = """
candidate:
  scanner: semgrep
  rule_id: rules.sql-concat
  path: app/db.py
  start_line: 3
  severity_reported: high
  cwe: ["CWE-89"]
code: |
  def find(cur, user_id):
      # 呼び出し元で int に変換済み
      return cur.execute("select * from t where id = " + str(int(user_id)))
ground_truth:
  vulnerable: false
  severity: none
  rationale: 呼び出し前に int に変換されており注入できない
"""


def make_dataset(tmp_path: Path) -> Path:
    root = tmp_path / "ds"
    cases = root / "cases"
    cases.mkdir(parents=True)
    (cases / "0001.yaml").write_text(VULNERABLE_CASE, encoding="utf-8")
    (cases / "0002.yaml").write_text(SAFE_CASE, encoding="utf-8")
    return root


def make_config(**overrides: Any) -> Config:
    payload: dict[str, Any] = {
        "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
        "reviewers": [
            {
                "name": "r1",
                "transport": "http",
                "dialect": "openai_chat",
                "base_url": "http://stub/v1",
                "model": "stub",
            }
        ],
    }
    payload.update(overrides)
    return Config.model_validate(payload)


def setup_with(script: list[Any]) -> ReviewerSetup:
    provider = ScriptedProvider(script)
    config = ReviewerConfig(
        name="r1", transport="http", dialect="openai_chat", base_url="http://stub/v1", model="stub"
    )
    return ReviewerSetup(
        runtimes=[build_runtime(Reviewer("r1", provider), config, default_concurrency=2)],
        providers=[provider],
        configs={"r1": config},
    )


async def test_a_stopped_run_names_the_reason_in_the_warnings(tmp_path):
    """途中で止まった run は、なぜ止まったかを warnings に残す.

    数字だけを見せると、打ち切られた評価を「完全な評価」と読み違える。
    """
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with([verdict_payload(vulnerable=False, severity="none")] * 2)

    result = await run_eval(
        dataset, make_config(budget={"max_total_tokens": 1}), reviewer_setup=setup
    )

    # 打ち切られたことは件数でも分かる
    assert result.metrics.not_reviewed == 1
    # そして、止まった理由が警告として残る
    assert any("トークン上限" in warning for warning in result.warnings)
