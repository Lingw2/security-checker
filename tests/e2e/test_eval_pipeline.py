"""E2E: 評価コマンド (設計書 §27).

実行時と同じ経路 (Context Builder → Reviewer → Aggregator → Finding) を通し、
そこから採点することを確かめる。LLM は ScriptedProvider で置き換える。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import Config, ReviewerConfig
from security_checker.errors import ConfigError, ExitCode
from security_checker.eval.dataset import load_dataset
from security_checker.eval.runner import run_eval, to_markdown
from security_checker.models.enums import FindingStatus
from security_checker.providers.errors import ProviderServerError
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup
from security_checker.testing import ScriptedProvider, verdict_payload

runner = CliRunner()

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


async def test_a_perfect_run_scores_full_recall(tmp_path):
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with(
        [
            verdict_payload(vulnerable=True, severity="high", cwe=["CWE-78"], confidence=0.95),
            verdict_payload(vulnerable=False, severity="none", confidence=0.9),
        ]
    )

    result = await run_eval(dataset, make_config(), reviewer_setup=setup)

    assert result.metrics.recall == 1.0
    assert result.metrics.missed_true_positives == 0
    assert result.metrics.fp_reduction == 1.0
    assert result.metrics.cwe_match_rate == 1.0
    assert {outcome.case_id for outcome in result.outcomes} == {"0001", "0002"}


async def test_cwe_match_rate_only_counts_what_the_reviewer_answered(tmp_path):
    """スキャナの CWE (正解と同じ) を数えると、LLM が何を答えても 100% になる (#319)."""
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with(
        [
            verdict_payload(vulnerable=True, severity="high", cwe=["CWE-22"], confidence=0.95),
            verdict_payload(vulnerable=False, severity="none", confidence=0.9),
        ]
    )
    result = await run_eval(dataset, make_config(), reviewer_setup=setup)
    assert result.metrics.cwe_match_rate == 0.0


def test_markdown_neutralizes_llm_summaries():
    """比較表も report.md と同じ規則で無害化する (#328)."""
    from security_checker.eval.metrics import CaseOutcome, evaluate_outcomes
    from security_checker.eval.runner import EvalResult
    from security_checker.models.enums import Severity

    outcome = CaseOutcome(
        case_id="0001",
        expected_vulnerable=True,
        expected_severity=Severity.HIGH,
        status=FindingStatus.FALSE_POSITIVE,
        severity=Severity.NONE,
        summary="<img src=x> @octocat [押して](https://attacker.example)",
    )
    result = EvalResult(
        dataset="ds", cases=1, metrics=evaluate_outcomes([outcome]), outcomes=[outcome]
    )
    document = to_markdown(result)
    assert "0001" in document
    assert "<img" not in document
    assert "](https://" not in document
    assert "@octocat" not in document


async def test_a_missed_true_positive_is_named(tmp_path):
    """見逃しは数字だけでなく、どのケースかが分かる (§27.2)."""
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with(
        [
            verdict_payload(vulnerable=False, severity="none", confidence=0.9),
            verdict_payload(vulnerable=False, severity="none", confidence=0.9),
        ]
    )

    result = await run_eval(dataset, make_config(), reviewer_setup=setup)

    assert result.metrics.recall == 0.0
    assert result.metrics.missed_case_ids == ["0001"]
    assert "0001" in to_markdown(result)


async def test_the_real_context_builder_is_used(tmp_path):
    """評価専用の近道を作らない. プロンプトに実際のコードが載る."""
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with([verdict_payload(), verdict_payload(vulnerable=False, severity="none")])
    provider = setup.providers[0]

    await run_eval(dataset, make_config(), reviewer_setup=setup)

    assert isinstance(provider, ScriptedProvider)
    sent = "\n".join(request.user for request in provider.requests)
    assert "subprocess.run" in sent


async def test_markdown_puts_recall_first(tmp_path):
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with([verdict_payload(), verdict_payload(vulnerable=False, severity="none")])
    document = to_markdown(await run_eval(dataset, make_config(), reviewer_setup=setup))

    assert "主指標" in document
    assert "Recall" in document
    # 「必須条件」であることを表からも読み取れる
    assert "見逃した真陽性" in document


async def test_provider_errors_do_not_count_as_misses(tmp_path):
    """壊れた呼び出しを「見逃し」に数えると、故障が精度の問題に化ける."""
    from security_checker.providers.errors import ProviderServerError

    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with([ProviderServerError("500")] * 10)

    result = await run_eval(dataset, make_config(), reviewer_setup=setup)

    assert result.metrics.errors == 2
    assert result.metrics.missed_true_positives == 0
    assert all(outcome.status is FindingStatus.ERROR for outcome in result.outcomes)


def test_cli_requires_reviewers(tmp_path):
    dataset = make_dataset(tmp_path)
    config = tmp_path / "security-checker.yml"
    config.write_text("version: 1\n", encoding="utf-8")

    result = runner.invoke(
        app, ["eval", "--dataset", str(dataset), "--config", str(config), "--quiet"]
    )
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_cli_writes_json_and_markdown(tmp_path, monkeypatch):
    dataset = make_dataset(tmp_path)
    config = tmp_path / "security-checker.yml"
    config.write_text(
        "version: 1\nreviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://stub/v1\n    model: stub\n",
        encoding="utf-8",
    )

    async def fake_run_eval(dataset_arg, config_arg, **kwargs):
        from security_checker.eval.runner import run_eval as real

        return await real(
            dataset_arg, config_arg, reviewer_setup=setup_with([verdict_payload()] * 2)
        )

    monkeypatch.setattr("security_checker.cli.run_eval", fake_run_eval)
    out = tmp_path / "result.json"
    md = tmp_path / "result.md"

    result = runner.invoke(
        app,
        [
            "eval",
            "--dataset",
            str(dataset),
            "--config",
            str(config),
            "--output",
            str(out),
            "--markdown",
            str(md),
            "--quiet",
        ],
    )

    # 1 件目は正解 (脆弱)、2 件目は誤検知を脆弱と判定 → 見逃しは 0
    assert result.exit_code == ExitCode.OK
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["metrics"]["recall"] == 1.0
    assert "Recall" in md.read_text(encoding="utf-8")


def test_cli_keeps_config_warnings_out_of_stdout(tmp_path, monkeypatch):
    """標準出力は比較表 (Markdown) だけにする. `eval ... > result.md` に警告が混ざらない."""
    dataset = make_dataset(tmp_path)
    config = tmp_path / "security-checker.yml"
    # num_ctx は ollama_chat 専用なので、openai_chat に書くと設定の警告が出る
    config.write_text(
        "version: 1\nreviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://stub/v1\n    model: stub\n    num_ctx: 4096\n",
        encoding="utf-8",
    )

    async def fake_run_eval(dataset_arg, config_arg, **kwargs):
        from security_checker.eval.runner import run_eval as real

        return await real(
            dataset_arg, config_arg, reviewer_setup=setup_with([verdict_payload()] * 2)
        )

    monkeypatch.setattr("security_checker.cli.run_eval", fake_run_eval)

    result = runner.invoke(app, ["eval", "--dataset", str(dataset), "--config", str(config)])

    assert result.exit_code == ExitCode.OK
    assert result.stdout.startswith("# 評価結果")
    assert "num_ctx" not in result.stdout
    assert "num_ctx" in result.stderr


async def test_providers_are_closed_even_if_the_review_fails(tmp_path):
    """review_and_aggregate が例外で抜けても、Provider (の接続) を閉じる."""
    dataset = load_dataset(make_dataset(tmp_path))
    provider = ScriptedProvider([])
    setup = ReviewerSetup(providers=[provider])
    # 未知の集約戦略は review_and_aggregate の中で ConfigError になる
    config = make_config(aggregation={"strategy": "no-such-strategy"})

    with pytest.raises(ConfigError, match="no-such-strategy"):
        await run_eval(dataset, config, reviewer_setup=setup)
    assert provider.closed


# --- 採点できない run と保留だらけの run は失敗にする (#176, #177) ----------------------


def _invoke_eval(tmp_path: Path, monkeypatch: Any, script: list[Any], *extra: str) -> Any:
    dataset = make_dataset(tmp_path)
    config = tmp_path / "security-checker.yml"
    config.write_text(
        "version: 1\nreviewers:\n"
        "  - name: r1\n    transport: http\n    dialect: openai_chat\n"
        "    base_url: http://stub/v1\n    model: stub\n",
        encoding="utf-8",
    )

    async def fake_run_eval(dataset_arg, config_arg, **kwargs):
        from security_checker.eval.runner import run_eval as real

        return await real(dataset_arg, config_arg, reviewer_setup=setup_with(script))

    monkeypatch.setattr("security_checker.cli.run_eval", fake_run_eval)
    return runner.invoke(
        app, ["eval", "--dataset", str(dataset), "--config", str(config), "--quiet", *extra]
    )


def test_cli_fails_when_cases_could_not_be_graded(tmp_path, monkeypatch):
    script = [ProviderServerError("500")] * 6
    result = _invoke_eval(tmp_path, monkeypatch, script)
    assert result.exit_code == ExitCode.EXECUTION_ERROR
    assert "--allow-incomplete" in result.output


def test_cli_can_allow_incomplete_runs(tmp_path, monkeypatch):
    script = [ProviderServerError("500")] * 6
    result = _invoke_eval(tmp_path, monkeypatch, script, "--allow-incomplete")
    assert result.exit_code == ExitCode.OK


def test_cli_fails_when_too_many_cases_are_deferred(tmp_path, monkeypatch):
    unsure = verdict_payload(vulnerable=True, severity="high", confidence=0.3)
    result = _invoke_eval(tmp_path, monkeypatch, [unsure] * 2)
    assert result.exit_code == ExitCode.POLICY_VIOLATION
    assert "--max-deferred-rate" in result.output


def test_cli_deferred_rate_limit_can_be_raised(tmp_path, monkeypatch):
    unsure = verdict_payload(vulnerable=True, severity="high", confidence=0.3)
    result = _invoke_eval(tmp_path, monkeypatch, [unsure] * 2, "--max-deferred-rate", "1.0")
    assert result.exit_code == ExitCode.OK


async def test_a_run_stopped_by_budget_does_not_score_unreviewed_cases(tmp_path):
    dataset = load_dataset(make_dataset(tmp_path))
    setup = setup_with([verdict_payload(vulnerable=False, severity="none")] * 2)
    result = await run_eval(
        dataset, make_config(budget={"max_total_tokens": 1}), reviewer_setup=setup
    )
    assert result.metrics.not_reviewed == 1
    assert "未レビュー 1" in to_markdown(result)
