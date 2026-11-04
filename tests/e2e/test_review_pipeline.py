"""E2E: scan → context → review → aggregate → policy (設計書 §25.1).

LLM は ScriptedProvider で置き換える。CI は実 LLM を一切叩かない (§25 の原則)。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import Config, ReviewerConfig
from security_checker.errors import ConfigError, ExitCode
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, FindingStatus, Severity
from security_checker.report.json_writer import write_json
from security_checker.review.reviewer import Reviewer
from security_checker.review.scheduler import build_runtime
from security_checker.run import ReviewerSetup, run_review
from security_checker.testing import FakeScanner, ScriptedProvider, verdict_payload

SECRET = "xoxb-TESTONLY-DUMMY-NOT-A-REAL-SECRET"  # noqa: S105  gitleaks:allow


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text(
        "import subprocess\n\n\ndef run(name):\n    subprocess.run('ls ' + name, shell=True)\n",
        encoding="utf-8",
    )
    (root / "settings.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
    return root


def sast_candidate() -> Candidate:
    return Candidate(
        id="sast-1",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.command-injection",
        title="command-injection",
        message="shell=True にユーザー入力が渡ります",
        location=Location(path="app.py", start_line=5, end_line=5),
        severity_reported=Severity.HIGH,
        cwe=["CWE-78"],
    )


def secret_candidate() -> Candidate:
    return Candidate(
        id="secret-1",
        scanner="gitleaks",
        category=Category.SECRET,
        rule_id="slack-bot-token",
        title="シークレット検出",
        message="トークンが埋め込まれています",
        location=Location(path="settings.py", start_line=1, end_line=1, snippet="xoxb****"),
        severity_reported=Severity.CRITICAL,
        redacted=True,
    )


def make_config(tmp_path: Path, **overrides: Any) -> Config:
    payload: dict[str, Any] = {
        "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
        "output": {"dir": str(tmp_path / "out")},
        "reviewers": [
            {
                "name": "r1",
                "transport": "http",
                "dialect": "openai_chat",
                "base_url": "http://stub/v1",
                "model": "stub",
            }
        ],
        "policy": {"strict": False},
    }
    payload.update(overrides)
    return Config.model_validate(payload)


def setup_with(script: Sequence[Any]) -> ReviewerSetup:
    provider = ScriptedProvider(script)
    reviewer = Reviewer("r1", provider)
    config = ReviewerConfig(
        name="r1", transport="http", dialect="openai_chat", base_url="http://stub/v1", model="stub"
    )
    return ReviewerSetup(
        runtimes=[build_runtime(reviewer, config, default_concurrency=2)],
        providers=[provider],
        configs={"r1": config},
    )


async def test_full_pipeline_produces_findings(workspace, tmp_path):
    scanners = [FakeScanner("semgrep", candidates=[sast_candidate(), secret_candidate()])]
    setup = setup_with([verdict_payload(), verdict_payload(vulnerable=False, severity="none")])

    outcome = await run_review(
        make_config(tmp_path),
        workspace,
        base_dir=tmp_path,
        scanners=scanners,
        reviewer_setup=setup,
    )

    report = outcome.report
    assert report.coverage.candidates_reviewed == 2
    assert report.finding_counts["confirmed"] == 1
    assert report.finding_counts["false_positive"] == 1
    assert report.reviewers[0].calls == 2
    assert report.usage.total_tokens > 0
    assert outcome.decision.exit_code is ExitCode.POLICY_VIOLATION


async def test_prompt_never_contains_the_secret_value(workspace, tmp_path):
    """検出値を外部に送らないことをパイプライン全体で検証する (§19.2)."""
    scanners = [FakeScanner("gitleaks", candidates=[secret_candidate()])]
    setup = setup_with([verdict_payload()])
    provider = setup.providers[0]

    outcome = await run_review(
        make_config(tmp_path),
        workspace,
        base_dir=tmp_path,
        scanners=scanners,
        reviewer_setup=setup,
    )

    assert isinstance(provider, ScriptedProvider)
    sent = provider.requests[0].user
    assert SECRET not in sent
    assert "xoxb" in sent

    write_json(outcome.report, outcome.output_dir)
    for path in outcome.output_dir.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8", errors="replace")


async def test_trace_is_written_with_hashes(workspace, tmp_path):
    scanners = [FakeScanner("semgrep", candidates=[sast_candidate()])]
    outcome = await run_review(
        make_config(tmp_path),
        workspace,
        base_dir=tmp_path,
        scanners=scanners,
        reviewer_setup=setup_with([verdict_payload()]),
    )

    # trace_dir は出力先からの相対 (レポートに絶対パスを残さない)
    assert outcome.report.trace_dir is not None
    assert not Path(outcome.report.trace_dir).is_absolute()
    trace_dir = outcome.output_dir / outcome.report.trace_dir
    run = json.loads((trace_dir / "run.json").read_text(encoding="utf-8"))
    assert run["target"] == workspace.name  # 絶対パスを残さない (§6.1)
    call = json.loads((trace_dir / "calls" / "0000.json").read_text(encoding="utf-8"))
    assert call["prompt"]["system_sha256"]
    assert "system" not in call["prompt"]  # 既定では全文を残さない


async def test_budget_limit_marks_remaining_as_not_reviewed(workspace, tmp_path):
    candidates = [sast_candidate().model_copy(update={"id": f"c{index}"}) for index in range(5)]
    config = make_config(tmp_path, budget={"max_candidates": 2})
    outcome = await run_review(
        config,
        workspace,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=candidates)],
        reviewer_setup=setup_with([verdict_payload(), verdict_payload()]),
    )

    assert outcome.report.finding_counts["not_reviewed"] == 3
    assert any("max_candidates" in w.message for w in outcome.report.warnings)


async def test_provider_errors_are_reported_as_error_findings(workspace, tmp_path):
    from security_checker.providers.errors import ProviderServerError

    outcome = await run_review(
        make_config(tmp_path),
        workspace,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[sast_candidate()])],
        reviewer_setup=setup_with([ProviderServerError("500")] * 3),
    )

    assert outcome.report.findings[0].status is FindingStatus.ERROR
    assert outcome.report.reviewers[0].verdicts_error == 1


async def test_strict_makes_error_findings_exit_3(workspace, tmp_path):
    from security_checker.providers.errors import ProviderServerError

    config = make_config(tmp_path, policy={"strict": True})
    outcome = await run_review(
        config,
        workspace,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[sast_candidate()])],
        reviewer_setup=setup_with([ProviderServerError("500")] * 3),
    )
    assert outcome.decision.exit_code is ExitCode.EXECUTION_ERROR


async def test_score_counts_only_confirmed_and_likely(workspace, tmp_path):
    """review_required は減点しない (§17.3)."""
    candidates = [sast_candidate(), secret_candidate()]
    outcome = await run_review(
        make_config(tmp_path),
        workspace,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=candidates)],
        reviewer_setup=setup_with(
            [verdict_payload(confidence=0.3), verdict_payload(vulnerable=False, severity="none")]
        ),
    )

    assert outcome.report.finding_counts["review_required"] == 1
    assert outcome.report.score.value == 100


async def test_missing_reviewers_is_config_error(workspace, tmp_path):
    config = make_config(tmp_path, reviewers=[])
    with pytest.raises(ConfigError, match="reviewers"):
        await run_review(config, workspace, base_dir=tmp_path, scanners=[])
