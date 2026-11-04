"""E2E: API キーなしで、実際のコマンドを Reviewer にして最後まで通す (設計書 §9.7).

P2.5 の受け入れ条件そのもの:
  - **API キーなしで** end-to-end 動作する
  - プリセットを 1 つも同梱しなくても `command` 直書きで動く

Reviewer 役は、実在のコマンドを模したものではなく §9.7 の契約
(stdin を読み、stdout にテキストを返し、exit 0) だけを満たす最小のスクリプト。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from security_checker.config.schema import Config
from security_checker.models.candidate import Candidate, Location
from security_checker.models.enums import Category, FindingStatus, Severity
from security_checker.run import run_review
from security_checker.testing import FakeScanner, verdict_payload

#: stdin を読み捨て、散文で包んだ verdict を stdout に返す。
#: prompt_only しか使えない transport でも §10.2 の抽出パスで拾えることを確かめる。
REVIEWER_SCRIPT = (
    "import json,sys;"
    "prompt=sys.stdin.read();"
    "sys.stderr.write('reviewed %d chars' % len(prompt));"
    "print('判定結果です:');"
    "print('```json');"
    "print(json.dumps(json.loads(sys.argv[1]), ensure_ascii=False));"
    "print('```')"
)

#: レビュー対象を書き換えようとする Reviewer。P3 が守られることを実測する。
WRITER_SCRIPT = (
    "import json,pathlib,sys;"
    "sys.stdin.read();"
    "pathlib.Path('scratch.txt').write_text('x', encoding='utf-8');"
    "print(json.dumps(json.loads(sys.argv[1]), ensure_ascii=False))"
)


def reviewer_command(script: str, **verdict_overrides: Any) -> list[str]:
    return [sys.executable, "-c", script, json.dumps(verdict_payload(**verdict_overrides))]


def candidate() -> Candidate:
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


def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "app"
    root.mkdir()
    (root / "app.py").write_text(
        "import subprocess\n\n\ndef run(name):\n    subprocess.run('ls ' + name, shell=True)\n",
        encoding="utf-8",
    )
    return root


def make_config(tmp_path: Path, command: list[str]) -> Config:
    return Config.model_validate(
        {
            "scanners": {"semgrep": {"enabled": False}, "gitleaks": {"enabled": False}},
            "output": {"dir": str(tmp_path / "out")},
            # API キーの指定が 1 つも無いことが、この試験の要点。
            "reviewers": [
                {
                    "name": "local-command",
                    "transport": "process",
                    "command": command,
                    "prompt_via": "stdin",
                    "timeout_s": 60,
                }
            ],
            "policy": {"strict": False},
        }
    )


async def test_process_transport_runs_without_any_api_key(tmp_path):
    root = workspace(tmp_path)
    outcome = await run_review(
        make_config(tmp_path, reviewer_command(REVIEWER_SCRIPT)),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )

    report = outcome.report
    assert report.coverage.candidates_reviewed == 1
    assert report.findings[0].status is FindingStatus.CONFIRMED
    assert report.reviewers[0].transport == "process"
    assert report.reviewers[0].dialect == "text_io"
    assert report.reviewers[0].verdicts_ok == 1


async def test_cost_is_unknown_and_tokens_are_estimates(tmp_path):
    """計測できないものを計測したふりをしない (§9.7 / §24.3)."""
    root = workspace(tmp_path)
    outcome = await run_review(
        make_config(tmp_path, reviewer_command(REVIEWER_SCRIPT)),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )

    usage = outcome.report.usage
    assert usage.cost_known is False
    assert usage.estimated_usd is None
    assert usage.total_tokens > 0


async def test_direct_command_surfaces_the_responsibility_warning(tmp_path):
    root = workspace(tmp_path)
    outcome = await run_review(
        make_config(tmp_path, reviewer_command(REVIEWER_SCRIPT)),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )
    assert any(
        w.source == "reviewer" and "書き込み能力" in w.message for w in outcome.report.warnings
    )


async def test_a_writing_reviewer_is_detected_and_the_repository_is_untouched(tmp_path):
    """P3 (No Automatic Modification) の実測 (§9.7 の 4)."""
    root = workspace(tmp_path)
    before = sorted(path.name for path in root.iterdir())

    outcome = await run_review(
        make_config(tmp_path, reviewer_command(WRITER_SCRIPT)),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )

    assert sorted(path.name for path in root.iterdir()) == before
    assert any("scratch.txt" in w.message for w in outcome.report.warnings)


async def test_trace_records_argv_stderr_and_exit_code(tmp_path):
    """§9.7 の監査証跡. http と同じ形式で残る."""
    root = workspace(tmp_path)
    outcome = await run_review(
        make_config(tmp_path, reviewer_command(REVIEWER_SCRIPT)),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )

    # trace_dir は出力先からの相対 (レポートに絶対パスを残さない)
    assert outcome.report.trace_dir is not None
    assert not Path(outcome.report.trace_dir).is_absolute()
    trace_dir = outcome.output_dir / outcome.report.trace_dir
    call = json.loads((trace_dir / "calls" / "0000.json").read_text(encoding="utf-8"))
    assert call["params"]["transport"] == "process"
    assert call["params"]["argv"][0] == sys.executable
    assert call["params"]["cwd"] == "isolated-temp-dir"
    assert call["response"]["exit_code"] == 0
    assert "reviewed" in call["response"]["stderr"]
    # 応答はコードを引用しうる. 既定 (save_prompts: false) では全文を残さない (#447)
    assert call["response"]["raw"] is None
    assert call["response"]["raw_sha256"]
    assert call["response"]["raw_chars"] > 0


async def test_a_failing_command_becomes_an_error_finding(tmp_path):
    """壊れたコマンドでも黙って消えない. レポートに残る (P9)."""
    root = workspace(tmp_path)
    command = [sys.executable, "-c", "import sys;sys.stdin.read();sys.exit(3)"]
    outcome = await run_review(
        make_config(tmp_path, command),
        root,
        base_dir=tmp_path,
        scanners=[FakeScanner("semgrep", candidates=[candidate()])],
    )

    assert outcome.report.findings[0].status is FindingStatus.ERROR
    assert outcome.report.reviewers[0].verdicts_error == 1
