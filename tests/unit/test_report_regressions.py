"""レポート出力の回帰 (#202, #241, #251, #280, #307, #321).

人間が読む出力 (report.md・ターミナル・PR コメント) と SARIF が、
壊れた事実を隠さず、絶対パスやリンクを残さないことを固定する。
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from security_checker.errors import ExitCode
from security_checker.github.comment import render_inline, render_summary
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category, FindingStatus, ScanStatus
from security_checker.models.report import ReportWarning, ScannerRun
from security_checker.policy.engine import PolicyDecision
from security_checker.report import markdown
from security_checker.report.markdown import render_markdown
from security_checker.report.sanitize import text
from security_checker.report.sarif import is_uploadable, render_sarif
from security_checker.report.terminal import render
from security_checker.run import output_relative
from tests.factories import make_candidate, make_finding, make_report

OK = PolicyDecision(exit_code=ExitCode.OK)


# --- リンクを書かせない (#251) ------------------------------------------------------


def test_text_neutralizes_links_and_autolinks():
    out = text("see [公式の修正手順](https://attacker.example) or https://x.example www.y.example")
    assert "](" not in out
    assert "https://" not in out
    assert "www." not in out
    # 表示としては読める
    assert "公式の修正手順" in out
    assert "attacker.example" in out


def test_text_neutralizes_reference_definitions():
    assert "]:" not in text("[a]: https://attacker.example")


# --- 値をマスクしたことを人間が読む出力に出す (#241) ----------------------------------


def secret_candidate() -> Candidate:
    return make_candidate(
        "s1",
        scanner="gitleaks",
        rule_id="generic-api-key",
        category=Category.SECRET,
        redacted=True,
    )


def test_redacted_candidates_are_marked_in_markdown_and_comments():
    candidate = secret_candidate()
    finding = make_finding(candidate, FindingStatus.CONFIRMED)
    report = make_report([candidate], [finding])
    assert "マスクしてから保存・送信" in render_markdown(report, OK)
    assert "マスクしてから保存・送信" in render_summary(report)
    assert "マスクしてから保存・送信" in render_inline(finding)
    assert "🔒" in render_markdown(make_report([candidate]), OK)


def test_redacted_candidates_are_marked_in_the_terminal_and_sarif():
    candidate = secret_candidate()
    console = Console(record=True, width=200)
    render(make_report([candidate]), OK, Path("out"), console=console)
    assert "値はマスク済み" in console.export_text()
    result = render_sarif(make_report([candidate]))["runs"][0]["results"][0]
    assert result["properties"]["redacted"] is True


# --- report.md の大きさ (#280) -------------------------------------------------------


def test_markdown_caps_unreviewed_and_warning_lists():
    limit = markdown.MAX_LIST_ITEMS
    candidates = [make_candidate(f"c{i}", path=f"f{i}.py") for i in range(limit + 7)]
    findings = [make_finding(c, FindingStatus.NOT_REVIEWED, verdicts=[]) for c in candidates]
    warnings = [
        ReportWarning(level="warn", source="semgrep", message=f"w{i}") for i in range(limit + 3)
    ]
    body = render_markdown(make_report(candidates, findings, warnings=warnings), OK)
    assert "ほか 7 件は `report.json` を参照" in body
    assert "ほか 3 件の警告は `report.json` を参照" in body
    assert f"f{limit + 6}.py" not in body


# --- SARIF (#307, #321) --------------------------------------------------------------


def test_sarif_counts_candidates_without_location():
    candidate = make_candidate("nowhere", category=Category.DEPENDENCY, location=None)
    run = render_sarif(make_report([candidate]))["runs"][0]
    assert run["results"] == []
    assert run["properties"]["results_without_location"] == 1
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert any(n["descriptor"]["id"] == "results-without-location" for n in notes)


def test_sarif_is_not_uploadable_when_an_enabled_scanner_is_unavailable():
    runs = [
        ScannerRun(
            scanner="gitleaks", category="secret", status=ScanStatus.SKIPPED, unavailable=True
        )
    ]
    sarif = render_sarif(make_report([], scanners=runs))
    assert not is_uploadable(sarif)


def test_sarif_stays_uploadable_when_a_scanner_had_nothing_to_scan():
    runs = [ScannerRun(scanner="osv", category="dependency", status=ScanStatus.SKIPPED)]
    assert is_uploadable(render_sarif(make_report([], scanners=runs)))


# --- 絶対パスを残さない (#202) ----------------------------------------------------------


def test_paths_inside_the_output_directory_are_made_relative(tmp_path):
    out = tmp_path / ".security-checker"
    assert output_relative(out / "raw" / "semgrep.json", out) == "raw/semgrep.json"
    assert output_relative(out / "trace" / "R1", out) == "trace/R1"


async def test_report_does_not_carry_absolute_paths(tmp_path):
    from security_checker.config.schema import Config
    from security_checker.run import run_scan
    from security_checker.testing import FakeScanner

    outcome = await run_scan(
        Config(), tmp_path, base_dir=tmp_path, scanners=[FakeScanner("semgrep")]
    )
    dumped = outcome.report.model_dump_json()
    assert str(tmp_path) not in dumped
    assert outcome.report.target.root == tmp_path.name
