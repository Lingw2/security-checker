"""スキャナのアダプタの回帰 (#271〜#279, #331, #332, #335, #337).

正規化の誤り (重大度・ID・重複・修正版) と、成果物に残すもの (秘密・除外したファイル)、
起動したプロセスを残さないことを固定する。
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import GitleaksConfig, TrivyConfig
from security_checker.models.enums import Severity
from security_checker.scanners.base import ScanContext, Target, run_command
from security_checker.scanners.gitleaks import GitleaksScanner
from security_checker.scanners.osv import _fixed_version, parse_osv
from security_checker.scanners.semgrep import parse_semgrep, redact_semgrep_payload
from security_checker.scanners.trivy import TrivyScanner
from security_checker.scanners.untrusted import residual_warnings


def semgrep_result(
    check_id: str = "r",
    *,
    path: str = "app.py",
    line: int = 1,
    severity: str = "ERROR",
    lines: str = "requires login",
    cwe: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {
            "message": "m",
            "severity": severity,
            "lines": lines,
            "metadata": {"cwe": cwe or []},
        },
    }


# --- semgrep -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("ERROR", Severity.HIGH),
        ("WARNING", Severity.MEDIUM),
    ],
)
def test_semgrep_reads_new_and_legacy_severities(tmp_path, raw, expected):
    candidates, _ = parse_semgrep({"results": [semgrep_result(severity=raw)]}, tmp_path)
    assert candidates[0].severity_reported is expected


def test_semgrep_ids_do_not_shift_when_lines_says_requires_login(tmp_path):
    """CE の lines は固定文字列. 上に検出が増えても既存の ID を変えない (#272)."""
    (tmp_path / "app.py").write_text("eval(a)\neval(b)\n", encoding="utf-8")
    before, _ = parse_semgrep({"results": [semgrep_result(line=2)]}, tmp_path)
    after, _ = parse_semgrep(
        {"results": [semgrep_result(line=1), semgrep_result(line=2)]}, tmp_path
    )
    assert before[0].id == after[1].id
    assert after[1].location is not None
    assert after[1].location.snippet == "eval(b)"


def test_bundled_rule_ids_do_not_depend_on_the_install_location(tmp_path):
    check_ids = [
        "home.alice.venv.lib.python3.12.site-packages.security_checker.rules.semgrep.llm-x",
        "opt.app.security_checker.rules.semgrep.llm-x",
    ]
    results = [semgrep_result(check_id, path=f"f{i}.py") for i, check_id in enumerate(check_ids)]
    candidates, _ = parse_semgrep({"results": results}, tmp_path)
    assert {c.rule_id for c in candidates} == {"bundled.llm-x"}


def test_semgrep_secret_rules_do_not_keep_the_matched_line(tmp_path):
    secret = "hunter2-super-secret-value"  # noqa: S105 - ダミーの値
    item = semgrep_result(
        "generic.secrets.security.detected-generic-secret",
        lines=f'password = "{secret}"',
        cwe=["CWE-798: Use of Hard-coded Credentials"],
    )
    candidates, _ = parse_semgrep({"results": [item]}, tmp_path)
    dumped = candidates[0].model_dump_json()
    assert secret not in dumped
    assert candidates[0].redacted
    assert secret not in json.dumps(redact_semgrep_payload({"results": [item]}))


# --- osv ---------------------------------------------------------------------------


def osv_entry(version: str, vuln_id: str = "GHSA-1") -> dict[str, Any]:
    return {
        "package": {"name": "django", "ecosystem": "PyPI", "version": version},
        "vulnerabilities": [{"id": vuln_id, "summary": "s"}],
        "groups": [{"ids": [vuln_id], "max_severity": "7.5"}],
    }


def test_osv_does_not_duplicate_resolved_dependencies(tmp_path):
    payload = {
        "results": [
            {
                "source": {"path": str(tmp_path / "requirements.txt"), "type": "unknown"},
                "packages": [osv_entry("3.2.0")],
            },
            {
                "source": {"path": str(tmp_path / "requirements.txt"), "type": "lockfile"},
                "packages": [osv_entry("3.2")],
            },
        ]
    }
    candidates, _ = parse_osv(payload, tmp_path)
    assert len(candidates) == 1
    assert candidates[0].package is not None
    assert candidates[0].package.version == "3.2"  # 書かれた側を残す


def advisory(*affected: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"id": "GHSA-1", "affected": list(affected)}]


def branch(fixed: str, versions: list[str], kind: str = "ECOSYSTEM") -> dict[str, Any]:
    return {
        "package": {"name": "django"},
        "versions": versions,
        "ranges": [{"type": kind, "events": [{"introduced": "0"}, {"fixed": fixed}]}],
    }


def test_osv_fixed_version_follows_the_installed_branch():
    vulns = advisory(branch("2.2.28", ["2.2.27"]), branch("3.2.13", ["3.2.0", "3.2.12"]))
    assert _fixed_version(vulns, "django", "3.2.0") == "3.2.13"


def test_osv_fixed_version_is_not_guessed_across_branches():
    vulns = advisory(branch("2.2.28", []), branch("3.2.13", []))
    assert _fixed_version(vulns, "django", "3.2.0") is None


def test_osv_fixed_version_ignores_git_commits():
    vulns = advisory(branch("abc123def", [], kind="GIT"), branch("1.2.3", []))
    assert _fixed_version(vulns, "django", None) == "1.2.3"


# --- trivy -------------------------------------------------------------------------


def test_untrusted_target_warns_about_trivy_annotations(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM x\n# trivy:ignore:DS-0017\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text("resource x {}\n", encoding="utf-8")
    warnings = residual_warnings(tmp_path)
    assert any("trivy:ignore" in w and "Dockerfile" in w for w in warnings)
    assert not any("main.tf" in w for w in warnings)


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("偽のコマンドは #!/bin/sh のスクリプトで作るため POSIX のみ")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bin_dir


def fake_command(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


VERSION_GUARD = 'case "$1" in --version|version) echo "fake 1.0"; exit 0;; esac\n'


async def test_trivy_gets_a_timeout_longer_than_timeout_s(fake_bin, tmp_path):
    args_file = tmp_path / "args"
    fake_command(
        fake_bin,
        "trivy",
        VERSION_GUARD + f"echo \"$@\" > '{args_file}'\n"
        'while [ "$1" != "--output" ]; do shift; done; echo "{}" > "$2"\n',
    )
    raw = tmp_path / "raw"
    raw.mkdir()
    scanner = TrivyScanner(TrivyConfig(timeout_s=120))
    await scanner.scan(Target(root=tmp_path), ScanContext(raw_dir=raw, exclude=[]))
    assert "--timeout 180s" in args_file.read_text(encoding="utf-8")


# --- gitleaks ----------------------------------------------------------------------


async def test_gitleaks_raw_output_drops_excluded_files(fake_bin, tmp_path):
    findings = [
        {"File": "vendor/x.py", "RuleID": "r", "StartLine": 1, "Secret": "s1", "Match": "s1"},
        {"File": "app.py", "RuleID": "r", "StartLine": 1, "Secret": "s2", "Match": "s2"},
    ]
    (tmp_path / "payload.json").write_text(json.dumps(findings), encoding="utf-8")
    fake_command(
        fake_bin,
        "gitleaks",
        VERSION_GUARD
        + 'case "$2" in --help) exit 0;; esac\n'
        + 'while [ "$1" != "--report-path" ]; do shift; done\n'
        + f"cp '{tmp_path}/payload.json' \"$2\"\nexit 0\n",
    )
    raw = tmp_path / "raw"
    raw.mkdir()
    result = await GitleaksScanner(GitleaksConfig()).scan(
        Target(root=tmp_path), ScanContext(raw_dir=raw, exclude=["vendor/**"])
    )
    assert result.raw_path is not None
    written = json.loads(result.raw_path.read_text(encoding="utf-8"))
    assert [entry["File"] for entry in written] == ["app.py"]


# --- 起動したプロセスを残さない (#331, #332) ---------------------------------------


def grandchild_script(pid_file: Path) -> list[str]:
    script = (
        "import pathlib,subprocess,sys,time;"
        "c=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']);"
        "pathlib.Path(sys.argv[1]).write_text(str(c.pid));time.sleep(60)"
    )
    return [sys.executable, "-c", script, str(pid_file)]


async def wait_gone(pid: int) -> bool:
    for _ in range(100):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        await asyncio.sleep(0.05)
    os.kill(pid, signal.SIGKILL)
    return False


def has_content(path: Path) -> bool:
    return path.exists() and bool(path.read_text())


async def wait_for_file(path: Path) -> None:
    for _ in range(200):
        if has_content(path):
            return
        await asyncio.sleep(0.05)


@pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
async def test_scanner_timeout_kills_grandchildren(tmp_path):
    pid_file = tmp_path / "pid"
    result = await run_command(grandchild_script(pid_file), cwd=tmp_path, timeout_s=2)
    assert result.timed_out
    assert await wait_gone(int(pid_file.read_text()))


@pytest.mark.skipif(os.name != "posix", reason="プロセスグループは POSIX の概念")
async def test_cancelling_a_scanner_stops_its_processes(tmp_path):
    pid_file = tmp_path / "pid"
    task = asyncio.create_task(run_command(grandchild_script(pid_file), cwd=tmp_path, timeout_s=60))
    await wait_for_file(pid_file)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await wait_gone(int(pid_file.read_text()))
