"""osv-scanner / trivy アダプタ (設計書 §7.3).

パーサは実ツールの出力を縮めたフィクスチャで、実行時の分岐 (終了コードの解釈) は
PATH に置いた偽のコマンドで確かめる。実ツール・ネットワークは使わない。
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import OsvConfig, TrivyConfig
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.scanners.base import ScanContext, Target
from security_checker.scanners.osv import OsvScanner, parse_osv, severity_from_score
from security_checker.scanners.trivy import TrivyScanner, parse_trivy, resolve_trivy_scanners


def osv_payload(raw_fixture: Callable[[str], Any], root: Path) -> Any:
    # JSON 文字列の中に埋めるので、パスも JSON としてエスケープする (Windows の \\ 対策)
    text = json.dumps(raw_fixture("osv_basic.json")).replace("{ROOT}", json.dumps(str(root))[1:-1])
    return json.loads(text)


# --- osv: パーサ ----------------------------------------------------------------------


def test_osv_groups_aliases_into_one_candidate(raw_fixture, tmp_path):
    candidates, warnings = parse_osv(osv_payload(raw_fixture, tmp_path), tmp_path)
    assert warnings == []
    keys = [(c.package.name, c.rule_id, c.package.manifest) for c in candidates if c.package]
    # PYSEC と GHSA の別名は 1 件にまとまる
    assert keys == [
        ("flask", "GHSA-68rp-wp8r-4726", "requirements.txt"),
        ("requests", "GHSA-x84v-xcm2-53pg", "requirements.txt"),
        ("requests", "GHSA-j8r2-6x86-q33q", "requirements.txt"),
        ("urllib3", "GHSA-v845-jxx5-vc9f", "sub/requirements.txt"),
    ]
    flask = candidates[0]
    assert flask.category is Category.DEPENDENCY
    assert flask.location is None
    assert flask.cve == ["CVE-2026-27205"]
    assert flask.severity_reported is Severity.MEDIUM  # max_severity 4.3
    assert flask.fix_available == "3.1.3"
    assert candidates[1].severity_reported is Severity.HIGH  # 7.5


def test_osv_ids_are_stable_and_distinct(raw_fixture, tmp_path):
    first, _ = parse_osv(osv_payload(raw_fixture, tmp_path), tmp_path)
    again, _ = parse_osv(osv_payload(raw_fixture, tmp_path), tmp_path)
    assert [c.id for c in first] == [c.id for c in again]
    assert len({c.id for c in first}) == len(first)


def test_osv_respects_exclude(raw_fixture, tmp_path):
    candidates, _ = parse_osv(osv_payload(raw_fixture, tmp_path), tmp_path, exclude=["sub/**"])
    assert all(c.package and c.package.manifest == "requirements.txt" for c in candidates)


def test_osv_falls_back_to_text_severity_and_then_medium(tmp_path):
    payload = {
        "results": [
            {
                "source": {"path": str(tmp_path / "package-lock.json")},
                "packages": [
                    {
                        "package": {"name": "a", "version": "1", "ecosystem": "npm"},
                        "vulnerabilities": [
                            {"id": "GHSA-1", "database_specific": {"severity": "CRITICAL"}},
                            {"id": "GHSA-2"},
                        ],
                    }
                ],
            }
        ]
    }
    candidates, _ = parse_osv(payload, tmp_path)
    by_id = {c.rule_id: c for c in candidates}
    assert by_id["GHSA-1"].severity_reported is Severity.CRITICAL
    # 重大度不明を info にするとゲートから消える
    assert by_id["GHSA-2"].severity_reported is Severity.MEDIUM
    assert "重大度不明" in by_id["GHSA-2"].message


@pytest.mark.parametrize(
    ("score", "severity"),
    [(9.8, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM), (0.1, Severity.LOW)],
)
def test_cvss_bands(score, severity):
    assert severity_from_score(score) is severity


def test_osv_reports_malformed_output():
    candidates, warnings = parse_osv({"unexpected": 1}, Path("/repo"))
    assert candidates == []
    assert warnings


# --- trivy: パーサ ----------------------------------------------------------------------


def test_trivy_misconfig_and_vulns(raw_fixture):
    candidates, warnings = parse_trivy(raw_fixture("trivy_basic.json"), Path("/repo"))
    assert warnings == []
    configs = [c for c in candidates if c.category is Category.CONFIG]
    deps = [c for c in candidates if c.category is Category.DEPENDENCY]
    assert {c.location.path for c in configs if c.location} == {"Dockerfile", "k8s/pod.yaml"}
    root_user = next(c for c in configs if c.rule_id == "DS-0002")
    assert root_user.severity_reported is Severity.HIGH
    assert root_user.location is not None and root_user.location.start_line == 3
    assert "対応:" in root_user.message
    assert deps[0].rule_id == "CVE-2018-18074"
    assert deps[0].package is not None and deps[0].package.manifest == "requirements.txt"
    assert deps[0].fix_available == "2.20.0"
    assert deps[0].cve == ["CVE-2018-18074"]


@pytest.mark.parametrize("severity", ["UNKNOWN", None, 3])
def test_trivy_misconfig_with_unknown_severity_is_medium(severity):
    """重大度不明の誤設定を info にするとゲートとスコアから消える. 依存の脆弱性と同じく中とする."""
    item: dict[str, Any] = {
        "ID": "DS-9999",
        "Status": "FAIL",
        "Title": "独自の check",
        "Message": "m",
    }
    if severity is not None:
        item["Severity"] = severity
    payload = {"Results": [{"Target": "Dockerfile", "Misconfigurations": [item]}]}
    candidates, _ = parse_trivy(payload, Path("/repo"))
    assert len(candidates) == 1
    assert candidates[0].severity_reported is Severity.MEDIUM
    assert "重大度不明" in candidates[0].message


def test_trivy_without_results_is_empty():
    assert parse_trivy({"SchemaVersion": 2}, Path("/repo")) == ([], [])


def test_trivy_secret_scanner_is_refused():
    """trivy のシークレット検出は値を生出力に残す. gitleaks に任せる (§19.2)."""
    selected, warnings = resolve_trivy_scanners(["config", "secret", "vuln", "license"])
    assert selected == ["misconfig", "vuln"]
    assert any("gitleaks" in w for w in warnings)
    assert any("license" in w for w in warnings)


# --- 実行時の分岐 (偽のコマンド) ---------------------------------------------------------


def fake_command(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    if os.name != "posix":
        pytest.skip("偽のコマンドは #!/bin/sh のスクリプトで作るため POSIX のみ")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    return bin_dir


def ctx(tmp_path: Path) -> ScanContext:
    raw = tmp_path / "raw"
    raw.mkdir(exist_ok=True)
    return ScanContext(raw_dir=raw, exclude=[])


VERSION_GUARD = 'case "$1" in --version) echo "fake 1.0"; exit 0;; esac\n'


async def test_osv_no_manifests_is_skipped_not_failed(fake_bin, tmp_path):
    """128 は「対象が無い」. v1 はこれで打ち切られる事故があった."""
    fake_command(fake_bin, "osv-scanner", VERSION_GUARD + "exit 128\n")
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.SKIPPED
    assert "マニフェスト" in (result.reason or "")


async def test_osv_vulnerabilities_found_is_ok(fake_bin, tmp_path, raw_fixture):
    payload = json.dumps(osv_payload(raw_fixture, tmp_path))
    (tmp_path / "payload.json").write_text(payload, encoding="utf-8")
    fake_command(
        fake_bin, "osv-scanner", VERSION_GUARD + f"cat '{tmp_path}/payload.json'\nexit 1\n"
    )
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.OK
    assert len(result.candidates) == 4
    # 生出力に絶対パスを残さない
    assert result.raw_path is not None
    assert str(tmp_path) not in result.raw_path.read_text(encoding="utf-8")


async def test_osv_vulnerable_exit_with_empty_output_is_failed(fake_bin, tmp_path):
    fake_command(fake_bin, "osv-scanner", VERSION_GUARD + "echo '{}'\nexit 1\n")
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED


async def test_osv_crash_is_failed(fake_bin, tmp_path):
    fake_command(fake_bin, "osv-scanner", VERSION_GUARD + "echo boom >&2\nexit 2\n")
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED
    assert result.stderr_excerpt == "boom"


async def test_osv_missing_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.SKIPPED


async def test_trivy_writes_and_parses_its_output(fake_bin, tmp_path, raw_fixture):
    (tmp_path / "payload.json").write_text(
        json.dumps(raw_fixture("trivy_basic.json")), encoding="utf-8"
    )
    # --output <path> の次の引数に書く
    fake_command(
        fake_bin,
        "trivy",
        VERSION_GUARD
        + 'while [ $# -gt 0 ]; do if [ "$1" = --output ]; then out="$2"; fi; shift; done\n'
        + f"cp '{tmp_path}/payload.json' \"$out\"\n",
    )
    result = await TrivyScanner(TrivyConfig(scanners=["config", "vuln"])).scan(
        Target(root=tmp_path), ctx(tmp_path)
    )
    assert result.status is ScanStatus.OK
    assert len(result.candidates) == 7  # Dockerfile 2 + k8s 3 + 依存 2


async def test_trivy_nonzero_exit_is_failed(fake_bin, tmp_path):
    fake_command(fake_bin, "trivy", VERSION_GUARD + "exit 1\n")
    result = await TrivyScanner(TrivyConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.FAILED


async def test_trivy_with_only_refused_scanners_is_failed(fake_bin, tmp_path):
    fake_command(fake_bin, "trivy", VERSION_GUARD)
    result = await TrivyScanner(TrivyConfig(scanners=["secret"])).scan(
        Target(root=tmp_path), ctx(tmp_path)
    )
    assert result.status is ScanStatus.FAILED
    assert "gitleaks" in (result.reason or "")


async def test_osv_keeps_stderr_warnings_on_success(fake_bin, tmp_path, raw_fixture):
    """読めなかったロックファイルの警告は stderr にしか出ない. 成功時も捨てない (#615)."""
    payload = json.dumps(osv_payload(raw_fixture, tmp_path))
    (tmp_path / "payload.json").write_text(payload, encoding="utf-8")
    fake_command(
        fake_bin,
        "osv-scanner",
        VERSION_GUARD
        + "echo 'Scanning dir .' >&2\n"
        + "echo 'Failed to parse lockfile weird.lock: unsupported format' >&2\n"
        + f"cat '{tmp_path}/payload.json'\nexit 1\n",
    )
    result = await OsvScanner(OsvConfig()).scan(Target(root=tmp_path), ctx(tmp_path))
    assert result.status is ScanStatus.OK
    assert result.stderr_excerpt is not None
    assert "weird.lock" in result.stderr_excerpt
    promoted = [w for w in result.parse_warnings if w.startswith("osv-scanner:")]
    assert promoted == ["osv-scanner: Failed to parse lockfile weird.lock: unsupported format"]


@pytest.mark.parametrize("severity", ["UNKNOWN", None])
def test_trivy_vulnerability_with_unknown_severity_says_so(severity):
    """誤設定・osv と同じく、medium に丸めたことを message に出す (#618)."""
    item: dict[str, Any] = {"VulnerabilityID": "CVE-2099-0001", "PkgName": "pkg"}
    if severity is not None:
        item["Severity"] = severity
    payload = {"Results": [{"Target": "go.sum", "Type": "gomod", "Vulnerabilities": [item]}]}
    candidates, _ = parse_trivy(payload, Path("/repo"))
    assert candidates[0].severity_reported is Severity.MEDIUM
    assert "重大度不明" in candidates[0].message
