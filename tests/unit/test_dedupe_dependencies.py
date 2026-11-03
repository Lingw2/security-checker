"""スキャナをまたいだ依存の脆弱性の重複 (#179)."""

from __future__ import annotations

from pathlib import Path

from security_checker.models.candidate import Candidate, PackageRef
from security_checker.models.enums import Category, ScanStatus, Severity
from security_checker.run import dedupe_and_sort
from security_checker.scanners.base import ScanResult
from tests.factories import make_candidate


def dependency(
    scanner: str,
    rule_id: str,
    *,
    cve: tuple[str, ...] = (),
    name: str = "jinja2",
    version: str = "3.1.2",
    manifest: str = "requirements.txt",
    ecosystem: str = "PyPI",
    severity: Severity = Severity.MEDIUM,
) -> Candidate:
    return make_candidate(
        f"{scanner}-{rule_id}-{version}-{manifest}",
        scanner=scanner,
        rule_id=rule_id,
        category=Category.DEPENDENCY,
        location=None,
        severity=severity,
        cve=list(cve),
        package=PackageRef(ecosystem=ecosystem, name=name, version=version, manifest=manifest),
    )


def result(scanner: str, *candidates: Candidate) -> ScanResult:
    return ScanResult(
        scanner=scanner,
        category=Category.DEPENDENCY,
        status=ScanStatus.OK,
        candidates=list(candidates),
        raw_path=Path("x"),
    )


OSV = dependency("osv", "GHSA-h5c8-rqwp-cp95", cve=("CVE-2024-22195",))


def test_the_same_vulnerability_from_two_scanners_is_one_candidate():
    trivy = dependency(
        "trivy",
        "CVE-2024-22195",
        cve=("CVE-2024-22195",),
        ecosystem="pip",
        severity=Severity.HIGH,
    )
    merged = dedupe_and_sort([result("osv", OSV), result("trivy", trivy)])
    assert len(merged) == 1
    assert merged[0].id == OSV.id
    assert merged[0].scanner == "osv"
    assert merged[0].also_reported_by == ["trivy"]
    assert merged[0].severity_reported is Severity.HIGH


def test_different_vulnerabilities_stay_separate():
    other = dependency("trivy", "CVE-2099-0001", cve=("CVE-2099-0001",))
    assert len(dedupe_and_sort([result("osv", OSV), result("trivy", other)])) == 2


def test_different_versions_or_manifests_stay_separate():
    trivy = ("CVE-2024-22195",)
    version = dependency("trivy", "CVE-2024-22195", cve=trivy, version="3.1.3")
    manifest = dependency("trivy", "CVE-2024-22195", cve=trivy, manifest="sub/requirements.txt")
    merged = dedupe_and_sort([result("osv", OSV), result("trivy", version, manifest)])
    assert len(merged) == 3


def test_candidates_from_one_scanner_are_not_merged():
    """同じスキャナの別エントリは、スキャナが分けて報告したものなので残す."""
    other = dependency("osv", "GHSA-xxxx", cve=("CVE-2024-22195",))
    assert len(dedupe_and_sort([result("osv", OSV, other)])) == 2


def test_other_categories_are_not_compared():
    a = make_candidate("a", rule_id="r", path="a.py")
    b = make_candidate("b", rule_id="r", path="a.py", scanner="other")
    assert len(dedupe_and_sort([result("x", a, b)])) == 2
