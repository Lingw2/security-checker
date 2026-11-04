"""osv-scanner アダプタ (依存の既知脆弱性).

1 候補 = 1 マニフェスト × 1 パッケージ × 1 脆弱性グループ。osv-scanner は同じ脆弱性の
別名 (PYSEC / GHSA / CVE) を `groups` にまとめて返すので、それを単位にする。
別名ごとに候補を作ると、同じ問題が 2〜3 回レビューされ、2〜3 回 PR に出る。

終了コード: 0 = 脆弱性なし / 1 = 脆弱性あり / 128 = 対象のマニフェストが無い。
128 は「検査できなかった」ではなく「検査対象が無い」なので skipped にする (v1 で踏んだ罠)。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, ClassVar

from security_checker.config.schema import OsvConfig
from security_checker.models.candidate import Candidate, IdFactory, PackageRef
from security_checker.models.enums import Category, Severity
from security_checker.scanners.base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    Target,
    as_dict,
    elapsed_ms,
    relative_path,
    run_command,
)
from security_checker.scanners.filters import is_excluded

EXIT_NO_PACKAGES = 128
MAX_REFERENCES = 5

#: OSV の database_specific.severity (GHSA の表記) → Severity
_TEXT_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def severity_from_score(score: float) -> Severity:
    """CVSS の基本値 → Severity (CVSS v3 の定性評価の帯)."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


def _group_severity(group: dict[str, Any], vulns: list[dict[str, Any]]) -> Severity | None:
    raw = group.get("max_severity")
    if isinstance(raw, str | int | float) and str(raw).strip():
        try:
            return severity_from_score(float(raw))
        except ValueError:
            pass
    # 数値が無ければ GHSA の文字列表記で最も重いものを使う
    texts = [
        _TEXT_SEVERITY.get(str(as_dict(v.get("database_specific")).get("severity", "")).upper())
        for v in vulns
    ]
    known = [severity for severity in texts if severity is not None]
    return max(known, key=lambda s: s.order) if known else None


def _fixed_version(vulns: list[dict[str, Any]], name: str) -> str | None:
    fixed: list[str] = []
    for vuln in vulns:
        for affected in vuln.get("affected") or []:
            package = as_dict(as_dict(affected).get("package"))
            if package.get("name") != name:
                continue
            for range_ in as_dict(affected).get("ranges") or []:
                for event in as_dict(range_).get("events") or []:
                    value = as_dict(event).get("fixed")
                    if isinstance(value, str):
                        fixed.append(value)
    # 版の大小は生態系ごとに規則が違うので比較しない。最初に見つかったものを示す
    return fixed[0] if fixed else None


def parse_osv(
    payload: Any, root: Path, *, exclude: list[str] | None = None
) -> tuple[list[Candidate], list[str]]:
    """osv-scanner の JSON を Candidate に正規化する."""
    warnings: list[str] = []
    candidates: list[Candidate] = []
    ids = IdFactory()
    results = as_dict(payload).get("results")
    if not isinstance(results, list):
        if payload not in (None, {}):
            warnings.append("osv-scanner の出力に results がありません")
        return [], warnings

    for result in results:
        source = as_dict(as_dict(result).get("source"))
        raw_path = source.get("path")
        if not isinstance(raw_path, str):
            warnings.append("osv-scanner の結果に source.path がありません")
            continue
        manifest = relative_path(raw_path, root)
        if exclude and is_excluded(manifest, exclude):
            continue
        for entry in as_dict(result).get("packages") or []:
            package = as_dict(as_dict(entry).get("package"))
            name = package.get("name")
            ecosystem = package.get("ecosystem")
            if not isinstance(name, str) or not isinstance(ecosystem, str):
                warnings.append(f"{manifest}: パッケージ名の無い結果を読み飛ばしました")
                continue
            version = package.get("version") if isinstance(package.get("version"), str) else None
            vulns_by_id = {
                v["id"]: v
                for v in (as_dict(entry).get("vulnerabilities") or [])
                if isinstance(v, dict) and isinstance(v.get("id"), str)
            }
            groups = as_dict(entry).get("groups") or [{"ids": [key]} for key in vulns_by_id]
            for group in groups:
                group_ids = [i for i in as_dict(group).get("ids") or [] if isinstance(i, str)]
                if not group_ids:
                    continue
                vulns = [vulns_by_id[i] for i in group_ids if i in vulns_by_id]
                aliases = [a for a in as_dict(group).get("aliases") or [] if isinstance(a, str)]
                primary = sorted(group_ids)[0]
                summary = next(
                    (str(v["summary"]) for v in vulns if isinstance(v.get("summary"), str)), ""
                )
                severity = _group_severity(as_dict(group), vulns)
                ref = PackageRef(ecosystem=ecosystem, name=name, version=version, manifest=manifest)
                references = [
                    str(as_dict(r).get("url"))
                    for v in vulns
                    for r in v.get("references") or []
                    if isinstance(as_dict(r).get("url"), str)
                ]
                message = (
                    f"{name} {version or ''} に既知の脆弱性があります: {summary or primary}"
                ).replace("  ", " ")
                if severity is None:
                    message += " (重大度不明のため medium として扱います)"
                candidates.append(
                    Candidate(
                        id=ids.make("osv", primary, manifest, ref.as_key()),
                        scanner="osv",
                        category=Category.DEPENDENCY,
                        rule_id=primary,
                        title=summary or f"{name} の既知の脆弱性 {primary}",
                        message=message,
                        package=ref,
                        # 不明を info にするとゲートから消える。依存の脆弱性は控えめに中とする
                        severity_reported=severity or Severity.MEDIUM,
                        cve=sorted({a for a in [*aliases, *group_ids] if _CVE_RE.match(a)}),
                        references=list(dict.fromkeys(references))[:MAX_REFERENCES],
                        fix_available=_fixed_version(vulns, name),
                        raw={"ids": group_ids, "aliases": aliases},
                    )
                )
    return candidates, warnings


class OsvScanner(BaseScanner):
    """`osv-scanner scan source --recursive --format json .` を実行する."""

    name = "osv"
    category = Category.DEPENDENCY
    requires: ClassVar[list[str]] = ["osv-scanner"]
    install_hint = (
        "`brew install osv-scanner` で導入するか、scanners.osv.enabled: false で無効化してください"
    )

    settings: OsvConfig

    def __init__(self, settings: OsvConfig) -> None:
        super().__init__(settings)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        status = self.probe()
        if not status.available:
            return self.skipped(status.reason or "osv-scanner が利用できません", unavailable=True)

        raw_path = ctx.raw_dir / "osv.json"
        argv = [
            "osv-scanner",
            "scan",
            "source",
            "--recursive",
            "--format",
            "json",
            *(ctx.untrusted.osv_args() if ctx.untrusted else []),
            *self.settings.extra_args,
            ".",
        ]
        started = time.monotonic()
        result = await run_command(
            argv, cwd=target.root, timeout_s=self.settings.timeout_s, stdout_path=raw_path
        )
        duration = elapsed_ms(started)

        if result.timed_out:
            return self.failed(
                f"osv-scanner が {self.settings.timeout_s}s でタイムアウトしました",
                duration_ms=duration,
                version=status.version,
            )
        if result.exit_code == EXIT_NO_PACKAGES:
            return self.skipped(
                "依存マニフェスト / ロックファイルが見つからないため、依存の検査は対象外です",
                version=status.version,
            )
        if result.exit_code not in (0, 1):
            return self.failed(
                "osv-scanner の実行に失敗しました (依存の検査は行われていません)",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )
        try:
            text = raw_path.read_text(encoding="utf-8")
            payload = json.loads(text) if text.strip() else {}
        except (OSError, json.JSONDecodeError) as exc:
            return self.failed(
                f"osv-scanner の出力を解釈できません: {exc}",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )
        if result.exit_code == 1 and not as_dict(payload).get("results"):
            # 「脆弱性あり」で終わったのに結果が空なのは、出力が壊れている
            return self.failed(
                "osv-scanner は脆弱性ありで終了しましたが、結果を読み取れませんでした",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )

        candidates, warnings = parse_osv(payload, target.root, exclude=ctx.exclude)
        # 生出力の絶対パスを相対にして残す (レポートに絶対パスを書かない §6.1)
        raw_path.write_text(
            text.replace(str(target.root.resolve()) + "/", "").replace(str(target.root) + "/", ""),
            encoding="utf-8",
        )
        return self.ok(
            candidates,
            duration_ms=duration,
            exit_code=result.exit_code,
            version=status.version,
            raw_path=raw_path,
            parse_warnings=[*warnings, *_stderr_warnings(result.stderr)],
            # 成功時も残す. 読めなかったロックファイルの警告は stderr にしか出ない
            stderr=result.stderr,
        )


#: 検査されなかった依存があることを示す stderr の行. 進捗表示 (Scanning ...) は拾わない
_STDERR_WARNING_RE = re.compile(
    r"\b(?:fail(?:ed|ure)?|error|unable|could ?n[o']t|cannot|unsupported|skipp(?:ed|ing))\b",
    re.IGNORECASE,
)
MAX_STDERR_WARNINGS = 10


def _stderr_warnings(stderr: bytes) -> list[str]:
    """stderr のうち、検査の取りこぼしを示す行を parse_warnings に昇格する."""
    lines = [
        line.strip()
        for line in stderr.decode("utf-8", "replace").splitlines()
        if _STDERR_WARNING_RE.search(line)
    ]
    shown = [f"osv-scanner: {line[:300]}" for line in lines[:MAX_STDERR_WARNINGS]]
    if len(lines) > MAX_STDERR_WARNINGS:
        rest = len(lines) - MAX_STDERR_WARNINGS
        shown.append(f"osv-scanner: ほか {rest} 行の警告 (stderr を参照)")
    return shown
