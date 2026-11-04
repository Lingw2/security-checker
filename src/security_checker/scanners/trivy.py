"""trivy アダプタ (設定ファイルの誤設定 / 依存の脆弱性).

`scanners.trivy.scanners` で何を見るかを選ぶ。

  - `config` (`misconfig`): Dockerfile / Kubernetes / Terraform などの誤設定 → category: config
  - `vuln`: 依存の既知脆弱性 → category: dependency (osv と重なるので、どちらか一方で足りる)

`secret` は受け付けない。trivy のシークレット検出は検出値そのものを出力に含めるため、
生出力 (raw/) に値が残る。シークレットは値を伏せる処理のある gitleaks で見る (§19.2)。
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, ClassVar

from security_checker.config.schema import TrivyConfig
from security_checker.models.candidate import Candidate, IdFactory, Location, PackageRef
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

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_SCANNER_ALIASES = {"config": "misconfig", "misconfig": "misconfig", "vuln": "vuln"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
MAX_REFERENCES = 5


def resolve_trivy_scanners(requested: list[str]) -> tuple[list[str], list[str]]:
    """設定の scanners を trivy の --scanners に変換する. 受け付けないものは警告にする."""
    resolved: list[str] = []
    warnings: list[str] = []
    for name in requested:
        mapped = _SCANNER_ALIASES.get(name)
        if mapped is None:
            reason = (
                "検出値が生出力に残るため使いません。シークレットは gitleaks で検査します"
                if name == "secret"
                else "未対応です (config / vuln のみ)"
            )
            warnings.append(f"scanners.trivy.scanners の '{name}' は{reason}")
            continue
        if mapped not in resolved:
            resolved.append(mapped)
    return resolved, warnings


def _references(item: dict[str, Any]) -> list[str]:
    urls = [item.get("PrimaryURL"), *(item.get("References") or [])]
    return list(dict.fromkeys(u for u in urls if isinstance(u, str)))[:MAX_REFERENCES]


def parse_trivy(
    payload: Any, root: Path, *, exclude: list[str] | None = None
) -> tuple[list[Candidate], list[str]]:
    """trivy の JSON を Candidate に正規化する."""
    warnings: list[str] = []
    candidates: list[Candidate] = []
    ids = IdFactory()
    results = as_dict(payload).get("Results")
    if results is None:
        return [], warnings  # 対象が何も無いとき trivy は Results を出さない
    if not isinstance(results, list):
        return [], ["trivy の出力の Results が配列ではありません"]

    for result in results:
        result = as_dict(result)
        target = result.get("Target")
        if not isinstance(target, str):
            warnings.append("trivy の結果に Target がありません")
            continue
        path = relative_path(target, root)
        if exclude and is_excluded(path, exclude):
            continue

        for item in result.get("Misconfigurations") or []:
            item = as_dict(item)
            if item.get("Status") != "FAIL":
                continue
            rule = item.get("ID") or item.get("AVDID")
            if not isinstance(rule, str):
                warnings.append(f"{path}: ID の無い誤設定を読み飛ばしました")
                continue
            cause = as_dict(item.get("CauseMetadata"))
            raw_start, raw_end = cause.get("StartLine"), cause.get("EndLine")
            start = raw_start if isinstance(raw_start, int) else 0
            end = raw_end if isinstance(raw_end, int) else start
            message = str(
                item.get("Message") or item.get("Description") or item.get("Title") or rule
            )
            resolution = item.get("Resolution")
            severity = SEVERITY_MAP.get(str(item.get("Severity")).upper())
            if isinstance(resolution, str):
                message += f" (対応: {resolution})"
            if severity is None:
                message += " (重大度不明のため medium として扱います)"
            candidates.append(
                Candidate(
                    # 行番号を ID に含めない (§6.1)。同じルールの同じ指摘は出現順で区別する
                    id=ids.make("trivy", rule, path, f"{cause.get('Resource') or ''} {message}"),
                    scanner="trivy",
                    category=Category.CONFIG,
                    rule_id=rule,
                    title=str(item.get("Title") or rule),
                    message=message,
                    location=Location(path=path, start_line=start, end_line=max(end, start)),
                    # 不明を info にするとゲートから消える。依存の脆弱性・osv にそろえて中とする
                    severity_reported=severity or Severity.MEDIUM,
                    references=_references(item),
                )
            )

        ecosystem = str(result.get("Type") or "unknown")
        for item in result.get("Vulnerabilities") or []:
            item = as_dict(item)
            vuln_id = item.get("VulnerabilityID")
            name = item.get("PkgName")
            if not isinstance(vuln_id, str) or not isinstance(name, str):
                warnings.append(f"{path}: ID かパッケージ名の無い脆弱性を読み飛ばしました")
                continue
            version = item.get("InstalledVersion")
            ref = PackageRef(
                ecosystem=ecosystem,
                name=name,
                version=version if isinstance(version, str) else None,
                manifest=path,
            )
            title = str(item.get("Title") or vuln_id)
            fixed = item.get("FixedVersion")
            severity = SEVERITY_MAP.get(str(item.get("Severity")).upper())
            message = f"{name} {ref.version or ''} に既知の脆弱性があります: {title}"
            if severity is None:
                # 誤設定・osv と同じく、medium に丸めたことを隠さない
                message += " (重大度不明のため medium として扱います)"
            candidates.append(
                Candidate(
                    id=ids.make("trivy", vuln_id, path, ref.as_key()),
                    scanner="trivy",
                    category=Category.DEPENDENCY,
                    rule_id=vuln_id,
                    title=title,
                    message=message,
                    package=ref,
                    severity_reported=severity or Severity.MEDIUM,
                    cwe=[c for c in item.get("CweIDs") or [] if isinstance(c, str)],
                    cve=[vuln_id] if _CVE_RE.match(vuln_id) else [],
                    references=_references(item),
                    fix_available=fixed if isinstance(fixed, str) and fixed else None,
                )
            )
    return candidates, warnings


class TrivyScanner(BaseScanner):
    """`trivy fs --scanners <...> --format json .` を実行する."""

    name = "trivy"
    category = Category.CONFIG
    requires: ClassVar[list[str]] = ["trivy"]
    install_hint = (
        "`brew install trivy` で導入するか、scanners.trivy.enabled: false で無効化してください"
    )

    settings: TrivyConfig

    def __init__(self, settings: TrivyConfig) -> None:
        super().__init__(settings)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        status = self.probe()
        if not status.available:
            return self.skipped(status.reason or "trivy が利用できません", unavailable=True)

        selected, config_warnings = resolve_trivy_scanners(self.settings.scanners)
        if not selected:
            return self.failed(
                "scanners.trivy.scanners に有効な検査対象がありません: "
                + " / ".join(config_warnings),
                version=status.version,
            )

        raw_path = ctx.raw_dir / "trivy.json"
        argv = [
            "trivy",
            "fs",
            "--quiet",
            "--scanners",
            ",".join(selected),
            "--format",
            "json",
            "--output",
            str(raw_path),
            *(ctx.untrusted.trivy_args() if ctx.untrusted else []),
            *self.settings.extra_args,
            ".",
        ]
        started = time.monotonic()
        result = await run_command(argv, cwd=target.root, timeout_s=self.settings.timeout_s)
        duration = elapsed_ms(started)

        if result.timed_out:
            return self.failed(
                f"trivy が {self.settings.timeout_s}s でタイムアウトしました",
                duration_ms=duration,
                version=status.version,
            )
        # --exit-code を渡していないので、非 0 は「検出あり」ではなく実行失敗
        if result.exit_code != 0:
            return self.failed(
                "trivy の実行に失敗しました (設定ファイル / 依存の検査は行われていません)",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
            )
        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return self.failed(
                f"trivy の出力を解釈できません: {exc}",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )

        candidates, warnings = parse_trivy(payload, target.root, exclude=ctx.exclude)
        return self.ok(
            candidates,
            duration_ms=duration,
            exit_code=result.exit_code,
            version=status.version,
            raw_path=raw_path,
            parse_warnings=[*config_warnings, *warnings],
        )
