"""semgrep アダプタ (SAST)."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, ClassVar

from security_checker.config.schema import SemgrepConfig
from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate, IdFactory, Location
from security_checker.models.enums import Category, Severity
from security_checker.rules import BUNDLED_PREFIX, bundled_semgrep_rule
from security_checker.scanners.base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    Target,
    UnparseableOutputError,
    as_dict,
    elapsed_ms,
    relative_path,
    run_command,
)
from security_checker.scanners.filters import is_excluded

CWE_RE = re.compile(r"CWE-\d+")

SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}


def _extract_cwe(metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("cwe")
    values = raw if isinstance(raw, list) else [raw] if isinstance(raw, str) else []
    found: list[str] = []
    for value in values:
        if isinstance(value, str):
            found.extend(CWE_RE.findall(value))
    return list(dict.fromkeys(found))


def _extract_references(metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("references")
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


def parse_semgrep(
    payload: Any,
    root: Path,
    *,
    exclude: list[str] | None = None,
) -> tuple[list[Candidate], list[str]]:
    """semgrep の JSON を Candidate に正規化する.

    壊れたエントリは parse_warnings に落として続行する (設計書 §7.2-5)。
    出力全体を解釈できなければ `UnparseableOutputError` を投げる。
    """
    warnings: list[str] = []
    candidates: list[Candidate] = []
    ids = IdFactory()

    if not isinstance(payload, dict):
        raise UnparseableOutputError("JSON のトップレベルがオブジェクトではありません")

    results = payload.get("results")
    if results is None:
        raise UnparseableOutputError("results フィールドがありません")
    if not isinstance(results, list):
        raise UnparseableOutputError("results が配列ではありません")

    for index, item in enumerate(results):
        if not isinstance(item, dict):
            warnings.append(f"semgrep: results[{index}] がオブジェクトではありません")
            continue
        check_id = item.get("check_id")
        raw_path = item.get("path")
        if not isinstance(check_id, str) or not isinstance(raw_path, str):
            warnings.append(f"semgrep: results[{index}] に check_id / path がありません")
            continue

        path = relative_path(raw_path, root)
        if exclude and is_excluded(path, exclude):
            continue

        extra = as_dict(item.get("extra"))
        metadata = as_dict(extra.get("metadata"))
        start = as_dict(item.get("start"))
        end = as_dict(item.get("end"))
        start_line = start.get("line")
        end_line = end.get("line")
        if not isinstance(start_line, int):
            warnings.append(f"semgrep: {check_id} ({path}) に start.line がありません")
            start_line = 0
        if not isinstance(end_line, int):
            end_line = start_line

        snippet_raw = extra.get("lines")
        snippet = snippet_raw.strip() if isinstance(snippet_raw, str) else None
        message = extra.get("message")
        message_text = message.strip() if isinstance(message, str) else check_id
        severity_raw = extra.get("severity")
        severity = SEVERITY_MAP.get(
            severity_raw.upper() if isinstance(severity_raw, str) else "",
            Severity.LOW,
        )
        confidence_raw = metadata.get("confidence")
        confidence = (
            CONFIDENCE_MAP.get(confidence_raw.upper()) if isinstance(confidence_raw, str) else None
        )
        fix = extra.get("fix")

        candidates.append(
            Candidate(
                id=ids.make("semgrep", check_id, path, snippet or check_id),
                scanner="semgrep",
                category=Category.SAST,
                rule_id=check_id,
                title=check_id.rsplit(".", 1)[-1],
                message=message_text,
                location=Location(
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=snippet,
                ),
                severity_reported=severity,
                confidence_reported=confidence,
                cwe=_extract_cwe(metadata),
                references=_extract_references(metadata),
                fix_available=fix if isinstance(fix, str) else None,
                raw=item,
            )
        )

    errors = payload.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                detail = error.get("message") or error.get("type") or "不明なエラー"
                warnings.append(f"semgrep: {detail}")

    return candidates, warnings


def resolve_config(value: str) -> str:
    """`bundled:<名前>` を同梱ルールのパスにする. それ以外 (レジストリ名・パス) はそのまま渡す."""
    if not value.startswith(BUNDLED_PREFIX):
        return value
    path = bundled_semgrep_rule(value.removeprefix(BUNDLED_PREFIX))
    if path is None:  # 設定の検証を通っていれば起きない
        raise ConfigError(f"未知の同梱ルール {value} です")
    return str(path)


class SemgrepScanner(BaseScanner):
    """`semgrep scan --json` を実行して Candidate を得る."""

    name = "semgrep"
    category = Category.SAST
    requires: ClassVar[list[str]] = ["semgrep"]
    install_hint = (
        "`brew install semgrep` / `pip install semgrep` で導入するか、"
        "scanners.semgrep.enabled: false で無効化してください"
    )

    settings: SemgrepConfig

    def __init__(self, settings: SemgrepConfig) -> None:
        super().__init__(settings)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        status = self.probe()
        if not status.available:
            return self.skipped(status.reason or "semgrep が利用できません")

        raw_path = ctx.raw_dir / "semgrep.json"
        argv = ["semgrep", "scan"]
        for config in self.settings.configs:
            argv += ["--config", resolve_config(config)]
        argv += [
            "--json",
            "--quiet",
            "--metrics=off",
        ]
        for pattern in ctx.exclude:
            argv += ["--exclude", pattern]
        if ctx.untrusted:
            argv += ctx.untrusted.semgrep_args()
        argv += [*self.settings.extra_args, "."]

        started = time.monotonic()
        result = await run_command(
            argv,
            cwd=target.root,
            timeout_s=self.settings.timeout_s,
            stdout_path=raw_path,
        )
        duration = elapsed_ms(started)

        if result.timed_out:
            return self.failed(
                f"semgrep が {self.settings.timeout_s}s でタイムアウトしました",
                duration_ms=duration,
                version=status.version,
            )
        # semgrep は「検出あり」でも 0 を返す。2 以上が実行失敗。
        if result.exit_code is None or result.exit_code >= 2:
            return self.failed(
                "semgrep の実行に失敗しました",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )

        try:
            payload = json.loads(raw_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return self.failed(
                f"semgrep の出力を解釈できません: {exc}",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )

        try:
            candidates, warnings = parse_semgrep(payload, target.root, exclude=ctx.exclude)
        except UnparseableOutputError as exc:
            return self.failed(
                f"semgrep の出力を解釈できません: {exc}",
                exit_code=result.exit_code,
                stderr=result.stderr,
                duration_ms=duration,
                version=status.version,
                raw_path=raw_path,
            )
        return self.ok(
            candidates,
            duration_ms=duration,
            exit_code=result.exit_code,
            version=status.version,
            raw_path=raw_path,
            parse_warnings=warnings,
        )
