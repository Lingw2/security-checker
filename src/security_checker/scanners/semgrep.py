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
    # semgrep 1.72.0 からの正式な値
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # 古い値 (公式の対応: ERROR = HIGH / WARNING = MEDIUM / INFO = LOW)
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}
#: semgrep CE (未ログイン) が extra.lines に入れる固定の文字列. スニペットとしては使えない
_LOGIN_PLACEHOLDER = "requires login"
#: 同梱ルールの check_id に semgrep が前置する、インストール先から作った接頭辞の終わり
_BUNDLED_RULE_PREFIX = "security_checker.rules.semgrep."
CONFIDENCE_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}


def _extract_cwe(metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("cwe")
    values = raw if isinstance(raw, list) else [raw] if isinstance(raw, str) else []
    found: list[str] = []
    for value in values:
        if isinstance(value, str):
            found.extend(CWE_RE.findall(value))
    return list(dict.fromkeys(found))


#: 秘密の値そのものを指す CWE (ハードコードされた資格情報・鍵)
_SECRET_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-522"})


def is_secret_result(item: dict[str, Any]) -> bool:
    """検出箇所が秘密の値そのものか. その行は raw にもレポートにも平文で残さない (§19.2)."""
    check_id = item.get("check_id")
    if isinstance(check_id, str) and "secret" in check_id.lower():
        return True
    metadata = as_dict(as_dict(item.get("extra")).get("metadata"))
    return bool(_SECRET_CWES & set(_extract_cwe(metadata)))


def redact_semgrep_payload(payload: Any) -> Any:
    """raw/semgrep.json に書く形. 秘密系ルールの検出では一致した行を落とす."""
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return payload
    results: list[Any] = []
    for item in payload["results"]:
        if isinstance(item, dict) and is_secret_result(item):
            extra = dict(as_dict(item.get("extra")))
            extra.pop("lines", None)
            item = {**item, "extra": extra}
        results.append(item)
    return {**payload, "results": results}


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

        check_id = _normalize_check_id(check_id)
        snippet_raw = extra.get("lines")
        snippet = snippet_raw.strip() if isinstance(snippet_raw, str) else None
        if snippet in (None, "", _LOGIN_PLACEHOLDER):
            # CE では lines が固定文字列になり、ID が出現順だけで決まってしまう (§6.1)
            snippet = _read_lines(root, path, start_line, end_line)
        secret = is_secret_result(item)
        # ID の材料には一致した行を使うが (ハッシュにしか残らない)、秘密の行は保存しない
        fingerprint = snippet or check_id
        if secret:
            snippet = None
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
                id=ids.make("semgrep", check_id, path, fingerprint),
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
                # 秘密系ルールの autofix は値を含みうる. 一致した行と一緒に落とす
                fix_available=fix if isinstance(fix, str) and not secret else None,
                raw=redact_semgrep_payload({"results": [item]})["results"][0] if secret else item,
                redacted=secret,
            )
        )

    errors = payload.get("errors")
    if isinstance(errors, list):
        for error in errors:
            if isinstance(error, dict):
                detail = error.get("message") or error.get("type") or "不明なエラー"
                warnings.append(f"semgrep: {detail}")

    return candidates, warnings


def _normalize_check_id(check_id: str) -> str:
    """同梱ルールの ID から、インストール先のパスに由来する接頭辞を外す.

    semgrep はローカルのルールファイルの check_id に、そのファイルの場所をドット区切りにした
    接頭辞を付ける。そのままでは rule_id・候補 ID・ignore の指定が環境ごとに変わる。
    """
    _, found, rest = check_id.rpartition(_BUNDLED_RULE_PREFIX)
    return f"bundled.{rest}" if found and rest else check_id


def _read_lines(root: Path, path: str, start: int, end: int) -> str | None:
    """検出箇所の行を検査対象から読む. 読めなければ None (ID は出現順だけで区別する)."""
    if start < 1:
        return None
    try:
        lines = (root / path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    selected = lines[start - 1 : max(end, start)]
    text = "\n".join(selected).strip()
    return text or None


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
            return self.skipped(status.reason or "semgrep が利用できません", unavailable=True)

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

        # 秘密系ルールで一致した行を、成果物 (CI の artifact) に平文で残さない
        redacted = redact_semgrep_payload(payload)
        if redacted is not payload:
            raw_path.write_text(json.dumps(redacted, ensure_ascii=False), encoding="utf-8")
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
