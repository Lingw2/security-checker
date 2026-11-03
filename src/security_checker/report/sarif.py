"""SARIF 出力 — GitHub Code Scanning へのアップロード用 (設計書 §18.3, §18.4).

ここで決めたことは Ruleset のゲートに直結する。変えるときは §18.4 を読み直すこと。

  - `tool.driver.name` は常に `security-checker`。Ruleset はこの名前をキーにするため、
    変わると**気づかないうちにゲートが外れる** (§18.4.4)。内訳は ruleId の接頭辞で表す。
  - `level` は**スキャナ由来の severity** で決める (NEXT-STEPS D3)。
    LLM の判定で決めると、非決定性で alert が開閉を繰り返す。LLM の判定は
    `message` と `properties` に載せる。
  - `security-severity` は付けない (ADR 0009)。GitHub が読むのは rule のものだけで、
    rule に置くと `review_required` までその重大度の security alert になる。
    ゲートは `level` と Alerts の閾値で掛ける。
  - `review_required` は `note` に固定する。
    CI を落とさない約束を Ruleset 側で破らない (§18.4.1)。
  - `false_positive` と抑制済みの Finding は出さない。
  - diff モードで変更に関係しなかった候補は `note` で残す。
    出さなければ既存 alert が閉じ、元の level で出せば既定ブランチの判定と食い違う。
  - スキャナが 1 つでも失敗したら `executionSuccessful: false` にする (§18.4.2)。
    そのような SARIF はアップロードしてはならない (`is_uploadable` で判定できる)。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from security_checker.context.redact import redact_known_patterns
from security_checker.models.candidate import Candidate
from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
#: Ruleset のキーになる名前. 変更禁止 (§18.4.4)
TOOL_NAME = "security-checker"
INFORMATION_URI = "https://github.com/Sh1n1230/security-checker"
#: Candidate の安定 ID (§6.1) を入れる指紋のキー. GitHub はこのキーを読まず、upload-sarif が
#: 計算する primaryLocationLineHash で alert を追跡する (ADR 0009)。他の SARIF の読み手向けに残す
FINGERPRINT_KEY = "primary"

MAX_MESSAGE_CHARS = 1000

_LEVELS = ("note", "warning", "error")

_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
    Severity.NONE: "note",
}


#: Code Scanning に出さない状態
_EXCLUDED = (FindingStatus.FALSE_POSITIVE,)
#: alert としては残すがゲートに掛けない状態. 判定が無い・割れたものを「脆弱」として数えない
_NON_BLOCKING = (
    FindingStatus.REVIEW_REQUIRED,
    FindingStatus.INCONCLUSIVE,
    FindingStatus.NOT_REVIEWED,
    FindingStatus.ERROR,
)


def render_sarif(report: Report) -> dict[str, Any]:
    """Report を SARIF 2.1.0 の dict にする."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    if report.findings:
        for finding in report.findings:
            if finding.status in _EXCLUDED or finding.suppressed is not None:
                continue
            result = _finding_result(finding, report.target.repo_prefix)
            if result is not None:
                rules.setdefault(result["ruleId"], _rule(finding.candidate))
                results.append(result)
    else:
        # scan (LLM なし): スキャナの検出をそのまま出す
        for candidate in report.candidates:
            result = _candidate_result(candidate, report.target.repo_prefix)
            if result is not None:
                rules.setdefault(result["ruleId"], _rule(candidate))
                results.append(result)

    # diff モードでレビューしなかった候補. 出さないと PR の解析で「修正済み」に見え、
    # ゲートに掛けると既定ブランチの判定と食い違う。どちらも起こさない note にする
    for candidate in report.outside_diff:
        result = _base_result(
            candidate,
            level="note",
            text=f"[outside diff] {candidate.message or candidate.title}",
            prefix=report.target.repo_prefix,
        )
        if result is not None:
            result["properties"]["status"] = "outside_diff"
            rules.setdefault(result["ruleId"], _rule(candidate))
            results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": report.tool_version,
                        "semanticVersion": report.tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "invocations": [_invocation(report)],
                "results": results,
                "properties": {
                    "run_id": report.run_id,
                    "mode": report.target.mode,
                    "scanners": {run.scanner: run.status.value for run in report.scanners},
                },
            }
        ],
    }


def is_uploadable(sarif: dict[str, Any]) -> bool:
    """Code Scanning にアップロードしてよいか (§18.4.2).

    失敗したスキャナの結果を含まない SARIF を上げると、既存の alert が「解決済み」として閉じる。
    """
    invocations = [
        invocation for run in sarif.get("runs", []) for invocation in run.get("invocations", [])
    ]
    # 実行記録の無い SARIF も「成功した」とは見なさない
    return bool(invocations) and all(
        invocation.get("executionSuccessful", False) for invocation in invocations
    )


def write_sarif(report: Report, output_dir: Path) -> Path:
    """report.sarif を書き出してパスを返す."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.sarif"
    path.write_text(
        json.dumps(render_sarif(report), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


# --- 部品 -------------------------------------------------------------------


def rule_id(candidate: Candidate) -> str:
    """`{scanner}/{rule_id}`. tool 名を固定する代わりに、内訳はここで表す (§18.4.4)."""
    return f"{candidate.scanner}/{candidate.rule_id}"


def _scanner_severity(candidate: Candidate) -> Severity:
    return candidate.severity_reported or Severity.INFO


def _downgrade(level: str) -> str:
    return _LEVELS[max(_LEVELS.index(level) - 1, 0)]


def _rule(candidate: Candidate) -> dict[str, Any]:
    tags = ["security", candidate.category.value, *candidate.cwe]
    rule: dict[str, Any] = {
        "id": rule_id(candidate),
        "name": candidate.rule_id,
        "shortDescription": {"text": _truncate(candidate.title or candidate.rule_id, 200)},
        "properties": {"tags": tags},
    }
    # helpUri は絶対 URI でなければならない。独自ルールの references には文章も書ける
    help_uri = next((ref for ref in candidate.references if _is_web_url(ref)), None)
    if help_uri is not None:
        rule["helpUri"] = help_uri
    return rule


def _is_web_url(value: str) -> bool:
    return value.startswith(("http://", "https://")) and " " not in value


def artifact_uri(path: str) -> str:
    """パスを uri-reference に符号化する. 区切りの / だけを残す.

    `#` や `%` をそのまま入れると別のファイルを指し、空白や `[` `]` はスキーマ違反になる。
    """
    return "/".join(quote(segment, safe="") for segment in path.replace("\\", "/").split("/"))


def _location(candidate: Candidate, prefix: str = "") -> dict[str, Any] | None:
    if candidate.location is not None:
        start = max(candidate.location.start_line, 1)
        end = max(candidate.location.end_line, start)
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": artifact_uri(prefix + candidate.location.path),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": start, "endLine": end},
            }
        }
    if candidate.package is not None and candidate.package.manifest:
        # 依存起因はマニフェストの先頭に置く (Code Scanning は位置の無い結果を受け付けない)
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": artifact_uri(prefix + candidate.package.manifest),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {"startLine": 1},
            }
        }
    return None


def _base_result(
    candidate: Candidate, *, level: str, text: str, prefix: str = ""
) -> dict[str, Any] | None:
    location = _location(candidate, prefix)
    if location is None:
        return None
    return {
        "ruleId": rule_id(candidate),
        "level": level,
        # LLM の本文がシークレットを引用している可能性を残さない (§19.2)
        "message": {"text": _truncate(redact_known_patterns(text), MAX_MESSAGE_CHARS)},
        "locations": [location],
        "partialFingerprints": {FINGERPRINT_KEY: candidate.id},
        "properties": {
            "scanner": candidate.scanner,
            "category": candidate.category.value,
            "severity_reported": _scanner_severity(candidate).value,
            "cwe": list(candidate.cwe),
        },
    }


def _candidate_result(candidate: Candidate, prefix: str = "") -> dict[str, Any] | None:
    severity = _scanner_severity(candidate)
    return _base_result(
        candidate,
        level=_LEVEL_BY_SEVERITY[severity],
        text=candidate.message or candidate.title,
        prefix=prefix,
    )


def _finding_result(finding: Finding, prefix: str = "") -> dict[str, Any] | None:
    candidate = finding.candidate
    severity = _scanner_severity(candidate)
    level = _LEVEL_BY_SEVERITY[severity]
    if finding.status is FindingStatus.LIKELY:
        level = _downgrade(level)
    elif finding.status in _NON_BLOCKING:
        level = "note"

    result = _base_result(
        candidate,
        level=level,
        text=_finding_message(finding),
        prefix=prefix,
    )
    if result is None:
        return None
    result["properties"].update(
        {
            "status": finding.status.value,
            "llm_severity": finding.severity.value,
            "confidence": round(finding.confidence, 3),
            "agreement": finding.agreement.value,
            "cwe": list(finding.cwe),
            "reviewers": [
                {
                    "name": verdict.reviewer,
                    "status": verdict.status.value,
                    "vulnerable": verdict.vulnerable,
                    "severity": verdict.severity.value,
                    "confidence": verdict.confidence,
                }
                for verdict in finding.verdicts
            ],
        }
    )
    return result


_STATUS_PREFIX: dict[FindingStatus, str] = {
    FindingStatus.CONFIRMED: "[confirmed]",
    FindingStatus.LIKELY: "[likely]",
    FindingStatus.REVIEW_REQUIRED: "[review required]",
    FindingStatus.INCONCLUSIVE: "[inconclusive]",
    FindingStatus.NOT_REVIEWED: "[not reviewed]",
    FindingStatus.ERROR: "[review error]",
}


def _finding_message(finding: Finding) -> str:
    """LLM の summary + reasoning 抜粋 (§18.3). 判定が無ければスキャナのメッセージ."""
    parts = [_STATUS_PREFIX.get(finding.status, f"[{finding.status.value}]")]
    summary = finding.summary.strip()
    parts.append(summary or finding.candidate.message or finding.candidate.title)
    reasoning = finding.supporting_reasoning
    if reasoning and reasoning not in summary:
        parts.append("\n\n" + reasoning)
    return " ".join(parts[:2]) + "".join(parts[2:])


def _invocation(report: Report) -> dict[str, Any]:
    notifications = [
        {
            "level": "error",
            "message": {
                "text": f"{run.scanner} が失敗しました: {run.reason or '理由不明'}",
            },
            "descriptor": {"id": f"scanner-failed/{run.scanner}"},
        }
        for run in report.scanners
        if run.status is ScanStatus.FAILED
    ]
    invocation: dict[str, Any] = {
        "executionSuccessful": not report.has_failed_scanner,
        "startTimeUtc": report.started_at.isoformat().replace("+00:00", "Z"),
        "endTimeUtc": report.finished_at.isoformat().replace("+00:00", "Z"),
    }
    if notifications:
        invocation["toolExecutionNotifications"] = notifications
    return invocation


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
