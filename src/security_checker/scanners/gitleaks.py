"""gitleaks アダプタ (Secret).

設計書 §19.2 により、検出値 (`Secret` / `Match`) は Candidate にもレポートにも載せない。
生出力もマスキングしてから `raw/gitleaks.json` に保存する
(そのままだと、漏洩したシークレットを成果物として再配布することになるため)。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, ClassVar

from security_checker.config.schema import GitleaksConfig
from security_checker.context.redact import mask_secret, redact_text
from security_checker.models.candidate import Candidate, IdFactory, Location
from security_checker.models.enums import Category, Severity
from security_checker.scanners.base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    Target,
    UnparseableOutputError,
    elapsed_ms,
    relative_path,
    run_command,
)
from security_checker.scanners.filters import is_excluded

SECRET_FIELDS = ("Secret", "Match")


def redact_raw_entry(entry: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    """生出力から検出値を除去する. 位置・ルール・フィンガープリントは残す.

    パスは相対化する。レポートに絶対パス (ユーザー名を含む) を残さないため。
    """
    secrets = [entry[field] for field in SECRET_FIELDS if isinstance(entry.get(field), str)]
    raw_file = entry.get("File")
    relative = (
        relative_path(raw_file, root) if root is not None and isinstance(raw_file, str) else None
    )
    redacted: dict[str, Any] = {}
    for key, value in entry.items():
        if key in SECRET_FIELDS and isinstance(value, str):
            redacted[key] = mask_secret(value) if key == "Secret" else redact_text(value, secrets)
        elif isinstance(value, str) and relative is not None and isinstance(raw_file, str):
            redacted[key] = value.replace(raw_file, relative)
        else:
            redacted[key] = value
    return redacted


def parse_gitleaks(
    payload: Any,
    root: Path,
    *,
    exclude: list[str] | None = None,
) -> tuple[list[Candidate], list[str]]:
    """gitleaks の JSON を Candidate に正規化する (値はマスク済み).

    出力全体を解釈できなければ `UnparseableOutputError` を投げる。
    """
    warnings: list[str] = []
    candidates: list[Candidate] = []
    ids = IdFactory()

    if payload is None:
        return [], []
    if not isinstance(payload, list):
        raise UnparseableOutputError("JSON のトップレベルが配列ではありません")

    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            warnings.append(f"gitleaks: findings[{index}] がオブジェクトではありません")
            continue
        rule_id = item.get("RuleID")
        raw_file = item.get("File")
        if not isinstance(rule_id, str) or not isinstance(raw_file, str):
            warnings.append(f"gitleaks: findings[{index}] に RuleID / File がありません")
            continue

        path = relative_path(raw_file, root)
        if exclude and is_excluded(path, exclude):
            continue

        start_line = item.get("StartLine")
        end_line = item.get("EndLine")
        if not isinstance(start_line, int):
            warnings.append(f"gitleaks: {rule_id} ({path}) に StartLine がありません")
            start_line = 0
        if not isinstance(end_line, int):
            end_line = start_line

        raw_secret = item.get("Secret")
        raw_match = item.get("Match")
        secret = raw_secret if isinstance(raw_secret, str) else ""
        match = raw_match if isinstance(raw_match, str) else ""
        masked_match = redact_text(match, [secret]).strip() if match else None
        description = item.get("Description")
        description_text = (
            description.strip() if isinstance(description, str) and description.strip() else rule_id
        )
        candidates.append(
            Candidate(
                id=ids.make("gitleaks", rule_id, path, masked_match or rule_id),
                scanner="gitleaks",
                category=Category.SECRET,
                rule_id=rule_id,
                title=f"シークレット検出: {rule_id}",
                message=(
                    f"{description_text} (検出値はマスクして扱います。"
                    "リポジトリからの削除と鍵のローテーションが必要です)"
                ),
                location=Location(
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    snippet=masked_match,
                ),
                severity_reported=Severity.CRITICAL,
                cwe=["CWE-798"],
                raw=redact_raw_entry(item, root),
                redacted=True,
                secret_digest=hashlib.sha256(secret.encode("utf-8")).hexdigest()
                if secret
                else None,
            )
        )

    return candidates, warnings


class GitleaksScanner(BaseScanner):
    """`gitleaks dir` (旧版は `gitleaks detect --no-git`) を実行する."""

    name = "gitleaks"
    category = Category.SECRET
    requires: ClassVar[list[str]] = ["gitleaks"]
    install_hint = (
        "`brew install gitleaks` で導入するか、scanners.gitleaks.enabled: false で"
        "無効化してください"
    )

    settings: GitleaksConfig

    def __init__(self, settings: GitleaksConfig) -> None:
        super().__init__(settings)

    @staticmethod
    def _supports_dir_subcommand() -> bool:
        """gitleaks 8.19+ は `dir`。旧版は `detect --no-git --source`."""
        executable = shutil.which("gitleaks")
        if executable is None:
            return False
        try:
            completed = subprocess.run(
                [executable, "dir", "--help"],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        status = self.probe()
        if not status.available:
            return self.skipped(status.reason or "gitleaks が利用できません", unavailable=True)

        raw_path = ctx.raw_dir / "gitleaks.json"
        with tempfile.TemporaryDirectory(prefix="security-checker-gitleaks-") as tmpdir:
            # 生の検出値をそのまま成果物ディレクトリに書かせない (§19.2)
            staging = Path(tmpdir) / "gitleaks-raw.json"
            # cwd を対象ルートにして "." を渡す。出力パスが相対になり、
            # レポートに絶対パスが混入しない (§6.1)。
            if self._supports_dir_subcommand():
                argv = ["gitleaks", "dir", "."]
            else:
                argv = ["gitleaks", "detect", "--no-git", "--source", "."]
            argv += [
                "--report-format",
                "json",
                "--report-path",
                str(staging),
                "--exit-code",
                "0",
                *(ctx.untrusted.gitleaks_args() if ctx.untrusted else []),
                *self.settings.extra_args,
            ]

            started = time.monotonic()
            result = await run_command(argv, cwd=target.root, timeout_s=self.settings.timeout_s)
            duration = elapsed_ms(started)

            if result.timed_out:
                return self.failed(
                    f"gitleaks が {self.settings.timeout_s}s でタイムアウトしました",
                    duration_ms=duration,
                    version=status.version,
                )
            # --exit-code 0 を渡しているため、非 0 は「検出あり」ではなく実行失敗を意味する。
            if result.exit_code != 0:
                return self.failed(
                    "gitleaks の実行に失敗しました (シークレット検査は行われていません)",
                    exit_code=result.exit_code,
                    stderr=result.stderr,
                    duration_ms=duration,
                    version=status.version,
                )

            # gitleaks は検出 0 件でも `[]` を書く。無いのは検査結果を受け取れていないということ
            # (extra_args で --report-path を上書きした場合など)
            if not staging.exists() or staging.stat().st_size == 0:
                return self.failed(
                    "gitleaks がレポートを書きませんでした (シークレット検査の結果がありません)",
                    exit_code=result.exit_code,
                    stderr=result.stderr,
                    duration_ms=duration,
                    version=status.version,
                )
            try:
                payload: Any = json.loads(staging.read_text(encoding="utf-8"))
                candidates, warnings = parse_gitleaks(payload, target.root, exclude=ctx.exclude)
            except (OSError, json.JSONDecodeError, UnparseableOutputError) as exc:
                return self.failed(
                    f"gitleaks の出力を解釈できません: {exc}",
                    exit_code=result.exit_code,
                    stderr=result.stderr,
                    duration_ms=duration,
                    version=status.version,
                )

        redacted_payload = [
            redact_raw_entry(entry, target.root) for entry in payload if isinstance(entry, dict)
        ]
        raw_path.write_text(
            json.dumps(redacted_payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        return self.ok(
            candidates,
            duration_ms=duration,
            exit_code=result.exit_code,
            version=status.version,
            raw_path=raw_path,
            parse_warnings=warnings,
            stderr=result.stderr,
        )
