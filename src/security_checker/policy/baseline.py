"""Baseline — 既知の候補を記録し、CI を落とさない (設計書 §17.2).

既存のリポジトリに導入すると、初回は過去の負債がまとめて出る。それを全部直すまで
CI を赤にしておくのは現実的でない。baseline に記録した候補は `suppressed` として
レポートに残しつつ、レビューとゲートの対象から外す。新しく増えたものだけが落ちる。

キーは Candidate の安定 ID (§6.1)。行番号を含まないので、無関係な編集で baseline が壊れない。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from security_checker.errors import ConfigError
from security_checker.models.candidate import Candidate

BASELINE_VERSION = 2
#: 読めるが、秘密の値までは照合できない形式
LEGACY_VERSIONS = (1,)


@dataclass(frozen=True)
class Baseline:
    """読み込んだ baseline. 秘密の候補は ID に加えて値の要約でも照合する (ADR 0008)."""

    ids: frozenset[str] = frozenset()
    salt: str = ""
    #: 候補 ID → 記録時の秘密の値の要約
    secret_hashes: dict[str, str] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    def covers(self, candidate: Candidate) -> bool:
        """記録済みの候補か. ID が同じでも、秘密の値が違えば新しい候補として扱う."""
        if candidate.id not in self.ids:
            return False
        recorded = self.secret_hashes.get(candidate.id)
        if recorded is None or candidate.secret_digest is None:
            return True
        return secret_hash(self.salt, candidate.secret_digest) == recorded


def secret_hash(salt: str, digest: str) -> str:
    """baseline に書く要約. ファイルごとのソルトで、別のリポジトリと値を突き合わせられなくする."""
    return hashlib.sha256(f"{salt}\x00{digest}".encode()).hexdigest()


def load_baseline(path: Path) -> Baseline:
    """baseline を読む. 壊れていれば ConfigError (黙って空にしない)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(
            f"policy.baseline のファイルが見つかりません: {path}。"
            "`security-checker baseline update` で作成できます"
        ) from exc
    except (OSError, ValueError) as exc:
        raise ConfigError(f"baseline を読めません ({path}): {exc}") from exc
    version = data.get("version") if isinstance(data, dict) else None
    if version != BASELINE_VERSION and version not in LEGACY_VERSIONS:
        raise ConfigError(f"baseline の形式が不正です ({path}): version {BASELINE_VERSION} が必要")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise ConfigError(f"baseline の形式が不正です ({path}): entries がありません")
    ids: set[str] = set()
    hashes: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise ConfigError(f"baseline の形式が不正です ({path}): id の無い entry があります")
        ids.add(entry["id"])
        recorded = entry.get("secret_hash")
        if isinstance(recorded, str):
            hashes[entry["id"]] = recorded
    salt = data.get("salt")
    warnings: tuple[str, ...] = ()
    if version in LEGACY_VERSIONS:
        warnings = (
            f"{path} は古い形式 (version {version}) です。"
            "同じ場所で値を差し替えた秘密も抑制されます。"
            "`security-checker baseline update` で更新してください",
        )
    return Baseline(
        ids=frozenset(ids),
        salt=salt if isinstance(salt, str) else "",
        secret_hashes=hashes,
        warnings=warnings,
    )


def render_baseline(
    candidates: list[Candidate], *, tool_version: str, salt: str | None = None
) -> dict[str, Any]:
    """baseline の中身. 人間がレビューできるよう、ID だけでなく場所とルールも書く."""
    resolved_salt = salt or secrets.token_hex(16)
    rendered: list[dict[str, str]] = []
    for candidate in candidates:
        entry = {
            "id": candidate.id,
            "scanner": candidate.scanner,
            "rule_id": candidate.rule_id,
            "where": candidate.where,
            "title": candidate.title,
        }
        if candidate.secret_digest is not None:
            entry["secret_hash"] = secret_hash(resolved_salt, candidate.secret_digest)
        rendered.append(entry)
    return {
        "version": BASELINE_VERSION,
        "tool": "security-checker",
        "tool_version": tool_version,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "salt": resolved_salt,
        "entries": sorted(rendered, key=lambda e: (e["where"], e["rule_id"], e["id"])),
    }


def _existing_salt(path: Path) -> str | None:
    """更新の差分を候補の増減だけにするため、既存のソルトを引き継ぐ."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    salt = data.get("salt") if isinstance(data, dict) else None
    return salt if isinstance(salt, str) and salt else None


def write_baseline(path: Path, candidates: list[Candidate], *, tool_version: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = render_baseline(candidates, tool_version=tool_version, salt=_existing_salt(path))
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path
