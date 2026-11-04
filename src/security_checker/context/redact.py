"""シークレットのマスキング (設計書 §19.2).

検出されたシークレットの値は Candidate にもレポートにも載せない。
形式が分かる程度に伏せた表現 (`AKIA****************`) に置換する。
値そのものを外部 LLM に送るのは二次漏洩であり、設計上の禁止事項。
"""

from __future__ import annotations

import re

#: 長さを隠すための固定の伏せ字. 形式の分からない値はこれだけにする
FIXED_MASK = "********"
MAX_MASK = 20

#: 形式を表す prefix. 判断材料になるので、これに一致したときだけ残す (値の一部は見せない)
_KNOWN_PREFIXES = (
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "AKIA",
    "ASIA",
    "AIza",
    "xoxb-",
    "xoxa-",
    "xoxp-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "npm_",
    "hf_",
    "pypi-",
    "eyJ",
)


def mask_secret(value: str) -> str:
    """値を伏せる. 既知の形式なら prefix だけを残し、それ以外は長さも隠す.

    8 文字のパスワードの先頭 4 文字のように、値の半分を見せることはしない (#433)。
    """
    if not value:
        return ""
    prefix = next((p for p in _KNOWN_PREFIXES if value.startswith(p) and len(value) > len(p)), "")
    if not prefix:
        return FIXED_MASK
    return prefix + "*" * min(len(value) - len(prefix), MAX_MASK)


def redact_text(text: str, secrets: list[str]) -> str:
    """テキスト中に現れるシークレット値をマスク済み表現に置き換える."""
    redacted = text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        redacted = redacted.replace(secret, mask_secret(secret))
    return redacted


#: 既知形式のキー. ログのマスキング (§19.1) と文脈のマスキング (§19.2) で共有する
_GENERIC_KEY_RE = re.compile(
    r"\b(github_pat_[A-Za-z0-9_]{20,}"
    r"|gh[pousr]_[A-Za-z0-9]{16,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|sk-[A-Za-z0-9_-]{8,}"
    r"|AIza[A-Za-z0-9_-]{10,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{12,}"
    r"|xox[abeprs]-[A-Za-z0-9-]{8,}"
    r"|xapp-[A-Za-z0-9-]{8,}"
    r"|npm_[A-Za-z0-9]{30,}"
    r"|hf_[A-Za-z0-9]{30,}"
    r"|pypi-[A-Za-z0-9_-]{50,})"
)
#: URL に埋め込んだ資格情報 (`scheme://user:password@host`). ユーザー名とホストは残す
_URL_CREDENTIAL_RE = re.compile(
    r"(?P<head>\b[a-z][a-z0-9+.-]*://[^\s:/@]+:)(?P<value>[^\s@/]+)(?=@)"
)
#: Authorization ヘッダの値 (`Bearer <token>` / `Basic <base64>`)
_AUTH_SCHEME_RE = re.compile(r"(?P<head>\b(?:Bearer|Basic)\s+)(?P<value>[A-Za-z0-9._~+/=-]{12,})")


def redact_known_patterns(text: str) -> str:
    """既知の API キー形式・URL の資格情報・Authorization の値を伏せる (§19.1)."""
    masked = _GENERIC_KEY_RE.sub(lambda m: mask_secret(m.group(0)), text)
    masked = _URL_CREDENTIAL_RE.sub(lambda m: m.group("head") + FIXED_MASK, masked)
    return _AUTH_SCHEME_RE.sub(lambda m: m.group("head") + mask_secret(m.group("value")), masked)
