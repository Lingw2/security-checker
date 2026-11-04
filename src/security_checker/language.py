"""レポート本文の言語 (設計書 §18).

LLM が返す自然言語フィールド (`reasoning` / `impact` / `remediation.approach` など) の
言語を決める。ここで決めた言語が、terminal / markdown / json のすべての出力に効く
(レポート本文は LLM の出力そのものなので、出力形式ごとに訳し直す場所がない)。

既定は `auto`: 利用者のロケールから推定し、判定できなければ英語にする。
**推定結果は必ずトレースに残す** (§24.2)。同じリポジトリでも実行環境によって
本文の言語が変わりうるため、「どの言語で書かせたか」が後から分からないと監査できない。
"""

from __future__ import annotations

import os
from collections.abc import Mapping

AUTO = "auto"
DEFAULT_LANGUAGE = "en"
LOCALE_VARS = ("LC_ALL", "LC_MESSAGES", "LANG")
#: ロケール未設定を表す値. これらは「英語」ではなく「不明」として扱う.
NEUTRAL_LOCALES = frozenset({"c", "posix", ""})

#: 言語タグ → プロンプトに書く名前. 未知のタグはそのまま渡す (ここは網羅を目指さない).
LANGUAGE_NAMES = {
    "ar": "Arabic",
    "de": "German",
    "en": "English",
    "es": "Spanish",
    "fr": "French",
    "hi": "Hindi",
    "id": "Indonesian",
    "it": "Italian",
    "ja": "Japanese (日本語)",
    "ko": "Korean (한국어)",
    "pt": "Portuguese",
    "ru": "Russian",
    "th": "Thai",
    "tr": "Turkish",
    "vi": "Vietnamese",
    "zh": "Chinese (中文)",
    "zh-hans": "Simplified Chinese (简体中文)",
    "zh-hant": "Traditional Chinese (繁體中文)",
}


def normalize_language(value: str) -> str:
    """設定値を正規化する. `AUTO` → `auto`、`en_US` → `en-US`。空は呼び出し側で拒否する."""
    cleaned = value.strip()
    if cleaned.lower() == AUTO:
        return AUTO
    return cleaned.replace("_", "-")


def resolve_language(configured: str, environ: Mapping[str, str] | None = None) -> str:
    """設定値を実際の言語タグに解決する. `auto` のときだけ環境を見る.

    POSIX と同じく、LC_ALL → LC_MESSAGES → LANG のうち**空でない最初の変数**で決める。
    その値が C / POSIX なら、後ろの変数は見ずに既定 (英語) にする
    (`LC_ALL=C` を明示したのに `LANG` の言語で書かせない)。
    """
    configured = normalize_language(configured)
    if configured != AUTO:
        return configured
    source = environ if environ is not None else os.environ
    for variable in LOCALE_VARS:
        value = source.get(variable)
        if not value:
            continue
        return _tag_from_locale(value) or DEFAULT_LANGUAGE
    return DEFAULT_LANGUAGE


#: 中国語の地域 → 文字体系. 地域を捨てると繁体字と簡体字を区別できない (#305)
_TRADITIONAL_CHINESE_REGIONS = frozenset({"tw", "hk", "mo"})
#: ロケールの修飾子 (`@latin` など) → 言語タグの文字体系
_SCRIPT_MODIFIERS = {"latin": "Latn", "cyrillic": "Cyrl", "devanagari": "Deva"}


def _tag_from_locale(value: str | None) -> str | None:
    """`ja_JP.UTF-8` → `ja`、`zh_TW` → `zh-Hant`、`sr_RS@latin` → `sr-Latn`.

    ロケール未設定 (C / POSIX) は不明として扱う。
    """
    if not value:
        return None
    base, _, modifier = value.partition("@")
    head = base.split(".")[0].strip()
    if head.lower() in NEUTRAL_LOCALES:
        return None
    parts = head.replace("_", "-").split("-")
    language = parts[0].lower()
    if not language:
        return None
    region = parts[1].lower() if len(parts) > 1 else ""
    if language == "zh":
        return "zh-Hant" if region in _TRADITIONAL_CHINESE_REGIONS else "zh-Hans"
    script = _SCRIPT_MODIFIERS.get(modifier.split(".")[0].lower())
    return f"{language}-{script}" if script else language


def language_name(tag: str) -> str:
    """プロンプトに書く言語名. 未知のタグは主言語 (`fr-CA` → French)、それも無ければタグ自体."""
    lowered = tag.lower()
    return LANGUAGE_NAMES.get(lowered) or LANGUAGE_NAMES.get(lowered.split("-")[0], tag)


def output_language_instruction(tag: str) -> str:
    """出力言語の指示. 英語なら**何も足さない** (v1 プロンプトと完全一致させるため).

    構造化フィールドの値 (enum・CWE・パス・コード) まで訳されるとスキーマ検証や
    突き合わせが壊れるため、訳す対象を明示的に列挙する。
    """
    if tag.lower().split("-")[0] == DEFAULT_LANGUAGE:
        return ""
    return (
        "OUTPUT LANGUAGE:\n"
        f"Write every natural-language field in {language_name(tag)}: "
        "`reasoning`, `impact`, `attack_vector`, `attack_path`, "
        "`vulnerability_type`, `remediation.approach`, and `evidence[].note`.\n"
        "Do NOT translate anything else. These must stay exactly as specified by the "
        "schema or the source: JSON keys, enum values (`severity`, `exploitability`), "
        "CWE identifiers, file paths, symbol names, and the code inside "
        "`remediation.example`."
    )
