"""レポート本文の言語解決 (設計書 §18)."""

from __future__ import annotations

import pytest

from security_checker.language import (
    output_language_instruction,
    resolve_language,
)
from security_checker.review import prompts


def test_explicit_setting_ignores_the_environment():
    assert resolve_language("ja", {"LANG": "en_US.UTF-8"}) == "ja"


@pytest.mark.parametrize(
    ("locale", "expected"),
    [
        ("ja_JP.UTF-8", "ja"),
        ("ja", "ja"),
        ("ko_KR.UTF-8", "ko"),
        ("zh_CN.UTF-8", "zh-Hans"),
        ("zh_TW.UTF-8", "zh-Hant"),
        ("zh_HK", "zh-Hant"),
        ("sr_RS.UTF-8@latin", "sr-Latn"),
        ("en_US.UTF-8", "en"),
        ("pt_BR@euro", "pt"),
    ],
)
def test_auto_reads_the_locale(locale, expected):
    assert resolve_language("auto", {"LANG": locale}) == expected


def test_lc_all_wins_over_lang():
    assert resolve_language("auto", {"LC_ALL": "ja_JP.UTF-8", "LANG": "en_US.UTF-8"}) == "ja"


@pytest.mark.parametrize("locale", ["C", "POSIX", ""])
def test_neutral_locales_fall_back_to_english(locale):
    """ロケール未設定は「英語指定」ではなく「不明」. CI ではこの経路を通る."""
    assert resolve_language("auto", {"LANG": locale}) == "en"


def test_auto_without_any_locale_falls_back_to_english():
    assert resolve_language("auto", {}) == "en"


def test_english_adds_no_instruction():
    """英語では v1 プロンプトと 1 文字も変えない (プロンプト版を分けずに済ませるため)."""
    assert output_language_instruction("en") == ""
    assert prompts.render_system("en") == prompts.render_system()


def test_non_english_names_the_language_and_the_fields():
    instruction = output_language_instruction("ja")
    assert "Japanese" in instruction
    for field in ("reasoning", "impact", "remediation.approach"):
        assert field in instruction


def test_instruction_protects_structural_values():
    """enum や CWE まで訳されるとスキーマ検証と突き合わせが壊れる."""
    instruction = output_language_instruction("ja")
    assert "Do NOT translate anything else" in instruction
    for protected in ("severity", "CWE", "file paths", "remediation.example"):
        assert protected in instruction


def test_unknown_tag_is_passed_through():
    assert "sv" in output_language_instruction("sv")


def test_system_prompt_carries_the_instruction():
    rendered = prompts.render_system("ja")
    assert rendered.startswith("You are an independent security auditor")
    assert "OUTPUT LANGUAGE" in rendered
    assert "Japanese" in rendered


def test_repair_prompt_repeats_the_language():
    """修復時に言語指示が消えると、前回と違う言語で返ってくる."""
    repair = prompts.render_repair("{}", "エラー", {}, "ja")
    assert "OUTPUT LANGUAGE" in repair
    assert prompts.render_repair("{}", "エラー", {}, "en").count("OUTPUT LANGUAGE") == 0


def test_explicit_c_locale_is_not_overridden_by_lang():
    """空でない最初の変数で決める. LC_ALL=C なら LANG は見ない (#221)."""
    assert resolve_language("auto", {"LC_ALL": "C", "LANG": "ja_JP.UTF-8"}) == "en"
    assert resolve_language("auto", {"LC_ALL": "", "LANG": "ja_JP.UTF-8"}) == "ja"


@pytest.mark.parametrize(
    ("raw", "expected"), [("AUTO", "auto"), (" en_US ", "en-US"), ("ja", "ja")]
)
def test_output_language_is_normalized(raw, expected):
    """設定の値を正規化する (#220)."""
    from security_checker.config.schema import OutputConfig

    assert OutputConfig(language=raw).language == expected


@pytest.mark.parametrize("raw", ["", "   ", "日本語", "en US"])
def test_broken_output_language_is_rejected(raw):
    from pydantic import ValidationError

    from security_checker.config.schema import OutputConfig

    with pytest.raises(ValidationError, match=r"output\.language"):
        OutputConfig(language=raw)


def test_traditional_and_simplified_chinese_have_names():
    from security_checker.language import language_name

    assert "Traditional" in language_name("zh-Hant")
    assert "Simplified" in language_name("zh-Hans")
    assert language_name("fr-CA") == "French"
