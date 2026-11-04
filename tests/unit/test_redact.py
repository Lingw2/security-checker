"""マスキング関数のテスト (設計書 §19)."""

from __future__ import annotations

import pytest

from security_checker.context.redact import mask_secret, redact_known_patterns, redact_text


@pytest.mark.parametrize(
    ("value", "expected_prefix"),
    [
        ("AKIATESTONLY000000", "AKIA"),
        ("xoxb-abcdef", "xoxb-"),
        ("github_pat_" + "11ABCDEFG0123456789", "github_pat_"),
        ("sk_" + "live_0123456789abcdef", "sk_live_"),
    ],
)
def test_mask_keeps_only_a_known_prefix(value, expected_prefix):
    masked = mask_secret(value)
    assert masked.startswith(expected_prefix)
    assert set(masked[len(expected_prefix) :]) == {"*"}


@pytest.mark.parametrize("value", ["ab", "hunter22", "correct-horse-battery-staple"])
def test_mask_hides_unknown_values_and_their_length(value):
    """形式の分からない値は一部も長さも見せない (#433)."""
    assert mask_secret(value) == "********"


def test_mask_empty():
    assert mask_secret("") == ""


def test_redact_text_replaces_all_occurrences():
    text = 'key = "TESTONLY-1234567890"; backup = "TESTONLY-1234567890"'
    redacted = redact_text(text, ["TESTONLY-1234567890"])
    assert "TESTONLY-1234567890" not in redacted
    assert redacted.count("********") == 2


def test_redact_known_patterns_masks_api_keys():
    text = "使用中のキー: sk-abcdefghijklmnop と ghp_0123456789abcdefgh"
    redacted = redact_known_patterns(text)
    assert "sk-abcdefghijklmnop" not in redacted
    assert "ghp_0123456789abcdefgh" not in redacted


@pytest.mark.parametrize(
    "secret",
    [
        # このリポジトリ自身の gitleaks 検査に掛からないよう、実行時に組み立てる
        "github_pat_" + "11ABCDEFG0123456789abcdef",
        "sk_" + "live_0123456789abcdefghij",
        "glp" + "at-0123456789abcdefghij",
        "npm_" + "0123456789abcdefghijklmnopqrstuvwxyz",
    ],
)
def test_redact_known_patterns_covers_more_formats(secret):
    """名前に手掛かりの無い変数に入っていても伏せる (#306)."""
    assert secret not in redact_known_patterns(f"value = {secret}")


def test_url_credentials_and_authorization_values_are_masked():
    """URL の資格情報と Authorization の値 (#308). ユーザー名とホストは判断材料なので残す."""
    text = (
        "postgres://app:s3cr3t-pass@db.internal:5432/x Authorization: Bearer abcdefghijklmnop0123"
    )
    redacted = redact_known_patterns(text)
    assert "s3cr3t-pass" not in redacted
    assert "postgres://app:" in redacted
    assert "@db.internal" in redacted
    assert "abcdefghijklmnop0123" not in redacted


def test_quoted_passwords_with_symbols_are_masked():
    """記号を含むパスワードの代入 (#434). 関数呼び出しや属性参照は伏せない."""
    from security_checker.context.builder import mask_sensitive_values

    assert "p@ss!w0rd#" not in mask_sensitive_values('password = "p@ss!w0rd#"')
    assert mask_sensitive_values('password = "p@ss!w0rd#"').endswith('"')
    assert mask_sensitive_values("token = os.environ['X']") == "token = os.environ['X']"
    assert mask_sensitive_values("password = get_password()") == "password = get_password()"
