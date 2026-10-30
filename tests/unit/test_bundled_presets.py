"""同梱プリセット (データ) の検証 (設計書 §9.7, §9.8).

プリセットはコードではなくデータなので、壊れていても実行するまで気づけない。
ここで「読める・妥当・中立」を機械的に確かめる。
"""

from __future__ import annotations

from pathlib import Path

import yaml

from security_checker.config.schema import Config, ReviewerConfig
from security_checker.providers.base import StructuredMode
from security_checker.providers.presets.loader import (
    BUNDLED_HTTP_DIR,
    BUNDLED_PROCESS_DIR,
    HttpPreset,
    ProcessPreset,
    load_http_presets,
    load_process_presets,
)
from security_checker.providers.registry import build_http_provider, build_process_provider

# ユーザー側のプリセットを混ぜないよう、同梱分だけを読む
EMPTY = Path("/nonexistent-preset-dir")


def bundled_http() -> dict[str, HttpPreset]:
    return load_http_presets(user_dir=EMPTY)


def bundled_process() -> dict[str, ProcessPreset]:
    return load_process_presets(user_dir=EMPTY)


def test_bundled_presets_load():
    """同梱データが pydantic の検証を通る (壊れた YAML を配布しない)."""
    assert bundled_http()
    assert bundled_process()


def test_every_bundled_process_preset_declares_readonly_flags():
    """採否条件 2 (書き込み無効化の手段がある) の担保 (§9.7).

    申告がないプリセットは、command 直書きと同じく起動時に警告される。
    同梱するものは申告を必須にする。
    """
    for name, preset in bundled_process().items():
        assert preset.requires_readonly_flags, f"{name} が requires_readonly_flags を申告していない"


def test_bundled_process_presets_do_not_use_a_shell():
    """argv のリストで起動する (§9.7 の 3). シェルのメタ文字を含めない."""
    for name, preset in bundled_process().items():
        assert preset.command, f"{name} の command が空"
        joined = " ".join(preset.command)
        for metachar in ("|", ";", "&&", ">", "<", "$("):
            assert metachar not in joined, f"{name} の command に {metachar} が含まれている"


def test_bundled_process_presets_pass_the_prompt_via_stdin_or_file():
    """プロンプトを argv に埋め込まない (§9.7 の 3)."""
    for preset in bundled_process().values():
        assert preset.prompt_via in ("stdin", "file")


def test_bundled_http_presets_never_carry_a_plaintext_key():
    """平文キーはスキーマに存在しない (§19.1). データ側からも入れられないことを確かめる."""
    for path in sorted(BUNDLED_HTTP_DIR.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "api_key" not in raw, f"{path.name} に平文キーの項目がある"


def test_bundled_presets_carry_no_ranking_markers():
    """順位づけ・推奨マークを持ち込まない (§9.8).

    スキーマが extra="forbid" なので未知のキーは読み込み時に落ちるが、
    「既定にする」「おすすめ」といった概念が後から紛れ込むのを禁じておく。
    """
    forbidden = ("recommended", "default", "priority", "rank", "preferred")
    for directory in (BUNDLED_HTTP_DIR, BUNDLED_PROCESS_DIR):
        for path in sorted(directory.glob("*.yml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            for key in forbidden:
                assert key not in raw, f"{path.name} に {key} がある"


def test_no_reviewer_is_enabled_by_default():
    """同梱プリセットがあっても、既定 Reviewer は 1 つも存在しない (§9.8)."""
    assert Config().reviewers == []


def test_bundled_process_preset_builds_without_a_responsibility_warning():
    """申告済みプリセット経由なら、利用者責任の警告を出さない (§9.7 の 2)."""
    presets = bundled_process()
    name = sorted(presets)[0]
    warnings: list[str] = []
    provider = build_process_provider(
        ReviewerConfig(name="r1", transport="process", preset=name),
        presets=presets,
        warnings=warnings,
    )
    assert provider.capabilities.structured_output is StructuredMode.PROMPT_ONLY
    assert warnings == []


def test_direct_command_still_warns_even_when_a_preset_exists():
    """command 直書きは中身を検証できない. プリセットがあっても警告は消さない."""
    warnings: list[str] = []
    build_process_provider(
        ReviewerConfig(name="r1", transport="process", command=["echo", "hi"]),
        presets=bundled_process(),
        warnings=warnings,
    )
    assert len(warnings) == 1


def test_bundled_http_preset_supplies_dialect_and_base_url():
    """preset を指定すると、設定に model だけ書けば動く (§9.3)."""
    presets = bundled_http()
    name = sorted(presets)[0]
    preset = presets[name]
    assert preset.api_key_env is not None
    provider = build_http_provider(
        ReviewerConfig(name="r1", transport="http", preset=name, model="m"),
        environ={preset.api_key_env: "dummy"},
        presets=presets,
    )
    assert provider.base_url == preset.base_url


def test_copilot_preset_reads_the_prompt_from_stdin():
    """`-p` を付けると標準入力が無視され、レビュー対象が渡らない.

    プロンプトを argv に埋め込まない (§9.7 の 3) ためにも、`-p` / `--prompt` を含めない。
    """
    preset = bundled_process()["copilot"]
    assert preset.prompt_via == "stdin"
    for arg in preset.command:
        assert arg not in ("-p", "-i") and not arg.startswith(("--prompt", "--interactive")), arg


def test_copilot_preset_denies_every_permission_kind():
    """採否条件 2 の担保. 拒否はツール名ではなく権限の種類で指定する (§9.7).

    種類のどれかが抜けると、その種類のツールは非対話モードの既定の挙動に委ねられる。
    """
    command = bundled_process()["copilot"].command
    for kind in ("shell", "write", "read", "url", "memory"):
        assert f"--deny-tool={kind}" in command, kind
    for flag in ("--disable-builtin-mcps", "--no-custom-instructions", "--no-ask-user", "-s"):
        assert flag in command, flag
    assert not any(arg.startswith(("--allow-", "--yolo")) for arg in command)
