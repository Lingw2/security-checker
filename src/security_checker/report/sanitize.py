"""LLM / スキャナ由来の文字列を Markdown に埋め込むための無害化 (設計書 §19.4).

LLM の出力 (reasoning・summary・attack_path・remediation) は、レビュー対象のコードに
仕込まれた文字列に誘導されうる。PR コメントにも `report.md` (= GitHub の Step Summary)
にも同じ規則で通し、どちらか片方だけが緩い状態を作らない。

- 文中 (`text`): HTML (コメント・タグ)・画像・リンク (`[..](..)` と自動リンク) を無効化し、
  @メンションを無効化し、既知形式のシークレットを伏せる。
- コードスパン (`code_span`): バッククォートで外に抜けられないようにする。
- コードブロック (`code_block`): 中身に現れる最長のバッククォート列より長いフェンスで囲む。

GitHub 側のサニタイズでスクリプトは実行されないが、偽の結論・誤誘導するリンク・
内容を隠す要素を書けると「割れた判断は人間が見る」という前提が弱まる。
"""

from __future__ import annotations

import re

from security_checker.context.redact import redact_known_patterns

_MENTION_RE = re.compile(r"(?<![\w`])@(?=[A-Za-z0-9])")
#: 自動リンクになる URL の頭. 直後に不可視文字を挟んでリンクにさせない
_AUTOLINK_RE = re.compile(r"(?i)\b(https?|ftp)://|\bwww\.")
_BACKTICK_RUN_RE = re.compile(r"`+")
#: 値をマスクした候補に付ける注記 (§19.2 の 3 番). report.md と PR コメントで共通
REDACTED_NOTE = "🔒 検出した値はマスクしてから保存・送信しています"
#: メンションの直後に挟む不可視文字 (ZERO WIDTH SPACE)
_ZWSP = "\u200b"


def text(value: str) -> str:
    """文中に埋め込む文字列を無害化する."""
    cleaned = redact_known_patterns(value)
    cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
    cleaned = cleaned.replace("![", "!\\[")
    # bot のコメントとして信用されたリンクを LLM に書かせない (表示は残し、押せなくする)
    cleaned = cleaned.replace("](", "]\\(").replace("]:", "]\\:")
    cleaned = _AUTOLINK_RE.sub(lambda m: m.group(0)[:-1] + _ZWSP + m.group(0)[-1], cleaned)
    return _MENTION_RE.sub("@" + _ZWSP, cleaned)


def code_span(value: str) -> str:
    """1 行のコードスパンにする. 中身のバッククォートは外に抜けられないよう置き換える."""
    cleaned = " ".join(redact_known_patterns(value).split()).replace("`", "'")
    return f"`{cleaned}`" if cleaned else "``"


def code_block(value: str, language: str = "") -> list[str]:
    """フェンス付きコードブロックの行. フェンスは中身のどのバッククォート列よりも長くする."""
    body = redact_known_patterns(value)
    longest = max((len(m.group(0)) for m in _BACKTICK_RUN_RE.finditer(body)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + language, body, fence]
