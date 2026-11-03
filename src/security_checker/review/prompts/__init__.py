"""プロンプトテンプレート (設計書 §11).

テンプレートはバージョン番号付きで置く (`system.v1.jinja`)。
プロンプト変更は評価指標に直結するため、差し替えは版を分けて行う。
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from security_checker.language import DEFAULT_LANGUAGE, output_language_instruction
from security_checker.models.task import ReviewTask

PROMPT_DIR = Path(__file__).parent
PROMPT_VERSION = "v2"


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(PROMPT_DIR),
        undefined=StrictUndefined,
        autoescape=False,  # noqa: S701 - HTML ではなくプロンプトを生成するため
        keep_trailing_newline=True,
    )


def render_system(language: str = DEFAULT_LANGUAGE) -> str:
    """system プロンプト. 英語のときはテンプレートと完全に一致する.

    言語指示はテンプレートに埋め込まず末尾に足す。英語では 1 文字も変わらないため、
    プロンプト版を分けずに済む (§11 のテンプレート版管理の意図を保つ)。
    """
    base = _environment().get_template(f"system.{PROMPT_VERSION}.jinja").render()
    instruction = output_language_instruction(language)
    return f"{base}\n{instruction}\n" if instruction else base


def render_user(task: ReviewTask, schema: dict[str, object]) -> str:
    primary = task.code_context.primary
    return (
        _environment()
        .get_template(f"user.{PROMPT_VERSION}.jinja")
        .render(
            candidate=task.candidate,
            finding=_finding_fields(task),
            primary=primary,
            primary_path=_one_line(primary.path) if primary is not None else "",
            primary_text=_sanitize(primary.numbered()) if primary is not None else "",
            callers=[
                {
                    "path": caller.path,
                    "start_line": caller.start_line,
                    "end_line": caller.end_line,
                    "text": _sanitize(caller.numbered()),
                }
                for caller in task.code_context.callers
            ],
            facts=task.repo_facts,
            notes=task.notes,
            schema=json.dumps(schema, ensure_ascii=False, indent=2),
        )
    )


def _finding_fields(task: ReviewTask) -> dict[str, str]:
    """スキャナの出力に由来する欄. 検査対象のコードを含みうるので信頼しない (§19.4).

    semgrep は message や fix のメタ変数を一致したコードに置き換えて返す。
    改行を残すと、見出しに見える行を作れてしまう。
    """
    candidate = task.candidate
    package = candidate.package
    return {
        "rule_id": _one_line(candidate.rule_id),
        "message": _one_line(candidate.message),
        "cwe": _one_line(", ".join(candidate.cwe)),
        "cve": _one_line(", ".join(candidate.cve)),
        "package": _one_line(f"{package.ecosystem}:{package.name}@{package.version or 'unknown'}")
        if package is not None
        else "",
        "fix_available": _one_line(candidate.fix_available or ""),
    }


def _one_line(text: str) -> str:
    return " ".join(_sanitize(text).split())


_DELIMITERS = (
    "<<<UNTRUSTED_CODE>>>",
    "<<<END_UNTRUSTED_CODE>>>",
    "<<<UNTRUSTED_FINDING>>>",
    "<<<END_UNTRUSTED_FINDING>>>",
    "<<<UNTRUSTED_OPINIONS>>>",
    "<<<END_UNTRUSTED_OPINIONS>>>",
)


def _sanitize(text: str) -> str:
    """信頼できない文字列にデリミタが現れたらエスケープする (§19.4-2).

    コードだけでなく、Judge に渡す他の Reviewer の意見にも使う。意見はコードを読んだ
    モデルの出力なので、コード由来の文字列をそのまま含みうる。
    """
    for delimiter in _DELIMITERS:
        text = text.replace(delimiter, delimiter[:-3] + "_ESCAPED>>>")
    return text


@dataclass(frozen=True)
class PeerOpinion:
    """Judge に渡す 1 Reviewer の意見. モデル名・Provider 名を含めない (§16 匿名化)."""

    label: str
    vulnerable: bool
    severity: str
    confidence: float
    false_positive_probability: float
    exploitability: str
    reasoning: str
    attack_path: list[str] = field(default_factory=list)
    needs_more_context: list[str] = field(default_factory=list)

    def sanitized(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "confidence": self.confidence,
            "false_positive_probability": self.false_positive_probability,
            "exploitability": self.exploitability,
            "reasoning": _sanitize(self.reasoning),
            "attack_path": [_sanitize(step) for step in self.attack_path],
            "needs_more_context": [_sanitize(item) for item in self.needs_more_context],
        }


def render_judge_system(language: str = DEFAULT_LANGUAGE) -> str:
    base = _environment().get_template(f"judge_system.{PROMPT_VERSION}.jinja").render()
    instruction = output_language_instruction(language)
    return f"{base}\n{instruction}\n" if instruction else base


def render_judge_user(
    task: ReviewTask, schema: dict[str, object], opinions: Sequence[PeerOpinion]
) -> str:
    """Judge 用の user プロンプト. 元の文脈 (コード) も必ず渡す (§16-2)."""
    return (
        _environment()
        .get_template(f"judge_user.{PROMPT_VERSION}.jinja")
        .render(
            review=render_user(task, schema),
            opinions=[opinion.sanitized() for opinion in opinions],
        )
    )


def render_repair(
    previous_output: str,
    error: str,
    schema: dict[str, object],
    language: str = DEFAULT_LANGUAGE,
) -> str:
    """修復リトライ用の指示 (§10.2). 1 回だけ使う.

    判定内容は変えさせない。言語指示も再掲する (前回出力の言語を保たせるため)。
    """
    instruction = output_language_instruction(language)
    suffix = f"\n{instruction}" if instruction else ""
    return (
        "あなたの前回の出力は次の理由で不正でした:\n"
        f"{error}\n\n"
        "前回の出力:\n"
        f"{previous_output[:4000]}\n\n"
        "同じ判定内容のまま、スキーマに適合する JSON オブジェクトのみを再出力してください。"
        "JSON 以外の文字は一切出力しないでください。\n"
        f"{json.dumps(schema, ensure_ascii=False)}"
        f"{suffix}"
    )
