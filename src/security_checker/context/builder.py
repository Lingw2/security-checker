"""Context Builder — Candidate → ReviewTask (設計書 §8).

ここが Secret 値のマスキングの **必須通過点** である (§19.2)。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from security_checker.config.schema import ContextConfig
from security_checker.context.budget import (
    CHARS_PER_TOKEN,
    PROMPT_OVERHEAD_TOKENS,
    estimate_tokens,
)
from security_checker.context.redact import mask_secret, redact_known_patterns, redact_text
from security_checker.context.slicer import clip_lines, line_window, shrink
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category
from security_checker.models.task import (
    CodeContext,
    CodeSlice,
    RepoFacts,
    ReviewTask,
    TokenBudget,
)

MIN_WINDOW_LINES = 6
SECRET_MIN_LENGTH = 8


class ContextBuilder:
    """候補ごとにレビュー用の文脈を組み立てる."""

    def __init__(
        self,
        root: Path,
        config: ContextConfig,
        repo_facts: RepoFacts,
        *,
        max_input_tokens: int | None = None,
    ) -> None:
        """`max_input_tokens` は Provider 側の上限 (max_context_tokens - 出力上限).

        全 Reviewer に同じ依頼を送る (§11.4) ので、Reviewer のうち最も小さい値を渡す。
        """
        self.root = root
        self.config = config
        self.input_limit = min(config.max_tokens_per_task, max_input_tokens or sys.maxsize)
        self.repo_facts = repo_facts if config.include_repo_facts else RepoFacts()

    def build(self, candidate: Candidate) -> ReviewTask:
        notes: list[str] = []
        primary: CodeSlice | None = None
        truncated = False

        if candidate.location is not None:
            primary = line_window(
                self.root, candidate.location, window_lines=self.config.window_lines
            )
            if primary is None:
                notes.append("対象ファイルを読み込めなかったため、コード本文は提示されていません。")
        elif candidate.package is not None:
            notes.append("依存パッケージに対する指摘のため、コード本文はありません。")

        if primary is not None:
            # 文脈窓には、検出された行以外の値も入りうる。カテゴリによらず伏せる (§19.2)
            primary = primary.model_copy(update={"text": mask_sensitive_values(primary.text)})

        if primary is not None and candidate.category is Category.SECRET:
            primary = self._redact_slice(primary, candidate)
            notes.append(
                "この候補はシークレット検出です。値はマスクしてあり、原文は送信していません。"
            )

        if primary is not None:
            primary, truncated = self._fit_budget(primary, candidate)
            if primary is None:
                notes.append(
                    "トークン予算に収まらないため、コード本文は提示していません。"
                    "判断に足りなければ needs_more_context に記載してください。"
                )
            elif truncated:
                notes.append(
                    "トークン予算のため文脈を切り詰めています。"
                    "判断に足りなければ needs_more_context に記載してください。"
                )

        # スキャナの message や fix にも検査対象の文字列が入る。ReviewTask に入る文字列は
        # すべてここでマスクする (§19.2 の必須通過点)。レポート用の Candidate は変えない
        candidate = candidate.model_copy(
            update={
                "message": mask_sensitive_values(candidate.message),
                "fix_available": mask_sensitive_values(candidate.fix_available)
                if candidate.fix_available
                else None,
            }
        )
        context = CodeContext(primary=primary, truncated=truncated)
        estimated = PROMPT_OVERHEAD_TOKENS + (
            estimate_tokens(primary.text) if primary is not None else 0
        )
        return ReviewTask(
            candidate=candidate,
            code_context=context,
            repo_facts=self.repo_facts,
            budget=TokenBudget(
                max_tokens_per_task=self.input_limit,
                estimated_input_tokens=estimated,
            ),
            notes=notes,
        )

    # --- 内部 -------------------------------------------------------------

    def _redact_slice(self, slice_: CodeSlice, candidate: Candidate) -> CodeSlice:
        """コード片に残っている検出値をマスクする (§19.2-2).

        形式が判断材料になるので完全消去はせず、prefix だけ残す。
        """
        secrets = _secret_hints(candidate)
        text = redact_text(slice_.text, secrets) if secrets else slice_.text
        text = _mask_long_tokens_on_line(text, candidate)
        text = _mask_detected_lines(text, slice_.start_line, candidate)
        return slice_.model_copy(update={"text": text})

    def _fit_budget(self, slice_: CodeSlice, candidate: Candidate) -> tuple[CodeSlice | None, bool]:
        """予算超過時はウィンドウを縮める (primary は最後まで守る・§8.3).

        予算はプロンプト全体の上限なので、本文に使えるのは本文以外を除いた残りである。
        行数で収まらなければ文字数で切り、それでも収まらなければ本文を送らない。
        """
        limit = self.input_limit - PROMPT_OVERHEAD_TOKENS
        if limit <= 0:
            return None, True
        if estimate_tokens(slice_.text) <= limit:
            return slice_, False

        focus = candidate.location.start_line if candidate.location else slice_.start_line
        keep = max(MIN_WINDOW_LINES, self.config.window_lines)
        while keep >= MIN_WINDOW_LINES:
            current = shrink(slice_, keep_lines=keep, focus_line=focus)
            if estimate_tokens(current.text) <= limit:
                return current, True
            keep //= 2

        # 文字数の換算は概算なので、実際に数えて収まるまで縮める
        max_chars = limit * CHARS_PER_TOKEN
        while max_chars > 0:
            clipped = clip_lines(slice_, focus_line=focus, max_chars=max_chars)
            if clipped is None:
                return None, True
            if estimate_tokens(clipped.text) <= limit:
                return clipped, True
            max_chars //= 2
        return None, True


def _secret_hints(candidate: Candidate) -> list[str]:
    """Candidate に残っている「値らしきもの」を集める.

    Candidate 側は既にマスク済みだが、コード片には原文が残っているため、
    ここでスニペットに含まれる長いトークンを潰す手掛かりに使う。
    """
    hints: list[str] = []
    snippet = candidate.location.snippet if candidate.location else None
    if snippet:
        hints.extend(part for part in snippet.split() if len(part) >= SECRET_MIN_LENGTH)
    return hints


def _mask_long_tokens_on_line(text: str, candidate: Candidate) -> str:
    """検出行に含まれる引用符付きの長い文字列をマスクする.

    gitleaks は値を返すが我々はそれを保持しないため、行単位で保守的に伏せる。
    """
    if candidate.location is None:
        return text
    masked_lines: list[str] = []
    for line in text.splitlines():
        masked_lines.append(_mask_quoted(line))
    return "\n".join(masked_lines)


def _mask_detected_lines(text: str, first_line: int, candidate: Candidate) -> str:
    """検出された行の、値らしい長いトークンを引用符の有無によらず伏せる.

    スキャナが値を返しても我々は保持しないため、検出行の範囲だけを保守的に潰す。
    `.env` の `KEY=value` のような引用符の無い値もここで伏せる。
    """
    if candidate.location is None:
        return text
    start = max(1, candidate.location.start_line)
    end = max(start, candidate.location.end_line)
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if start <= first_line + index <= end:
            lines[index] = _DETECTED_LINE_TOKEN_RE.sub(lambda m: mask_secret(m.group(0)), line)
    return "\n".join(lines)


def mask_sensitive_values(text: str) -> str:
    """どの候補の文脈にも適用するマスキング (§19.2).

    秘密鍵の本文・既知形式のキー・JWT・名前から秘密と分かる代入の値を伏せる。
    形式は判断材料になるため、prefix は残す。
    """
    masked = _PEM_BODY_RE.sub(_mask_pem_body, text)
    masked = redact_known_patterns(masked)
    masked = _JWT_RE.sub(lambda m: mask_secret(m.group(0)), masked)
    # 引用符で囲んだ値は記号を含んでも終わりの引用符まで伏せる (`password = "p@ss!w0rd#"`)
    masked = _SENSITIVE_QUOTED_RE.sub(
        lambda m: (
            m.group("key") + m.group("quote") + mask_secret(m.group("value")) + m.group("quote")
        ),
        masked,
    )
    return _SENSITIVE_ASSIGNMENT_RE.sub(
        lambda m: m.group("key") + m.group("quote") + mask_secret(m.group("value")), masked
    )


def _mask_pem_body(match: re.Match[str]) -> str:
    body = "\n".join(
        "*" * min(len(line), 20) if line.strip() else line for line in match.group(2).split("\n")
    )
    return match.group(1) + body + match.group(3)


_PEM_BODY_RE = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)"
    r"(.*?)"
    r"(-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)",
    re.DOTALL,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
# 名前から秘密と分かる代入 (`API_KEY=...` / `password: ...` / `"token": "..."`)。
# 値は記号を含まないトークンに限り、関数呼び出しや属性参照 (`os.environ[...]`) は伏せない。
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]*"
    r"(?:secret|token|passw(?:or)?d|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|credential)"
    r"[A-Za-z0-9_.-]*[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"']?)(?P<value>[A-Za-z0-9+/=_~-]{8,})(?=[\s\"',;#}\]]|$)",
    re.IGNORECASE,
)
_SENSITIVE_QUOTED_RE = re.compile(
    _SENSITIVE_ASSIGNMENT_RE.pattern.split("(?P<quote>")[0]
    + r"(?P<quote>[\"'])(?P<value>(?:(?!(?P=quote))[^\s\\])(?:(?!(?P=quote))[^\n\\]){6,}"
    r"(?:(?!(?P=quote))[^\s\\]))(?P=quote)",
    re.IGNORECASE,
)
# 検出行で伏せるトークン。数字を含む 16 文字以上に限り、`SERVICE_CREDENTIALS` のような
# 変数名は残す (何の値かは判断材料になる)。
_DETECTED_LINE_TOKEN_RE = re.compile(r"(?=[A-Za-z0-9+/_.~:@-]*[0-9])[A-Za-z0-9+/_.~:@-]{16,}={0,2}")


def _mask_quoted(line: str) -> str:
    result = line
    for quote in ('"', "'"):
        parts = result.split(quote)
        if len(parts) < 3:
            continue
        for index in range(1, len(parts), 2):
            value = parts[index]
            if len(value) >= SECRET_MIN_LENGTH and " " not in value:
                parts[index] = mask_secret(value)
        result = quote.join(parts)
    return result
