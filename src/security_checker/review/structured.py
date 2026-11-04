"""Structured Output — スキーマ生成・抽出・修復 (設計書 §10).

出力の形を LLM に委ねない。壊れた応答は握り潰さず、1 回だけ修復を試み、
それでも駄目なら `schema_error` として **レポートに残す**(黙って消さない・P9)。
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from pydantic import ValidationError

from security_checker.models.task import ReviewTask
from security_checker.models.verdict import ReviewJudgement

FENCE_MARKERS = ("```json", "```JSON", "```")


@lru_cache(maxsize=1)
def verdict_schema() -> dict[str, Any]:
    """ReviewVerdict の LLM 生成部分を JSON Schema にする.

    `$ref` を展開し `additionalProperties: false` を全体に付ける
    (json_schema モードの strict 指定を通すため)。
    """
    raw = ReviewJudgement.model_json_schema()
    defs = raw.pop("$defs", {})
    hardened = _harden(_inline_refs(raw, defs))
    return hardened if isinstance(hardened, dict) else {}


def _inline_refs(node: Any, defs: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            target = defs.get(ref.split("/")[-1], {})
            merged = {**_inline_refs(target, defs)}
            merged.update({k: v for k, v in node.items() if k != "$ref"})
            return merged
        return {key: _inline_refs(value, defs) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline_refs(item, defs) for item in node]
    return node


def _harden(node: Any) -> Any:
    if isinstance(node, dict):
        hardened = {
            # properties の中身はプロパティ名 → スキーマ. 名前そのもの (title など) は消さない
            key: {name: _harden(sub) for name, sub in value.items()}
            if key == "properties" and isinstance(value, dict)
            else _harden(value)
            for key, value in node.items()
        }
        if hardened.get("type") == "object" and "properties" in hardened:
            hardened["additionalProperties"] = False
            # strict な json_schema モードでは「全プロパティが required」であることを
            # 求める実装があるため、省略可能な項目も null 許容にしたうえで必須にする。
            hardened["required"] = sorted(hardened["properties"])
        hardened.pop("title", None)
        # pydantic は docstring を description にする. 内部向けの日本語のメモを
        # プロンプトの一部として LLM に送らない (送る説明はテンプレートで版管理する) (#290)
        hardened.pop("description", None)
        return hardened
    if isinstance(node, list):
        return [_harden(item) for item in node]
    return node


def extract_json(text: str) -> dict[str, Any] | None:
    """応答から最初の JSON オブジェクトを取り出す.

    ```json フェンス・前後の散文・末尾の余計な文章を許容する (§10.2)。
    """
    if not text:
        return None
    candidate = _strip_fence(text.strip())
    direct = _try_load(candidate)
    if direct is not None:
        return direct
    return _first_object(candidate)


def _strip_fence(text: str) -> str:
    for marker in FENCE_MARKERS:
        if text.startswith(marker):
            without_open = text[len(marker) :]
            closing = without_open.rfind("```")
            return (without_open[:closing] if closing != -1 else without_open).strip()
    return text


def _try_load(text: str) -> dict[str, Any] | None:
    try:
        loaded = json.loads(text)
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _first_object(text: str) -> dict[str, Any] | None:
    """最初の「釣り合った」波括弧ブロックを探す. 文字列内の括弧は数えない."""
    depth = 0
    start = -1
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start != -1:
                found = _try_load(text[start : index + 1])
                if found is not None:
                    return found
                start = -1
    return None


class SchemaViolationError(Exception):
    """検証に失敗した. message は修復プロンプトにそのまま載せる."""

    def __init__(self, message: str, *, raw_text: str) -> None:
        super().__init__(message)
        self.raw_text = raw_text


def parse_judgement(payload: dict[str, Any] | None, raw_text: str) -> ReviewJudgement:
    """応答を ReviewJudgement に変換する. 失敗は SchemaViolationError として上げる."""
    data = payload if payload is not None else extract_json(raw_text)
    if data is None:
        raise SchemaViolationError(
            "応答から JSON オブジェクトを取り出せませんでした", raw_text=raw_text
        )
    try:
        return ReviewJudgement.model_validate(data)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '(root)'}: {error['msg']}"
            for error in exc.errors()[:5]
        )
        raise SchemaViolationError(details, raw_text=raw_text) from exc


def drop_hallucinated_evidence(
    judgement: ReviewJudgement, task: ReviewTask
) -> tuple[ReviewJudgement, list[str]]:
    """提示した範囲外を指す evidence を落とす (§11.3).

    ハルシネーションした位置をレポートに載せない。落としたことは warning に残す。
    コードを 1 行も提示していない候補 (依存パッケージなど) の evidence はすべて範囲外である。
    """
    if not judgement.evidence:
        return judgement, []
    context = task.code_context
    shown = [*([context.primary] if context.primary is not None else []), *context.callers]

    kept = []
    warnings = []
    for item in judgement.evidence:
        path = item.path.replace("\\", "/").removeprefix("./")
        inside = item.start_line <= item.end_line and any(
            path == slice_.path
            and slice_.start_line <= item.start_line
            and item.end_line <= slice_.end_line
            for slice_ in shown
        )
        if inside:
            kept.append(item)
        else:
            warnings.append(
                f"提示範囲外の evidence を除外しました: "
                f"{item.path}:{item.start_line}-{item.end_line}"
            )
    if len(kept) == len(judgement.evidence):
        return judgement, []
    return judgement.model_copy(update={"evidence": kept}), warnings
