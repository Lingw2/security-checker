"""`gemini_generate` 方言 — `POST {base_url}/models/{model}:generateContent` (設計書 §9.5).

この形は **モデル名を URL に含める**。ペイロードでモデルを指定する他の形と違うため、
`endpoint()` が model を受け取る契約になっている。

構造化出力は `responseMimeType` + `responseSchema` で指定する。ただし
`responseSchema` は **OpenAPI のサブセット**であり、JSON Schema の全機能を通さない。
未対応のキーワードを送ると 400 になるため、送る前に落とす層をここに持つ。
"""

from __future__ import annotations

from typing import Any

from security_checker.models.verdict import Usage
from security_checker.providers.base import Capabilities, CompletionRequest, StructuredMode
from security_checker.providers.errors import ProviderResponseError
from security_checker.providers.http.dialects.base import (
    DialectOptions,
    DialectResponse,
    output_limit,
)

#: responseSchema が解釈できるキーワード. これ以外は落とす
SUPPORTED_KEYWORDS = frozenset(
    {
        "type",
        "format",
        "description",
        "nullable",
        "enum",
        "items",
        "properties",
        "required",
        "maxItems",
        "minItems",
        # 数値の範囲 (confidence の 0〜1 など) は responseSchema でも縛れる (#298)
        "minimum",
        "maximum",
    }
)


class GeminiGenerateDialect:
    """`:generateContent` 形式のリクエスト・レスポンス変換."""

    name = "gemini_generate"

    def __init__(self, options: DialectOptions | None = None) -> None:
        # この形には文脈長やモデル保持の指定が無いため、受け取っても使わない
        self.options = options or DialectOptions()

    def endpoint(self, base_url: str, model: str) -> str:
        return f"{base_url.rstrip('/')}/models/{model}:generateContent"

    def headers(self, api_key: str | None) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if api_key:
            # クエリ文字列ではなくヘッダで渡す。URL はログや履歴に残りうるため
            headers["x-goog-api-key"] = api_key
        return headers

    def build_payload(
        self,
        req: CompletionRequest,
        *,
        model: str,
        capabilities: Capabilities,
        mode: StructuredMode,
    ) -> dict[str, Any]:
        generation: dict[str, Any] = {"maxOutputTokens": output_limit(req, capabilities)}
        if capabilities.supports_temperature:
            generation["temperature"] = req.temperature
        if capabilities.supports_seed and req.seed is not None:
            generation["seed"] = req.seed

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": req.user}]}],
            "generationConfig": generation,
        }
        if capabilities.supports_system_role:
            payload["systemInstruction"] = {"parts": [{"text": req.system}]}
        else:
            payload["contents"] = [
                {"role": "user", "parts": [{"text": f"{req.system}\n\n{req.user}"}]}
            ]

        if req.json_schema is not None:
            if mode is StructuredMode.JSON_SCHEMA:
                generation["responseMimeType"] = "application/json"
                generation["responseSchema"] = to_response_schema(req.json_schema)
            elif mode is StructuredMode.JSON_MODE:
                # スキーマなしで「JSON を返せ」とだけ言える
                generation["responseMimeType"] = "application/json"
        return payload

    def parse_response(self, payload: dict[str, Any]) -> DialectResponse:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ProviderResponseError(_no_candidates_reason(payload))
        first = candidates[0]
        if not isinstance(first, dict):
            raise ProviderResponseError("candidates[0] がオブジェクトではありません")

        content = first.get("content")
        parts = content.get("parts") if isinstance(content, dict) else None
        texts: list[str] = []
        if isinstance(parts, list):
            texts = [part["text"] for part in parts if isinstance(part, dict) and "text" in part]
        text = "".join(str(value) for value in texts)

        raw_usage = payload.get("usageMetadata")
        usage = Usage()
        if isinstance(raw_usage, dict):
            usage = Usage(
                input_tokens=_as_int(raw_usage.get("promptTokenCount")),
                # この形の candidatesTokenCount は思考トークンを含まないが、課金は両者の合計
                output_tokens=_as_int(raw_usage.get("candidatesTokenCount"))
                + _as_int(raw_usage.get("thoughtsTokenCount")),
                reasoning_tokens=_as_int(raw_usage.get("thoughtsTokenCount")),
                cached_tokens=_as_int(raw_usage.get("cachedContentTokenCount")),
            )

        model_reported = payload.get("modelVersion")
        return DialectResponse(
            text=text,
            usage=usage,
            finish_reason=str(first.get("finishReason") or "stop"),
            model_reported=model_reported if isinstance(model_reported, str) else None,
        )

    def health_payload(self, model: str, capabilities: Capabilities) -> dict[str, Any]:
        return {
            "contents": [{"role": "user", "parts": [{"text": "ping"}]}],
            "generationConfig": {"maxOutputTokens": 1},
        }

    def is_auth_error(self, status: int, body: str) -> bool:
        # この形は鍵の不備を 401 ではなく 400 で返す
        return status == 400 and "api key" in body.lower()

    def explain_error(self, status: int, body: str) -> str | None:
        lowered = body.lower()
        if status == 400 and "api key" in lowered:
            # この形は鍵の不備を 401 ではなく 400 で返すため、認証エラーに見えない
            return "API キーが受け付けられませんでした。api_key_env の環境変数を確認してください"
        if status == 404 and "model" in lowered:
            return (
                "model に指定した ID がこのエンドポイントに存在しません。"
                "設定の model を確認してください"
            )
        if status == 400 and "response_schema" in lowered.replace(
            "responseschema", "response_schema"
        ):
            return (
                "スキーマが受け付けられませんでした。"
                "capabilities.structured_output: json_mode を指定すると回避できます"
            )
        return None


def to_response_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """JSON Schema を responseSchema (OpenAPI サブセット) に変換する.

    落とすのは「表現できないもの」だけで、構造は保つ。落ちるのは主に
    `maxLength` / `pattern` / `minimum` のような**値の制約**で、これらは
    プロンプト側のスキーマ提示に残るため、完全に失われるわけではない。
    """
    return _convert(schema, defs=_collect_defs(schema))


def _collect_defs(schema: dict[str, Any]) -> dict[str, Any]:
    defs = schema.get("$defs") or schema.get("definitions")
    return defs if isinstance(defs, dict) else {}


def _convert(node: Any, *, defs: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}

    if "$ref" in node:
        resolved = _resolve_ref(str(node["$ref"]), defs)
        return _convert(resolved, defs=defs)

    if "anyOf" in node:
        return _convert_any_of(node, defs=defs)

    converted: dict[str, Any] = {}
    for key, value in node.items():
        if key not in SUPPORTED_KEYWORDS:
            continue  # responseSchema が解釈できないものは送らない (400 になる)
        if key == "type":
            converted.update(_convert_type(value))
        elif key == "properties" and isinstance(value, dict):
            converted["properties"] = {
                name: _convert(child, defs=defs) for name, child in value.items()
            }
        elif key == "items":
            converted["items"] = _convert(value, defs=defs)
        else:
            converted[key] = value

    properties = converted.get("properties")
    if isinstance(properties, dict) and isinstance(converted.get("required"), list):
        # 実体のないキーを required に残すと弾かれる
        converted["required"] = [name for name in converted["required"] if name in properties]
    return converted


def _convert_any_of(node: dict[str, Any], *, defs: dict[str, Any]) -> dict[str, Any]:
    """`anyOf` は表現できない. null との union は nullable に畳む."""
    branches = [branch for branch in node.get("anyOf", []) if isinstance(branch, dict)]
    nullable = any(branch.get("type") == "null" for branch in branches)
    concrete = [branch for branch in branches if branch.get("type") != "null"]
    if not concrete:
        return {"type": "STRING", "nullable": True}
    # 複数の型の union は表現できないため、先頭を採る (欠落は値の制約と同じ扱い)
    converted = _convert(concrete[0], defs=defs)
    if nullable:
        converted["nullable"] = True
    for key in ("description",):
        if key in node and key not in converted:
            converted[key] = node[key]
    return converted


def _convert_type(value: Any) -> dict[str, Any]:
    """`["string", "null"]` のような型の配列を nullable に畳み、大文字に揃える."""
    if isinstance(value, list):
        names = [str(name) for name in value]
        nullable = "null" in names
        concrete = [name for name in names if name != "null"]
        if not concrete:
            return {"type": "STRING", "nullable": True}
        return {"type": concrete[0].upper(), "nullable": nullable}
    return {"type": str(value).upper()}


def _resolve_ref(ref: str, defs: dict[str, Any]) -> dict[str, Any]:
    name = ref.rsplit("/", 1)[-1]
    target = defs.get(name)
    if not isinstance(target, dict):
        raise ProviderResponseError(f"スキーマの参照 '{ref}' を解決できません")
    return target


def _no_candidates_reason(payload: dict[str, Any]) -> str:
    """応答が空の理由を伝える. 「何も返らなかった」で終わらせない (§20.2)."""
    feedback = payload.get("promptFeedback")
    if isinstance(feedback, dict) and feedback.get("blockReason"):
        return (
            f"入力が拒否されました (blockReason: {feedback['blockReason']})。"
            "レビュー対象のコードが安全フィルタに掛かった可能性があります"
        )
    return "応答に candidates がありません"


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) else 0
