"""設定スキーマ (設計書 §12).

全項目に既定値があり、設定ファイルなしでも動く。
`api_key:` という平文キーのフィールドは **意図的に存在しない** (§19.1)。
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from security_checker.models.enums import FindingStatus, Severity
from security_checker.rules import BUNDLED_PREFIX, bundled_semgrep_rule, bundled_semgrep_rules


class StrictModel(BaseModel):
    """未知キーを拒否する基底. 設定ミスを黙って無視しない."""

    model_config = ConfigDict(extra="forbid")


DEFAULT_EXCLUDES = (
    "**/vendor/**",
    "**/node_modules/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/.git/**",
    "**/.security-checker/**",
    "**/*.min.js",
)


#: `target.exclude` を書き換えても必ず外すもの. 自分の出力と git の内部を検査対象にしない
ALWAYS_EXCLUDES = (
    "**/.git/**",
    "**/.security-checker/**",
)


class TargetConfig(StrictModel):
    root: str = "."
    mode: Literal["auto", "full", "diff"] = "auto"
    #: 設定すると既定の一覧を**置き換える** (ALWAYS_EXCLUDES だけは常に足す)
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))

    @field_validator("exclude")
    @classmethod
    def _keep_always_excludes(cls, value: list[str]) -> list[str]:
        """前回のレポートや .git/ の中身を検査して、自分の出力を指摘しない."""
        return [*value, *(pattern for pattern in ALWAYS_EXCLUDES if pattern not in value)]


class ScannerConfig(StrictModel):
    enabled: bool = True
    timeout_s: int = Field(default=600, gt=0)
    extra_args: list[str] = Field(default_factory=list)


class SemgrepConfig(ScannerConfig):
    #: `--config` に渡すもの. 1 つなら文字列、複数ならリスト。`bundled:<名前>` で同梱ルールを指す
    config: str | list[str] = Field(
        default_factory=lambda: ["p/default", "bundled:llm", "bundled:ci-lock"]
    )

    @field_validator("config")
    @classmethod
    def _known_bundled_rules(cls, value: str | list[str]) -> str | list[str]:
        values = [value] if isinstance(value, str) else value
        if not values:
            raise ValueError("scanners.semgrep.config が空です")
        for item in values:
            if item.startswith(BUNDLED_PREFIX) and (
                bundled_semgrep_rule(item.removeprefix(BUNDLED_PREFIX)) is None
            ):
                known = ", ".join(BUNDLED_PREFIX + name for name in bundled_semgrep_rules())
                raise ValueError(f"未知の同梱ルール {item} です。利用可能: {known or '(なし)'}")
        return value

    @property
    def configs(self) -> list[str]:
        return [self.config] if isinstance(self.config, str) else list(self.config)


class GitleaksConfig(ScannerConfig):
    timeout_s: int = Field(default=300, gt=0)


class OsvConfig(ScannerConfig):
    timeout_s: int = Field(default=300, gt=0)


class TrivyConfig(ScannerConfig):
    scanners: list[str] = Field(default_factory=lambda: ["config"])


class ScannersConfig(StrictModel):
    semgrep: SemgrepConfig = SemgrepConfig()
    gitleaks: GitleaksConfig = GitleaksConfig()
    # 依存の既知脆弱性は件数が多く機械的に見つかる。未導入なら skipped になるだけなので既定で有効
    osv: OsvConfig = OsvConfig()
    # 誤設定の検査はノイズが多く、既定にする根拠が弱い。opt-in
    trivy: TrivyConfig = TrivyConfig(enabled=False)


class ContextConfig(StrictModel):
    window_lines: int = Field(default=40, gt=0)
    max_callers: int = Field(default=3, ge=0)
    max_tokens_per_task: int = Field(default=8000, gt=0)
    include_repo_facts: bool = True


class RateLimit(StrictModel):
    #: requests / minute
    rpm: int | None = Field(default=None, gt=0)
    #: tokens / minute (入力の見積り + 出力の上限で数える)
    tpm: int | None = Field(default=None, gt=0)
    #: requests / day. プロセスをまたいで ~/.cache/security-checker/quota.json に数える
    rpd: int | None = Field(default=None, gt=0)


class ReviewerCapabilities(StrictModel):
    """capability の明示指定 (最優先・設計書 §9.3).

    エンドポイントを叩いても分からないため、利用者が上書きできる経路を必ず残す。
    """

    structured_output: Literal["json_schema", "json_mode", "prompt_only"] | None = None
    max_context_tokens: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    supports_system_role: bool | None = None
    supports_temperature: bool | None = None
    supports_seed: bool | None = None
    reasoning: bool | None = None
    output_limit_param: Literal["max_tokens", "max_completion_tokens"] | None = None


#: transport: process の timeout_s の既定 (§9.7)
PROCESS_TIMEOUT_S = 300

#: masked_dump で伏せた値の表現
MASKED = "****"


class ReviewerConfig(StrictModel):
    """Reviewer 定義 (P2 以降で使用).

    `transport` は必須。省略時に何かを推測して補完しない (§12)。
    """

    name: str
    transport: Literal["http", "process"]
    #: false なら読み込み時に外す. 手元で共有の Reviewer を止めるために使う
    enabled: bool = True
    weight: float = Field(default=1.0, ge=0.0)
    #: 既定は transport で変わる (http 120 / process 300)。_default_timeout を参照
    timeout_s: int = Field(default=120, gt=0)
    concurrency: int = Field(default=1, gt=0)
    rate_limit: RateLimit = RateLimit()

    # http transport ("text_io" だけは process transport の方言)
    dialect: (
        Literal[
            "openai_chat",
            "anthropic_messages",
            "gemini_generate",
            "ollama_chat",
            "text_io",
        ]
        | None
    ) = None
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    max_output_tokens: int = Field(default=2000, gt=0)
    num_ctx: int | None = Field(default=None, gt=0)
    #: モデルの保持時間 (例: "5m"). 連続レビューでの再ロードを避ける. ollama_chat のみ
    keep_alive: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    #: ヘッダ名 → 値を読む環境変数名. 秘密を含むヘッダは headers ではなくこちらに書く (§19.1)
    headers_env: dict[str, str] = Field(default_factory=dict)
    capabilities: ReviewerCapabilities = ReviewerCapabilities()
    seed: int | None = None

    # process transport
    preset: str | None = None
    command: list[str] | None = None
    #: プロンプトの渡し方. どちらでも argv には本文を埋め込まない (設計書 §9.7)
    prompt_via: Literal["stdin", "file"] = "stdin"
    #: stdout の解釈方法. 現状は「最初の JSON オブジェクトを抽出する」のみ
    parse: Literal["json_in_stdout"] = "json_in_stdout"

    @model_validator(mode="before")
    @classmethod
    def _default_timeout(cls, data: Any) -> Any:
        """process の応答は数十秒〜数分かかるので、既定のタイムアウトを長くする (§9.7)."""
        if isinstance(data, dict) and data.get("transport") == "process":
            return {"timeout_s": PROCESS_TIMEOUT_S, **data}
        return data

    @model_validator(mode="after")
    def _validate_transport(self) -> ReviewerConfig:
        if self.transport == "http":
            if self.dialect == "text_io":
                raise ValueError(
                    f"reviewer '{self.name}': dialect: text_io は transport: process 専用です"
                )
            # preset を指定した場合、dialect / base_url はプリセットデータ側が供給しうる
            required = ("model",) if self.preset else ("dialect", "base_url", "model")
            missing = [field for field in required if getattr(self, field) is None]
            if missing:
                raise ValueError(
                    f"reviewer '{self.name}': transport: http には {', '.join(missing)} が必要です"
                    + ("" if self.preset else " (または preset)")
                )
        else:
            if self.preset is None and not self.command:
                raise ValueError(
                    f"reviewer '{self.name}': transport: process には preset か command が必要です"
                )
            if self.dialect not in (None, "text_io"):
                raise ValueError(
                    f"reviewer '{self.name}': transport: process の dialect は text_io のみです"
                )
        return self


class ConsensusConfig(StrictModel):
    min_votes: int = Field(default=2, ge=1)
    min_ratio: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: Literal["median", "max", "weighted_mean"] = "median"


class WeightedConfig(StrictModel):
    threshold: float = Field(default=0.6, ge=0.0, le=1.0)


class JudgeConfig(StrictModel):
    #: Judge 役の Reviewer (reviewers の name). 一次レビューには参加しない
    reviewer: str | None = None
    #: Judge が失敗したとき / Judge に回さない候補の集約戦略
    fallback: Literal["consensus", "weighted"] = "consensus"
    #: 判断が割れた候補 (fallback で review_required) だけを Judge に回す (§16-6)
    only_on_disagreement: bool = True


class AggregationConfig(StrictModel):
    strategy: str = "consensus"
    consensus: ConsensusConfig = ConsensusConfig()
    weighted: WeightedConfig = WeightedConfig()
    judge: JudgeConfig = JudgeConfig()


class PolicyConfig(StrictModel):
    fail_on: Severity = Severity.HIGH
    fail_on_status: list[FindingStatus] = Field(
        default_factory=lambda: [FindingStatus.CONFIRMED, FindingStatus.LIKELY]
    )
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    strict: bool = True
    baseline: str | None = None
    min_score: int | None = Field(default=None, ge=0, le=100)


class BudgetConfig(StrictModel):
    max_candidates: int = Field(default=200, gt=0)
    max_usd: float | None = Field(default=1.0, ge=0.0)
    max_total_tokens: int | None = Field(default=2_000_000, gt=0)
    on_exceed: Literal["stop_and_report", "warn_and_continue"] = "stop_and_report"
    #: run 全体のレビュー時間の上限 (秒). Judge の段も含む (§23)
    deadline_s: float = Field(default=1800.0, gt=0)


class ConcurrencyConfig(StrictModel):
    scanners: int = Field(default=4, gt=0)
    reviews_per_provider: int = Field(default=4, gt=0)


OutputFormat = Literal["terminal", "json", "markdown", "sarif"]


def _default_formats() -> list[OutputFormat]:
    # markdown も既定に含める。report.json は機械可読用で人間が読む物ではないため、
    # 既定のままだと「人間が読める保存済みレポート」が 1 つも残らない (§18.1)。
    return ["terminal", "json", "markdown"]


class OutputConfig(StrictModel):
    dir: str = ".security-checker/"
    formats: list[OutputFormat] = Field(default_factory=_default_formats)
    save_prompts: bool = False
    #: レポート本文 (LLM が書く自然言語) の言語. "auto" はロケールから推定する。
    #: 出力形式ごとに訳し直す場所はないため、ここが全形式に効く (設計書 §18)。
    language: str = "auto"


class GithubConfig(StrictModel):
    comment: bool = True
    comment_mode: Literal["sticky", "new"] = "sticky"
    inline_comments: bool = True
    inline_min_status: FindingStatus = FindingStatus.LIKELY
    max_inline_comments: int = Field(default=20, ge=0)
    #: 指摘ゼロのとき、既存コメントが無ければ何も投稿しない (§21.3 ノイズ抑制 2)
    comment_on_clean: bool = False
    #: 自分の投稿とみなすコメントの投稿者 (login). マーカーは誰でも書けるため投稿者も確かめる。
    #: GITHUB_TOKEN なら既定のまま。PAT や GitHub App のトークンではその login にする
    comment_author: str = "github-actions[bot]"


class LoggingConfig(StrictModel):
    level: Literal["debug", "info", "warn", "error"] = "info"
    format: Literal["text", "json"] = "text"


class Config(StrictModel):
    """解決済みの全設定."""

    version: Annotated[int, Field(ge=1)] = 1
    target: TargetConfig = TargetConfig()
    scanners: ScannersConfig = ScannersConfig()
    context: ContextConfig = ContextConfig()
    reviewers: list[ReviewerConfig] = Field(default_factory=list)
    aggregation: AggregationConfig = AggregationConfig()
    policy: PolicyConfig = PolicyConfig()
    budget: BudgetConfig = BudgetConfig()
    concurrency: ConcurrencyConfig = ConcurrencyConfig()
    output: OutputConfig = OutputConfig()
    github: GithubConfig = GithubConfig()
    logging: LoggingConfig = LoggingConfig()

    @model_validator(mode="after")
    def _validate_reviewers(self) -> Config:
        names = [reviewer.name for reviewer in self.reviewers]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ValueError(f"reviewer 名が重複しています: {', '.join(duplicates)}")
        if self.aggregation.strategy == "judge":
            judge_name = self.aggregation.judge.reviewer
            if judge_name is None:
                raise ValueError("aggregation.strategy: judge には judge.reviewer が必要です")
            if judge_name not in names:
                raise ValueError(
                    f"aggregation.judge.reviewer '{judge_name}' が reviewers に存在しません"
                )
        return self

    def scanner_settings(self) -> dict[str, ScannerConfig]:
        return {
            "semgrep": self.scanners.semgrep,
            "gitleaks": self.scanners.gitleaks,
            "osv": self.scanners.osv,
            "trivy": self.scanners.trivy,
        }

    def masked_dump(self) -> dict[str, Any]:
        """`config show` とトレース用. 秘匿値は保持しないが、名前解決の結果だけを見せる.

        headers だけは任意の文字列を値に取れ、利用者がトークンを書きうるため値を伏せる。
        出力は Issue に貼られたり CI の artifact に上がったりする。
        どのヘッダを送るかは見せ、値は先頭も残さない (形式の判定に使う場面が無いため)。
        """
        dumped = self.model_dump(mode="json")
        for reviewer in dumped["reviewers"]:
            reviewer["headers"] = dict.fromkeys(reviewer["headers"], MASKED)
        return dumped
