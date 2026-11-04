"""抑制の適用 — baseline / ignore ファイル / コード内注釈 (設計書 §17.2).

抑制した候補は**消さない**。レポートの `suppressed` に理由付きで残し、レビュー (LLM の費用) と
ゲートの対象から外す。

信用できない検査対象 (fork PR, §21.2) では、検査対象のツリーにある ignore ファイルと
コード内注釈を読まない。PR 側が自分の指摘を自分で抑制できてしまうため。
ignore ファイルは設定ファイルの隣 (信頼できる側) から読む。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from security_checker.config.schema import Config
from security_checker.models.candidate import Candidate
from security_checker.models.finding import SuppressionReason
from security_checker.models.report import SuppressedCandidate
from security_checker.policy.baseline import Baseline, load_baseline
from security_checker.policy.ignore import AnnotationReader, IgnoreFile, load_ignore_file


@dataclass
class SuppressionRules:
    baseline: Baseline = field(default_factory=Baseline)
    ignore: IgnoreFile | None = None
    annotations: AnnotationReader | None = None
    warnings: list[str] = field(default_factory=list)
    #: 検査対象を信用しない (§21.2)。スキャナ自身の設定の読み込みも止める (#43)
    untrusted_target: bool = False


def load_rules(
    config: Config,
    root: Path,
    *,
    config_dir: Path | None = None,
    untrusted_target: bool = False,
) -> SuppressionRules:
    """設定から抑制規則を組み立てる. baseline の相対パスは設定ファイルの場所が基準."""
    rules = SuppressionRules(untrusted_target=untrusted_target)
    base_dir = config_dir or root
    if config.policy.baseline is not None:
        path = Path(config.policy.baseline).expanduser()
        rules.baseline = load_baseline(path if path.is_absolute() else base_dir / path)

    ignore_dir = base_dir if untrusted_target else root
    rules.ignore, ignore_warnings = load_ignore_file(ignore_dir)
    rules.warnings = [*rules.baseline.warnings, *ignore_warnings]
    if untrusted_target:
        rules.warnings.append(
            "検査対象を信用しない設定のため、コード内の ignore 注釈と検査対象の "
            ".security-checker-ignore は読みません"
        )
    else:
        rules.annotations = AnnotationReader(root)
    return rules


def apply_suppressions(
    candidates: list[Candidate], rules: SuppressionRules
) -> tuple[list[Candidate], list[SuppressedCandidate], list[str]]:
    """(残す候補, 抑制した候補, 警告) を返す. 優先順は 注釈 → ignore ファイル → baseline."""
    kept: list[Candidate] = []
    suppressed: list[SuppressedCandidate] = []
    warnings: list[str] = []
    for candidate in candidates:
        annotation = rules.annotations.find(candidate) if rules.annotations else None
        if annotation is not None:
            if annotation.reason is None:
                warnings.append(
                    f"{candidate.where}: 理由の無い ignore 注釈で {candidate.rule_id} を"
                    "抑制しました。reason= を書いてください"
                )
            suppressed.append(
                SuppressedCandidate(
                    candidate=candidate,
                    reason=SuppressionReason.INLINE_ANNOTATION,
                    note=annotation.reason,
                )
            )
            continue
        matched = rules.ignore.match(candidate) if rules.ignore else None
        if matched is not None:
            suppressed.append(
                SuppressedCandidate(
                    candidate=candidate, reason=SuppressionReason.IGNORE_FILE, note=matched
                )
            )
            continue
        if rules.baseline.covers(candidate):
            suppressed.append(
                SuppressedCandidate(candidate=candidate, reason=SuppressionReason.BASELINE)
            )
            continue
        if candidate.id in rules.baseline.ids:
            # 値を書かずに伝える。同じ場所で鍵を差し替えたときの新しい秘密を見逃さない
            warnings.append(
                f"{candidate.where}: baseline に記録した秘密と値が違うため、"
                "新しい候補として扱います"
            )
        kept.append(candidate)
    if rules.annotations is not None:
        warnings.extend(rules.annotations.warnings)
    return kept, suppressed, warnings
