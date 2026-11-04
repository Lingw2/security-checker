"""信用できない検査対象でスキャナ自身の設定を読ませない (設計書 §21.2, #43).

各スキャナは、検査対象のツリーにある自分の設定ファイルを自動で読む
(`.gitleaks.toml`・`trivy.yaml`・`.trivyignore`・`osv-scanner.toml` など)。
fork PR を権限付きで検査するとき、PR がこれらを置けば**自分の検出を候補の段階で消せる**。
`.security-checker-ignore` やコード内注釈を読まないのと同じ理由で、
ここでも対象のツリーを信用しない。

方針:
  - 明示的な設定を渡して自動読み込みを止められるものは止める (検査対象の外の一時ファイルを渡す)。
  - スキャナ側で止められないもの (`.gitleaksignore`・`.semgrepignore`) は、黙って効かせず
    警告に積む (P9: 受け付けたが効かない / 効いてしまう状態を隠さない)。
  - 利用者が信頼できる設定の `extra_args` で自分の設定を渡した場合は、
    そちらが後に来るので優先される。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: 既定のルールだけを使う gitleaks の設定 (検査対象の `.gitleaks.toml` の代わり)
GITLEAKS_DEFAULT_CONFIG = "[extend]\nuseDefault = true\n"

#: 走査しないディレクトリ (巨大になりうる / 検査対象ではない)
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__"})
#: 警告に列挙する件数の上限
_LIST_LIMIT = 5


@dataclass(frozen=True)
class UntrustedOverrides:
    """検査対象の外に置いた、各スキャナに明示的に渡す設定."""

    gitleaks_config: Path
    gitleaks_ignore_dir: Path
    trivy_config: Path
    osv_config: Path

    def gitleaks_args(self) -> list[str]:
        return [
            "--config",
            str(self.gitleaks_config),
            "--gitleaks-ignore-path",
            str(self.gitleaks_ignore_dir),
            "--ignore-gitleaks-allow",
        ]

    def semgrep_args(self) -> list[str]:
        return ["--disable-nosem"]

    def trivy_args(self) -> list[str]:
        # 空文字列は「読み込まない」(trivy の公式の指定方法)
        return ["--config", str(self.trivy_config), "--ignorefile", ""]

    def osv_args(self) -> list[str]:
        return ["--config", str(self.osv_config)]


def prepare_overrides(directory: Path) -> UntrustedOverrides:
    """`directory` (検査対象の外) に上書き用の設定を作る."""
    directory.mkdir(parents=True, exist_ok=True)
    gitleaks_config = directory / "gitleaks.toml"
    gitleaks_config.write_text(GITLEAKS_DEFAULT_CONFIG, encoding="utf-8")
    gitleaks_ignore_dir = directory / "gitleaks-ignore"
    gitleaks_ignore_dir.mkdir(exist_ok=True)
    trivy_config = directory / "trivy.yaml"
    trivy_config.write_text("", encoding="utf-8")
    osv_config = directory / "osv-scanner.toml"
    osv_config.write_text("", encoding="utf-8")
    return UntrustedOverrides(
        gitleaks_config=gitleaks_config,
        gitleaks_ignore_dir=gitleaks_ignore_dir,
        trivy_config=trivy_config,
        osv_config=osv_config,
    )


def residual_warnings(root: Path) -> list[str]:
    """スキャナ側で読み込みを止められない、検査対象の除外ファイルを警告にする."""
    warnings: list[str] = []
    if (root / ".gitleaksignore").is_file():
        warnings.append(
            "検査対象を信用しない設定ですが、検査対象の .gitleaksignore は"
            " gitleaks が必ず読みます。ここに書かれた検出は報告されません"
        )
    semgrepignores = _find(root, ".semgrepignore")
    if semgrepignores:
        listed = ", ".join(semgrepignores[:_LIST_LIMIT])
        more = (
            f" ほか {len(semgrepignores) - _LIST_LIMIT} 件"
            if len(semgrepignores) > _LIST_LIMIT
            else ""
        )
        warnings.append(
            "検査対象を信用しない設定ですが、検査対象の .semgrepignore は"
            " semgrep が必ず読みます。"
            f"除外されたファイルは検査されません: {listed}{more}"
        )
    annotated = _find_trivy_annotations(root)
    if annotated:
        listed = ", ".join(annotated[:_LIST_LIMIT])
        more = f" ほか {len(annotated) - _LIST_LIMIT} 件" if len(annotated) > _LIST_LIMIT else ""
        # trivy にはコード内注釈を無効にするフラグが無い (0.75.0 時点)
        warnings.append(
            "検査対象を信用しない設定ですが、trivy はファイル内の trivy:ignore 注釈を必ず読みます。"
            f"注釈で抑制された誤設定は報告されません: {listed}{more}"
        )
    return warnings


#: trivy が誤設定を検査するファイル. 注釈はこの中にしか効かない
_TRIVY_CONFIG_SUFFIXES = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".dockerfile")
_TRIVY_ANNOTATION = b"trivy:ignore"
_MAX_ANNOTATION_SCAN_BYTES = 1_000_000


def _find_trivy_annotations(root: Path) -> list[str]:
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(files):
            lowered = name.lower()
            if not (lowered.endswith(_TRIVY_CONFIG_SUFFIXES) or lowered.startswith("dockerfile")):
                continue
            path = Path(current) / name
            try:
                if path.stat().st_size > _MAX_ANNOTATION_SCAN_BYTES:
                    continue
                if _TRIVY_ANNOTATION in path.read_bytes():
                    found.append(path.relative_to(root).as_posix())
            except OSError:
                continue
    return found


def _find(root: Path, name: str) -> list[str]:
    found: list[str] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        if name in files:
            found.append((Path(current) / name).relative_to(root).as_posix())
    return found
