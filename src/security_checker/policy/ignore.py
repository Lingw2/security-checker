"""`.security-checker-ignore` とコード内注釈による抑制 (設計書 §17.2).

`.security-checker-ignore` (gitignore 記法 + ルール単位):

    # パスの除外 (target.exclude と同じ glob)
    tests/fixtures/**
    # ルールの除外. scanner/rule_id でも rule_id だけでもよい
    rule:semgrep/python.lang.security.audit.eval
    # ルールをパスで限定する
    rule:generic-api-key docs/**

コード内注釈. 行末に書くとその行だけに効き、注釈だけの行に書くと次の行に効く:

    subprocess.run(cmd, shell=True)  # security-checker: ignore[rule_id] reason=固定文字列のみ

    # security-checker: ignore[rule_id] reason=固定文字列のみ
    subprocess.run(cmd, shell=True)

**理由の記述を必須とする。** 理由の無い注釈も抑制はするが、警告を出す。
抑制は「誰かが判断した」記録であり、判断の根拠が残らない抑制は負債になる。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from security_checker.models.candidate import Candidate
from security_checker.scanners.filters import is_excluded

IGNORE_FILENAME = ".security-checker-ignore"

_ANNOTATION_RE = re.compile(
    r"security-checker:\s*ignore\[(?P<rules>[^\]]*)\](?:\s+reason=(?P<reason>.*))?",
    re.IGNORECASE,
)
#: .security-checker-ignore の行内コメントの始まり (空白類の後の、エスケープされていない #)
_INLINE_COMMENT_RE = re.compile(r"\s+(?<!\\)#")
#: 注釈の後ろに付きがちなコメント終端を理由から落とす
_COMMENT_TAIL_RE = re.compile(r"\s*(?:\*/|-->|#}|%>)\s*$")
#: 注釈の前に付くコメント記号. これ以外が残れば、その行にはコードがある
_COMMENT_LEAD_RE = re.compile(r"[\s#/*<!\-;%{]*")


@dataclass(frozen=True)
class RuleIgnore:
    rule: str
    paths: tuple[str, ...] = ()

    def matches(self, candidate: Candidate) -> bool:
        if not rule_matches(self.rule, candidate):
            return False
        if not self.paths:
            return True
        path = _candidate_path(candidate)
        return path is not None and is_excluded(path, list(self.paths))


@dataclass
class IgnoreFile:
    path_patterns: list[str] = field(default_factory=list)
    rules: list[RuleIgnore] = field(default_factory=list)

    def match(self, candidate: Candidate) -> str | None:
        """一致した行 (理由として残す) を返す."""
        path = _candidate_path(candidate)
        if path is not None:
            for pattern in self.path_patterns:
                if is_excluded(path, [pattern]):
                    return pattern
        for rule in self.rules:
            if rule.matches(candidate):
                return "rule:" + rule.rule + ("" if not rule.paths else " " + " ".join(rule.paths))
        return None


def _candidate_path(candidate: Candidate) -> str | None:
    """照合に使うパス. 依存の候補は location を持たないので manifest を使う."""
    if candidate.location is not None:
        return candidate.location.path
    return candidate.package.manifest if candidate.package else None


def rule_matches(rule: str, candidate: Candidate) -> bool:
    return rule in ("*", candidate.rule_id, f"{candidate.scanner}/{candidate.rule_id}")


def parse_ignore_file(text: str, source: str = IGNORE_FILENAME) -> tuple[IgnoreFile, list[str]]:
    """内容を解釈する. 解釈できない行は黙って捨てず、警告にする."""
    ignore = IgnoreFile()
    warnings: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        # 行内コメントは空白類 (スペース・タブ) の後の # から. `\#` はリテラルの #
        line = (
            _INLINE_COMMENT_RE.split(raw, maxsplit=1)[0].replace("\\#", "#").strip()
            if not raw.lstrip().startswith("#")
            else ""
        )
        if not line:
            continue
        if line.startswith("!"):
            warnings.append(f"{source}:{number}: 否定パターン (!) には対応していません: {line}")
            continue
        if line.startswith("rule:"):
            parts = line[len("rule:") :].split()
            if not parts:
                warnings.append(f"{source}:{number}: rule: の後にルール ID がありません")
                continue
            ignore.rules.append(RuleIgnore(rule=parts[0], paths=tuple(parts[1:])))
            continue
        # 書かれたとおりに持つ (理由として表示する)。解釈は target.exclude と共通 (is_excluded)
        ignore.path_patterns.append(line)
    return ignore, warnings


def load_ignore_file(directory: Path) -> tuple[IgnoreFile | None, list[str]]:
    path = directory / IGNORE_FILENAME
    if not path.is_file():
        return None, []
    return parse_ignore_file(path.read_text(encoding="utf-8", errors="replace"), str(path))


@dataclass(frozen=True)
class Annotation:
    rules: tuple[str, ...]
    reason: str | None


def is_annotation_only(line: str) -> bool:
    """注釈の前にコードが無い行か. 行末の注釈はその行だけのものとして扱う."""
    match = _ANNOTATION_RE.search(line)
    return match is not None and _COMMENT_LEAD_RE.fullmatch(line[: match.start()]) is not None


def parse_annotation(line: str) -> Annotation | None:
    match = _ANNOTATION_RE.search(line)
    if match is None:
        return None
    rules = tuple(rule.strip() for rule in match.group("rules").split(",") if rule.strip())
    reason = match.group("reason")
    if reason is not None:
        reason = _COMMENT_TAIL_RE.sub("", reason).strip() or None
    # 空の ignore[] は何も抑制しない. 全ルールを外すなら ignore[*] と明示させる
    return Annotation(rules=rules, reason=reason)


class AnnotationReader:
    """候補の行と、直前の注釈だけの行から注釈を探す. 同じファイルは一度だけ読む."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._cache: dict[str, list[str] | None] = {}
        #: 書き間違いの注釈 (空の ignore[] など). 黙って無視せずレポートに出す
        self.warnings: list[str] = []
        self._warned: set[tuple[str, int]] = set()

    def _lines(self, relative: str) -> list[str] | None:
        if relative not in self._cache:
            path = (self._root / relative).resolve()
            # シンボリックリンクなどで検査対象の外を読まない
            if not path.is_relative_to(self._root) or not path.is_file():
                self._cache[relative] = None
            else:
                try:
                    self._cache[relative] = path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                except OSError:
                    self._cache[relative] = None
        return self._cache[relative]

    def find(self, candidate: Candidate) -> Annotation | None:
        location = candidate.location
        if location is None or location.start_line < 1:
            return None
        lines = self._lines(location.path)
        if lines is None:
            return None
        for number in (location.start_line, location.start_line - 1):
            if 1 <= number <= len(lines):
                line = lines[number - 1]
                if number != location.start_line and not is_annotation_only(line):
                    continue
                annotation = parse_annotation(line)
                if annotation is not None and not annotation.rules:
                    if (location.path, number) not in self._warned:
                        self._warned.add((location.path, number))
                        self.warnings.append(
                            f"{location.path}:{number}: 空の ignore[] は何も抑制しません。"
                            "全ルールを外すなら ignore[*] と書いてください"
                        )
                    continue
                if annotation is not None and any(
                    rule_matches(rule, candidate) for rule in annotation.rules
                ):
                    return annotation
        return None
