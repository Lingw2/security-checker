"""baseline / .security-checker-ignore / コード内注釈 (設計書 §17.2).

抑制は「消す」ではなく「理由付きで脇に置く」。レポートに残り、レビューとゲートの対象から外れる。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import Config
from security_checker.errors import ConfigError, ExitCode
from security_checker.models.candidate import Candidate, Location, PackageRef
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.finding import SuppressionReason
from security_checker.policy.baseline import Baseline, load_baseline, write_baseline
from security_checker.policy.ignore import (
    AnnotationReader,
    parse_annotation,
    parse_ignore_file,
)
from security_checker.policy.suppress import SuppressionRules, apply_suppressions, load_rules
from security_checker.run import run_scan
from security_checker.scanners.gitleaks import parse_gitleaks
from security_checker.testing.fakes import FakeScanner
from tests.factories import make_candidate

# --- baseline -----------------------------------------------------------------------


def test_baseline_round_trip(tmp_path):
    candidates = [make_candidate("b", path="b.py"), make_candidate("a", path="a.py")]
    path = write_baseline(tmp_path / "base.json", candidates, tool_version="2.0.0")
    assert load_baseline(path).ids == {"a", "b"}
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    # 人間がレビューできるよう、場所順に並び、ルールと場所も書かれる
    assert [e["where"] for e in entries] == ["a.py:42", "b.py:42"]
    assert entries[0]["rule_id"] == "rules.command-injection"


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '{"version": 99, "entries": []}',
        '{"version": 1}',
        '{"version": 1, "entries": [{}]}',
    ],
)
def test_broken_baseline_is_a_config_error(tmp_path, content):
    """壊れた baseline を空として扱うと、抑制が黙って外れて CI が突然落ちる (逆も然り)."""
    path = tmp_path / "base.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline(path)


def test_missing_baseline_suggests_the_command(tmp_path):
    with pytest.raises(ConfigError, match="baseline update"):
        load_baseline(tmp_path / "nope.json")


# --- ignore ファイル ---------------------------------------------------------------------


IGNORE = """\
# コメント
docs/**
/build/
secrets.example
rule:semgrep/python.lang.security.audit.eval
rule:generic-api-key tests/**   # 行末コメント
!keep.py
rule:
"""


def test_parse_ignore_file():
    ignore, warnings = parse_ignore_file(IGNORE)
    assert ignore.path_patterns == ["docs/**", "/build/", "secrets.example"]
    assert [(r.rule, r.paths) for r in ignore.rules] == [
        ("semgrep/python.lang.security.audit.eval", ()),
        ("generic-api-key", ("tests/**",)),
    ]
    # 解釈できない行は黙って捨てない
    assert len(warnings) == 2
    assert any("否定パターン" in w for w in warnings)


def test_ignore_matches_paths_and_rules():
    ignore, _ = parse_ignore_file(IGNORE)
    assert ignore.match(make_candidate(path="docs/a.py")) == "docs/**"
    # 理由には書かれたとおりの行を返す
    assert ignore.match(make_candidate(path="build/x/y.py")) == "/build/"
    assert ignore.match(make_candidate(path="config/secrets.example")) == "secrets.example"
    assert ignore.match(make_candidate(path="src/build/y.py")) is None  # 先頭の / はルート起点
    assert ignore.match(make_candidate(rule_id="python.lang.security.audit.eval")) is not None
    scoped = make_candidate(scanner="gitleaks", rule_id="generic-api-key", path="tests/t.py")
    assert ignore.match(scoped) == "rule:generic-api-key tests/**"
    outside = make_candidate(scanner="gitleaks", rule_id="generic-api-key", path="src/t.py")
    assert ignore.match(outside) is None
    assert ignore.match(make_candidate(path="src/app.py")) is None


# --- コード内注釈 ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "rules", "reason"),
    [
        ("x()  # security-checker: ignore[rules.a] reason=固定値のみ", ("rules.a",), "固定値のみ"),
        ("/* security-checker: ignore[a, b] reason=テスト用 */", ("a", "b"), "テスト用"),
        ("# Security-Checker: ignore[] ", ("*",), None),
        ("<!-- security-checker: ignore[x] reason=y -->", ("x",), "y"),
    ],
)
def test_parse_annotation(line, rules, reason):
    annotation = parse_annotation(line)
    assert annotation is not None
    assert annotation.rules == rules
    assert annotation.reason == reason


def test_annotation_on_the_line_or_the_line_above(tmp_path):
    (tmp_path / "app.py").write_text(
        "# security-checker: ignore[rules.command-injection] reason=入力は固定\n"
        "run(cmd, shell=True)\n"
        "run(other, shell=True)  # security-checker: ignore[other-rule] reason=別ルール\n",
        encoding="utf-8",
    )
    reader = AnnotationReader(tmp_path)
    above = make_candidate(location=Location(path="app.py", start_line=2, end_line=2))
    assert reader.find(above) is not None
    # 別のルールへの注釈では抑制しない
    other = make_candidate(location=Location(path="app.py", start_line=3, end_line=3))
    assert reader.find(other) is None


def test_annotation_reader_does_not_escape_the_root(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("# security-checker: ignore[*] reason=x\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link.py").symlink_to(outside)
    reader = AnnotationReader(root)
    candidate = make_candidate(location=Location(path="link.py", start_line=1, end_line=1))
    assert reader.find(candidate) is None


# --- 適用 --------------------------------------------------------------------------


def test_apply_order_and_reasons(tmp_path):
    (tmp_path / ".security-checker-ignore").write_text("vendor/**\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("x  # security-checker: ignore[*]\n", encoding="utf-8")
    (tmp_path / "base.json").write_text(
        json.dumps({"version": 1, "entries": [{"id": "known"}, {"id": "annotated"}]}),
        encoding="utf-8",
    )
    config = Config.model_validate({"policy": {"baseline": "base.json"}})
    rules = load_rules(config, tmp_path)
    candidates = [
        make_candidate("annotated", location=Location(path="a.py", start_line=1, end_line=1)),
        make_candidate("vendored", path="vendor/lib.py"),
        make_candidate("known", path="b.py"),
        make_candidate("new", path="c.py"),
    ]
    kept, suppressed, warnings = apply_suppressions(candidates, rules)
    assert [c.id for c in kept] == ["new"]
    assert [(s.candidate.id, s.reason) for s in suppressed] == [
        ("annotated", SuppressionReason.INLINE_ANNOTATION),
        ("vendored", SuppressionReason.IGNORE_FILE),
        ("known", SuppressionReason.BASELINE),
    ]
    # 理由の無い注釈は抑制するが警告する
    assert len(warnings) == 1 and "reason=" in warnings[0]


def test_baseline_path_is_relative_to_the_config_file(tmp_path):
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    (config_dir / "base.json").write_text(
        json.dumps({"version": 1, "entries": [{"id": "x"}]}), encoding="utf-8"
    )
    config = Config.model_validate({"policy": {"baseline": "base.json"}})
    rules = load_rules(config, tmp_path / "target", config_dir=config_dir)
    assert rules.baseline.ids == {"x"}


def test_untrusted_target_does_not_read_annotations_or_its_ignore_file(tmp_path):
    """fork PR が自分の指摘を自分で抑制できないようにする."""
    target = tmp_path / "pr"
    target.mkdir()
    (target / ".security-checker-ignore").write_text("**\n", encoding="utf-8")
    (target / "a.py").write_text(
        "x  # security-checker: ignore[*] reason=だまし\n", encoding="utf-8"
    )
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / ".security-checker-ignore").write_text("docs/**\n", encoding="utf-8")
    rules = load_rules(Config(), target, config_dir=trusted, untrusted_target=True)
    kept, suppressed, _ = apply_suppressions(
        [
            make_candidate("a", location=Location(path="a.py", start_line=1, end_line=1)),
            make_candidate("d", path="docs/x.py"),
        ],
        rules,
    )
    assert [c.id for c in kept] == ["a"]
    assert [s.candidate.id for s in suppressed] == ["d"]
    assert any("読みません" in w for w in rules.warnings)


# --- パイプラインと CLI ---------------------------------------------------------------


async def test_suppressed_candidates_do_not_fail_the_gate(tmp_path):
    (tmp_path / "base.json").write_text(
        json.dumps({"version": 1, "entries": [{"id": "old"}]}), encoding="utf-8"
    )
    config = Config.model_validate({"policy": {"baseline": "base.json", "fail_on": "high"}})
    scanner = FakeScanner("semgrep", candidates=[make_candidate("old", severity=Severity.CRITICAL)])
    outcome = await run_scan(
        config,
        tmp_path,
        base_dir=tmp_path,
        scanners=[scanner],
        suppression=load_rules(config, tmp_path),
    )
    assert outcome.decision.exit_code is ExitCode.OK
    assert outcome.report.candidates == []
    assert outcome.report.suppressed[0].reason is SuppressionReason.BASELINE
    assert outcome.report.suppression_label == "1 件 (baseline 1)"


runner = CliRunner()


def no_scanners(tmp_path: Path, extra: str = "") -> None:
    (tmp_path / "security-checker.yml").write_text(
        "version: 1\nscanners:\n  semgrep: { enabled: false }\n  gitleaks: { enabled: false }\n"
        "  osv: { enabled: false }\n" + extra,
        encoding="utf-8",
    )


def test_cli_baseline_update_writes_the_default_file(tmp_path, monkeypatch):
    no_scanners(tmp_path)
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["baseline", "update", str(tmp_path)])
    assert result.exit_code == ExitCode.OK, result.output
    assert load_baseline(tmp_path / ".security-checker-baseline.json").ids == frozenset()
    assert "policy:" in result.stdout


def test_cli_baseline_update_refuses_a_broken_run(tmp_path, monkeypatch):
    """スキャナが失敗した run を記録すると、復旧後に既存の検出が「新規」として噴き出す."""
    no_scanners(tmp_path)
    monkeypatch.chdir(tmp_path)

    broken = FakeScanner("semgrep", status=ScanStatus.FAILED, reason="x")
    monkeypatch.setattr("security_checker.run.build_scanners", lambda config: ([broken], []))
    result = runner.invoke(app, ["baseline", "update", str(tmp_path), "-o", "b.json"])
    assert result.exit_code == ExitCode.EXECUTION_ERROR
    assert not (tmp_path / "b.json").exists()


def test_cli_baseline_update_refuses_a_run_with_skipped_scanners(tmp_path, monkeypatch):
    """未導入のスキャナを含む run を記録すると、導入した日に既存の検出が「新規」になる (#213)."""
    no_scanners(tmp_path)
    monkeypatch.chdir(tmp_path)
    skipped = FakeScanner("osv", status=ScanStatus.SKIPPED, reason="未導入")
    monkeypatch.setattr("security_checker.run.build_scanners", lambda config: ([skipped], []))
    result = runner.invoke(app, ["baseline", "update", str(tmp_path), "-o", "b.json"])
    assert result.exit_code == ExitCode.EXECUTION_ERROR
    assert "osv (未導入)" in result.output
    assert not (tmp_path / "b.json").exists()


def test_cli_baseline_update_formats_a_broken_ignore_file(tmp_path, monkeypatch):
    """壊れた ignore ファイルでトレースバックにしない (#192)."""
    no_scanners(tmp_path, "policy:\n  baseline: nope.json\n")
    monkeypatch.chdir(tmp_path)

    def broken(*args, **kwargs):
        raise ConfigError("ignore ファイルが壊れています [x]")

    monkeypatch.setattr("security_checker.cli.load_rules", broken)
    result = runner.invoke(app, ["baseline", "update", str(tmp_path), "-o", "b.json"])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "壊れています [x]" in result.output


def test_cli_scan_with_a_missing_baseline_is_a_config_error(tmp_path, monkeypatch):
    no_scanners(tmp_path, "policy:\n  baseline: nope.json\n")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == ExitCode.CONFIG_ERROR


# --- 同じ場所で差し替えた秘密を抑制しない (#158) -----------------------------------


def _secret_candidate(secret: str) -> Candidate:
    payload = [
        {
            "RuleID": "generic-api-key",
            "File": "config.py",
            "StartLine": 3,
            "EndLine": 3,
            "Secret": secret,
            "Match": f'API_KEY = "{secret}"',
            "Description": "d",
        }
    ]
    return parse_gitleaks(payload, Path("/repo"))[0][0]


OLD_VALUE = "TESTONLYoldDummyValue1111"  # gitleaks:allow
NEW_VALUE = "TESTONLYnewDummyValue2222xyz"  # gitleaks:allow


def test_a_rotated_secret_is_not_covered_by_the_baseline(tmp_path):
    old, new = _secret_candidate(OLD_VALUE), _secret_candidate(NEW_VALUE)
    assert old.id == new.id  # ID は行の形だけで決まる。値の照合は baseline の役目
    path = write_baseline(tmp_path / "base.json", [old], tool_version="2.0.0")
    rules = SuppressionRules(baseline=load_baseline(path))

    kept, suppressed, warnings = apply_suppressions([old], rules)
    assert (kept, len(suppressed), warnings) == ([], 1, [])

    kept, suppressed, warnings = apply_suppressions([new], rules)
    assert [candidate.id for candidate in kept] == [new.id]
    assert suppressed == []
    assert "値が違う" in warnings[0]
    assert NEW_VALUE not in warnings[0]


def test_baseline_file_does_not_contain_the_secret_or_its_plain_hash(tmp_path):
    old = _secret_candidate(OLD_VALUE)
    text = write_baseline(tmp_path / "b.json", [old], tool_version="2.0.0").read_text("utf-8")
    assert OLD_VALUE not in text
    assert old.secret_digest is not None
    assert old.secret_digest not in text
    assert "secret_hash" in text


def test_the_salt_is_kept_when_the_baseline_is_updated(tmp_path):
    path = tmp_path / "b.json"
    old = _secret_candidate(OLD_VALUE)
    write_baseline(path, [old], tool_version="2.0.0")
    first = load_baseline(path)
    write_baseline(path, [old], tool_version="2.0.1")
    assert load_baseline(path) == first
    other = load_baseline(write_baseline(tmp_path / "other.json", [old], tool_version="2.0.0"))
    assert other.secret_hashes != first.secret_hashes  # 別のファイルとは突き合わせられない


def test_a_legacy_baseline_still_suppresses_by_id_and_warns(tmp_path):
    old, new = _secret_candidate(OLD_VALUE), _secret_candidate(NEW_VALUE)
    path = tmp_path / "v1.json"
    path.write_text(json.dumps({"version": 1, "entries": [{"id": old.id}]}), encoding="utf-8")
    baseline = load_baseline(path)
    assert baseline.covers(new)
    assert "baseline update" in baseline.warnings[0]


def test_the_secret_digest_never_reaches_a_report():
    candidate = _secret_candidate(OLD_VALUE)
    assert candidate.secret_digest is not None
    assert "secret_digest" not in candidate.model_dump()
    assert candidate.secret_digest not in candidate.model_dump_json()
    assert candidate.secret_digest not in repr(candidate)


def test_baseline_without_a_recorded_hash_matches_by_id():
    baseline = Baseline(ids=frozenset({"c1"}))
    assert baseline.covers(make_candidate("c1"))
    assert not baseline.covers(make_candidate("c2"))


# --- 行末の注釈は次の行に効かない (#157) ----------------------------------------


def test_trailing_annotation_does_not_reach_the_next_line(tmp_path):
    (tmp_path / "app.py").write_text(
        "run(a, shell=True)  # security-checker: ignore[rules.command-injection] reason=固定\n"
        "run(user_input, shell=True)\n",
        encoding="utf-8",
    )
    reader = AnnotationReader(tmp_path)
    same = make_candidate(location=Location(path="app.py", start_line=1, end_line=1))
    following = make_candidate(location=Location(path="app.py", start_line=2, end_line=2))
    assert reader.find(same) is not None
    assert reader.find(following) is None


@pytest.mark.parametrize(
    "comment",
    [
        "# security-checker: ignore[*] reason=x",
        "    // security-checker: ignore[*] reason=x",
        "/* security-checker: ignore[*] reason=x */",
        "<!-- security-checker: ignore[*] reason=x -->",
        "-- security-checker: ignore[*] reason=x",
        "{# security-checker: ignore[*] reason=x #}",
    ],
)
def test_annotation_only_line_applies_to_the_next_line(tmp_path, comment):
    (tmp_path / "app.py").write_text(f"{comment}\nrun(a)\n", encoding="utf-8")
    candidate = make_candidate(location=Location(path="app.py", start_line=2, end_line=2))
    assert AnnotationReader(tmp_path).find(candidate) is not None


# --- rule:<id> <path> は依存の候補にも効く (#156) ---------------------------------


@pytest.mark.parametrize("scanner", ["osv", "trivy"])
def test_rule_with_path_matches_the_manifest_of_a_dependency(scanner):
    dependency = make_candidate(
        scanner=scanner,
        rule_id="GHSA-xxxx",
        location=None,
        package=PackageRef(ecosystem="PyPI", name="foo", version="1.0", manifest="uv.lock"),
    )
    assert parse_ignore_file("rule:GHSA-xxxx uv.lock\n")[0].match(dependency) is not None
    assert parse_ignore_file("rule:GHSA-xxxx other.lock\n")[0].match(dependency) is None
