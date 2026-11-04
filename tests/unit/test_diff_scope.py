"""diff モード — 変更行に関係する候補だけを残す (設計書 §7.4)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from security_checker.errors import ConfigError, ExitCode
from security_checker.github.pr import (
    DiffError,
    DiffScope,
    compute_diff,
    parse_unified_diff,
    prepare_scope,
    resolve_base,
)
from security_checker.models.candidate import Location, PackageRef
from security_checker.models.enums import Category
from security_checker.report.sarif import render_sarif
from tests.factories import make_candidate, make_report

DIFF = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,0 +11,3 @@ def handler():
+    a = 1
+    b = 2
+    c = 3
@@ -40 +43 @@ def other():
-    old()
+    new()
@@ -50,2 +53,0 @@ def gone():
-    x
-    y
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1 @@
-requests==2.0
+requests==2.1
diff --git a/removed.yml b/removed.yml
deleted file mode 100644
--- a/removed.yml
+++ /dev/null
@@ -1,2 +0,0 @@
-a: 1
-b: 2
"""


def test_parse_unified_diff_collects_added_ranges():
    added, changed = parse_unified_diff(DIFF)
    assert added["src/app.py"] == ((11, 13), (43, 43))
    assert added["requirements.txt"] == ((1, 1),)
    # 純粋な削除ハンクは追加行を持たない
    assert "removed.yml" not in added
    assert changed == {"src/app.py", "requirements.txt", "removed.yml"}


def test_parse_unified_diff_ignores_header_like_lines_inside_hunks():
    # SQL / Lua のコメント (`-- `) の削除や `++ ` で始まる行の追加は、
    # ハンクの本文でも `--- ` / `+++ ` になる。ファイルヘッダと取り違えない
    diff = """\
diff --git a/db/schema.sql b/db/schema.sql
--- a/db/schema.sql
+++ b/db/schema.sql
@@ -3 +2,0 @@
--- old comment
@@ -10,0 +10,2 @@
+select 1;
+++ not a header
@@ -20,0 +21 @@
+select 2;
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,0 +2 @@
+x = 1
"""
    added, changed = parse_unified_diff(diff)
    assert added == {"db/schema.sql": ((10, 11), (21, 21)), "src/app.py": ((2, 2),)}
    assert changed == {"db/schema.sql", "src/app.py"}


@pytest.fixture
def scope() -> DiffScope:
    added, changed = parse_unified_diff(DIFF)
    return DiffScope(base="origin/main", added=added, changed_files=frozenset(changed))


def test_code_candidates_must_overlap_added_lines(scope):
    assert scope.touches(make_candidate(line=12))
    assert scope.touches(make_candidate(line=43))
    assert not scope.touches(make_candidate(line=20))
    assert not scope.touches(make_candidate(path="other.py", line=12))
    # 複数行にまたがる候補は、どこか 1 行でも重なれば残す
    spanning = make_candidate(location=Location(path="src/app.py", start_line=5, end_line=11))
    assert scope.touches(spanning)


def test_secret_candidates_follow_the_same_rule(scope):
    assert scope.touches(make_candidate(category=Category.SECRET, line=11))
    assert not scope.touches(make_candidate(category=Category.SECRET, line=1))


def test_dependency_candidates_need_a_changed_manifest(scope):
    changed = make_candidate(
        category=Category.DEPENDENCY,
        location=None,
        package=PackageRef(ecosystem="PyPI", name="requests", manifest="requirements.txt"),
    )
    untouched = make_candidate(
        category=Category.DEPENDENCY,
        location=None,
        package=PackageRef(ecosystem="npm", name="x", manifest="package-lock.json"),
    )
    assert scope.touches(changed)
    assert not scope.touches(untouched)


def test_config_candidates_need_a_changed_file(scope):
    inside = make_candidate(
        category=Category.CONFIG, location=Location(path="removed.yml", start_line=1, end_line=1)
    )
    outside = make_candidate(
        category=Category.CONFIG, location=Location(path="Dockerfile", start_line=1, end_line=1)
    )
    assert scope.touches(inside)
    assert not scope.touches(outside)


def test_web_candidates_are_never_dropped(scope):
    assert scope.touches(make_candidate(category=Category.WEB, location=None))


def test_split_keeps_order(scope):
    a = make_candidate("a", line=11)
    b = make_candidate("b", line=99)
    c = make_candidate("c", line=13)
    inside, outside = scope.split([a, b, c])
    assert [x.id for x in inside] == ["a", "c"]
    assert [x.id for x in outside] == ["b"]


def test_commentable_lines(scope):
    assert scope.is_commentable("src/app.py", 12)
    assert not scope.is_commentable("src/app.py", 14)


# --- 基準の決定 ----------------------------------------------------------------


def test_full_mode_never_diffs():
    assert resolve_base("full", "origin/main", {"GITHUB_BASE_REF": "main"}) is None


def test_auto_uses_the_pr_context():
    assert resolve_base("auto", None, {"GITHUB_BASE_REF": "main"}) == "origin/main"
    assert resolve_base("auto", None, {}) is None
    assert resolve_base("auto", "HEAD~1", {}) == "HEAD~1"


def test_explicit_diff_without_base_is_a_config_error():
    with pytest.raises(ConfigError) as info:
        resolve_base("diff", None, {})
    assert info.value.exit_code is ExitCode.CONFIG_ERROR


# --- 実際の git リポジトリで ------------------------------------------------------


def git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text("a = 1\nb = 2\n", encoding="utf-8")
    (tmp_path / "keep.py").write_text("x = 1\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "init")
    git(tmp_path, "switch", "-q", "-c", "feature")
    (tmp_path / "app.py").write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")
    git(tmp_path, "commit", "-q", "-am", "change")
    # コミットしていない変更も対象に含める (手元で PR 前に確かめる用途)
    (tmp_path / "new.py").write_text("y = 1\n", encoding="utf-8")
    git(tmp_path, "add", "new.py")
    return tmp_path


def test_compute_diff_against_a_real_repository(repo):
    scope = compute_diff(repo, "main")
    assert scope.added == {"app.py": ((3, 3),), "new.py": ((1, 1),)}
    assert scope.changed_files == {"app.py", "new.py"}


def test_compute_diff_paths_are_relative_to_the_scan_root(repo):
    sub = repo / "pkg"
    sub.mkdir()
    (sub / "mod.py").write_text("z = 1\n", encoding="utf-8")
    git(repo, "add", ".")
    scope = compute_diff(sub, "main")
    # Candidate のパスはスキャン対象からの相対なので、それに合わせる
    assert scope.changed_files == {"mod.py"}


def test_unknown_base_is_reported_with_a_hint(repo):
    with pytest.raises(DiffError, match="fetch-depth"):
        compute_diff(repo, "origin/no-such-branch")


def test_auto_falls_back_to_full_with_a_warning(tmp_path):
    scope, warnings = prepare_scope("auto", tmp_path, None, {"GITHUB_BASE_REF": "main"})
    assert scope is None
    assert warnings and "全件" in warnings[0]


def test_explicit_diff_failure_is_an_error(tmp_path):
    with pytest.raises(DiffError):
        prepare_scope("diff", tmp_path, "main", {})


# --- SARIF との関係 ---------------------------------------------------------------


def test_outside_diff_candidates_stay_in_sarif_as_notes():
    """出さなければ既存 alert が閉じ、元の level で出せば既定ブランチの判定と食い違う."""
    report = make_report([make_candidate("in")], outside_diff=[make_candidate("out", line=1)])
    results = render_sarif(report)["runs"][0]["results"]
    by_id = {r["partialFingerprints"]["primary"]: r for r in results}
    assert by_id["in"]["level"] == "error"
    assert by_id["out"]["level"] == "note"
    assert "security-severity" not in by_id["out"]["properties"]
    assert by_id["out"]["properties"]["status"] == "outside_diff"


# --- 未追跡ファイル・バイナリ・引用されたパス (#668, #669, #670) ------------------


def test_untracked_new_files_are_inside_the_diff(repo):
    (repo / "fresh.py").write_text("p = 1\nq = 2\n", encoding="utf-8")
    (repo / "ignored.log").write_text("x\n", encoding="utf-8")
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    scope = compute_diff(repo, "main")
    assert scope.added["fresh.py"] == ((1, 2),)
    assert "fresh.py" in scope.changed_files
    assert "ignored.log" not in scope.changed_files


def test_untracked_binary_files_count_as_changed_without_lines(repo):
    (repo / "lib.jar").write_bytes(b"PK\x03\x04\x00\x00binary")
    scope = compute_diff(repo, "main")
    assert "lib.jar" in scope.changed_files
    assert "lib.jar" not in scope.added


def test_binary_changes_are_counted_as_changed_files(repo):
    (repo / "lib.jar").write_bytes(b"PK\x03\x04\x00\x00v1")
    git(repo, "add", "lib.jar")
    scope = compute_diff(repo, "main")
    assert "lib.jar" in scope.changed_files


def test_parse_binary_diff_without_file_headers():
    diff = (
        "diff --git a/vendor/x.jar b/vendor/x.jar\n"
        "index 1111111..2222222 100644\n"
        "Binary files a/vendor/x.jar and b/vendor/x.jar differ\n"
    )
    added, changed = parse_unified_diff(diff)
    assert added == {}
    assert changed == {"vendor/x.jar"}


def test_c_quoted_paths_are_unescaped():
    diff = (
        'diff --git "a/we\\"ird\\tname.py" "b/we\\"ird\\tname.py"\n'
        '--- "a/we\\"ird\\tname.py"\n'
        '+++ "b/we\\"ird\\tname.py"\n'
        "@@ -0,0 +1,2 @@\n"
        "+a\n"
        "+b\n"
        'diff --git "a/\\346\\227\\245.py" "b/\\346\\227\\245.py"\n'
        "Binary files a/x and b/x differ\n"
    )
    added, changed = parse_unified_diff(diff)
    assert added == {'we"ird\tname.py': ((1, 2),)}
    assert changed == {'we"ird\tname.py', "日.py"}
