"""inline コメントと SARIF の位置 (#161, #162) と、重複したサマリ (#165)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from security_checker.config.schema import GithubConfig
from security_checker.github.client import GithubClient, PullRequestContext, post_comments
from security_checker.github.comment import STALE_SUMMARY, SUMMARY_MARKER, plan_inline
from security_checker.github.pr import (
    DiffError,
    head_line_mapper,
    map_line_to_head,
    repo_prefix,
)
from security_checker.models.enums import FindingStatus
from security_checker.models.report import TargetInfo
from security_checker.report.sarif import render_sarif
from tests.factories import make_candidate, make_finding, make_report


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@e", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def merge_repo(tmp_path: Path) -> tuple[Path, str]:
    """base 側が上に 5 行足した状態の、refs/pull/N/merge 相当の HEAD を作る."""
    root = tmp_path / "r"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("line1\nline2\nline3\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "init")
    git(root, "checkout", "-qb", "feature")
    (root / "app.py").write_text("line1\nline2\nos.system(user)\nline3\n", encoding="utf-8")
    git(root, "commit", "-qam", "feat")
    head = git(root, "rev-parse", "HEAD")
    git(root, "checkout", "-q", "main")
    (root / "app.py").write_text("h1\nh2\nh3\nh4\nh5\nline1\nline2\nline3\n", encoding="utf-8")
    git(root, "commit", "-qam", "main")
    git(root, "checkout", "-q", "--detach", "main")
    git(root, "merge", "-q", "--no-edit", "feature")
    return root, head


def test_merge_commit_lines_are_mapped_to_the_head(merge_repo: tuple[Path, str]) -> None:
    root, head = merge_repo
    to_head = head_line_mapper(root, head)
    assert to_head is not None
    assert to_head("app.py", 8) == 3  # os.system(user)
    assert to_head("app.py", 1) is None  # base 側で増えた行は head に無い


def test_no_mapping_when_the_head_itself_was_checked_out(merge_repo: tuple[Path, str]) -> None:
    root, head = merge_repo
    git(root, "checkout", "-q", "--detach", head)
    assert head_line_mapper(root, head) is None


def test_an_unknown_head_is_an_error_not_a_guess(merge_repo: tuple[Path, str]) -> None:
    root, _ = merge_repo
    with pytest.raises(DiffError):
        head_line_mapper(root, "0" * 40)


def test_plan_uses_head_lines_and_counts_unmapped(merge_repo: tuple[Path, str]) -> None:
    root, head = merge_repo
    mapped = make_candidate("c1", path="app.py", line=8)
    unmapped = make_candidate("c2", path="app.py", line=1)
    findings = [make_finding(c, FindingStatus.CONFIRMED) for c in (mapped, unmapped)]
    plan = plan_inline(
        make_report([mapped, unmapped], findings),
        GithubConfig(),
        {"app.py": [(1, 4)]},
        set(),
        to_head=head_line_mapper(root, head),
    )
    assert [(c.path, c.line) for c in plan.comments] == [("app.py", 3)]
    assert plan.unmapped == 1
    assert plan.outside_diff == 0


@pytest.mark.parametrize(
    ("diff", "line", "expected"),
    [
        ("@@ -0,0 +1,5 @@\n", 8, 3),
        ("@@ -3 +3 @@\n", 3, None),
        ("@@ -3,2 +3,0 @@\n", 10, 12),
        ("@@ -10,0 +11 @@\n", 5, 5),
    ],
)
def test_map_line_to_head(diff: str, line: int, expected: int | None) -> None:
    assert map_line_to_head(diff, line) == expected


# --- サブディレクトリを検査したときのパス (#162) ---------------------------------------


def test_repo_prefix(tmp_path: Path) -> None:
    git(tmp_path, "init", "-q")
    sub = tmp_path / "services" / "api"
    sub.mkdir(parents=True)
    assert repo_prefix(sub) == "services/api/"
    assert repo_prefix(tmp_path) == ""


def test_repo_prefix_outside_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path.parent))
    assert repo_prefix(tmp_path) is None


def _subdir_report() -> Any:
    candidate = make_candidate("c1", path="app.py", line=3)
    finding = make_finding(candidate, FindingStatus.CONFIRMED)
    return make_report(
        [candidate],
        [finding],
        target=TargetInfo(root="/repo/services/api", mode="full", repo_prefix="services/api/"),
    )


def test_sarif_paths_start_at_the_repository_root() -> None:
    result = render_sarif(_subdir_report())["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "services/api/app.py"


def test_inline_paths_start_at_the_repository_root() -> None:
    plan = plan_inline(_subdir_report(), GithubConfig(), {"services/api/app.py": [(1, 4)]}, set())
    assert [(c.path, c.line) for c in plan.comments] == [("services/api/app.py", 3)]
    assert plan.outside_diff == 0


# --- 実行が重なってできた重複サマリ (#165) -----------------------------------------------


def test_the_newest_summary_is_updated_and_older_ones_are_marked_stale() -> None:
    comments = [
        {"id": 1, "body": f"{SUMMARY_MARKER} old", "user": {"login": "github-actions[bot]"}},
        {"id": 2, "body": f"{SUMMARY_MARKER} new", "user": {"login": "github-actions[bot]"}},
    ]
    patched: dict[int, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=comments if "/issues/" in request.url.path else [])
        comment_id = int(request.url.path.rsplit("/", 1)[1])
        patched[comment_id] = json.loads(request.content)["body"]
        return httpx.Response(200, json={"id": comment_id, "html_url": "u"})

    candidate = make_candidate("c1")
    report = make_report([candidate], [make_finding(candidate, FindingStatus.CONFIRMED)])
    settings = GithubConfig().model_copy(update={"inline_comments": False})
    with GithubClient("t", transport=httpx.MockTransport(handler)) as client:
        result = post_comments(client, PullRequestContext("o/r", 1), report, settings)
    assert patched[1] == STALE_SUMMARY
    assert patched[2].startswith(SUMMARY_MARKER)
    assert SUMMARY_MARKER not in STALE_SUMMARY
    assert any("concurrency" in warning for warning in result.warnings)
