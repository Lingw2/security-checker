"""PR コメント (設計書 §21.3).

この種のツールが嫌われる最大の理由は「push のたびに同じ指摘が積み上がる」こと。
重複投稿しないこと・ノイズを出さないこと・LLM 本文を無害化することを回帰として押さえる。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from security_checker.cli import app
from security_checker.config.schema import GithubConfig
from security_checker.errors import ConfigError, ExitCode
from security_checker.github.client import (
    GithubClient,
    GithubError,
    PullRequestContext,
    context_from_env,
    post_comments,
)
from security_checker.github.comment import (
    SUMMARY_MARKER,
    commentable_ranges,
    existing_finding_ids,
    finding_marker,
    plan_inline,
    render_inline,
    render_summary,
    sanitize,
)
from security_checker.models.candidate import Location
from security_checker.models.enums import FindingStatus, ScanStatus, Severity
from security_checker.models.finding import Finding
from security_checker.models.report import ScannerRun
from security_checker.models.verdict import VerdictStatus
from security_checker.policy.engine import PolicyDecision
from security_checker.report.markdown import render_markdown
from security_checker.report.sarif import render_sarif
from tests.factories import make_candidate, make_finding, make_report, make_verdict

PR = PullRequestContext(repository="o/r", number=7, head_sha="abc")


# --- 無害化 ------------------------------------------------------------------------


def test_sanitize_neutralizes_markers_mentions_and_secrets():
    text = sanitize(f"{SUMMARY_MARKER} ping @octocat see a@b.com key sk-{'A' * 40} `@decorator`")
    assert "<!--" not in text
    assert "@octocat" not in text
    assert "@​octocat" in text
    assert "a@b.com" in text  # メールアドレスは壊さない
    assert "A" * 40 not in text


def test_llm_text_cannot_forge_the_summary_marker():
    candidate = make_candidate()
    finding = make_finding(
        candidate,
        FindingStatus.CONFIRMED,
        summary=f"{SUMMARY_MARKER} 偽のサマリ",
        verdicts=[make_verdict("r1", reasoning="<!-- security-checker:finding:zzz -->")],
    )
    body = render_summary(make_report([candidate], [finding]))
    assert body.count("<!--") == 1
    assert body.startswith(SUMMARY_MARKER)
    inline = render_inline(finding)
    assert existing_finding_ids([inline]) == {candidate.id}


# --- サマリ ------------------------------------------------------------------------


def test_summary_orders_review_required_right_after_confirmed():
    confirmed = make_candidate("c1", path="a.py")
    likely = make_candidate("c2", path="b.py")
    split = make_candidate("c3", path="c.py")
    fp = make_candidate("c4", path="d.py")
    findings = [
        make_finding(likely, FindingStatus.LIKELY, summary="可能性大"),
        make_finding(
            split,
            FindingStatus.REVIEW_REQUIRED,
            summary="判断割れ",
            verdicts=[
                make_verdict("alpha", "c3", reasoning="文字列連結"),
                make_verdict("beta", "c3", vulnerable=False, reasoning="整数にキャスト済み"),
            ],
        ),
        make_finding(confirmed, FindingStatus.CONFIRMED, summary="確定"),
        make_finding(fp, FindingStatus.FALSE_POSITIVE, summary="誤検出の本文"),
    ]
    body = render_summary(make_report([confirmed, likely, split, fp], findings))
    assert body.index("確定") < body.index("判断割れ") < body.index("可能性大")
    assert "誤検出の本文" not in body
    assert "**1 confirmed** · 1 likely · **1 review required** · 1 false positive" in body
    assert "`alpha`: 脆弱" in body
    assert "`beta`: 脆弱でない" in body


def test_summary_reports_failed_scanners_and_unreviewed():
    candidate = make_candidate()
    runs = [ScannerRun(scanner="trivy", category="config", status=ScanStatus.FAILED)]
    report = make_report(
        [candidate],
        [make_finding(candidate, FindingStatus.NOT_REVIEWED, verdicts=[])],
        scanners=runs,
    )
    body = render_summary(report)
    assert "`trivy` が失敗" in body
    assert "未レビュー 1 件" in body


def test_summary_for_clean_review():
    candidate = make_candidate()
    report = make_report([candidate], [make_finding(candidate, FindingStatus.FALSE_POSITIVE)])
    assert "✅ 問題は検出されませんでした" in render_summary(report)


def test_summary_for_scan_only_says_it_is_not_a_verdict():
    body = render_summary(make_report([make_candidate()]))
    assert "判定結果ではありません" in body
    assert "src/app.py:42" in body


def test_summary_footer_links_the_report():
    body = render_summary(make_report([]), report_url="https://example.com/run/1")
    assert "[full report](https://example.com/run/1)" in body


# --- inline の計画 -----------------------------------------------------------------


def findings_at(*specs: tuple[str, FindingStatus, int]) -> tuple[Any, ...]:
    candidates = [
        make_candidate(cid, location=Location(path="src/app.py", start_line=line, end_line=line))
        for cid, _, line in specs
    ]
    findings = [
        make_finding(candidate, status)
        for candidate, (_, status, _) in zip(candidates, specs, strict=True)
    ]
    return candidates, findings


def test_inline_respects_min_status_diff_and_dedupe():
    candidates, findings = findings_at(
        ("conf", FindingStatus.CONFIRMED, 12),
        ("like", FindingStatus.LIKELY, 13),
        ("rr", FindingStatus.REVIEW_REQUIRED, 12),
        ("old", FindingStatus.CONFIRMED, 14),
        ("far", FindingStatus.CONFIRMED, 99),
    )
    report = make_report(candidates, findings)
    plan = plan_inline(
        report,
        GithubConfig(),  # 既定: likely 以上
        {"src/app.py": [(10, 15)]},
        posted_ids={"old"},
    )
    assert [c.finding_id for c in plan.comments] == ["conf", "like"]
    assert plan.already_posted == 1
    assert plan.outside_diff == 1
    assert plan.comments[0].line == 12
    assert plan.comments[0].body.startswith(finding_marker(findings[0]))


def test_inline_limit_moves_the_rest_to_the_summary():
    candidates, findings = findings_at(
        ("a", FindingStatus.CONFIRMED, 11),
        ("b", FindingStatus.CONFIRMED, 12),
        ("c", FindingStatus.CONFIRMED, 13),
    )
    plan = plan_inline(
        make_report(candidates, findings),
        GithubConfig(max_inline_comments=2),
        {"src/app.py": [(10, 15)]},
        set(),
    )
    assert len(plan.comments) == 2
    assert plan.over_limit == 1


def test_inline_can_be_disabled_or_widened():
    candidates, findings = findings_at(("rr", FindingStatus.REVIEW_REQUIRED, 12))
    report = make_report(candidates, findings)
    ranges = {"src/app.py": [(10, 15)]}
    assert plan_inline(report, GithubConfig(), ranges, set()).comments == []
    wide = GithubConfig(inline_min_status=FindingStatus.REVIEW_REQUIRED)
    assert len(plan_inline(report, wide, ranges, set()).comments) == 1
    off = GithubConfig(inline_comments=False)
    assert plan_inline(report, off, ranges, set()).comments == []


def test_multiline_finding_is_anchored_inside_the_diff():
    candidate = make_candidate(location=Location(path="src/app.py", start_line=5, end_line=30))
    report = make_report([candidate], [make_finding(candidate, FindingStatus.CONFIRMED)])
    plan = plan_inline(report, GithubConfig(), {"src/app.py": [(1, 8), (20, 22)]}, set())
    assert plan.comments[0].line == 22


def test_commentable_ranges_from_a_patch():
    patch = "@@ -1,3 +1,4 @@\n a\n+b\n c\n d\n@@ -20 +21,0 @@\n-x\n@@ -40 +41 @@\n-y\n+z"
    assert commentable_ranges(patch) == [(1, 4), (41, 41)]


# --- 投稿 (GitHub API はモック) -----------------------------------------------------


BOT = {"login": "github-actions[bot]", "type": "Bot"}
STRANGER = {"login": "someone", "type": "User"}


class FakeGithub:
    """GitHub API の振る舞いを最小限まねる."""

    def __init__(self, *, issue_comments: list[dict[str, Any]] | None = None) -> None:
        self.issue_comments = issue_comments or []
        self.review_comments: list[dict[str, Any]] = []
        self.files = [{"filename": "src/app.py", "patch": "@@ -10,0 +11,5 @@\n+a"}]
        self.calls: list[tuple[str, str, Any]] = []
        self.fail_writes_with: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        body: Any = json.loads(request.content) if request.content else {}
        path = request.url.path
        self.calls.append((request.method, path, body))
        if request.method != "GET" and self.fail_writes_with:
            return httpx.Response(
                self.fail_writes_with, json={"message": "Resource not accessible"}
            )
        if path == "/repos/o/r/issues/7/comments" and request.method == "GET":
            return httpx.Response(200, json=self.issue_comments)
        if path == "/repos/o/r/issues/7/comments":
            comment = {
                "id": 100,
                "body": body["body"],
                "html_url": "https://gh/c/100",
                "user": BOT,
            }
            self.issue_comments.append(comment)
            return httpx.Response(201, json=comment)
        if path.startswith("/repos/o/r/issues/comments/"):
            return httpx.Response(200, json={"id": 1, "html_url": "https://gh/c/1"})
        if path == "/repos/o/r/pulls/7/files":
            return httpx.Response(200, json=self.files)
        if path == "/repos/o/r/pulls/7/comments":
            return httpx.Response(200, json=self.review_comments)
        if path == "/repos/o/r/pulls/7/reviews":
            for comment in body["comments"]:
                self.review_comments.append({"body": comment["body"], "user": BOT})
            return httpx.Response(200, json={"id": 5})
        return httpx.Response(404, json={"message": "not found"})

    def client(self) -> GithubClient:
        return GithubClient("t", transport=httpx.MockTransport(self.handler))

    def writes(self) -> list[tuple[str, str]]:
        return [(m, p) for m, p, _ in self.calls if m != "GET"]


def confirmed_report() -> Any:
    candidate = make_candidate(line=12)
    return make_report([candidate], [make_finding(candidate, FindingStatus.CONFIRMED)])


def test_first_run_creates_summary_and_inline_review():
    fake = FakeGithub()
    with fake.client() as client:
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.summary_action == "created"
    assert result.inline_posted == 1
    review = next(body for m, p, body in fake.calls if p.endswith("/reviews"))
    assert review["event"] == "COMMENT"
    assert review["commit_id"] == "abc"
    assert review["comments"][0] == {
        "path": "src/app.py",
        "line": 12,
        "side": "RIGHT",
        "body": review["comments"][0]["body"],
    }


def test_second_run_edits_the_summary_and_does_not_repost_inline():
    fake = FakeGithub()
    with fake.client() as client:
        post_comments(client, PR, confirmed_report(), GithubConfig())
        fake.calls.clear()
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.summary_action == "updated"
    assert result.inline_posted == 0
    assert result.inline_already_posted == 1
    assert fake.writes() == [("PATCH", "/repos/o/r/issues/comments/100")]


def test_someone_elses_comment_quoting_the_marker_is_not_edited():
    """マーカーが本文の途中にあるだけのコメントは自分のものと見なさない."""
    fake = FakeGithub(issue_comments=[{"id": 9, "body": f"> {SUMMARY_MARKER}\n引用"}])
    with fake.client() as client:
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.summary_action == "created"


def test_summary_marker_from_another_author_is_not_edited():
    """マーカーは誰でも書ける. 第三者のコメントを sticky サマリの更新先にしない (#77)."""
    fake = FakeGithub(issue_comments=[{"id": 9, "body": SUMMARY_MARKER, "user": STRANGER}])
    with fake.client() as client:
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.summary_action == "created"
    assert ("PATCH", "/repos/o/r/issues/comments/9") not in fake.writes()
    assert any("1 件" in w for w in result.warnings)


def test_finding_marker_from_another_author_does_not_suppress_inline():
    fake = FakeGithub()
    with fake.client() as client:
        post_comments(client, PR, confirmed_report(), GithubConfig())
        for comment in fake.review_comments:
            comment["user"] = STRANGER  # 作者が同じ本文を先に書いておいた状況
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.inline_posted == 1
    assert result.inline_already_posted == 0
    assert any("inline" in w for w in result.warnings)


def test_comment_author_can_be_configured_for_other_tokens():
    fake = FakeGithub(issue_comments=[{"id": 9, "body": SUMMARY_MARKER, "user": STRANGER}])
    with fake.client() as client:
        result = post_comments(
            client, PR, confirmed_report(), GithubConfig(comment_author="someone")
        )
    assert result.summary_action == "updated"
    assert result.warnings == []


def test_clean_run_without_existing_comment_posts_nothing():
    fake = FakeGithub()
    with fake.client() as client:
        result = post_comments(client, PR, make_report([]), GithubConfig())
    assert result.summary_action == "skipped"
    assert fake.writes() == []


def test_clean_run_updates_an_existing_comment_to_green():
    fake = FakeGithub(
        issue_comments=[{"id": 3, "body": SUMMARY_MARKER + "\n古い指摘", "user": BOT}]
    )
    with fake.client() as client:
        result = post_comments(client, PR, make_report([]), GithubConfig())
    assert result.summary_action == "updated"
    patch = next(body for m, p, body in fake.calls if m == "PATCH")
    assert "✅ 問題は検出されませんでした" in patch["body"]


def test_comment_on_clean_posts_even_without_findings():
    fake = FakeGithub()
    with fake.client() as client:
        result = post_comments(client, PR, make_report([]), GithubConfig(comment_on_clean=True))
    assert result.summary_action == "created"


def test_new_mode_always_creates():
    fake = FakeGithub(issue_comments=[{"id": 3, "body": SUMMARY_MARKER}])
    with fake.client() as client:
        result = post_comments(
            client, PR, confirmed_report(), GithubConfig(comment_mode="new", inline_comments=False)
        )
    assert result.summary_action == "created"


def test_comment_disabled_by_config():
    fake = FakeGithub()
    with fake.client() as client:
        result = post_comments(client, PR, confirmed_report(), GithubConfig(comment=False))
    assert result.summary_action == "skipped"
    assert fake.calls == []


def test_read_only_token_is_a_warning_not_a_crash():
    """fork PR の GITHUB_TOKEN は read-only. それはツールの故障ではない (§21.2)."""
    fake = FakeGithub()
    fake.fail_writes_with = 403
    with fake.client() as client:
        result = post_comments(client, PR, confirmed_report(), GithubConfig())
    assert result.summary_action == "none"
    assert any("workflow_run" in w for w in result.warnings)


def test_server_errors_are_raised():
    fake = FakeGithub()
    fake.fail_writes_with = 500
    with fake.client() as client, pytest.raises(GithubError):
        post_comments(client, PR, confirmed_report(), GithubConfig())


def test_pagination_follows_link_headers():
    pages = {
        "1": (
            [{"id": 1, "body": "x"}],
            '<https://api.github.com/repos/o/r/issues/7/comments?page=2>; rel="next"',
        ),
        "2": ([{"id": 2, "body": SUMMARY_MARKER}], None),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        page = request.url.params.get("page", "1")
        items, link = pages[page]
        headers = {"Link": link} if link else {}
        return httpx.Response(200, json=items, headers=headers)

    with GithubClient("t", transport=httpx.MockTransport(handler)) as client:
        assert [c["id"] for c in client.issue_comments(PR)] == [1, 2]


# --- PR の特定 ----------------------------------------------------------------------


def test_context_from_event_payload(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"pull_request": {"number": 3, "head": {"sha": "s1"}}}), encoding="utf-8"
    )
    pr = context_from_env({"GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": str(event)})
    assert pr == PullRequestContext(repository="o/r", number=3, head_sha="s1")


def test_explicit_arguments_win(tmp_path):
    pr = context_from_env({"GITHUB_REPOSITORY": "x/y"}, repository="o/r", number=9, head_sha="h")
    assert pr == PullRequestContext(repository="o/r", number=9, head_sha="h")


def test_context_requires_a_pr():
    with pytest.raises(ConfigError):
        context_from_env({"GITHUB_REPOSITORY": "o/r"})


# --- CLI ------------------------------------------------------------------------------

runner = CliRunner()


def write_report(tmp_path: Path) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(confirmed_report().dump()), encoding="utf-8")
    return path


def test_cli_requires_a_token(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    result = runner.invoke(app, ["comment", str(write_report(tmp_path))])
    assert result.exit_code == ExitCode.CONFIG_ERROR
    assert "GITHUB_TOKEN" in result.stderr


def test_cli_rejects_a_missing_report(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    result = runner.invoke(app, ["comment", str(tmp_path / "nope.json")])
    assert result.exit_code == ExitCode.CONFIG_ERROR


def test_cli_posts_from_a_saved_report(tmp_path, monkeypatch):
    fake = FakeGithub()
    real_client = GithubClient

    def patched(token: str, **kwargs: Any) -> GithubClient:
        return real_client(token, transport=httpx.MockTransport(fake.handler))

    monkeypatch.setattr("security_checker.cli.GithubClient", patched)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        ["comment", str(write_report(tmp_path)), "--repo", "o/r", "--pr", "7", "--sha", "abc"],
    )
    assert result.exit_code == ExitCode.OK, result.output
    assert "summary: created" in result.stdout
    assert "投稿 1" in result.stdout


def test_report_round_trips_through_json():
    """comment は report.json を読み直す. 書いた形がそのまま読めること."""
    from security_checker.models.report import Report

    report = confirmed_report()
    again = Report.model_validate_json(json.dumps(report.dump()))
    assert again.findings[0].status is FindingStatus.CONFIRMED
    assert again.findings[0].severity is Severity.HIGH


def test_comment_neutralizes_html_images_and_backtick_breakout():
    candidate = make_candidate(path="src/a`b.py", line=3)
    finding = make_finding(
        candidate,
        FindingStatus.CONFIRMED,
        summary="<details><summary>✅ No issues</summary> ![x](https://attacker.example/p.png)",
        verdicts=[make_verdict("r1", attack_path=["a`<img src=x>`b", "sink"])],
    )
    body = render_summary(make_report([candidate], [finding]))
    inline = render_inline(finding)
    for text in (body, inline):
        assert "<details><summary>✅ No issues" not in text
        assert "![x]" not in text
    assert "`src/a'b.py:3`" in body
    # コードスパンの中に閉じ込められている (外に抜けて HTML として描画されない)
    assert "`a'<img src=x>'b`" in body


# --- 指摘の理由に反対意見やエラーを載せない (#164) -----------------------------------------


def _mixed_finding() -> Finding:
    candidate = make_candidate("c1")
    verdicts = [
        make_verdict(
            "alpha",
            "c1",
            status=VerdictStatus.PROVIDER_ERROR,
            vulnerable=False,
            severity=Severity.NONE,
            reasoning="alpha: HTTP 503 が 3 回続きました",
            remediation=None,
            attack_path=[],
        ),
        make_verdict(
            "gamma",
            "c1",
            vulnerable=False,
            severity=Severity.NONE,
            reasoning="呼び出し元で整数にキャストされており到達しません",
        ),
        make_verdict("beta", "c1", reasoning="入力がシェルに連結されています"),
    ]
    return make_finding(candidate, FindingStatus.LIKELY, verdicts=verdicts)


def test_every_output_gives_the_same_supporting_reason():
    finding = _mixed_finding()
    report = make_report([finding.candidate], [finding])
    sarif_message = render_sarif(report)["runs"][0]["results"][0]["message"]["text"]
    outputs = {
        "inline": render_inline(finding),
        "summary": render_summary(report),
        "sarif": sarif_message,
        "markdown": render_markdown(report, PolicyDecision(exit_code=ExitCode.OK)),
    }
    for name, text in outputs.items():
        assert "入力がシェルに連結されています" in text, name
    for name in ("inline", "summary", "sarif"):
        assert "HTTP 503" not in outputs[name], name
        assert "キャストされており" not in outputs[name], name


def test_without_a_supporting_verdict_no_reason_is_shown():
    candidate = make_candidate("c1")
    verdict = make_verdict(
        "alpha", "c1", vulnerable=False, severity=Severity.NONE, reasoning="到達しません"
    )
    finding = make_finding(candidate, FindingStatus.REVIEW_REQUIRED, verdicts=[verdict])
    assert finding.supporting_reasoning == ""
    assert "到達しません" not in render_inline(finding)


# --- レビューできなかった run を「問題なし」にしない (#597) ------------------------


@pytest.mark.parametrize(
    "status", [FindingStatus.ERROR, FindingStatus.NOT_REVIEWED, FindingStatus.INCONCLUSIVE]
)
def test_a_run_where_no_candidate_could_be_reviewed_is_still_posted(status):
    candidate = make_candidate()
    report = make_report([candidate], [make_finding(candidate, status, verdicts=[])])
    fake = FakeGithub()
    with fake.client() as client:
        result = post_comments(client, PR, report, GithubConfig())
    assert result.summary_action == "created"
    body = render_summary(report)
    assert "✅" not in body
    assert "レビューできなかった候補があります" in body


# --- 表示の崩れ・紛らわしさ (#598, #599, #600, #601) ------------------------------


def test_skipped_scanners_are_named_in_the_summary():
    runs = [
        ScannerRun(scanner="trivy", category="config", status=ScanStatus.SKIPPED, reason="未導入")
    ]
    body = render_summary(make_report([], scanners=runs))
    assert "`trivy` はスキップされました (未導入)" in body


def test_reviewer_names_go_through_code_span():
    candidate = make_candidate()
    finding = make_finding(
        candidate, FindingStatus.CONFIRMED, verdicts=[make_verdict("a`b|c", candidate.id)]
    )
    body = render_summary(make_report([candidate], [finding]))
    assert "a`b" not in body
    assert "`a'b\\|c`" in body


def test_false_positive_count_is_not_called_suppressed():
    candidate = make_candidate()
    report = make_report([candidate], [make_finding(candidate, FindingStatus.FALSE_POSITIVE)])
    body = render_summary(report)
    assert "(suppressed)" not in body
    assert "1 false positive (PR には非表示)" in body


def test_a_long_summary_is_cut_between_findings_and_keeps_the_footer(monkeypatch):
    candidates = [make_candidate(f"c{i}", path=f"f{i}.py") for i in range(15)]
    findings = [
        make_finding(
            c,
            FindingStatus.CONFIRMED,
            summary="x",
            verdicts=[make_verdict("r1", c.id, reasoning="y" * 1400)],
        )
        for c in candidates
    ]
    report = make_report(candidates, findings)
    from security_checker.github import comment as module

    full = render_summary(report)
    monkeypatch.setattr(module, "MAX_BODY_CHARS", 4_000)
    body = render_summary(report)
    assert len(body) <= 4_000
    assert "長すぎるため省略しました" in body
    assert body.count("<details>") == body.count("</details>")
    assert body.rstrip().endswith(full.rstrip().splitlines()[-1])
