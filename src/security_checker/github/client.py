"""GitHub REST API の最小クライアントと、PR コメントの投稿 (設計書 §21.3).

依存を増やさないため httpx だけで書く。テストでは `transport` を差し替える。
fork PR では GITHUB_TOKEN が read-only に降格されるため、書き込みは 403 で失敗する。
それは「ツールの故障」ではないので例外にせず、結果に理由を残して呼び出し側に返す (§21.2)。
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from security_checker.config.schema import GithubConfig
from security_checker.errors import ConfigError, SecurityCheckerError
from security_checker.github.comment import (
    STALE_SUMMARY,
    SUMMARY_MARKER,
    commentable_ranges,
    existing_finding_ids,
    has_problems,
    plan_inline,
    render_summary,
)
from security_checker.github.pr import DiffError, head_line_mapper
from security_checker.models.report import Report

DEFAULT_API_URL = "https://api.github.com"
TIMEOUT_S = 30.0
MAX_PAGES = 30


class GithubError(SecurityCheckerError):
    """GitHub API の呼び出しに失敗した."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class PullRequestContext:
    """どの PR に書くか."""

    repository: str
    number: int
    head_sha: str | None = None


def context_from_env(
    environ: Mapping[str, str] | None = None,
    *,
    repository: str | None = None,
    number: int | None = None,
    head_sha: str | None = None,
) -> PullRequestContext:
    """引数 → GitHub Actions の環境変数 → イベントペイロードの順で PR を特定する."""
    env = os.environ if environ is None else environ
    event: dict[str, Any] = {}
    event_path = env.get("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).is_file():
        try:
            event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            event = {}
    pull = event.get("pull_request") or {}
    repo = repository or env.get("GITHUB_REPOSITORY")
    pr_number = number or pull.get("number")
    sha = head_sha or (pull.get("head") or {}).get("sha")
    if not repo or not pr_number:
        raise ConfigError(
            "コメント先の PR を特定できません。--repo と --pr を指定するか、"
            "pull_request イベントの GitHub Actions から実行してください"
        )
    return PullRequestContext(repository=repo, number=int(pr_number), head_sha=sha)


class GithubClient:
    """必要な API だけを持つ同期クライアント."""

    def __init__(
        self,
        token: str,
        *,
        api_url: str = DEFAULT_API_URL,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=api_url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "security-checker",
            },
            timeout=TIMEOUT_S,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GithubClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self._client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise GithubError(f"GitHub API に接続できません: {exc}") from exc
        if response.status_code >= 400:
            message = ""
            try:
                message = str(response.json().get("message", ""))
            except ValueError:
                message = response.text[:200]
            raise GithubError(
                f"GitHub API {method} {url} が {response.status_code} を返しました: {message}",
                status_code=response.status_code,
            )
        return response

    def _paginate(self, url: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        params: dict[str, Any] | None = {"per_page": 100}
        for _ in range(MAX_PAGES):
            if next_url is None:
                break
            response = self._request("GET", next_url, params=params)
            items.extend(response.json())
            next_url = response.links.get("next", {}).get("url")
            params = None  # next の URL にはクエリが含まれている
        return items

    def issue_comments(self, pr: PullRequestContext) -> list[dict[str, Any]]:
        return self._paginate(f"/repos/{pr.repository}/issues/{pr.number}/comments")

    def create_issue_comment(self, pr: PullRequestContext, body: str) -> dict[str, Any]:
        url = f"/repos/{pr.repository}/issues/{pr.number}/comments"
        result: dict[str, Any] = self._request("POST", url, json={"body": body}).json()
        return result

    def update_issue_comment(
        self, pr: PullRequestContext, comment_id: int, body: str
    ) -> dict[str, Any]:
        url = f"/repos/{pr.repository}/issues/comments/{comment_id}"
        result: dict[str, Any] = self._request("PATCH", url, json={"body": body}).json()
        return result

    def review_comments(self, pr: PullRequestContext) -> list[dict[str, Any]]:
        return self._paginate(f"/repos/{pr.repository}/pulls/{pr.number}/comments")

    def pull_files(self, pr: PullRequestContext) -> list[dict[str, Any]]:
        return self._paginate(f"/repos/{pr.repository}/pulls/{pr.number}/files")

    def head_sha(self, pr: PullRequestContext) -> str:
        data = self._request("GET", f"/repos/{pr.repository}/pulls/{pr.number}").json()
        return str(data["head"]["sha"])

    def create_review(
        self, pr: PullRequestContext, commit_id: str, comments: list[dict[str, Any]]
    ) -> dict[str, Any]:
        url = f"/repos/{pr.repository}/pulls/{pr.number}/reviews"
        payload = {
            "commit_id": commit_id,
            # APPROVE / REQUEST_CHANGES は使わない. 合否は status check と Code Scanning が担う
            "event": "COMMENT",
            "comments": comments,
        }
        result: dict[str, Any] = self._request("POST", url, json=payload).json()
        return result


@dataclass
class CommentResult:
    """投稿結果. 何をしなかったかも理由付きで残す (黙って 0 件にしない)."""

    summary_action: str = "none"  # created / updated / skipped / none
    summary_url: str | None = None
    inline_posted: int = 0
    inline_already_posted: int = 0
    inline_outside_diff: int = 0
    inline_over_limit: int = 0
    inline_unmapped: int = 0
    warnings: list[str] = field(default_factory=list)


def _author(comment: Mapping[str, Any]) -> str | None:
    user = comment.get("user")
    login = user.get("login") if isinstance(user, Mapping) else None
    return login if isinstance(login, str) else None


def _body(comment: Mapping[str, Any]) -> str:
    body = comment.get("body")
    return body if isinstance(body, str) else ""


def _split_by_author(
    comments: list[dict[str, Any]], author: str, has_marker: Callable[[str], bool]
) -> tuple[list[dict[str, Any]], int]:
    """マーカー付きのコメントを、指定した投稿者のものとそれ以外の件数に分ける.

    マーカーは HTML コメントで画面に見えず、PR にコメントできる人なら誰でも書ける。
    投稿者を見ないと、第三者のコメントで sticky サマリの更新先や inline の投稿済み判定を左右できる。
    """
    ours = [c for c in comments if has_marker(_body(c)) and _author(c) == author]
    foreign = sum(1 for c in comments if has_marker(_body(c)) and _author(c) != author)
    return ours, foreign


def _foreign_warning(count: int, kind: str, author: str) -> str:
    return (
        f"{kind}のマーカーを含む、{author} 以外のコメントが {count} 件あります。"
        "無視しました (別のトークンで投稿している場合は github.comment_author を設定してください)"
    )


def post_comments(
    client: GithubClient,
    pr: PullRequestContext,
    report: Report,
    settings: GithubConfig,
    *,
    report_url: str | None = None,
) -> CommentResult:
    """sticky サマリと inline コメントを投稿する."""
    result = CommentResult()
    if not settings.comment:
        result.summary_action = "skipped"
        result.warnings.append("github.comment: false のため PR コメントを投稿しません")
        return result

    try:
        _post_summary(client, pr, report, settings, report_url, result)
        _post_inline(client, pr, report, settings, result)
    except GithubError as exc:
        if exc.status_code in (403, 404):
            # fork PR の read-only トークンなど. ツールの故障ではない (§21.2)
            result.warnings.append(
                f"PR にコメントできませんでした (権限不足の可能性。fork PR では workflow_run "
                f"パターンを使ってください): {exc}"
            )
            return result
        raise
    return result


def _post_summary(
    client: GithubClient,
    pr: PullRequestContext,
    report: Report,
    settings: GithubConfig,
    report_url: str | None,
    result: CommentResult,
) -> None:
    body = render_summary(report, report_url=report_url)
    existing = None
    if settings.comment_mode == "sticky":
        ours, foreign = _split_by_author(
            client.issue_comments(pr),
            settings.comment_author,
            lambda body: body.startswith(SUMMARY_MARKER),
        )
        # 実行が重なると複数できる。最新を更新し、残りは古い結果だと書く。
        # 人の返信がぶら下がっている可能性があるので消さない
        existing = ours[-1] if ours else None
        for stale in ours[:-1]:
            client.update_issue_comment(pr, int(stale["id"]), STALE_SUMMARY)
        if len(ours) > 1:
            result.warnings.append(
                f"サマリコメントが {len(ours)} 件ありました。実行が重なった可能性があります。"
                "workflow に concurrency を設定してください (docs/github-actions.md)"
            )
        if foreign:
            result.warnings.append(_foreign_warning(foreign, "サマリ", settings.comment_author))

    if existing is not None:
        updated = client.update_issue_comment(pr, int(existing["id"]), body)
        result.summary_action = "updated"
        result.summary_url = updated.get("html_url")
        return
    if not has_problems(report) and not settings.comment_on_clean:
        # 問題ゼロで既存コメントも無いなら、何も投稿しない (§21.3 ノイズ抑制 2)
        result.summary_action = "skipped"
        return
    created = client.create_issue_comment(pr, body)
    result.summary_action = "created"
    result.summary_url = created.get("html_url")


def _post_inline(
    client: GithubClient,
    pr: PullRequestContext,
    report: Report,
    settings: GithubConfig,
    result: CommentResult,
) -> None:
    if not settings.inline_comments or not report.findings:
        return
    commentable = {
        str(item["filename"]): commentable_ranges(str(item.get("patch") or ""))
        for item in client.pull_files(pr)
    }
    ours, foreign = _split_by_author(
        client.review_comments(pr),
        settings.comment_author,
        lambda body: bool(existing_finding_ids([body])),
    )
    if foreign:
        result.warnings.append(
            _foreign_warning(foreign, "inline コメント", settings.comment_author)
        )
    posted = existing_finding_ids(_body(c) for c in ours)
    sha = pr.head_sha or client.head_sha(pr)
    try:
        to_head = head_line_mapper(Path(report.target.root), sha)
        plan = plan_inline(report, settings, commentable, posted, to_head=to_head)
    except DiffError as exc:
        # 行番号を確かめられないまま付けると、無関係な行に指摘が載る
        result.warnings.append(
            "PR の head と検査したコミットの行を対応づけられないため、"
            f"inline コメントを省きます: {exc}"
        )
        return
    result.inline_unmapped = plan.unmapped
    if plan.unmapped:
        result.warnings.append(
            f"base 側の変更と重なる {plan.unmapped} 件は、"
            "行を対応づけられないので inline を省きました"
        )
    result.inline_already_posted = plan.already_posted
    result.inline_outside_diff = plan.outside_diff
    result.inline_over_limit = plan.over_limit
    if not plan.comments:
        return
    client.create_review(
        pr,
        sha,
        [{"path": c.path, "line": c.line, "side": "RIGHT", "body": c.body} for c in plan.comments],
    )
    result.inline_posted = len(plan.comments)
