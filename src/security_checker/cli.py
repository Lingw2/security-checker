"""CLI (設計書 §12, §17.1, §9.8).

`scan` は LLM を使わないスキャン、`review` は LLM Reviewer を使ったレビュー、
`init` は環境を検出しての設定生成、`config` は解決済み設定の確認。
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
import yaml
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text

from security_checker import __version__
from security_checker.config.loader import (
    CONFIG_FILENAMES,
    LOCAL_CONFIG_FILENAMES,
    LoadedConfig,
    available_presets,
    load_config,
)
from security_checker.config.schema import Config
from security_checker.context.budget import estimate_tokens
from security_checker.context.redact import redact_known_patterns
from security_checker.errors import ConfigError, ExitCode, SecurityCheckerError
from security_checker.eval.dataset import load_dataset
from security_checker.eval.metrics import DEFAULT_MAX_DEFERRED_RATE
from security_checker.eval.runner import run_eval, to_markdown
from security_checker.github.client import (
    DEFAULT_API_URL,
    GithubClient,
    context_from_env,
    post_comments,
)
from security_checker.github.pr import DiffScope, prepare_scope
from security_checker.language import resolve_language
from security_checker.models.enums import Severity
from security_checker.models.report import Report
from security_checker.observability import logging as log
from security_checker.observability.cost import PriceTable, load_price_table
from security_checker.observability.estimate import estimate_run
from security_checker.observability.explain import explain as explain_finding
from security_checker.observability.explain import load_report
from security_checker.observability.explain import render as render_explanation
from security_checker.policy.baseline import write_baseline
from security_checker.policy.suppress import SuppressionRules, load_rules
from security_checker.providers.check import catalog, check_reviewer
from security_checker.providers.detect import Detection, detect_all
from security_checker.report.json_writer import write_json
from security_checker.report.markdown import write_markdown
from security_checker.report.sarif import write_sarif
from security_checker.report.terminal import render
from security_checker.review import prompts
from security_checker.review.structured import verdict_schema
from security_checker.run import RunOutcome, build_tasks, run_review, run_scan

app = typer.Typer(
    name="security-checker",
    help="拡張可能な AI Security Review プラットフォーム",
    no_args_is_help=True,
    add_completion=False,
)
config_app = typer.Typer(help="設定の確認", no_args_is_help=True)
app.add_typer(config_app, name="config")


def _console(*, stderr: bool = False) -> Console:
    """出力先が端末でなければ rich に折り返させない.

    CI のログは TTY ではなく、rich は既定の 80 桁で単語の途中でも改行する。
    コマンドやパスが 2 行に分かれると、コピーしても grep しても使えない。
    """
    console = Console(stderr=stderr)
    if not console.is_terminal:
        console.soft_wrap = True
    return console


err_console = _console(stderr=True)


def _fail(message: str, code: ExitCode) -> NoReturn:
    # メッセージはパスやスキャナの出力を含みうる. `[` を rich のマークアップとして読ませない
    err_console.print(f"[bold red]エラー:[/bold red] {escape(redact_known_patterns(message))}")
    raise typer.Exit(code=int(code))


def _print_warnings(console: Console, messages: list[str]) -> None:
    for message in messages:
        console.print(f"[yellow]警告[/yellow]: {escape(message)}", highlight=False)


def _print_report_warnings(console: Console, report: Report) -> None:
    """スキャナの skipped / failed と設定の警告.

    「0 件」と「検査できなかった」を見分けられるようにする。
    """
    for warning in report.warnings:
        style = "bold red" if warning.level == "error" else "yellow"
        console.print(Text(f"{warning.source}: {warning.message}", style=style))


def _load(
    root: Path,
    config_path: Path | None,
    preset: str | None,
    overrides: dict[str, Any],
) -> LoadedConfig:
    if not root.is_dir():
        # 書き間違いを「設定が空」に見せない (既定値だけの設定で続行しない)
        _fail(f"検査対象が見つかりません: {root}", ExitCode.CONFIG_ERROR)
    try:
        return load_config(root, config_path=config_path, preset=preset, cli_overrides=overrides)
    except ConfigError as exc:
        _fail(str(exc), ExitCode.CONFIG_ERROR)


def _cli_overrides(
    *,
    fail_on: Severity | None,
    min_score: int | None,
    strict: bool | None,
    exclude: list[str] | None,
    output_dir: Path | None,
    formats: list[str] | None,
    semgrep_config: str | None,
) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    if fail_on is not None:
        policy["fail_on"] = fail_on.value
    if min_score is not None:
        policy["min_score"] = min_score
    if strict is not None:
        policy["strict"] = strict

    overrides: dict[str, Any] = {}
    if policy:
        overrides["policy"] = policy
    if exclude:
        overrides["target"] = {"exclude": exclude}
    output: dict[str, Any] = {}
    if output_dir is not None:
        output["dir"] = str(output_dir)
    if formats:
        output["formats"] = formats
    if output:
        overrides["output"] = output
    if semgrep_config is not None:
        overrides["scanners"] = {"semgrep": {"config": semgrep_config}}
    return overrides


BaseOption = Annotated[
    str | None,
    typer.Option(
        "--base",
        help="diff モードの比較基準 (例: origin/main)。PR の文脈では GITHUB_BASE_REF から決まる",
    ),
]
FormatOption = Annotated[
    list[str] | None,
    typer.Option(
        "--format",
        "-f",
        help="出力形式 (複数指定可): terminal/json/markdown/sarif。設定の formats を置き換える",
    ),
]
LogFormatOption = Annotated[
    str | None,
    typer.Option("--log-format", help="構造化ログを標準エラーに出す: text | json"),
]
LogLevelOption = Annotated[
    str | None, typer.Option("--log-level", help="debug | info | warn | error")
]


def _configure_logging(loaded: LoadedConfig) -> None:
    """logging.* を利用者が指定したときだけログを出す (既定はノイズにしない)."""
    if not any(
        key.startswith("logging.") and layer != "default" for key, layer in loaded.origins.items()
    ):
        log.disable()
        return
    log.configure(level=loaded.config.logging.level, fmt=loaded.config.logging.format)


def _logging_overrides(fmt: str | None, level: str | None) -> dict[str, Any]:
    logging: dict[str, Any] = {}
    if fmt is not None:
        logging["format"] = fmt
    if level is not None:
        logging["level"] = level
    return {"logging": logging} if logging else {}


FullOption = Annotated[
    bool, typer.Option("--full", help="diff モードにせず、全件を検査する (target.mode: full)")
]


def _suppression(loaded: LoadedConfig, root: Path) -> SuppressionRules:
    """baseline / ignore / 注釈 (§17.2). baseline の相対パスは設定ファイルの場所が基準."""
    try:
        return load_rules(
            loaded.config,
            root,
            config_dir=loaded.config_path.parent if loaded.config_path is not None else None,
            untrusted_target=loaded.untrusted_target,
        )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)


def _diff_scope(
    loaded: LoadedConfig, root: Path, base: str | None, full: bool
) -> tuple[DiffScope | None, list[str]]:
    """target.mode と --base / --full から検査範囲を決める (§7.4)."""
    mode = "full" if full else loaded.config.target.mode
    if base is not None and mode == "auto":
        mode = "diff"
    try:
        return prepare_scope(mode, root, base)
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)


def _write_reports(loaded: LoadedConfig, outcome: RunOutcome, *, quiet: bool) -> None:
    """設定された形式で書き出す. terminal 以外はファイルとして残す (§18.1)."""
    formats = loaded.config.output.formats
    if "json" in formats:
        write_json(outcome.report, outcome.output_dir)
    if "markdown" in formats:
        write_markdown(outcome.report, outcome.decision, outcome.output_dir)
    if "sarif" in formats:
        write_sarif(outcome.report, outcome.output_dir)
    if not quiet and "terminal" in formats:
        details = next(
            (
                outcome.output_dir / name
                for fmt, name in (("markdown", "report.md"), ("json", "report.json"))
                if fmt in formats
            ),
            None,
        )
        render(outcome.report, outcome.decision, outcome.output_dir, details=details)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="検査対象ディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    preset: Annotated[
        str | None,
        typer.Option("--preset", "-p", help=f"プリセット: {', '.join(available_presets())}"),
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="この重大度以上の検出で exit 1")
    ] = None,
    min_score: Annotated[
        int | None, typer.Option("--min-score", min=0, max=100, help="スコア下限 (下回れば exit 1)")
    ] = None,
    strict: Annotated[
        bool | None,
        typer.Option("--strict/--no-strict", help="スキャナの失敗を exit 3 にする (既定: 有効)"),
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="除外パターン (複数指定可)")
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="レポート出力先 (既定: .security-checker/)"),
    ] = None,
    formats: FormatOption = None,
    base: BaseOption = None,
    full: FullOption = False,
    log_format: LogFormatOption = None,
    log_level: LogLevelOption = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="ターミナル出力を抑制する")] = False,
) -> None:
    """スキャナのみで検査する (LLM を使わない)."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"検査対象が見つかりません: {path}", ExitCode.CONFIG_ERROR)

    overrides = _cli_overrides(
        fail_on=fail_on,
        min_score=min_score,
        strict=strict,
        exclude=exclude,
        output_dir=output_dir,
        formats=formats,
        semgrep_config=None,
    )
    overrides.update(_logging_overrides(log_format, log_level))
    loaded = _load(root, config_path, preset, overrides)
    _configure_logging(loaded)
    diff, diff_warnings = _diff_scope(loaded, root, base, full)

    try:
        outcome = asyncio.run(
            run_scan(
                loaded.config,
                root,
                extra_warnings=[*loaded.warnings, *diff_warnings],
                diff=diff,
                suppression=_suppression(loaded, root),
            )
        )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    _write_reports(loaded, outcome, quiet=quiet)
    raise typer.Exit(code=int(outcome.decision.exit_code))


@app.command()
def review(
    path: Annotated[Path, typer.Argument(help="検査対象ディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    preset: Annotated[
        str | None,
        typer.Option("--preset", "-p", help=f"プリセット: {', '.join(available_presets())}"),
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="この重大度以上の判定で exit 1")
    ] = None,
    strict: Annotated[
        bool | None,
        typer.Option("--strict/--no-strict", help="スキャナ/Reviewer の失敗を exit 3 にする"),
    ] = None,
    max_candidates: Annotated[
        int | None, typer.Option("--max-candidates", min=1, help="レビューする候補の上限")
    ] = None,
    exclude: Annotated[
        list[str] | None, typer.Option("--exclude", help="除外パターン (複数指定可)")
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", "-o", help="レポート出力先 (既定: .security-checker/)"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="LLM に送信せず、送信予定の内容を表示する (--estimate とは同時に指定できない)",
        ),
    ] = False,
    estimate: Annotated[
        bool,
        typer.Option("--estimate", help="LLM に送信せず、使用量と金額の見積りだけを表示する"),
    ] = False,
    min_score: Annotated[
        int | None, typer.Option("--min-score", min=0, max=100, help="スコア下限 (下回れば exit 1)")
    ] = None,
    formats: FormatOption = None,
    base: BaseOption = None,
    full: FullOption = False,
    log_format: LogFormatOption = None,
    log_level: LogLevelOption = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="ターミナル出力を抑制する")] = False,
) -> None:
    """スキャン結果を LLM Reviewer でレビューする."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"検査対象が見つかりません: {path}", ExitCode.CONFIG_ERROR)

    overrides = _cli_overrides(
        fail_on=fail_on,
        min_score=min_score,
        strict=strict,
        exclude=exclude,
        output_dir=output_dir,
        formats=formats,
        semgrep_config=None,
    )
    if max_candidates is not None:
        overrides["budget"] = {"max_candidates": max_candidates}
    overrides.update(_logging_overrides(log_format, log_level))
    loaded = _load(root, config_path, preset, overrides)
    _configure_logging(loaded)
    diff, diff_warnings = _diff_scope(loaded, root, base, full)

    price_table = load_price_table(
        loaded.config_path.parent if loaded.config_path is not None else None
    )
    if dry_run and estimate:
        # 片方を黙って無視しない (P9)
        _fail("--dry-run と --estimate は同時に指定できません", ExitCode.CONFIG_ERROR)
    if dry_run:
        _dry_run(loaded, root, diff, diff_warnings)
        raise typer.Exit(code=int(ExitCode.OK))
    if estimate:
        _estimate(loaded, root, diff, diff_warnings, price_table)
        raise typer.Exit(code=int(ExitCode.OK))

    try:
        outcome = asyncio.run(
            run_review(
                loaded.config,
                root,
                price_table=price_table,
                extra_warnings=[*loaded.warnings, *diff_warnings],
                diff=diff,
                suppression=_suppression(loaded, root),
            )
        )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    _write_reports(loaded, outcome, quiet=quiet)
    raise typer.Exit(code=int(outcome.decision.exit_code))


def _scan_for_preview(
    loaded: LoadedConfig, root: Path, diff: DiffScope | None, diff_warnings: list[str]
) -> RunOutcome:
    """--dry-run / --estimate の前段. 本番の review と同じ警告を積み、壊れたら整形して止める."""
    try:
        return asyncio.run(
            run_scan(
                loaded.config,
                root,
                extra_warnings=[*loaded.warnings, *diff_warnings],
                diff=diff,
                suppression=_suppression(loaded, root),
            )
        )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)


def _estimate(
    loaded: LoadedConfig,
    root: Path,
    diff: DiffScope | None,
    diff_warnings: list[str],
    price_table: PriceTable,
) -> None:
    """何件・いくらかかるかを、送信前に見せる (設計書 §24.3)."""
    console = _console()
    outcome = _scan_for_preview(loaded, root, diff, diff_warnings)
    _print_report_warnings(console, outcome.report)
    tasks, overflow = build_tasks(outcome.report.candidates, root, loaded.config)
    result = estimate_run(tasks, loaded.config, price_table)
    console.print(
        f"[bold]estimate[/bold]: 候補 {len(outcome.report.candidates)} 件中 {len(tasks)} 件を"
        f"レビュー予定 (上限超過 {len(overflow)} 件 / 抑制 {len(outcome.report.suppressed)} 件 / "
        f"diff 外 {len(outcome.report.outside_diff)} 件)"
    )
    for item in result.reviewers:
        usd = f"${item.usd:.4f}" if item.usd is not None else "unknown"
        console.print(
            f"  {escape(item.name):<20} {item.calls:>4} 回  入力 約 {item.input_tokens:,}  "
            f"出力 最大 {item.max_output_tokens:,}  {usd}"
            + (f"  [dim]{escape(item.note)}[/dim]" if item.note else "")
        )
    total = result.total_usd
    budget = loaded.config.budget.max_usd
    console.print(
        "[bold]合計[/bold]: "
        + (
            f"約 ${total:.4f} (上限寄りの見積り)"
            if total is not None
            else "unknown (価格不明を含む)"
        )
        + (f" / 予算 budget.max_usd ${budget}" if budget is not None else "")
    )
    if total is not None and budget is not None and total > budget:
        console.print(
            "[yellow]見積りが予算を超えています。[/yellow]実行すると予算に達した時点で停止し、"
            "それまでの結果を出力します"
        )


def _dry_run(
    loaded: LoadedConfig, root: Path, diff: DiffScope | None, diff_warnings: list[str]
) -> None:
    """何が送信されるかを、送信前に全部見せる (設計書 §19.3).

    プロンプトはコードを含む. rich のマークアップとして解釈させない (`[slug]` などが消える)。
    """
    console = _console()
    outcome = _scan_for_preview(loaded, root, diff, diff_warnings)
    _print_report_warnings(console, outcome.report)
    if diff is not None:
        console.print(
            f"[bold]diff[/bold]: {escape(diff.base)} との差分 ({len(diff.changed_files)} ファイル) "
            f"に関係する候補だけを送信します (対象外 {len(outcome.report.outside_diff)} 件)"
        )
    tasks, overflow = build_tasks(outcome.report.candidates, root, loaded.config)

    console.print(
        f"[bold]dry-run[/bold]: 候補 {len(outcome.report.candidates)} 件中 "
        f"{len(tasks)} 件を送信予定 (超過 {len(overflow)} 件は未レビュー)"
    )
    console.print(
        Text.assemble(
            ("reviewers", "bold"),
            ": " + (", ".join(r.name for r in loaded.config.reviewers) or "(未設定)"),
        )
    )
    # system プロンプトは全タスク共通. 言語指示は output.language とロケールで変わるので必ず見せる
    configured = loaded.config.output.language
    language = resolve_language(configured)
    system = prompts.render_system(language)
    console.print(
        Panel(
            Text(system),
            title=Text(
                f"system (全タスク共通)  language: {language} ← output.language: {configured}"
            ),
            title_align="left",
            border_style="magenta",
        )
    )
    schema = verdict_schema()
    system_tokens = estimate_tokens(system)
    total = 0
    for task in tasks:
        user = prompts.render_user(task, schema)
        total += system_tokens + estimate_tokens(user)
        console.print(
            Panel(
                Text(user),
                title=Text(f"{task.candidate.id}  {task.candidate.where}"),
                title_align="left",
                border_style="blue",
            )
        )
    console.print(
        f"[bold]推定入力トークン[/bold]: 約 {total:,} (system を含む. "
        f"× Reviewer {len(loaded.config.reviewers)} 個)"
    )


INIT_HEADER = """\
# security-checker の設定 (設計書 §12)
# すべての項目に既定値があるため、必要なものだけを書けば動きます。
#
# reviewers に既定値はありません。特定のベンダーを標準として押し付けないためです (§9.8)。
# 以下は `security-checker init` が **この環境で実際に使えるもの** を検出して生成しました。
#
# transport: process は、そのコマンド側の既存ログインをそのまま使います (API キー不要)。
# 起動は毎回作り直す空の一時ディレクトリで行い、書き込みがあれば検知して警告しますが、
# コマンド自体の書き込み能力を無効化できているかは本体からは検証できません。
# 非対話・ツール無効 (または読み取り専用) のフラグを command に含めてください (§9.7)。
"""


def _reviewer_block(name: str, command: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "transport": "process",
        "command": command,
        "prompt_via": "stdin",
        "timeout_s": 300,
        "concurrency": 1,
    }


def _print_detections(console: Console, detections: list[Detection]) -> list[Detection]:
    """検出結果を表示する. 推奨マークは付けず、検出順のまま並べる (§9.8)."""
    console.print("環境を検出しています…\n")
    usable: list[Detection] = []
    for transport, title in (
        ("process", "process transport で使えるコマンド"),
        ("http", "http transport で使える資格情報"),
    ):
        rows = [item for item in detections if item.transport == transport]
        console.print(f"  [bold]{title}[/bold]")
        if not rows:
            console.print("    [dim](プリセットがありません)[/dim]")
        for item in rows:
            mark = "[green]✓[/green]" if item.available else "[dim]✗[/dim]"
            console.print(f"    {mark} {escape(item.name):<28} [dim]({escape(item.detail)})[/dim]")
            if item.available:
                usable.append(item)
        console.print()
    return usable


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="設定ファイルを置くディレクトリ")] = Path("."),
    command: Annotated[
        str | None,
        typer.Option(
            "--command",
            help="process transport の Reviewer にするコマンド (例: 'mycmd --non-interactive')",
        ),
    ] = None,
    name: Annotated[
        str | None, typer.Option("--name", help="--command で作る Reviewer の名前")
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="http の検出を採用するときの model (省略時は仮の値を書く)"),
    ] = None,
    local: Annotated[
        bool,
        typer.Option(
            "--local",
            help="security-checker.local.yml に書く (git 管理しない個人用の上書き層)",
        ),
    ] = False,
    force: Annotated[bool, typer.Option("--force", help="既存の設定ファイルを上書きする")] = False,
    stdout: Annotated[
        bool, typer.Option("--stdout", help="ファイルに書かず標準出力に表示する")
    ] = False,
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="検出されたものをすべて採用する")
    ] = False,
) -> None:
    """環境を検出して設定ファイルを生成する (設計書 §9.8)."""
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"ディレクトリが見つかりません: {path}", ExitCode.CONFIG_ERROR)
    # --stdout では標準出力を YAML だけにする (`> security-checker.yml` で使えるように)
    console = _console(stderr=stdout)

    usable = _print_detections(console, detect_all())
    blocks: list[dict[str, Any]] = []

    if usable and command is not None and not yes:
        # --command は「これを使う」という明示なので、検出分を対話で尋ねない。
        # 尋ねると、CI やスクリプトから呼んだときに標準入力が無くて失敗する。
        console.print(
            "[dim]--command が指定されているため、検出されたものは採用しません。"
            "検出分も使うなら --yes を付けるか、--command なしで実行してください[/dim]\n"
        )
        usable = []
    elif usable and not yes:
        for index, item in enumerate(usable, start=1):
            console.print(f"    [bold]{index}[/bold]. {escape(item.name)} ({item.transport})")
        try:
            answer = typer.prompt(
                "Reviewer にするものを番号で (カンマ区切り・空欄で全部・'-' で選ばない)",
                default="",
                show_default=False,
                err=stdout,
            ).strip()
        except typer.Abort:
            # 標準入力が無い (CI・パイプ) と、尋ねても答えが返らない. 黙って Aborted にしない
            _fail(
                "番号を尋ねられませんでした (標準入力がありません)。"
                "検出したものをすべて採用するなら --yes、使わないなら --command を指定してください",
                ExitCode.CONFIG_ERROR,
            )
        usable = _select(usable, answer, console)
    blocks.extend(dict(item.config) for item in usable)
    placeholder_models = _fill_http_models(blocks, model)

    if command is not None:
        argv = _split_command(command)
        if not argv:
            _fail("--command が空です", ExitCode.CONFIG_ERROR)
        reviewer_name = name or Path(argv[0]).name
        taken = {str(block["name"]) for block in blocks}
        if reviewer_name in taken:
            if name is not None:
                _fail(
                    f"Reviewer '{name}' は検出したプリセットと名前が重複しています。"
                    "--name で別の名前を指定してください",
                    ExitCode.CONFIG_ERROR,
                )
            reviewer_name = _unique_name(reviewer_name, taken)
        blocks.append(_reviewer_block(reviewer_name, argv))

    if not blocks:
        console.print(
            "[yellow]Reviewer は生成しませんでした。[/yellow]\n"
            "プリセットが 1 つも無くても、コマンドを直接指定すれば使えます:\n"
            "  [bold]security-checker init --command "
            "'<your-command> --non-interactive --no-tools'[/bold]\n"
            "LLM を使わない検査は [bold]security-checker scan[/bold] で今すぐ実行できます。"
        )
        raise typer.Exit(code=int(ExitCode.OK))

    generated = {"version": 1, "reviewers": blocks}
    try:
        # 直後の review / providers check で読めない設定を書かない
        Config.model_validate(generated)
    except ValidationError as exc:
        _fail(f"生成した設定が不正です: {exc}", ExitCode.CONFIG_ERROR)
    document = INIT_HEADER + yaml.safe_dump(
        generated,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    for reviewer_name in placeholder_models:
        console.print(
            f"[yellow]Reviewer '{escape(reviewer_name)}' の model は仮の値 "
            f"({PLACEHOLDER_MODEL}) です。[/yellow]使うモデルの ID に書き換えてください "
            "(または --model で指定してください)"
        )
    if stdout:
        print(document)
        raise typer.Exit(code=int(ExitCode.OK))

    destination = root / (LOCAL_CONFIG_FILENAMES[0] if local else CONFIG_FILENAMES[0])
    if destination.exists() and not force:
        _fail(
            f"{destination} は既に存在します。--force で上書きするか、--stdout で内容だけ"
            "表示できます"
            + (
                ""
                if local
                else "。共有設定を残したまま手元用の Reviewer を足すなら --local を使ってください"
            ),
            ExitCode.CONFIG_ERROR,
        )
    destination.write_text(document, encoding="utf-8")
    console.print(f"[green]書き出しました[/green]: {escape(str(destination))}")
    if local:
        console.print("[dim]このファイルは共有設定に後勝ちで重なります。[/dim]")
        if _git_ignores(root, destination):
            console.print("[dim].gitignore で無視されるため、コミットされません[/dim]")
        else:
            # 個人の Reviewer (コマンドやエンドポイント) を誤ってコミットさせない
            console.print(
                f"[yellow]{escape(destination.name)} は git で無視されていません。[/yellow]"
                f".gitignore に次の行を足してください:\n  {escape(destination.name)}"
            )
    console.print("次: [bold]security-checker review --dry-run[/bold] で送信内容を確認できます")


PLACEHOLDER_MODEL = "<model-id>"


def _fill_http_models(blocks: list[dict[str, Any]], model: str | None) -> list[str]:
    """http の検出に model を入れる. 仮の値を入れた Reviewer の名前を返す.

    プリセットはエンドポイントの「形」だけを持ち、model は持たない (§9.8)。
    """
    placeholders: list[str] = []
    for block in blocks:
        if block.get("transport") == "http" and "model" not in block:
            block["model"] = model or PLACEHOLDER_MODEL
            if model is None:
                placeholders.append(str(block["name"]))
    return placeholders


def _split_command(command: str) -> list[str]:
    """--command を argv に分ける. Windows ではバックスラッシュをエスケープとして読まない."""
    if os.name != "nt":
        return shlex.split(command)
    return [_unquote(token) for token in shlex.split(command, posix=False)]


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _unique_name(base: str, taken: set[str]) -> str:
    index = 2
    while f"{base}-{index}" in taken:
        index += 1
    return f"{base}-{index}"


def _git_ignores(root: Path, path: Path) -> bool:
    """git が実際にそのファイルを無視するか. git が無い・リポジトリでないなら偽."""
    try:
        completed = subprocess.run(
            ["git", "check-ignore", "-q", "--", str(path)],
            cwd=root,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


def _select(usable: list[Detection], answer: str, console: Console) -> list[Detection]:
    """番号の入力を選択に変換する. 解釈できない入力は黙って無視せず知らせる."""
    if answer == "-":
        return []
    if not answer:
        return usable
    chosen: list[Detection] = []
    for token in answer.split(","):
        cleaned = token.strip()
        if not cleaned.isdigit() or not 1 <= int(cleaned) <= len(usable):
            console.print(
                f"[yellow]無視しました[/yellow]: '{escape(cleaned)}' は番号ではありません"
            )
            continue
        chosen.append(usable[int(cleaned) - 1])
    return chosen


@config_app.command("show")
def config_show(
    path: Annotated[Path, typer.Argument(help="対象ディレクトリ")] = Path("."),
    config_path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    preset: Annotated[str | None, typer.Option("--preset", "-p")] = None,
    explain: Annotated[
        bool, typer.Option("--explain", help="どの層で値が決まったかを表示する")
    ] = False,
) -> None:
    """解決された最終設定を出力する (秘匿値は保持しない設計のため常に安全)."""
    root = path.expanduser().resolve()
    loaded = _load(root, config_path, preset, {})
    console = _console()

    # 受け付けたが効かない設定は、config show でも必ず見えるようにする (P9)。
    # 既定の出力は JSON なので、警告は標準エラーに出して混ぜない。
    warn_console = _console(stderr=True)
    _print_warnings(warn_console, list(loaded.warnings))

    if explain:
        console.print(f"[bold]preset[/bold]: {escape(str(loaded.preset or '(なし)'))}")
        console.print(f"[bold]config file[/bold]: {escape(str(loaded.config_path or '(なし)'))}")
        console.print(
            f"[bold]local config[/bold]: {escape(str(loaded.local_config_path or '(なし)'))}"
        )
        for key in sorted(loaded.origins):
            console.print(f"  {escape(key)} [dim]← {escape(str(loaded.origins[key]))}[/dim]")
        return

    print(json.dumps(loaded.config.masked_dump(), ensure_ascii=False, indent=2))


baseline_app = typer.Typer(help="既知の候補の記録 (段階導入用)", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")

DEFAULT_BASELINE = ".security-checker-baseline.json"


@baseline_app.command("update")
def baseline_update(
    path: Annotated[Path, typer.Argument(help="検査対象ディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help=f"書き出し先 (既定: policy.baseline か {DEFAULT_BASELINE})"
        ),
    ] = None,
) -> None:
    """いまの検出をすべて baseline に記録する (設計書 §17.2).

    記録した候補は以後 suppressed として残り、レビューとゲートの対象から外れる。
    新しく増えたものだけが CI を落とす。LLM は使わない (スキャナの検出を記録する)。
    """
    root = path.expanduser().resolve()
    if not root.is_dir():
        _fail(f"検査対象が見つかりません: {path}", ExitCode.CONFIG_ERROR)
    loaded = _load(root, config_path, None, {})
    config_dir = loaded.config_path.parent if loaded.config_path is not None else root
    configured = loaded.config.policy.baseline
    destination = output or (config_dir / (configured or DEFAULT_BASELINE))

    # 既存の baseline は外して、いまの検出をすべて記録し直す。ignore と注釈は効かせる
    config = loaded.config.model_copy(
        update={"policy": loaded.config.policy.model_copy(update={"baseline": None})}
    )
    _print_warnings(err_console, list(loaded.warnings))
    try:
        rules = load_rules(
            config, root, config_dir=config_dir, untrusted_target=loaded.untrusted_target
        )
        outcome = asyncio.run(run_scan(config, root, suppression=rules, diff=None))
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)
    if outcome.report.has_failed_scanner:
        # 壊れた run を baseline にすると、失敗したスキャナの既存の検出が「新規」扱いになる
        failed = ", ".join(r.scanner for r in outcome.report.scanners if r.status.value == "failed")
        _fail(f"スキャナが失敗したため baseline を更新しません: {failed}", ExitCode.EXECUTION_ERROR)
    skipped = [r for r in outcome.report.scanners if r.status.value == "skipped"]
    if skipped:
        # 未導入のスキャナの既存の検出は、導入した日にすべて「新規」になる。
        # 0 件の baseline を黙って書かない
        detail = ", ".join(f"{r.scanner} ({r.reason or 'skipped'})" for r in skipped)
        _fail(
            f"スキップされたスキャナがあるため baseline を更新しません: {detail}。"
            "導入するか、使わないなら scanners.<name>.enabled: false にしてください",
            ExitCode.EXECUTION_ERROR,
        )

    write_baseline(destination, outcome.report.candidates, tool_version=__version__)
    console = _console()
    console.print(
        f"[green]baseline を書き出しました[/green]: {escape(str(destination))} "
        f"({len(outcome.report.candidates)} 件)"
    )
    if configured is None:
        shown = (
            destination.relative_to(config_dir)
            if destination.is_relative_to(config_dir)
            else destination
        )
        hint = f"  policy:\n    baseline: {escape(str(shown))}"
        console.print(f"有効にするには設定に次を書いてください:\n{hint}")


@app.command()
def comment(
    report_path: Annotated[
        Path, typer.Argument(help="review / scan が書き出した report.json")
    ] = Path(".security-checker/report.json"),
    config_path: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="github.* を読む設定ファイル (省略時はカレントディレクトリから探す)",
        ),
    ] = None,
    repo: Annotated[
        str | None, typer.Option("--repo", help="owner/name (既定: GITHUB_REPOSITORY)")
    ] = None,
    pr: Annotated[
        int | None, typer.Option("--pr", help="PR 番号 (既定: イベントペイロード)")
    ] = None,
    sha: Annotated[
        str | None, typer.Option("--sha", help="inline コメントを付けるコミット (既定: PR の head)")
    ] = None,
    report_url: Annotated[
        str | None, typer.Option("--report-url", help="サマリに載せる full report のリンク")
    ] = None,
    inline: Annotated[
        bool | None,
        typer.Option("--inline/--no-inline", help="inline コメントを付けるか (既定: 設定に従う)"),
    ] = None,
    allow_readonly: Annotated[
        bool,
        typer.Option(
            "--allow-readonly",
            help="権限不足 (403 / 404) を exit 3 ではなく警告にする (fork PR など)",
        ),
    ] = False,
) -> None:
    """report.json を PR にコメントする (sticky サマリ + inline, 設計書 §21.3).

    レビューと投稿を分けてあるのは、fork PR の workflow_run パターンのため。
    書き込み権限を持つ側は PR のコードを実行せず、成果物の report.json だけを読む (§21.2)。
    トークンは環境変数 GITHUB_TOKEN (または GH_TOKEN) から読む。
    """
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        _fail("GITHUB_TOKEN (または GH_TOKEN) が設定されていません", ExitCode.CONFIG_ERROR)
    if not report_path.is_file():
        _fail(f"レポートが見つかりません: {report_path}", ExitCode.CONFIG_ERROR)
    try:
        report = Report.model_validate_json(report_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        _fail(f"レポートを読めません ({report_path}): {exc}", ExitCode.CONFIG_ERROR)

    root = (config_path.parent if config_path is not None else Path.cwd()).resolve()
    loaded = _load(root, config_path, None, {})
    settings = loaded.config.github
    if inline is not None:
        settings = settings.model_copy(update={"inline_comments": inline})

    try:
        context = context_from_env(repository=repo, number=pr, head_sha=sha)
        api_url = os.environ.get("GITHUB_API_URL") or DEFAULT_API_URL
        with GithubClient(token, api_url=api_url) as client:
            result = post_comments(
                client,
                context,
                report,
                settings,
                report_url=report_url,
                allow_readonly=allow_readonly,
            )
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    console = _console()
    _print_warnings(err_console, list(result.warnings))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        # ログを開かなくても Actions の画面に出るよう、注釈としても書く
        for message in result.warnings:
            print(f"::warning title=security-checker comment::{' '.join(message.split())}")
    console.print(
        f"summary: {result.summary_action}"
        + (f" ({result.summary_url})" if result.summary_url else "")
    )
    console.print(
        f"inline: 投稿 {result.inline_posted} / 投稿済み {result.inline_already_posted} / "
        f"diff 外 {result.inline_outside_diff} / 上限超過 {result.inline_over_limit} / "
        f"拒否 {result.inline_rejected}"
    )


providers_app = typer.Typer(help="LLM Provider の一覧と疎通確認", no_args_is_help=True)
app.add_typer(providers_app, name="providers")


@providers_app.command("list")
def providers_list() -> None:
    """使える transport・方言・プリセット・プラグインを一覧する (設計書 §29.3)."""
    console = _console()
    found = catalog()
    console.print("[bold]transport: http[/bold]  方言: " + ", ".join(found.dialects))
    console.print("[bold]transport: process[/bold]  任意のコマンド (command を直接書けば動く)")
    for title, presets in (
        ("http プリセット", found.http_presets),
        ("process プリセット", found.process_presets),
    ):
        console.print(f"[bold]{title}[/bold]")
        if not presets:
            console.print("  [dim](なし)[/dim]")
        for name, source in presets.items():
            console.print(f"  {escape(name)} [dim]({escape(str(source))})[/dim]")
    console.print("[bold]プラグイン[/bold] (entry_points: security_checker.providers)")
    for name in found.plugins or ["(なし)"]:
        console.print(Text(f"  {name}"))
    for message in found.warnings:
        err_console.print(f"[yellow]警告[/yellow]: {escape(message)}", highlight=False)


@providers_app.command("check")
def providers_check(
    name: Annotated[
        str | None, typer.Argument(help="確認する Reviewer の name (省略で全部)")
    ] = None,
    path: Annotated[Path, typer.Option("--path", help="設定を探すディレクトリ")] = Path("."),
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (既定は自動探索)")
    ] = None,
    no_probe: Annotated[
        bool,
        typer.Option("--no-probe", help="構造化出力の往復確認 (LLM を 1 回呼ぶ) を省く"),
    ] = False,
) -> None:
    """設定した Reviewer の疎通・capability・スキーマ対応を実地で確かめる (設計書 §29.3).

    構造化出力の確認では、合成した数行のコードを 1 件だけ送る (課金が発生しうる)。
    リポジトリのコードは送らない。
    """
    root = path.expanduser().resolve()
    loaded = _load(root, config_path, None, {})
    _print_warnings(err_console, list(loaded.warnings))
    reviewers = [r for r in loaded.config.reviewers if name is None or r.name == name]
    if not reviewers:
        _fail(
            f"Reviewer '{name}' は設定にありません" if name else "reviewers が設定されていません",
            ExitCode.CONFIG_ERROR,
        )
    console = _console()
    failed = False
    for reviewer in reviewers:
        result = asyncio.run(check_reviewer(reviewer, probe=not no_probe))
        mark = "[green]✓[/green]" if result.ok else "[red]✗[/red]"
        console.print(f"{mark} [bold]{escape(result.name)}[/bold] ({result.transport})")
        for step in result.steps:
            step_mark = "[green]ok[/green]" if step.ok else "[red]NG[/red]"
            console.print(
                f"    {step.label:<8} {step_mark}  {escape(step.detail)}", highlight=False
            )
        for suggestion in result.suggestions:
            console.print(f"    [yellow]→[/yellow] {escape(suggestion)}", highlight=False)
        failed = failed or not result.ok
    raise typer.Exit(code=int(ExitCode.EXECUTION_ERROR if failed else ExitCode.OK))


@app.command("explain")
def explain_command(
    finding_id: Annotated[str, typer.Argument(help="候補 / Finding の ID (先頭一致可)")],
    report_path: Annotated[Path, typer.Option("--report", "-r", help="report.json")] = Path(
        ".security-checker/report.json"
    ),
) -> None:
    """その判定に至った全 Reviewer の判断と、全呼び出しの記録を表示する (設計書 §24.2)."""
    try:
        report = load_report(report_path)
        result = explain_finding(report, finding_id, report_path=report_path)
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)
    print(render_explanation(result), end="")


@app.command("eval")
def eval_command(
    dataset_dir: Annotated[
        Path, typer.Option("--dataset", "-d", help="評価データセットのディレクトリ")
    ],
    config_path: Annotated[
        Path | None, typer.Option("--config", "-c", help="設定ファイル (Reviewer を含むもの)")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="結果 JSON の保存先")
    ] = None,
    markdown: Annotated[
        Path | None, typer.Option("--markdown", "-m", help="比較表 (Markdown) の保存先")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="標準出力を抑制する")] = False,
    allow_incomplete: Annotated[
        bool,
        typer.Option(
            "--allow-incomplete",
            help="採点できなかったケース (error / not_reviewed) があっても exit 3 にしない",
        ),
    ] = False,
    max_deferred_rate: Annotated[
        float,
        typer.Option(
            "--max-deferred-rate",
            min=0.0,
            max=1.0,
            help="review_required の割合の上限。超えたら exit 1",
        ),
    ] = DEFAULT_MAX_DEFERRED_RATE,
) -> None:
    """ラベル付きデータセットでレビュー精度を測る (設計書 §27).

    **主指標は Recall。** 見逃しを増やさずに誤検知を減らせているかを見る。
    """
    root = (config_path.parent if config_path is not None else Path.cwd()).resolve()
    loaded = _load(root, config_path, None, {})
    # 標準出力は比較表 (Markdown) のために空けておく。`> result.md` に警告が混ざらないように
    _print_warnings(err_console, list(loaded.warnings))

    try:
        dataset = load_dataset(dataset_dir)
        result = asyncio.run(run_eval(dataset, loaded.config))
    except SecurityCheckerError as exc:
        _fail(str(exc), exc.exit_code)

    document = to_markdown(result)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if markdown is not None:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(document, encoding="utf-8")
    if not quiet:
        print(document)

    metrics = result.metrics
    # 採点できなかった run の数字は信用できない。ツールの問題として先に落とす (§27.2)
    if (metrics.errors or metrics.not_reviewed) and not allow_incomplete:
        _fail(
            f"採点できなかったケースがあります (エラー {metrics.errors} / "
            f"未レビュー {metrics.not_reviewed})。予算や Reviewer の設定を確認してください。"
            "承知のうえで結果を見るなら --allow-incomplete を付けてください",
            ExitCode.EXECUTION_ERROR,
        )
    # 見逃しがあれば、それ自体を失敗として扱う (§27.2 の必須条件)
    if metrics.missed_true_positives:
        _fail(
            f"真陽性を {metrics.missed_true_positives} 件見逃しました: "
            f"{', '.join(metrics.missed_case_ids)}",
            ExitCode.POLICY_VIOLATION,
        )
    # 全部保留すれば見逃しは 0 になる。保留で主指標をすり抜けさせない
    if metrics.review_required_rate > max_deferred_rate:
        _fail(
            f"review_required の割合 {metrics.review_required_rate:.0%} が "
            f"上限 {max_deferred_rate:.0%} を超えました (--max-deferred-rate)",
            ExitCode.POLICY_VIOLATION,
        )


@app.command()
def version() -> None:
    """バージョンを表示する."""
    print(f"security-checker {__version__}")


def main() -> None:
    """コンソールスクリプトのエントリポイント."""
    try:
        app()
    except SecurityCheckerError as exc:  # pragma: no cover - 最後の砦
        err_console.print(f"[bold red]エラー:[/bold red] {escape(redact_known_patterns(str(exc)))}")
        sys.exit(int(exc.exit_code))
    except Exception as exc:
        # 想定外の例外 (書けない出力先・ディスク不足など) を
        # exit 1 (ポリシー違反) に見せない (§20.1)
        detail = redact_known_patterns("".join(traceback.format_exception(exc)))
        sys.stderr.write(detail)
        err_console.print(
            f"[bold red]内部エラー:[/bold red] {escape(redact_known_patterns(str(exc)))} "
            "(バグの可能性があります。上のスタックトレースを添えて報告してください)"
        )
        sys.exit(int(ExitCode.EXECUTION_ERROR))


if __name__ == "__main__":  # pragma: no cover
    main()
