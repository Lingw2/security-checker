# security-checker

[English](README.md) | **日本語**

[![CI](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Sh1n1230/security-checker/badge)](https://scorecard.dev/viewer/?uri=github.com/Sh1n1230/security-checker)
[![Release](https://img.shields.io/github/v/release/Sh1n1230/security-checker)](https://github.com/Sh1n1230/security-checker/releases)
[![License: MIT](https://img.shields.io/github/license/Sh1n1230/security-checker)](LICENSE)

既存のスキャナの検出結果を、**独立した LLM が第三者の監査役としてレビューする** AI Security Review
プラットフォームです。本物の問題を隠さずに誤検出を減らすことを目指しています
(設計は [docs/DESIGN.md](docs/DESIGN.md))。

> v1(bash / PowerShell 実装の `check.sh` / `check.ps1`)は撤去しました。必要なら `v1.1.0` タグを参照してください。

## 状況と使い方

Python 実装。移行計画(設計書 §32)のうち **P5「品質」まで実装済み**です。残りは公開 (P6) と運用の切り替え (P7) で、[docs/NEXT-STEPS.md](docs/NEXT-STEPS.md) に手順があります。

| フェーズ | 内容 | 状態 |
|---|---|---|
| P1 | models / config / CLI の骨格、`scan` サブコマンド、semgrep + gitleaks アダプタ | ✅ 完了 |
| P2 | 単一 LLM レビュー(`http` transport / Context Builder / Structured Output) | ✅ 完了 |
| P2.5 | `process` transport(API キーなしで動く) | ✅ 完了 |
| P3 | 4 方言 (`openai_chat` / `ollama_chat` / `anthropic_messages` / `gemini_generate`)、`weighted` 集約 | ✅ 完了 |
| P4 | SARIF / diff モード / PR コメント / GitHub Action / Dockerfile([docs/github-actions.md](docs/github-actions.md)) | ✅ 完了 |
| P5 | osv / trivy、Judge、baseline・ignore・注釈、`providers check`、`--estimate`、`explain`、rpd / tpm、構造化ログ、契約テスト・カセット | ✅ 実装済み |
| P6 | 評価と公開 | 🚧 データセット 100 件・docs 一式・英語 README・リリース用 workflow まで。実 LLM での評価と PyPI / GHCR 公開は未実施 |
| P7 | ゲート | 未着手 |

```sh
uv sync --group dev                      # 開発環境
uv run security-checker scan .           # スキャナのみで検査 (LLM は使わない)
uv run security-checker scan . --strict --fail-on high
uv run security-checker review .         # スキャン結果を LLM Reviewer でレビュー
uv run security-checker review . --dry-run       # 送信予定の内容を送信前に全部見る
uv run security-checker review . --base origin/main  # main からの変更行に関係する候補だけ
uv run security-checker scan . -f sarif          # Code Scanning 用の report.sarif を出す
uv run security-checker comment                  # report.json を PR にコメント (GITHUB_TOKEN)
uv run security-checker review . --estimate      # 呼び出し回数と金額の見積り (送らない)
uv run security-checker explain <id>             # その判定に至った全 Reviewer の判断と呼び出し記録
uv run security-checker baseline update          # いまの検出を baseline に記録 (段階導入)
uv run security-checker providers check          # Reviewer の疎通と構造化出力を確認
uv run security-checker config show --explain    # 解決された設定と、その決定元
uv run security-checker init                     # 環境を検出して設定を生成する
uv run security-checker eval --dataset benchmarks/datasets/handmade-v1  # ラベル付きデータでレビュー精度を測る
```

### Reviewer の設定 (review 用)

Reviewer は**ベンダーではなく transport × dialect** で指定します。`openai_chat` 方言を話す
エンドポイントであれば、提供元がどこであっても同じ設定で動きます。

```yaml
reviewers:
  - name: r1
    transport: http           # 必須。推測で補完しない
    dialect: openai_chat      # リクエスト/レスポンスの「形」
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: MY_API_KEY   # 環境変数名のみ。平文キーの項目は存在しない
    rate_limit: { rpm: 10 }   # 無料枠などの制限を宣言するとスケジューラが尊重する
```

既定の Reviewer は**ありません**(特定のベンダーを事実上の標準にしないため)。
ベンダー知識は `providers/presets/*.yml` の**データ**にのみ置き、コードには現れません。

同梱プリセットを使うと `base_url` などを省略できます(`http`: `openai` / `process`: `claude`。
アルファベット順で、推奨の意味はありません)。**一覧に無いものも同じように動きます** —
`dialect` + `base_url` や `command` を直接書くだけです。
`~/.config/security-checker/presets/<transport>/<name>.yml` に置けば、自分用のプリセットを
追加・上書きできます(PR 不要)。詳しくは [docs/providers.md](docs/providers.md)。

### API キーを持っていない場合 — `process` transport

**手元の非対話コマンドをそのまま Reviewer にできます。**認証はそのコマンド側の既存ログインに
委ねるため、API キーの設定は要りません。特定の CLI 向けの機能ではなく、
「stdin を受け取り stdout にテキストを返す」契約を満たすものはすべて同じ経路で扱われます。

```yaml
reviewers:
  - name: local-command
    transport: process
    command: ["<your-command>", "--non-interactive", "--no-tools"]
    prompt_via: stdin         # stdin | file
    timeout_s: 300
```

```sh
uv run security-checker init --command '<your-command> --non-interactive --no-tools'
```

起動対象は任意のコマンドなので、**P3(レビュー対象を書き換えない)を transport の性質に
よらず守ります**。毎回作り直す空の一時ディレクトリで `shell=False` 起動し、プロンプトは
stdin(または一時ファイル)でのみ渡し、実行後に書き込みを検知して警告し、タイムアウト時は
プロセスグループごと回収します。ただし**コマンド自体の書き込み能力を無効化できているかは
本体からは検証できない**ため、非対話・ツール無効のフラグは利用者が指定してください
(起動時に警告が出ます)。

`process` は「安価だが荒い」transport です。構造化出力は `prompt_only` のみ、
コストは `unknown`、トークンは推定値になります。詳細と注意点(**対象コマンドの利用規約は
利用者が確認してください**)は [docs/process-transport.md](docs/process-transport.md) に
まとめてあります。性質の異なる transport を混ぜると agreement が情報量を持ちやすくなります。

構造化出力は `json_schema → json_mode → prompt_only` の順に自動で降格し、
スキーマ違反の応答は 1 回だけ修復を試みます。それでも駄目なら `schema_error` として
**レポートに残します**(黙って消しません)。

### レビュー結果の読み方

判定は `confirmed` / `likely` / `review_required` / `false_positive` / `inconclusive` /
`error` / `not_reviewed` に分かれます。**`review_required`(判断が割れた・信頼度が低い)は
`confirmed` の直後に表示します。** 割れた判断こそ人間が見るべきものだからです。
Reviewer が 1 個のときは `agreement: not_applicable` とし、「1 モデルの合意」を
高い一致度として偽装しません。

コードを外部に送ることについては [docs/security-model.md](docs/security-model.md) を参照してください。

出力は `.security-checker/` 配下に、**人間向けの `report.md`** と機械可読の
`report.json`(`schema_version` 付き)、各スキャナの生出力 `raw/`。`report.json` は 19 個の
トップレベルキーを持つ機械可読レポートなので、**読むのは `report.md` かターミナル出力**です。

レポート本文(判断理由・攻撃経路・対応方針)は LLM が書いた文章そのものです。言語は
`output.language` で決まり、既定の `auto` はロケール(`LANG` など)から推定します。
日本語環境ならそのまま日本語で出力されます。明示するなら:

```yaml
output:
  language: ja      # auto | ja | en | ko | ... (未知のタグはそのまま LLM に渡す)
```

推定結果はトレースに記録されるので、後から「どの言語で書かせたか」を確認できます。
設定は `security-checker.yml`(サンプルはリポジトリ直下)を自動探索し、
**組み込み既定値 → `--preset` → 設定ファイル → ローカル設定 → 環境変数
(`SECURITY_CHECKER__POLICY__FAIL_ON` 形式)→ CLI フラグ** の順に、後勝ちで合成します。

手元でだけ使う Reviewer は `security-checker.local.yml`(git 管理外・`.gitignore` 済み)に
書きます。共有設定の後に重なるので、`security-checker.yml` を汚さずに個人の Reviewer を
足せます (`reviewers` は名前で合成します)。`security-checker init --local` で生成でき、`config show --explain` に
どの層で決まったかが出ます。

終了コードは目的別に分かれています(設計書 §17.1)。

| code | 意味 |
|---|---|
| 0 | ポリシー違反なし |
| 1 | `fail_on` 以上の検出、または `min_score` 未満 |
| 2 | 設定エラー |
| 3 | 実行エラー(`--strict` 時にスキャナの失敗・Reviewer の無効化・未レビューの候補がある) |

コマンドごとの条件は [docs/exit-codes.md](docs/exit-codes.md) にまとめています。

**1 と 3 を分けているのが v1 との最大の違いです。** v1 には「スキャナが失敗しても 0 件成功として扱われ、
スコアが満点に見える」欠陥がありました。v2 は `skipped`(未導入)と `failed`(異常終了)を区別し、
どちらの場合もスコアに `partial` フラグを立てます。

検出されたシークレットの値は Candidate にもレポートにも書き出しません(マスク済みの形式のみ)。
漏洩した値を成果物や外部 LLM に再送しないためです(設計書 §19.2)。

## インストール

```sh
uv tool install git+https://github.com/Sh1n1230/security-checker   # PyPI 公開までは git から
security-checker version
```

検出はスキャナが行います。使うものを入れてください(未導入のものは `skipped` として報告され、
「問題なし」とは扱われません)。

```sh
brew install gitleaks semgrep trivy osv-scanner                   # macOS
winget install Gitleaks.Gitleaks AquaSecurity.Trivy Google.OSVScanner && pipx install semgrep  # Windows
```

スキャナ同梱の Docker イメージ(`Dockerfile`)も使えます。

## GitHub Actions で使う

リポジトリ直下の [action.yml](action.yml) は **v2** を動かします。
各リポジトリのワークフローには呼び出しの数行だけを書きます([ci/security.yml](ci/security.yml) がそのサンプル)。

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # PR コメント
      security-events: write # SARIF を Code Scanning に登録するため
    steps:
      - uses: actions/checkout@<SHA> # vX.Y.Z
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Sh1n1230/security-checker@<SHA> # vX.Y.Z
```

- PR では**変更行に関係する候補だけ**をレビューし(diff モード)、sticky サマリ 1 件と
  inline コメントを付けます。push のたびにコメントが増えることはありません。
- `report.sarif`(ツール名・category とも `security-checker`)を Code Scanning に登録します。
  **スキャナが失敗した run の SARIF は上げません。** 既存の alert が「解決済み」に化けるためです。
- fork からの PR では LLM レビュー・コメント・SARIF 登録をスキップし、その旨をジョブサマリに残します。
  fork PR にも結果を付けるなら [ci/security-fork-publish.yml](ci/security-fork-publish.yml)
  (`workflow_run` パターン)を足します。`pull_request_target` は使いません。

入力の一覧、exit code、Code Scanning をマージゲートにするときの注意は
[docs/github-actions.md](docs/github-actions.md) にあります。
v1 の入力(`min-score` / `upload-sarif` / `token` / `url`)も受け付けますが、
`min-score` の既定は `0`(判定しない)に変わり、`url`(Web 検査)は v2 では未対応です。

## 補助ツール (contrib/host-audit/)

成果物ではなく「自分の環境・運用」を検査する単体ツール群(v1 から引き継いだもの。本体とは独立して動く)。すべて読み取り専用(install_hooks.sh を除く)。

| ツール | 内容 |
|---|---|
| `contrib/host-audit/audit_macos.sh` | Mac本体の設定監査(FileVault・ファイアウォール・SIP・共有設定等) |
| `contrib/host-audit/check_ports.sh` | 待ち受け中ポートの棚卸しと外部公開の警告 |
| `contrib/host-audit/check_permissions.sh [dir]` | ~/.ssh や認証情報ファイルの権限、誰でも書けるファイルの検出 |
| `contrib/host-audit/install_hooks.sh [repo]` | git フックを導入(pre-commit: シークレット検査 / pre-push: 保護ブランチへの直接 push と force push を禁止)。省略時は現在のリポジトリ |
| `contrib/host-audit/check_shell_env.sh` | シェル履歴・dotfiles・環境変数へのシークレット漏れを検出 |
| `contrib/host-audit/check_git_history.sh <repo>` | git全履歴からシークレット漏洩を検出(現在消していても過去分を発見) |
| `contrib/host-audit/check_tls_cert.sh <domain>` | TLS証明書の期限・古いTLS(1.0/1.1)受け入れを検査 |
| `contrib/host-audit/check_updates.sh` | OS/brewの未適用アップデートとバックアップ状態を確認 |
| `contrib/host-audit/run_all.sh [dir] [--domain d]` | 上記の環境系チェックを一括実行(定期実行向け) |

いずれも問題検出時は exit 1 を返すので、cron や CI に組み込めます。

### Windows版 (contrib/host-audit/windows/)

同等の環境系チェックの PowerShell 7 版です。

| ツール | 内容 |
|---|---|
| `contrib/host-audit/windows/audit_windows.ps1` | Windows本体の設定監査(BitLocker・Defender・ファイアウォール・共有設定等) |
| `contrib/host-audit/windows/check_ports.ps1` | 待ち受け中ポートの棚卸しと外部公開の警告 |
| `contrib/host-audit/windows/check_permissions.ps1 [-Target dir]` | ACLの緩いファイル・認証情報ファイルの検出 |
| `contrib/host-audit/windows/check_shell_env.ps1` | PowerShell履歴・環境変数へのシークレット漏れを検出 |
| `contrib/host-audit/windows/check_tls_cert.ps1 -Domain <domain>` | TLS証明書の期限・古いTLS(1.0/1.1)受け入れを検査 |
| `contrib/host-audit/windows/check_updates.ps1` | Windows Update/wingetの未適用アップデートを確認 |
| `contrib/host-audit/windows/run_all.ps1 [-Project dir] [-Domain d]` | 上記の環境系チェックを一括実行(タスクスケジューラ等での定期実行向け) |

`contrib/host-audit/check_git_history.sh` は bash 実装のため、Windows では Git Bash 経由(`contrib/host-audit/windows/run_all.ps1` から自動検出して呼び出し)で利用します。専用の `.ps1` 版はありません。

## 開発時のガードレール

AI エージェントにも人間にも危険な git 操作をさせないための仕掛けを、**強制力の順に3層**に分けています。

| 層 | 効く範囲 | 迂回手段 | 置き場所 |
|---|---|---|---|
| 1. GitHub Ruleset | 全員・全ツール(サーバ側) | **なし** | GitHub 設定 |
| 2. git フック | ローカルの全操作。人間にも任意のエージェントにも効く | `--no-verify` | `contrib/host-audit/hooks/` |
| 3. エージェントの権限設定 | そのツールのエージェントのみ | シェルの書き方で容易に迂回可 | `.claude/settings.json` |

```sh
./contrib/host-audit/install_hooks.sh          # 2 を導入する
```

**保護ブランチへの直接 push と force push の禁止は 1 と 2 に置いています。** 3 には置いていません。
コマンド文字列のパターンマッチは `git -C <path> push --force origin main` のような書き方で
容易にすり抜けるため、そこに防御を委ねてはいけないからです。3 には読み取り系 git コマンドの許可と、
force push・`filter-branch` の拒否(1 と 2 の補助)だけを宣言しています。commit・push・`gh pr` などに
確認を挟む設定は置いていません。防御は 1 と 2 が担っており、エージェントが issue や PR を自律的に
進める妨げになるためです。確認が欲しい人は自分の `~/.claude/settings.json` に `ask` を足してください。

`.claude/settings.json` は**宣言のみで実行スクリプトを含みません**。エージェント用のフックスクリプトは
「clone して開いた人のマシンで実行されるコード」になるため、このリポジトリでは置かない方針です。
他のツールを使う場合も、実体は `contrib/host-audit/hooks/` がそのまま使えます。

## Claude Code スキル (skills/)

Claude Code から自然言語で検査・修正を頼めるスキル(モデル非依存)。導入:

```sh
cp -r skills/security-check skills/security-fix ~/.claude/skills/
```

- **security-check**: 「セキュリティチェックして」→ `security-checker scan` / `review` を実行し、結果を解説
- **security-fix**: 「検出された問題を直して」→ 優先順位付けと安全な修正手順で対応

自動検出できるのは一部です。認証設計・権限管理などは
[checklist/CHECKLIST.md](checklist/CHECKLIST.md) で手動確認してください。

## 参加する

- [CONTRIBUTING.md](CONTRIBUTING.md) — 開発環境、PR の出し方、**設計上の不変条件**、
  プリセットの足し方（コードを書かずに新しい LLM を足す方法）
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — 行動規範（Contributor Covenant v2.1）
- [SECURITY.md](SECURITY.md) — **脆弱性は公開 Issue ではなく非公開で報告してください**
- [docs/README.md](docs/README.md) — ドキュメントの目次
- [docs/DESIGN.md](docs/DESIGN.md) — 「なぜそうなっているか」はここに書いてあります
- [docs/NEXT-STEPS.md](docs/NEXT-STEPS.md) — 残作業と、決める必要があること

Issue と PR は日本語でも英語でも構いません。

## ライセンス

[MIT](LICENSE)
