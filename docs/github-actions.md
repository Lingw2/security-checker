# GitHub Actions で使う

security-checker を PR ごとに動かし、結果を 3 か所に出す方法です。

| 出し先 | 中身 | 役割 |
|---|---|---|
| **status check** (ジョブの成否) | exit code | 「ツールが壊れたか」「ポリシー違反があるか」 |
| **PR コメント** | sticky サマリ 1 件 + 変更行への inline コメント | 人間が読む |
| **Code Scanning** (Security タブ) | `report.sarif` | 履歴管理と、Ruleset によるマージゲート |

設計の背景は [DESIGN.md](DESIGN.md) の §18.3〜18.4 と §21 にあります。

---

## 1. 最小構成

[ci/security.yml](../ci/security.yml) を `.github/workflows/` にコピーします。
複数のリポジトリに入れて必須チェックにするまでの手順は [adoption.md](adoption.md) にあります。

```yaml
permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # PR コメント
      security-events: write # SARIF のアップロード
    steps:
      - uses: actions/checkout@<SHA> # vX.Y.Z
        with:
          fetch-depth: 0             # diff モードで merge-base を求めるのに必要
          persist-credentials: false
      - uses: Sh1n1230/security-checker@<SHA> # vX.Y.Z
        env:
          YOUR_PROVIDER_API_KEY: ${{ secrets.YOUR_PROVIDER_API_KEY }}
```

- 設定はリポジトリ直下の `security-checker.yml` を読みます (`security-checker init` で生成)。
- 設定に `reviewers` が無ければ、LLM を使わずスキャンだけを行います (`review: auto`)。
- `env` には、設定の `api_key_env` で参照している変数**だけ**を渡してください。
- action はタグではなくコミット SHA で固定してください。タグは後から付け替えられます。

## 2. 入力

| 入力 | 既定 | 説明 |
|---|---|---|
| `config` | (自動探索) | 設定ファイルのパス |
| `preset` | | `minimal` / `frugal` / `thorough` / `ci` |
| `target` | `.` | 検査対象ディレクトリ。inline コメントを使うならリポジトリ直下のままにする |
| `mode` | `auto` | `auto` (PR は差分のみ・push は全件) / `full` / `diff` |
| `review` | `auto` | `auto` / `true` / `false`。fork PR では常にスキャンのみ |
| `fail-on` | `high` | この重大度以上の `confirmed` / `likely` で失敗 (`none` で判定しない) |
| `min-score` | `0` | このスコア未満で失敗 (0 で判定しない。スコアは補助指標) |
| `comment` | `true` | PR に sticky サマリと inline コメントを投稿する |
| `upload-sarif` | `true` | SARIF を Code Scanning に登録する |
| `gitleaks-version` / `trivy-version` / `osv-scanner-version` / `semgrep-version` | 空 (固定版) | スキャナの版。空なら [`scripts/scanner-versions.sh`](../scripts/scanner-versions.sh) の版を固定した sha256 で検証して入れる。別の版や `latest` はリリース側のチェックサムで検証し、警告を出す |
| `token` | `github.token` | PR コメントと、スキャナの版に `latest` を指定したときの解決に使う |
| `pr-number` / `head-sha` / `base` / `untrusted-target` | | §5 の workflow_run パターン用 |
| `url` | | v1 互換のため受け付けるだけ (v2 では未対応。警告を出す) |

出力は `score` / `rank` / `report-dir` / `report-json` / `confirmed-count` /
`review-required-count` / `exit-code` です。

### exit code

| code | 意味 |
|---|---|
| 0 | 問題なし |
| 1 | ポリシー違反 (`fail-on` 以上の confirmed / likely、または `min-score` 未満) |
| 2 | 設定エラー |
| 3 | 実行エラー (スキャナの失敗・Reviewer の無効化・未レビューの候補など。`policy.strict: true` のとき) |

コマンドごとの詳しい条件は [exit-codes.md](exit-codes.md) にまとめています。

`review_required` (Reviewer の判断が割れたもの) は**ジョブを落としません**。
サマリと Security タブには残るので、人間が確認してください。

## 3. diff モード

PR では、変更行に関係する候補だけをレビューします (コストのため)。

- コード・シークレット: 候補の行範囲が PR で**追加された行**と重なるもの
- 依存: マニフェスト / ロックファイルが変更されたとき

依存の脆弱性は、コードが変わらなくても新しく公開されます。ロックファイルを触らない PR では出ないため、
[ci/security.yml](../ci/security.yml) は週 1 回 (`schedule`) 既定ブランチを全件検査します。
- 設定ファイル: そのファイルが変更されたとき

比較の基準は `origin/<PR のベースブランチ>` との merge-base です。比べる相手はコミットではなく
**作業ツリー**なので、手元ではコミット前の変更や、まだ `git add` していない新規ファイル
(`.gitignore` で無視されるものを除く) も「この変更で増えた行」に含みます。
バイナリファイル (jar など) は行を持たないため、変更されたファイルとしてだけ数えます。
**checkout には `fetch-depth: 0` が必要です。** 浅い clone で基準が見つからないときは、
全件の検査に戻して警告を出します (`mode: diff` を明示した場合はエラー)。

手元でも同じことができます。

```sh
security-checker review --base origin/main   # main から分岐して以降の変更 (未コミット分を含む)
security-checker review --full               # 全件
```

## 4. PR コメント

- **sticky サマリ**: 1 件だけ作り、push のたびに**編集**します。コメントは増えません。
  指摘が無くなれば既存のコメントを ✅ に更新します。最初から指摘が無ければ何も投稿しません
  (`github.comment_on_clean: true` で常に投稿)。
- **inline コメント**: `github.inline_min_status` (既定 `likely`) 以上の指摘を、該当行に付けます。
  diff に含まれない行には付けられないため、範囲外の指摘はサマリにだけ出ます。
  上限は `github.max_inline_comments` (既定 20)。
  **同じ指摘 (同じ fingerprint) には二度とコメントしません。**
- `false_positive` は PR に出しません (`report.json` には残ります)。
- 既存のサマリと inline コメントは、**本文先頭のマーカーと投稿者の両方**で見分けます。
  投稿者は `github.comment_author` (既定 `github-actions[bot]`) です。PAT や GitHub App のトークンで
  投稿する場合は、その login を設定してください。マーカーを含む他人のコメントは無視し、件数を警告に出します。

本文の多くは LLM の出力で、レビュー対象のコードに由来する文字列を含みえます。
投稿前に @メンションの無効化・HTML (コメント・タグ) と画像の無効化・コードスパンからの脱出防止・
既知形式のシークレットのマスクを行います。Step Summary に載せる `report.md` にも同じ規則を適用します。

コメントの投稿は `review` と別のコマンドです。保存済みの `report.json` から投稿できます。

```sh
GITHUB_TOKEN=... security-checker comment .security-checker/report.json --repo owner/name --pr 12
```

- 権限不足 (403) と PR が見つからない (404) は **exit 3** です。`pull-requests: write` の付け忘れや
  PR 番号の誤りを緑のまま見逃さないためです。投稿できないと分かっている場面では `--allow-readonly` で
  警告に落とせます。
- 二次レート制限は `Retry-After` が 60 秒以内なら 1 回だけ待って送り直し、それ以上ならレート制限として exit 3。
- inline コメントのうち GitHub が 422 で受け付けないもの (行が diff に無いなど) は、それだけを数えて残りを投稿します。
- 警告は GitHub Actions では `::warning::` の注釈としても出します。

## 5. fork からの PR

`pull_request` イベントの fork PR では、

- **シークレットが渡りません。** LLM レビューはできないので、スキャンのみを行い、
  ジョブサマリにそう書きます (黙って 0 件にはしません)。
- **`GITHUB_TOKEN` が read-only になります。** コメントも SARIF のアップロードもできないので、
  どちらもスキップして理由を残します。

fork PR にもコメントと Code Scanning の結果を付けたいときは、
[ci/security-fork-publish.yml](../ci/security-fork-publish.yml) を追加します (`workflow_run` パターン)。

```text
fork PR ──► Security Check (pull_request)         権限なし・シークレットなし。スキャンのみ
                 │ completed
                 ▼
            Security Check (fork PR publish)       既定ブランチの定義で、権限付きで動く
              1. 既定ブランチを checkout (action と設定はこちらを使う)
              2. PR のコードを別ツリーに展開する (読むだけ。実行しない)
              3. untrusted-target: true で検査し、ref/sha を PR に向けて SARIF を登録・コメント
```

### `pull_request_target` を使わない理由

`pull_request_target` は、fork のコードを**書き込み権限とシークレット付きの文脈で**動かします。
PR のコードを checkout して何かを実行した瞬間に、シークレットとリポジトリへの書き込みが
外部の人に渡ります。サンプルでは使いません。

### publish 側で守っていること

- **成果物 (artifact) を信用しない。** fork 側は `pull_request` の workflow 自体を書き換えられるので、
  成果物の `report.sarif` は偽造できます。偽の「指摘ゼロ」を上げられると、Code Scanning のゲートが
  素通りになります。publish 側は成果物を使わず、**PR のコードを読むだけで検査し直します。**
  スキャナ (semgrep / gitleaks) はファイルを読むだけで、PR のコードを実行しません。
- **PR が置いた設定を読まない。** `untrusted-target: true` (環境変数
  `SECURITY_CHECKER_UNTRUSTED_TARGET=1`) のとき、検査対象のツリーにある `security-checker.yml` /
  `security-checker.local.yml` を一切読みません。読むと、その中の `command` がシークレット付きで
  実行されます。設定は検査対象の外 (既定ブランチの checkout) から `config` で渡します。
  スキャナ自身の設定 (`.gitleaks.toml`・`trivy.yaml`・`.trivyignore`・`osv-scanner.toml`) と
  `nosemgrep` / `gitleaks:allow` 注釈も効かせません。止められない `.gitleaksignore`・`.semgrepignore` は
  警告に出します (docs/security-model.md §5.1)。
- **`transport: process` の Reviewer を fork のコードに向けない。** 手元の AI CLI はツールを
  持ちうるため、信用できないコードに含まれる指示 (プロンプトインジェクション) で動かされる余地が
  あります。publish 側の設定には `transport: http` の Reviewer だけを置いてください。
- この workflow に、PR のコードのビルド・テスト・依存のインストールを**足さないでください。**

### 既知の限界

スキャナは検査対象に置かれた自身の設定 (`.gitleaks.toml`・`.semgrepignore` など) を読みます。
fork PR はこれで検出を減らせます。コードが実行されるわけではありませんが、
**fork PR の「指摘ゼロ」は、これらのファイルの変更が無いことを確かめてから信用してください。**

## 6. Code Scanning をマージゲートにする

SARIF は次の規約で作られます (§18.3〜18.4)。

- `tool.driver.name` と category は常に `security-checker`。Ruleset はこの名前で指定します。
- `level` は**スキャナの severity** で決めます。LLM の判定で決めると、非決定性で alert が
  開いたり閉じたりするためです。LLM の判定は `message` と `properties` に載ります。

| status | level |
|---|---|
| `confirmed` | critical/high → `error`、medium → `warning`、low 以下 → `note` |
| `likely` | 上の 1 段下 |
| `review_required`・判定なし・diff 外 | `note` |
| `false_positive`・抑制済み | 出力しない |

`security-severity` は付けません ([ADR 0009](adr/0009-gate-on-sarif-level-only.md))。
Ruleset では Alerts の閾値に `Errors` を選び、Security alerts の閾値は `None` にしてください。
代わりに Security タブの Critical / High の表示は出ません。

- **スキャナが 1 つでも失敗した run、または有効にしたスキャナが入っていない run の SARIF は
  アップロードしません。** 一部の結果が欠けた SARIF を上げると、既存の alert が「解決済み」として
  一括で閉じるためです。対象が無いだけの skip (osv-scanner のマニフェストが無いなど) は止めません。
  `invocations[].executionSuccessful: false` で判別でき、action はこれを見てスキップします。
  exit code 3 で status check も落ちます。
- diff モードでレビューしなかった候補も `note` で出します。出さなければ既存 alert が閉じ、
  元の level で出せば既定ブランチの判定と食い違うためです。

Ruleset の "Require code scanning results" (ツール名 `security-checker`) は、
**fork PR の `workflow_run` を用意し、外部からの PR でアップロードが通ることを確かめてから**
有効にしてください。先に有効にすると、外部からの PR は永久にマージできなくなります。

## 7. Docker イメージ

スキャナ同梱のイメージを [Dockerfile](../Dockerfile) からビルドできます
(GHCR への公開は今後の予定です)。

```sh
docker build -t security-checker .
# レポートを書けるよう、手元のユーザーで動かす
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" security-checker scan .
```
