# v2 残作業と手続き書

- 作成日: 2026-09-11 / 最終更新: 2026-11-04
- 基準: `origin/main` = `1afcd85`（#2 で P1〜P2.5 を squash merge 済み）
- 照合元: [DESIGN.md](DESIGN.md) §32 移行計画・§33 リスク

---

## 0. 現状（2026-11-04 時点の実測）

| 項目 | 状態 |
|---|---|
| リリース | `v2.1.0` を GitHub Release で公開済み。release-please のリリース PR (#100, `2.2.0`) が待機中。PyPI・GHCR は未公開 (変数で無効化中) |
| フェーズ | P1〜P5 完了。P6 は実 LLM での eval と PyPI / GHCR 公開が残り。P7 未着手 |
| 品質 | pytest 978 件 (POSIX 以外向けと実スキャナ未導入時の skip を除きすべて成功) / カバレッジ 95% / mypy --strict・ruff エラーなし |
| ドキュメント | 目次 [README.md](README.md)・終了コード [exit-codes.md](exit-codes.md) を追加。英語 README に終了コード・host-audit・ガードレール・スキルの節を追加 |
| ブランチ | D13 の古いブランチ (backup/*・feat/v2-*・docs/design-v2) は削除済み。残っているのは開いている PR のブランチだけ |
| Issue / PR | Issue が約 480 件 (大半はコードを機械的に読んで洗い出した `good first issue` / テストの穴)。外部からの PR が約 20 件レビュー待ち |
| 残っている人間の作業 | §2 の D1・D2・D12、§3 Step 6 の 1・3・4、Step 7。外部 PR のレビュー |

以下は 2026-10-04 時点の記録。

## 0''. 現状（2026-10-04 時点の実測）

| 項目 | 状態 |
|---|---|
| フェーズ | P1〜P5 完了（P4 の完了条件 = main の Security タブに `security-checker` の alert、を確認）。v1 撤去済み。P6 はリリース準備まで。P7 未着手 |
| 品質 | pytest 654 件すべて成功 / カバレッジ 94% / mypy --strict・ruff エラーなし |
| Scanner | semgrep・gitleaks・osv・trivy |
| Aggregator | consensus・weighted・judge |
| レポート | terminal・json・markdown・**sarif**、PR コメント (`comment`) |
| 残っている人間の作業 | §2 の D1・D2・D12・D13、§3 Step 6・Step 7、**Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests" を有効化**（無効のままだと release-please がリリース PR を作れず Release workflow が落ちる） |

以下は 2026-09-11 時点の記録。

## 0'. 現状（2026-09-11 時点の実測）

| 項目 | 状態 |
|---|---|
| フェーズ | P0（一部）・P1・P2・P2.5 完了。P3〜P7 未着手 |
| 品質 | pytest 351 件すべて成功 / カバレッジ 93% / mypy --strict・ruff エラーなし |
| Scanner | semgrep・gitleaks のみ（osv・trivy は未実装。有効化すると warning を出して無効化される） |
| Provider | `http` transport は `openai_chat` 方言のみ。`process` transport あり |
| Aggregator | `consensus` のみ（`weighted`・`judge` は未実装。指定すると ConfigError） |
| レポート | terminal・json・markdown。**SARIF は未実装** |
| 同梱プリセット | `providers/presets/{http,process}/` は空（意図どおり） |
| GitHub 設定 | squash のみ許可・ブランチ自動削除・Ruleset `protect main` あり。**Private vulnerability reporting は無効** |
| ローカル git | `main` が `origin/main` より 1 コミット遅れ。`feat/v2-core` の中身は `origin/main` と一致（マージ済み） |

---

## 1. 足りていないもの

### 1.1 今すぐ直すべきもの（設計原則に違反している）

**✅ 対処済み（2026-09-17）**: `config/unimplemented.py` が、受け付けたが効かない設定を検出して
警告に積むようになりました（レポートの `warnings[]`・ターミナル・`config show` の 3 箇所に出ます）。
実装が入った項目はこのモジュールからエントリを消します。

対象は `output.formats: [sarif]`（P4）・`policy.baseline`（P5）・`target.mode: diff`（P4）・
`github.*`（P4）・`logging.*`（P5）・`reviewers[].num_ctx`（P3）。
P4 で `sarif`・`diff`・`github.*` は実装し、警告から外した。
`github.*` と `logging.*` は**利用者が明示的に設定したときだけ**警告します（既定値のままならノイズになるため）。

### 1.2 フェーズ計画上の未実装（DESIGN.md §32）

| フェーズ | 未実装のもの | 設計書 |
|---|---|---|
| ~~**P3 Multi-LLM**~~ | **✅ 完了（2026-09-18）**: 4 方言すべて・`weighted` 集約・異なる transport の E2E | §9.4–9.6, §14.2 |
| ~~**P4 GitHub 統合**~~ | **✅ 実装済み（2026-10-04）**: `report/sarif.py`・`github/pr.py`（diff モード）・`github/comment.py`・`github/client.py`（sticky・inline・重複投稿防止）・`comment` コマンド・`action.yml`（v2・composite）・`Dockerfile`・`ci/security-fork-publish.yml`・`docs/github-actions.md`。**残り**: 自リポジトリの PR で動かし Security タブに `security-checker` の alert が出ることの確認（完了条件） / D8 の v1 撤去 | §7.4, §18.3–18.4, §21 |
| ~~**P5 品質**~~ | **✅ 実装済み（2026-10-04）**: osv・trivy アダプタ / `judge` 集約 / baseline・`.security-checker-ignore`・コード内注釈 / `rpd`（+ 受け付けていたが効いていなかった `tpm`） / `--estimate` / `explain` / `providers list`・`check` / 構造化ログ / `scanner_contract.py` / カセット（仕組みのみ。**実 LLM の記録はまだ無い**） | §16, §17.2, §22, §24, §25, §29.3 |
| **P6 評価と公開** | **済（2026-10-04）**: データセット 100 件（TP 48 / FP 52）/ docs 一式・`adr/` / 英語 README（正典）+ `README.ja.md` / `release.yml`（release-please・PyPI Trusted Publishing・GHCR。公開は変数で無効化中）/ CI の Docker ビルド確認。**残り（人間の作業）**: 実 LLM での eval と D12 / D1 の配布名確保と Trusted Publisher 登録 / `v2.0.0` リリース / README 以外の docs の英語化 | §26–27, §30–31 |
| **P7 ゲート** | v1 の生 SARIF 4 category の撤去 / Ruleset に "Require code scanning results"（`security-checker`） | §18.4.5 |
| ~~**v1 撤去**~~ | **✅ 完了（2026-10-04）**: `check.sh`・`check.ps1`・`lib/` を削除、`tools/` → `contrib/host-audit/`、`skills/` を v2 CLI 向けに書き換え、README の v1 節を整理、`security-windows` ジョブを `.ps1` 構文リントのみの `ps1-lint` に縮小。`ci/security.yml` は v2 の利用サンプルになったため残す | §5「v1 資産の扱い」 |

### 1.3 テストの穴（L3 自己適用の不変条件, §31.5）

**✅ 対処済み（2026-10-04）**: 3 点とも埋めた。

- プロンプトインジェクション: `tests/unit/test_prompt_injection.py`。この過程で、**呼び出し元のコード (callers) が
  デリミタのエスケープを通っていなかった**穴を見つけて塞いだ。
- 除外パス: `tests/unit/test_self_application.py`（本体が除外されていない / フィクスチャは除外されている）。
- terminal レポート: カバレッジ 60% → 99%。

以下は当初の記録。

- **プロンプトインジェクション耐性の回帰テストがない。** 現在あるのはデリミタとエスケープの存在確認（`tests/unit/test_reviewer.py`）まで。
  「注入文字列を埋めたフィクスチャで、FakeProvider に渡るプロンプトの構造が崩れない」ことを検証するテストを足す。
- **除外パス配下に本体パッケージが紛れ込んでいないことの検査**がない。
- terminal レポートのカバレッジが 60% と、ほかに比べて低い。

---

## 2. 人間が決めるべきもの

各項目に推奨を付けた。**「期限」は、決めないとそのフェーズに着手できない地点。**

| # | 決めること | 推奨 | 期限 |
|---|---|---|---|
| **D1** | **PyPI の配布名。** `security-checker` は**既に登録済み**（pypi.org で 200 を確認）。`security-checker-ai` は 2026-09-11 時点で未登録 | `security-checker-ai` を今すぐ確保（空のプレースホルダ公開か、Trusted Publishing の pending publisher 登録）。CLI 名は `security-checker` のまま（R8） | P6 前。名前は取られうるので早いほどよい |
| **D2** | **設計書の確定。** DESIGN.md の Status が `Draft` のまま。P0 の完了条件「設計合意」が未達 | 本書の D3〜D5 を反映したうえで `Accepted` にする | P3 前 |
| **D3** | **SARIF の `level` を何で決めるか**（R14）。LLM 判定で決めると、非決定性で alert が開閉を繰り返す | **決定（2026-09-15）: スキャナ由来の severity で決める。** LLM の判定は `message` と `properties` に載せる | 決定済み |
| **D4** | **評価（§27）を前倒しするか**（R1・R2）。LLM が FP を減らすかどうかは未検証 | 前倒しする。P3 と並行で自前データセットを 20 件ほど作り、single と consensus を比べる | P3 中 |
| **D5** | **このリポジトリ自身の dogfooding に使う Reviewer。** `security-checker.local.yml` に Claude Code の CLI（`claude-cli`）が入っているが、開発にも Claude Code を使っている。「開発に使う AI とレビューする AI を分ける」（§9）という原則と、自分のリポジトリで矛盾する | 自リポジトリでは開発に使っていない系統を Reviewer にする。`claude-cli` は他プロジェクト用と割り切るなら、そのままでよい | P3 の E2E 前 |
| **D6** | **無料 HTTP エンドポイントにコードを送ってよいか。** `openrouter/free` は、振り分け先のモデル提供者がプロンプトを学習・記録する可能性がある | 公開リポジトリのコードに限って許容する。非公開コードには使わない（→ `docs/security-model.md` に明記） | 他リポジトリで使う前 |
| **D7** | **`process` Reviewer の禁止ツールを列挙する書き方の妥当性。** `--disallowed-tools` は拒否リストなので、対象 CLI にツールが増えると漏れる（空の一時 cwd で起動しているので被害は限定的） | 対象 CLI が許可リスト方式か「ツール全無効」の指定を持っているなら、そちらに切り替える | 次に local 設定を触るとき |
| ~~**D8**~~ | **✅ 完了（2026-10-04）。** v1 資産の撤去時期 | P4 完了時（v2 で CI が回るようになった時点）に削除。`tools/` は `contrib/host-audit/` に移す。別リポジトリ化（R12）は v2.1 以降 | P4 完了時 |
| ~~**D9**~~ | **✅ 有効化済み（2026-10-04 確認）。** 脆弱性の報告窓口 | 今すぐ有効化し、`SECURITY.md` にその旨を書く | 今すぐ |
| **D10** | **ドキュメントの正典言語**（§30.1 は英語を正典としている） | **決定（2026-09-15）: 当面は日本語のまま。** 英語化は P6 でまとめて行う | P6 |
| **D11** | **v2.0 に同梱するプリセット** | **決定（2026-09-15）: 客観条件を満たすものを同梱する。** 対象は `process`: codex CLI・claude CLI、`http`: OpenAI 互換エンドポイント。アルファベット順・順位づけなし | P3 中 |
| **D12** | **既定の Reviewer 数・集約戦略** | 決めない。D4 の評価結果を見てから決める（R2） | P6 |
| ~~**D13**~~ | **✅ 完了（2026-11-04 確認）。** 不要ブランチの削除。 `backup/pre-secret-fix-20260906-184124`・`backup/pre-squash-20260830`・`feat/v2-p1-skeleton`・`docs/design-v2`・`feat/v2-core` | 中身が `origin/main` に入っていることを確認したうえで削除。backup/* は念のため 1 か月残してもよい | いつでも |

---

## 3. 手続き（この順に進める）

### Step 0. 地ならし（半日）

```sh
# ローカル main を最新化し、作業ブランチを切り直す
git switch main
git pull --ff-only
# feat/v2-core は squash merge 済みのため -d では消えない。差分が空であることを確かめてから -D
git diff --stat main feat/v2-core     # 何も出なければ中身は main に入っている
git branch -D feat/v2-core

# D13: 残りのブランチは中身を確かめてから削除
# （squash merge 済みのブランチは log では常に差分が出るので、diff で中身を比べる）
git diff --stat main feat/v2-p1-skeleton
git diff --stat main docs/design-v2
```

- [x] D9: GitHub の Settings → Security → Private vulnerability reporting を有効化
- [ ] D1: PyPI で `security-checker-ai` を確保
- [ ] `reports/`（v1 が他プロジェクトを検査した結果。git 管理外）をローカルから削除（§0 前提の確認）

### Step 1. 黙って無視される設定を塞ぐ（1 PR, `fix(config)`）

§1.1 の 4 項目。未実装の値が指定されたら `warnings[]` に積み、`--strict` なら exit 2 にする。
**P3 より先にやる。** 放置すると `--preset ci` を使った人が SARIF が出ていないことに気づけない。

- 完了条件: `review --preset ci` で「sarif は未実装」の警告が出ることをテストで確認できる

### Step 2. 人間の決定（D2〜D5）を設計書に反映（1 PR, `docs`）

- D3 を §18.3 / R14 に、D4 を §32 に書き込み、Status を `Accepted` に変える
- 本書の §2 のうち決めたものに「決定」と日付を入れる

### Step 3. P3 Multi-LLM（方言ごとに 1 PR）

1. `feat(providers): ollama_chat` — ローカルで API キーなしに検証できるので最初にやる
2. `feat(providers): anthropic_messages` — tool use forcing による structured output
3. `feat(providers): gemini_generate` — スキーマ変換層
4. `feat(aggregate): weighted`
5. `test(e2e)`: http と process の Reviewer 2 つで判断を割り、`review_required` が出る

各方言は `ProviderContractTests` を通すこと（§25.2）。
**並行して D4 の評価用ケースを 20 件作り始める**（`benchmarks/datasets/handmade-v1/cases/`）。

- 完了条件: DESIGN.md §32 の P3 行

### Step 4. P4 GitHub 統合 — 1〜4 は実装済み（2026-10-04）。5・6 が残り

実装時に設計から変えた点:

- **fork PR の `workflow_run` は artifact を使わない。** fork 側は `pull_request` の workflow を書き換えられ、artifact（SARIF）を偽造できるため。既定ブランチの action と設定で PR のコードを読むだけで検査し直す（§18.4.3・§21.2 に追記）。
- そのために `SECURITY_CHECKER_UNTRUSTED_TARGET=1`（action の `untrusted-target`）を追加した。検査対象のツリーにある設定（`.local.yml` を含む）を読まない。読むと PR 側の `command` がシークレット付きで実行される。
- action は Docker ではなく composite のまま（GHCR 公開は P6。`Dockerfile` は用意済み）。
- diff モードでレビューしなかった候補も SARIF に `note` / 0.0 で残す（出さないと既存 alert が閉じる）。


順番を守る。**SARIF を先、Ruleset は最後**（§18.4）。

1. `feat(report): sarif` — `tool.driver.name` と category を `security-checker` に固定、failed 時は `executionSuccessful: false`、`review_required` は `note`、level は D3 の決定に従う
2. `feat(target): diff モード` — 変更行と重なる候補だけ残す（§7.4）
3. `feat(github): sticky コメント + inline コメント`
4. `feat: action.yml + Dockerfile`、`workflow_run` サンプル、`docs/github-actions.md`
5. 自リポジトリの CI に v2 を追加する。**v1 の生 SARIF は残したまま**両方を上げ、差分（= LLM が潰した FP）を観察する（§18.4.5）
6. D8: v1 資産を撤去（`chore: v1 を撤去し tools を contrib/host-audit に移設`）

- 完了条件: 自リポジトリの PR で動き、Security タブに `security-checker` の alert が出る

### Step 5. P5 品質 — ✅ 実装済み（2026-10-04、カバレッジ 94%・mypy strict 通過）

実装時に設計から変えた点:

- Judge の採否理由は独立した `judge_rationale` ではなく、同じスキーマの `reasoning` に書かせる（スキーマを 1 つに保ち、修復リトライの経路を共有するため）。`aggregation.detail.judge.rationale` に残る。
- Judge は見逃しを増やさない方向に倒す: 「脆弱ではない」でも確信度 0.8 未満か文脈不足なら `review_required` のまま。
- ログは既定で出さない（`logging.*` か `--log-format` を指定したときだけ）。
- `rate_limit.tpm` はスキーマにあったのに効いていなかった（P9 違反）ので、rpd と一緒に実装した。
- 信用できない検査対象では ignore ファイルとコード内注釈を読まない（PR が自分の指摘を消せるため）。


優先度順: baseline・ignore（段階導入に必須）→ osv → judge → `providers check` → `--estimate` / rpd クォータ → trivy → `explain` → 構造化ログ → カセット。
§1.3 のテストの穴もここで埋める。

- 完了条件: カバレッジ 80% 以上（現状 93% を維持）、mypy strict が通る

### Step 6. P6 評価と公開 — 準備は済み。GitHub Release から小さく出す

残りの手順:

1. 手元の Reviewer 構成で eval を回す（課金が発生する。`review --estimate` 相当の見積りは `eval` には無いので、まず `--dataset` を数件に絞ったコピーで試す）
   ```sh
   security-checker eval -d benchmarks/datasets/handmade-v1 -c security-checker.local.yml \
     -o benchmarks/results/<date>.json -m benchmarks/results/<date>.md
   ```
   single / consensus / judge を比べ、D12 を決める。結果は README の Accuracy 節に書く
2. ✅ **済（2026-10-05）: `v2.0.0` を GitHub Release のみで公開。`release-as` も削除済み。** GitHub のみで小さく公開する（2026-10-05 決定）。 release-please のリリース PR をマージして `v2.0.0` の GitHub Release を作る。
   PyPI・GHCR は変数（`PUBLISH_PYPI` / `PUBLISH_GHCR`）未設定のまま止めておく。インストールは `uv tool install git+https://...@v2.0.0`。
   **リリース後に `release-please-config.json` の `release-as` を消す**（残すと次も 2.0.0 を作ろうとする）
3. D1: PyPI は**閉じた環境で一度通してから**公開する。TestPyPI（または社内インデックス）に Trusted Publisher を登録して
   配布物とインストール手順を確かめる → PyPI で配布名を確保・Trusted Publisher に `release.yml` / environment `pypi` を登録 →
   `pyproject.toml` の `name` と `src/security_checker/__init__.py` の `version("...")` を配布名に変える → リポジトリ変数 `PUBLISH_PYPI=true`
4. GHCR: リポジトリ変数 `PUBLISH_GHCR=true`

当初の手順:


1. `eval` コマンドとデータセット 100 件（`eval` コマンドは実装済み・#21。データセットはまだ土台のみ）。**Recall を主指標、FN 増加数 0 を必須条件**にする（§27.2）
2. 結果を見て D12（既定の Reviewer 数・戦略）を決める。効果がなければ README に「1 モデルで十分」と正直に書く
3. docs 一式、英語 README、OSS 付帯ファイル（§31.4）
4. release-please → PyPI（Trusted Publishing、D1 の名前で）→ GHCR → `v2.0.0`

**リリース PR の CI について。** release-please は `GITHUB_TOKEN` で PR を作るため、その PR では workflow が起動せず、
必須チェック `security` が無いままマージできない（`BLOCKED`）。当面はリリース PR を**人間が一度 close → reopen** して CI を起動する。
手間になったら GitHub App のトークンを release-please に渡す（PAT は置かない）。

### Step 7. P7 ゲートを締める

1. v1 の生 SARIF 4 category（`semgrep`・`gitleaks`・`trivy`・`osv-scanner`）を空 SARIF で閉じる
2. `workflow_run` パターンで **fork PR の SARIF アップロードが通ることを確認してから**、
   Ruleset に "Require code scanning results"（ツール名 `security-checker`）を追加する（R15・R16）

- 完了条件: high 以上の confirmed を含む PR がマージできないことを実際に確かめる
