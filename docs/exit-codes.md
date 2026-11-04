# 終了コード

CI でゲートを組むときに最初に見る表です。**「脆弱性が見つかった」(1) と「ツールが壊れた」(3) を必ず分けます**
(設計書 §17.1)。v1 はこれを混ぜていたため、スキャナが壊れていても緑になりました。

| code | 名前 | 意味 |
|---|---|---|
| 0 | `OK` | ポリシー違反なし |
| 1 | `POLICY_VIOLATION` | ポリシー違反 (下の表) |
| 2 | `CONFIG_ERROR` | 設定・引数・環境の不備。**実行前に止まる** (何も送らない) |
| 3 | `EXECUTION_ERROR` | 実行時の失敗。`policy.strict: true` (既定) で「検査が最後まで行われなかった」もここ |

定義は [`src/security_checker/errors.py`](../src/security_checker/errors.py) と
[`src/security_checker/policy/engine.py`](../src/security_checker/policy/engine.py) にあります。

## コマンドごと

| コマンド | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `scan` | 違反なし | `fail_on` 以上の検出 (LLM の判定なし・スキャナの重大度で判定)、または `min_score` 未満 | 設定エラー・検査対象が無い | strict でスキャナが `failed` |
| `review` | 違反なし | `fail_on` 以上で `fail_on_status` (既定 confirmed / likely) の Finding、または `min_score` 未満 | 設定エラー・API キーの環境変数が無い・検査対象が無い | strict で次のいずれか: スキャナの失敗 / Reviewer の無効化 (認証失敗など) / 予算・上限によるレビューの停止 / 未レビュー (`not_reviewed`) の候補 / 有効な判定が得られなかった (`error`) 候補 |
| `review --dry-run` / `--estimate` | 常に 0 (何も送らない) | — | 設定エラー | — |
| `eval` | 見逃し 0 かつ保留率が上限以下 | 真陽性の見逃しが 1 件以上、または `review_required` の割合が `--max-deferred-rate` 超 | 設定エラー・データセットが壊れている | 採点できなかったケース (error / not_reviewed) がある (`--allow-incomplete` で無視) |
| `baseline update` | 更新した | — | 設定エラー | スキャナが失敗した (壊れた結果で baseline を上書きしない) |
| `providers check` | 全 Reviewer が通った | — | 設定エラー・Reviewer が無い | 1 つでも失敗した |
| `comment` | 投稿した (または投稿不要) | — | `GITHUB_TOKEN` が無い・report.json が無い/読めない・PR の文脈が無い | GitHub API の失敗 |
| `explain` | 表示した | — | report.json が無い・ID が見つからない | — |
| `init` / `config show` / `version` | 成功 | — | 設定エラー | — |

## 注意

- **`review_required` (Reviewer の判断が割れたもの) は 1 にしません。** サマリと Security タブには残るので、
  人間が確認してください。ゲートにしたいなら `policy.fail_on_status` に `review_required` を足します。
- `inconclusive` (文脈不足で判定不能) は strict でも 3 にしません。`review_required` と同じく人間の確認待ちです。
- strict を外す (`--no-strict` / `policy.strict: false`) と、壊れた検査でも 0 / 1 で終わります。
  その場合もレポートの `warnings[]` とスコアの `partial` フラグには残ります。
- GitHub Action は同じ値を出力 `exit-code` に入れます ([github-actions.md](github-actions.md))。
