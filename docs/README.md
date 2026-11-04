# ドキュメント

目的から探してください。英語の概要は [README.md](../README.md)、日本語の概要は [README.ja.md](../README.ja.md) にあります。

## 使う

| 文書 | 内容 |
|---|---|
| [getting-started.md](getting-started.md) | インストールから最初の `scan` / `review` まで |
| [configuration.md](configuration.md) | 設定ファイルの探索・合成と全項目のリファレンス |
| [exit-codes.md](exit-codes.md) | 終了コード (0/1/2/3) とコマンドごとの条件。CI のゲートを組むときに |
| [scanners.md](scanners.md) | semgrep・gitleaks・osv-scanner・trivy の扱い、`skipped` と `failed` の違い |
| [providers.md](providers.md) | Reviewer (LLM) の足し方。transport × dialect、プリセット、プラグイン |
| [process-transport.md](process-transport.md) | API キー無しで、手元の非対話コマンドを Reviewer にする |
| [aggregation.md](aggregation.md) | 複数の Reviewer の判定のまとめ方 (consensus / weighted / judge) |
| [prompts.md](prompts.md) | Reviewer に送るプロンプトの構成と版 |

## CI に入れる

| 文書 | 内容 |
|---|---|
| [github-actions.md](github-actions.md) | GitHub Action・diff モード・PR コメント・Code Scanning (SARIF)・fork PR |
| [adoption.md](adoption.md) | 複数のリポジトリへの段階導入と、必須チェックにするまで |

## 仕組みと方針

| 文書 | 内容 |
|---|---|
| [security-model.md](security-model.md) | 何を送り、何を残すか。プロンプトインジェクションと信用できない検査対象への対策 |
| [evaluation.md](evaluation.md) | ラベル付きデータセットでレビュー精度を測る (`eval`) |
| [DESIGN.md](DESIGN.md) | 設計書 (全体の正典) |
| [adr/](adr/README.md) | 意思決定記録。「なぜそうなっているか」 |
| [NEXT-STEPS.md](NEXT-STEPS.md) | 残作業と、人間が決めること・やること |

## 開発に参加する

[CONTRIBUTING.md](../CONTRIBUTING.md) と [SECURITY.md](../SECURITY.md) を参照してください。
