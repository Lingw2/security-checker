# スキャナ

スキャナは「機械的な事実」(候補) を出し、LLM はその候補を判定するだけです。
LLM に脆弱性を探させないのは、見つけた・見つけないの再現性が無くなるためです。

| スキャナ | カテゴリ | 何を見るか | 導入 |
|---|---|---|---|
| semgrep | `sast` | コードのパターン | `brew install semgrep` / `pipx install semgrep` |
| gitleaks | `secret` | シークレットの直書き | `brew install gitleaks` |
| osv-scanner | `dependency` | 依存の既知脆弱性 (OSV データベース) | `brew install osv-scanner` |
| trivy | `config` / `dependency` | IaC・Dockerfile・Kubernetes の誤設定、依存の脆弱性 | `brew install trivy` |

無効にするには `scanners.<name>.enabled: false`。

GitHub Action（`action.yml`）・Docker イメージ・このリポジトリの CI は、スキャナを「最新版」ではなく
[`scripts/scanner-versions.sh`](../scripts/scanner-versions.sh) に書いた版で取得し、そこに固定した sha256 で検証します。
スキャナのリリースが乗っ取られても、悪性のバイナリが CI で動かないようにするためです（チェックサムを同じリリースから取ると、リリースごと差し替えられた場合に防げません）。

版は Action の入力（`gitleaks-version` など）や Docker の `--build-arg` で上書きできます。
固定版以外を指定した場合はリリース側のチェックサムで検証し、検証が弱くなることを警告に出します。
更新の手順は `scanner-versions.sh` 冒頭のコメントを参照してください。

## 状態を必ず区別する

| 状態 | 意味 | 扱い |
|---|---|---|
| `ok` | 実行できた (0 件を含む) | |
| `skipped` | 導入されていない・対象が無い | 警告。スコアは `partial` |
| `failed` | 異常終了・タイムアウト・出力が壊れている | **エラー**。`strict` なら exit 3。SARIF はアップロードしない |

v1 には「スキャナが失敗しても 0 件の成功として扱われ、満点に見える」欠陥がありました。
v2 は `skipped` と `failed` を型で分け、どちらもレポートの冒頭に出します。

## 個別の注意

### semgrep

- `scanners.semgrep.config` は `p/default` のようなルールセットか、ルールファイルのパス。
  複数ならリストで書きます。既定は `[p/default, bundled:llm, bundled:ci-lock]`。
- `bundled:<名前>` は security-checker が同梱するルールです。解決先は常にパッケージ内で、
  検査対象のツリーからは読みません。

  | 名前 | 内容 |
  |---|---|
  | `bundled:llm` | 第三者のテキスト (HTTP 応答・GitHub の Issue / PR / コメント・Web ページ) を、区切りを確認できない形で LLM に渡すコード (間接プロンプトインジェクション。OWASP LLM01 / CWE-1427)。system / instructions に入れば high、user メッセージなら medium。Python (OpenAI・Anthropic・Google Gen AI・LangChain) と JavaScript / TypeScript (fetch・axios・Octokit → OpenAI / Anthropic)。テストコード (`tests/`・`test_*.py`・`*.spec.ts` など) は対象外 |
  | `bundled:ci-lock` | GitHub Actions の workflow で、lock ファイルを強制していない依存の入れ方。`uv sync` に `--locked` も `--frozen` も無ければ medium、`--frozen` だけなら low。同じ job で `uv lock` を実行していれば対象外 |
- 生出力は `raw/semgrep.json` に、パスを相対にして保存します。

### gitleaks

- **検出値はマスクしてから**候補・生出力・LLM へのプロンプトに載せます (`xoxb****` のように形式だけ残す)。
  漏洩したシークレットを第三者 (外部 LLM) に再送しないためです。
- gitleaks 8.19 以降は `gitleaks dir`、それ以前は `detect --no-git` を使います。

### osv-scanner

- **既定で有効**です (osv-scanner が入っていなければ `skipped`)。送信を避けたい場合は
  `scanners.osv.enabled: false` にしてください。
- `osv-scanner scan source --recursive` を実行します。依存の問い合わせのため、
  **パッケージ名とバージョンが OSV の API に送られます** (コードは送りません)。
- 意図して残す脆弱性は、リポジトリの `osv-scanner.toml` に期限つきで書いて抑止します。

  ```toml
  [[IgnoredVulns]]
  id = "GHSA-xxxx-xxxx-xxxx"
  ignoreUntil = 2027-01-31   # 期限を必ず付ける
  reason = "到達しない経路でしか使っていない。上流の修正版を待つ"
  ```

  既存の指摘をまとめて扱う場合は `security-checker baseline update` で baseline に入れ、
  新しく出たものだけをゲートにできます。
- 同じ脆弱性の別名 (PYSEC / GHSA / CVE) は 1 件にまとめます。別名ごとに候補を作ると、
  同じ問題が何度もレビューされ、何度も PR に出るためです。
- 終了コード 128 (マニフェストが無い) は「対象が無い」なので `skipped` にします。
- 重大度が分からない脆弱性は `medium` として扱い、そのことをメッセージに書きます
  (`info` にするとゲートから消えるため)。

### trivy

- `scanners: [config]` で誤設定、`[vuln]` で依存の脆弱性を見ます (osv と重なるので、どちらかで足ります)。
- **`secret` は受け付けません。** trivy のシークレット検出は検出値を出力に含めるため、生出力に値が残ります。
  シークレットはマスク処理のある gitleaks で見てください。
- オフライン環境では `extra_args: ["--offline-scan", "--skip-check-update"]` などを渡します。

## 自作のスキャナを足す

`security_checker.scanners` の entry point に登録し、設定の `scanners.plugins` に書くと、
内蔵と同じように実行されます。適合性は公開の契約テストで確かめられます。

```yaml
scanners:
  plugins:
    myscan: {enabled: true, timeout_s: 300, extra_args: []}
```

**入れただけでは動きません。** 依存に入ったパッケージが黙ってスキャナとして動かないようにするためです。
登録されているのに設定に無いプラグインは警告を出し、設定にあるのに登録されていない名前は設定エラー (exit 2) にします。
プラグインのファクトリは `ScannerConfig` を 1 つ受け取ります。

```python
from security_checker.testing import ScannerContractTests


class TestMyScanner(ScannerContractTests):
    def make_scanner(self):
        return MyScanner(MyConfig())

    def populate(self, root):  # 任意: 検出させたいファイルを置く
        (root / "app.py").write_text("...")
```

検証する契約: ツールが無ければ `skipped` を返す / `failed` には理由がある / 候補 ID が run 内で一意で、
2 回走らせても変わらない / パスが検査対象の外を指さない / 生出力は `raw_dir` に書く。
