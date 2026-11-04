# Reviewer を足す

**このツールは「どの LLM を使うか」について立場を持ちません。**
既定の Reviewer は 1 つもなく、「対応 LLM 一覧」も作りません。
あなたが既に持っているものが正解です。

分類の軸はベンダーではなく、次の 2 つです。

| 軸 | 値 | 意味 |
|---|---|---|
| **transport** | `http` / `process` | どうやってモデルに到達するか |
| **dialect** | `openai_chat` ほか | リクエストとレスポンスの「形」 |

`anthropic_messages` は「Anthropic 社の」ではなく「Messages API という形の」という意味です。
その形を話すエンドポイントなら、提供元がどこであっても同じアダプタで扱えます。

> **実装状況（2026-09 時点）**: `http` transport の方言は `openai_chat` / `ollama_chat` /
> `anthropic_messages` / `gemini_generate` の 4 つすべてが実装済みです。
> `process` transport も実装済みで、**API キーなしで使えます**。

## generateContent 形式のエンドポイント

```yaml
reviewers:
  - name: r3
    transport: http
    dialect: gemini_generate
    base_url: https://<endpoint>/v1beta   # model は URL に自動で組み込まれます
    model: <model-id>
    api_key_env: MY_API_KEY
```

この形の特徴は 2 つです。

1. **モデル名が URL に入ります**（`{base_url}/models/{model}:generateContent`）。
   鍵はクエリ文字列ではなくヘッダで送ります（URL はログや履歴に残りうるため）
2. **構造化出力のスキーマが OpenAPI のサブセット**です。JSON Schema をそのまま送ると 400 になるので、
   送る前に変換します。`$ref` は展開し、`anyOf` の null との union は `nullable` に畳み、
   `additionalProperties` / `maxLength` / `pattern` / `minimum` のような**値の制約は落とします**

落ちた制約はプロンプト側のスキーマ提示には残るため、完全に失われるわけではありません。
出力の上限は既定で `max_tokens` で送ります。`max_completion_tokens` しか受け付けないエンドポイントでは
`capabilities.output_limit_param: max_completion_tokens` を指定してください (`openai` プリセットは指定済みです)。

それでもスキーマが拒否される場合は `capabilities.structured_output: json_mode` を指定してください
（エラーメッセージにもそう出ます）。

## Messages 形式のエンドポイント

```yaml
reviewers:
  - name: r2
    transport: http
    dialect: anthropic_messages
    base_url: https://<endpoint>       # /v1 は付けても付けなくても構いません
    model: <model-id>
    api_key_env: MY_API_KEY
```

この形は `openai_chat` と互換性がなく、違いは 2 つです。

1. **`system` がメッセージではなく独立したフィールド**（アダプタが吸収します）
2. **JSON Schema を直接指定する仕組みがない** — 代わりに**ツール呼び出しを強制**して
   構造化出力を得ます。応答の `content[].input` がそのまま検証済みの構造化データになるので、
   散文の混入を構造的に排除できます

思考トークンを持つモデルでは、方言によらず `capabilities.reasoning: true` を宣言してください。
出力の上限に余裕 (4096 トークン) を足すため、思考で上限を使い切って本文が切れるのを防げます。

## ローカルのエンドポイント（API キー不要）

`ollama_chat` 方言は `POST {base_url}/api/chat` を話します。

```yaml
reviewers:
  - name: local
    transport: http
    dialect: ollama_chat
    base_url: http://localhost:11434
    model: <model-id>
    num_ctx: 16384          # 文脈長。省略時は 8192
    keep_alive: 10m         # 連続レビューでのモデル再ロードを避ける（任意）
```

**`num_ctx` を必ず送るのがこの方言の存在理由です。** 同じエンドポイントは `openai_chat` でも
話せますが、その場合は文脈長を指定できず、エンドポイント側の既定値（2048）のまま
**警告もなく黙って切り詰められます**。長いコード文脈を渡すこのツールでは判定が壊れるため、
ローカルエンドポイントには `ollama_chat` を使ってください。

モデルを取得していない場合は、「モデルを取得してください（例: `ollama pull <model>`）」という
実行できる形のエラーになります。

---

## ルート 1: HTTP エンドポイント（API キーを使う）

`openai_chat` の形を話すサービスは多数あり、**そのどれも本体の変更なしに使えます**。

```yaml
reviewers:
  - name: r1
    transport: http              # 必須。省略時に推測で補完しません
    dialect: openai_chat
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: MY_API_KEY      # 環境変数名のみ。平文キーの項目は存在しません
    rate_limit: { rpm: 10 }      # 無料枠などの制限を宣言するとスケジューラが尊重します
```

同梱プリセットを使うと `base_url` と `api_key_env` を省略できます。

```yaml
reviewers:
  - name: r1
    transport: http
    preset: openai               # base_url と api_key_env (OPENAI_API_KEY) が埋まります
    model: <model-id>
```

`base_url` を書けばプリセットは要りません。**プリセットは省略記法にすぎません。**

### 構造化出力の降格

`json_schema` で送って 400 が返れば `json_mode` に、それも駄目なら `prompt_only` に自動で降格します。
降格したことは `degraded_to` とトレースに残ります。未知のエンドポイントでも「まず動く」ようにするためです。

---

## ルート 2: 非対話コマンド（API キー不要）

**手元の CLI に既にログインしているなら、その認証のままレビューさせられます。**
契約は「stdin でプロンプトを受け取り、stdout にテキストを返し、exit 0 で終わる」だけです。

```yaml
reviewers:
  - name: my-reviewer
    transport: process
    command: ["<your-command>", "<非対話フラグ>", "<ツール無効化フラグ>"]
    prompt_via: stdin            # stdin | file
    timeout_s: 300
    concurrency: 1
```

同梱プリセットがある場合は名前で呼べます。

```yaml
reviewers:
  - name: my-reviewer
    transport: process
    preset: claude
```

### まだ同梱されていないコマンドを使う（codex CLI など）

**同梱プリセットに無いものが使えない、ということはありません。** `command` を直接書いてください。
その際、次の 2 つを**あなたが確認して**指定します。本体からは検証できないためです。

1. **非対話モード**のフラグ（プロンプトを渡して応答だけ返して終了する）
2. **ツール実行・ファイル書き込みを無効化する**フラグ

```sh
<your-command> --help        # この 2 つに当たるフラグを確認する
```

```yaml
reviewers:
  - name: my-agent
    transport: process
    command: ["<your-command>", "<非対話フラグ>", "<ツール無効化フラグ>"]
    prompt_via: stdin
```

指定できているかを本体は検証できないため、起動時に「書き込み能力の無効化は利用者の責任である」旨を
警告します（同梱プリセットは `requires_readonly_flags: true` を申告しているため出ません）。

動いたら、同じ内容を `~/.config/security-checker/presets/process/<name>.yml` に置けば
名前で呼べるようになります。**PR は不要です。** 他の人にも役立つなら、そのまま PR もできます
（採否基準は [CONTRIBUTING.md](../CONTRIBUTING.md)）。

### 安全性（transport の性質によらず守るもの）

起動対象は任意のコマンドで、その中にはファイルを書き換える能力を持つものが含まれます。
**Security Reviewer がレビュー対象を勝手に編集してはいけない**ため、一律に次を強制します。

1. **リポジトリの外で起動する。** cwd は毎回作り直す空の一時ディレクトリ。コードは stdin で渡します
2. **シェルを経由しない。** argv のリストで `shell=False` 固定。プロンプトを引数に埋め込みません
3. **実行後に一時ディレクトリの差分を検査する。** 書き込みがあれば警告し、トレースに残します
   (検知できるのは一時ディレクトリの中だけです)
4. **タイムアウト時はプロセスグループごと回収する**

詳細は [process-transport.md](process-transport.md) を参照してください。
**対象コマンドの利用規約（自動化利用の可否）は利用者が確認してください。**

### 制約（正直に書きます）

| 項目 | `http` | `process` |
|---|---|---|
| 構造化出力 | `json_schema` / `json_mode` | **`prompt_only` のみ** |
| コスト計測 | 正確 | **不可**（`unknown`。トークンは推定値） |
| レイテンシ | 数秒 | 数十秒〜数分（既定 timeout 300s） |
| 並列度 | 数〜十数 | 既定 1 |
| 決定性 | temperature 0 / seed | 対象に依存。制御できない前提で扱います |

`process` は一般に「安価だが荒い」transport です。ただしこれは transport の性質であって、
対象の優劣ではありません。**性質の異なる transport を混ぜると、一致度 (agreement) が情報量を持ちます。**

---

## ルート 3: 新しい方言のアダプタを書く（外部パッケージ）

ここに到達するのは、**上の 2 つで表現できない API 形式が登場した場合だけ**です。
「新しいベンダーが出たから」という理由でここに来ることはありません。

```toml
[project.entry-points."security_checker.providers"]
my_provider = "my_plugin.provider:MyProvider"
```

`security_checker.testing.ProviderContractTests` を継承すれば、自作 Provider が契約を
満たしているか検証できます。`capabilities` の妥当性、`usage` の充足、`aclose()` を常に検証します。
`make_http_provider(handler)` を実装して偽のエンドポイントを注入できるようにすると、例外の正規化、
構造化出力の降格、リトライを内部で持たないことも検証します（実装しなければ skip になります）。
契約テストは pytest を使うので、`pip install "security-checker[testing]"` で入れてください。

---

## 環境から設定を作る

```sh
security-checker init
```

**おすすめは提示しません。** 同梱プリセットのコマンド名と環境変数名だけを手がかりに、
あなたの環境で実際に使えるものを検出し、アルファベット順に並べます。選んだ結果が
`security-checker.yml` として書き出され、以後は普通の設定ファイルとして編集できます。

手元でだけ使う Reviewer は `security-checker.local.yml`（git 管理外）に書きます。

```sh
security-checker init --local --command '<your-command> --非対話 --ツール無効'
```

## 同梱プリセット一覧

| transport | 名前 | 備考 |
|---|---|---|
| `http` | `openai` | `openai_chat` 方言 / `OPENAI_API_KEY` |
| `process` | `claude` | 非対話 + ツール全無効で起動 / 認証はそのコマンド側の既存ログイン |

アルファベット順です。順位づけ・推奨マークはありません。既定値にもなっていません。
一覧に無いものも、`command` や `base_url` を直接書けば同じように動きます。
