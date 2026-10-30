# プリセット (データ)

ここにあるのは **データだけ** です。コードにベンダー名もコマンド名も現れません(設計書 §9)。

プリセットは**省略記法にすぎません**。設定に `dialect` / `base_url` / `model`(`http`)や
`command`(`process`)を直接書けば、プリセットが 1 つもなくても同じように動きます。
**同梱プリセットに載っていないものが使えない、ということはありません。**

## 同梱しているもの

採否は人気や提供元ではなく、[設計書 §9.7](../../../../docs/DESIGN.md) の客観条件
(非対話モードがある / ツール実行・書き込みを無効化する手段がある / 標準出力から結果を取れる /
自動化利用が規約で明示的に禁止されていない)のみで判断し、**先着順・アルファベット順**で並べます。
順位づけ・推奨マーク・「おすすめ」表記は付けず、既定値にもしません。

| transport | 名前 | 備考 |
|---|---|---|
| `http` | `openai` | `openai_chat` 方言。`OPENAI_API_KEY` |
| `process` | `claude` | 非対話 + ツール全無効で起動。認証はそのコマンド側の既存ログイン |
| `process` | `copilot` | 非対話 + ツールを権限の種類ごとに全拒否で起動。認証はそのコマンド側の既存ログインか `GITHUB_TOKEN` など |

条件を満たすものの追加提案は歓迎します(Issue の「同梱プリセットの追加提案」テンプレート)。
提案を待たずに、自分の環境で今すぐ使うこともできます ↓

## 自分のプリセットを追加する

`~/.config/security-checker/presets/<transport>/<name>.yml`(`XDG_CONFIG_HOME` を尊重)に置きます。
同名のファイルを置けば同梱分を上書きできます。PR は不要で、コードも書きません。

### `http/<name>.yml`

```yaml
name: my-endpoint
dialect: openai_chat
base_url: https://example.internal/v1
api_key_env: MY_ENDPOINT_KEY
match:                       # 省略時は名前指定でのみ使われる
  host: example.internal
  model: "^my-model"
capabilities:
  structured_output: json_schema
  max_context_tokens: 128000
```

一致するエントリがない未知のエンドポイントでも、最も互換性の高い `json_mode` に
フォールバックして「まず動く」ようにしてあります(設計書 §9.3)。

### `process/<name>.yml`

```yaml
name: my-command
command: ["<binary>", "<non-interactive-flag>", "<disable-tools-flag>"]
prompt_via: stdin            # stdin | file
parse: json_in_stdout
capabilities:
  max_context_tokens: 200000
requires_readonly_flags: true   # 安全要件を満たしていることの申告 (§9.7)
```

`requires_readonly_flags: true` は「この `command` はツール実行・ファイル書き込みを
無効化してある」という宣言です。申告のないプリセット、および設定に `command` を
直接書いた場合は、起動時に「書き込み能力の無効化は利用者の責任である」旨を警告します。

`process` transport の構造化出力は `prompt_only` に固定されるため、
`capabilities.structured_output` を指定しても実態は変わりません(設計書 §9.7)。

詳細は [`docs/process-transport.md`](../../../../docs/process-transport.md) を参照してください。
