# プロンプト

テンプレートは `src/security_checker/review/prompts/` に**版番号付き**で置いています。

| ファイル | 用途 |
|---|---|
| `system.v2.jinja` | Reviewer の役割・ルール・重大度の定義・プロンプトインジェクションへの注意 |
| `user.v2.jinja` | 1 候補分の依頼 (スキャナの報告・コード・呼び出し元・リポジトリの事実・出力スキーマ) |
| `judge_system.v2.jinja` / `judge_user.v2.jinja` | Judge 用。一次レビューの依頼に、匿名化した意見を足す |

出力は JSON Schema (`ReviewJudgement`) で拘束します。構造化出力に対応していないエンドポイントでは
`json_mode` → `prompt_only` に段階的に降格し、スキーマ違反は 1 回だけ修復を依頼します。

## 守っていること

- **レビュー対象のコードは信頼できないデータとして扱います。** `<<<UNTRUSTED_CODE>>>` で囲み、
  コードの中に同じ区切りが現れたらエスケープします。呼び出し元のコードも、スキャナの出力
  (`<<<UNTRUSTED_FINDING>>>`。message や fix にはコードの文字列が入ります)も、Judge に渡す他の Reviewer の
  意見 (`<<<UNTRUSTED_OPINIONS>>>`) も同じです。スキャナの出力は 1 行にまとめ、秘密の値も伏せます。system プロンプトにはレビュー対象の文字列を
  1 文字も入れません。これらは回帰テスト (`tests/unit/test_prompt_injection.py`) で確かめています。
- **全 Reviewer に完全に同じ依頼を送ります。** 比較の公平性のためです。
- **温度は 0、seed は指定できる場合だけ使います。** それでも出力は決定的ではないため、
  SARIF の重大度はスキャナ由来の値で決めています (LLM の判定で alert が開閉しないように)。
- 本文の言語は `output.language` で決まり、英語のときは英語版テンプレートと 1 文字も変わりません。

## 変更するとき

プロンプトの変更は精度に直結します。

1. 新しい版を別ファイル (`system.v3.jinja` など) として作り、`PROMPT_VERSION` を切り替える
2. **変更前後で必ず `security-checker eval` を回し、結果を比べる**
   (Recall が下がっていないこと・見逃した真陽性が 0 であることが必須)
3. 結果を PR に貼る

送信内容は `security-checker review --dry-run` で、送る前に全部見られます。
