# Changelog

## [2.2.0](https://github.com/Sh1n1230/security-checker/compare/v2.1.0...v2.2.0) (2026-11-03)


### Features

* **config:** osv-scanner を既定で有効にし、週 1 回の全件検査をサンプルに加える ([#119](https://github.com/Sh1n1230/security-checker/issues/119)) ([93bcb14](https://github.com/Sh1n1230/security-checker/commit/93bcb14ec5e8c4a477b2d69851709821da66bd29))
* **scanners:** scanners.semgrep.config にリストと同梱ルール (bundled:&lt;名前&gt;) を書けるようにする ([#129](https://github.com/Sh1n1230/security-checker/issues/129)) ([3bcc903](https://github.com/Sh1n1230/security-checker/commit/3bcc9031896d34a880f6cac3fff6cd4ec7b94303))
* **scanners:** 同梱ルール bundled:ci-lock で、CI の uv sync が lock を強制していない手順を検出する ([#134](https://github.com/Sh1n1230/security-checker/issues/134)) ([6da15d4](https://github.com/Sh1n1230/security-checker/commit/6da15d4a02031d17e86cdea5b41d27b01722597c))
* **scanners:** 同梱ルール bundled:llm で、第三者のテキストを LLM に渡すコードを検出する ([#132](https://github.com/Sh1n1230/security-checker/issues/132)) ([97ecb1c](https://github.com/Sh1n1230/security-checker/commit/97ecb1c01ffae292a0363ab48e6fb5b9bf88396c))


### Bug Fixes

* **action:** 本体を uv.lock どおりに入れる ([#116](https://github.com/Sh1n1230/security-checker/issues/116)) ([30d258c](https://github.com/Sh1n1230/security-checker/commit/30d258cb82a844a2f4b28854dfd9772e793cf23b))
* **aggregate:** Reviewer の一部が失敗したとき、残った 1 体の判定だけで確定させない ([#111](https://github.com/Sh1n1230/security-checker/issues/111)) ([c7224ca](https://github.com/Sh1n1230/security-checker/commit/c7224ca4597b5b2c33dcf924c7809518b7d5adbc))
* **aggregate:** 半々の票と自信の無い「脆弱ではない」を review_required にし、重大度の丸めを上にそろえる ([#181](https://github.com/Sh1n1230/security-checker/issues/181)) ([49a8109](https://github.com/Sh1n1230/security-checker/commit/49a8109a1ccdfbe1838f4121db46c5bfb6073c6b))
* **cli:** eval の設定警告を標準エラーに出し、比較表に混ぜない ([#76](https://github.com/Sh1n1230/security-checker/issues/76)) ([98eb230](https://github.com/Sh1n1230/security-checker/commit/98eb230ae3c5a6f32a42eaa934b370e6dc8a0325))
* **config:** local 層の reviewers を name で合成し、共有の Reviewer を消さない ([#386](https://github.com/Sh1n1230/security-checker/issues/386)) ([5f3ff0c](https://github.com/Sh1n1230/security-checker/commit/5f3ff0c1e4743be9e4f7be725d6ae426706441f6))
* **config:** reviewers[].headers の値を config show とトレースで伏せ、headers_env を追加する ([#113](https://github.com/Sh1n1230/security-checker/issues/113)) ([0da1b95](https://github.com/Sh1n1230/security-checker/commit/0da1b953c905ca435df6df76229352598af510bb))
* **config:** transport に合わない項目と target.root を黙って無視しない ([#74](https://github.com/Sh1n1230/security-checker/issues/74)) ([73817a7](https://github.com/Sh1n1230/security-checker/commit/73817a7cb5ea553a0fd691728fd9e40d36dd6617))
* **context:** 文脈をプロンプト全体の予算に収め、長い行は文字数で切る ([#201](https://github.com/Sh1n1230/security-checker/issues/201)) ([33d3922](https://github.com/Sh1n1230/security-checker/commit/33d3922b70b76519ecbfd8328de42d83c44a7163))
* **context:** 文脈を検査対象の配下からだけ読み、引用符の無い値や周辺の秘密も伏せる ([#144](https://github.com/Sh1n1230/security-checker/issues/144)) ([7b2483d](https://github.com/Sh1n1230/security-checker/commit/7b2483df8a5722a35775a01c406fb0ead1f174c4))
* **context:** 未実装の context.max_callers を警告し、効くという記述を外す ([#115](https://github.com/Sh1n1230/security-checker/issues/115)) ([53f1f22](https://github.com/Sh1n1230/security-checker/commit/53f1f22b19a2d4602535a53cb3106f6549812fd8))
* **eval:** 保留と打ち切りで Recall と FP 削減率が良く見えないようにし、採点できない run を失敗にする ([#256](https://github.com/Sh1n1230/security-checker/issues/256)) ([8f04c04](https://github.com/Sh1n1230/security-checker/commit/8f04c044128a023f9143ddd6c6f682d7b5d731e2))
* **github:** diff の解析でハンク本文の --- / +++ 行をファイルヘッダと取り違えない ([#98](https://github.com/Sh1n1230/security-checker/issues/98)) ([8cc5187](https://github.com/Sh1n1230/security-checker/commit/8cc51876b4b721b68abb1161cd73340440c487c0))
* **github:** PR コメントの投稿済み判定で投稿者も確かめる ([#114](https://github.com/Sh1n1230/security-checker/issues/114)) ([c99a2bb](https://github.com/Sh1n1230/security-checker/commit/c99a2bb65a6e6541ac642614876b75f72c51f352))
* **policy:** baseline で秘密の値も照合し、差し替えた秘密を抑制しない ([#184](https://github.com/Sh1n1230/security-checker/issues/184)) ([fbadfdd](https://github.com/Sh1n1230/security-checker/commit/fbadfdd850d60c07ad72f6da53827fdfa48b2b4e))
* **policy:** strict では Reviewer の無効化・予算による停止・未レビューの候補を exit 3 にする ([#183](https://github.com/Sh1n1230/security-checker/issues/183)) ([6525906](https://github.com/Sh1n1230/security-checker/commit/652590650c7e40e48b7c4ec55225b1a86e8bc162))
* **policy:** 行末の ignore 注釈を次の行に効かせず、rule:&lt;id&gt; &lt;path&gt; を依存の候補にも効かせる ([#182](https://github.com/Sh1n1230/security-checker/issues/182)) ([d4243d3](https://github.com/Sh1n1230/security-checker/commit/d4243d3e19d1bfde507da09d9a2c8eacb6d7f408))
* **providers:** process transport で孫プロセスを残さず、リポジトリのパスを渡さず、既定の timeout を 300s にする ([#198](https://github.com/Sh1n1230/security-checker/issues/198)) ([92d37c8](https://github.com/Sh1n1230/security-checker/commit/92d37c883c4bed2e56fa58cca73a8d42f96862ab))
* **providers:** 降格を 400 に限り、思考トークンを出力に数え、出力上限のキーを選べるようにする ([#194](https://github.com/Sh1n1230/security-checker/issues/194)) ([8ff0b10](https://github.com/Sh1n1230/security-checker/commit/8ff0b104e00026876a14307c7ee1cb0523643881))
* **report:** SARIF を level だけのゲートにそろえ、URI を符号化し、指摘の理由を脆弱と判定した Reviewer から選ぶ ([#205](https://github.com/Sh1n1230/security-checker/issues/205)) ([6127f86](https://github.com/Sh1n1230/security-checker/commit/6127f862cc56144d4b9637086e1c307f96355f84))
* **review:** evidence を完全一致と両端の行で検証し、トレースに実際に送った seed と temperature を残す ([#190](https://github.com/Sh1n1230/security-checker/issues/190)) ([40f1e14](https://github.com/Sh1n1230/security-checker/commit/40f1e1493320b066964506b83f939b6916036476))
* **review:** スキャナの出力に由来する欄をデリミタで囲み、秘密の値を伏せる (プロンプト v2) ([#389](https://github.com/Sh1n1230/security-checker/issues/389)) ([28e3b79](https://github.com/Sh1n1230/security-checker/commit/28e3b79d4d2c80f1fa4dcf1fa2999b7392fb6725))
* **review:** 予算・無効化・デッドラインを送信の直前に判定し、修復の再送と 429 の扱いを §22・§23 に合わせる ([#188](https://github.com/Sh1n1230/security-checker/issues/188)) ([997699a](https://github.com/Sh1n1230/security-checker/commit/997699a9a8a7b2d944ace22a01fa6fdce2dd98b9))
* **run:** スキャナをまたいだ依存の脆弱性の重複を 1 件にまとめる ([#388](https://github.com/Sh1n1230/security-checker/issues/388)) ([5d64a52](https://github.com/Sh1n1230/security-checker/commit/5d64a52159b47aa93895d96db80c29ca67e629e2))
* **run:** レビューが例外で抜けても Provider を閉じる ([#79](https://github.com/Sh1n1230/security-checker/issues/79)) ([b32b0ae](https://github.com/Sh1n1230/security-checker/commit/b32b0ae2cb254383a87310d9ff1e1707c76463f0))
* **scanners:** semgrep の推移的な依存をハッシュで固定し、専用 venv に入れる ([#118](https://github.com/Sh1n1230/security-checker/issues/118)) ([c4060db](https://github.com/Sh1n1230/security-checker/commit/c4060db56d5a3bfd31db98500007c6e5bc802689))
* **scanners:** target.exclude の解釈を gitignore にそろえ、全スキャナと ignore ファイルで共通にする ([#117](https://github.com/Sh1n1230/security-checker/issues/117)) ([99c1ac1](https://github.com/Sh1n1230/security-checker/commit/99c1ac15b3ad3ca51de5f20e4ae582bc2dadc752))
* **scanners:** trivy の誤設定で重大度が不明なら medium として扱う ([#112](https://github.com/Sh1n1230/security-checker/issues/112)) ([f053621](https://github.com/Sh1n1230/security-checker/commit/f053621e2136383177be0e09cddd1b06908924f1))
* **scanners:** 出力全体を解釈できない run を failed にし、semgrep の --timeout に全体の上限を渡さない ([#385](https://github.com/Sh1n1230/security-checker/issues/385)) ([981b76e](https://github.com/Sh1n1230/security-checker/commit/981b76e808c35ec8363642eb4bc4043215fbb21c))


### Documentation

* **adr:** メンテナが 1 人の間はマージに承認を必須にしない (0007) ([#99](https://github.com/Sh1n1230/security-checker/issues/99)) ([f5c41c8](https://github.com/Sh1n1230/security-checker/commit/f5c41c8cdb5ef3c05044914115d16743b5ea30c5))
* 複数のリポジトリへの導入と、required check にするまでの手順を書く ([#122](https://github.com/Sh1n1230/security-checker/issues/122)) ([9129a80](https://github.com/Sh1n1230/security-checker/commit/9129a80f40204e3a744529d49943310653928601))

## [2.1.0](https://github.com/Sh1n1230/security-checker/compare/v2.0.0...v2.1.0) (2026-10-10)


### Features

* Python 3.14 に対応する ([#60](https://github.com/Sh1n1230/security-checker/issues/60)) ([90895c4](https://github.com/Sh1n1230/security-checker/commit/90895c41ba262c4345d0cd8a9a81a987d66d97c5))


### Bug Fixes

* **providers:** process transport の出力を上限つきで読み、メモリに溜めない ([#63](https://github.com/Sh1n1230/security-checker/issues/63)) ([5a2b1e3](https://github.com/Sh1n1230/security-checker/commit/5a2b1e3eef750d58bf59033fb345d7ba27c9a0cf))
* **report:** report.md と PR コメントで LLM 出力の Markdown/HTML を同じ規則で無害化する ([#58](https://github.com/Sh1n1230/security-checker/issues/58)) ([0ff5aa5](https://github.com/Sh1n1230/security-checker/commit/0ff5aa5c6b1a9cd1dd5bcb487f2382cd99a7e837))
* **scanners:** untrusted-target では検査対象のスキャナ設定を読ませない ([#61](https://github.com/Sh1n1230/security-checker/issues/61)) ([bfafbc3](https://github.com/Sh1n1230/security-checker/commit/bfafbc331cc3784bd99063dab7f3c80c1dc109ce))
* Windows で動かない箇所を直し、macOS / Windows でも CI を回す ([#65](https://github.com/Sh1n1230/security-checker/issues/65)) ([0b63f42](https://github.com/Sh1n1230/security-checker/commit/0b63f428dcb90ad061b065d8fd6de9f0a15d5e05))
* スキャナの版と sha256 を 1 か所に固定し、action・CI・Docker で共有する ([#72](https://github.com/Sh1n1230/security-checker/issues/72)) ([659b109](https://github.com/Sh1n1230/security-checker/commit/659b1091a4715aae2affa41542a7116909755141))

## [2.0.0](https://github.com/Sh1n1230/security-checker/compare/v1.1.0...v2.0.0) (2026-10-05)


### Features

* **eval:** eval コマンド — 精度を測れるようにする ([#21](https://github.com/Sh1n1230/security-checker/issues/21)) ([5729f4b](https://github.com/Sh1n1230/security-checker/commit/5729f4b33f898f7a97f2c24729d895f928af0f03))
* P4〜P6 — GitHub 統合・品質・公開準備 ([#35](https://github.com/Sh1n1230/security-checker/issues/35)) ([3ce8122](https://github.com/Sh1n1230/security-checker/commit/3ce8122510ab23e45e425736ac9cde59fe488a58))


### Bug Fixes

* __version__ を pyproject.toml から取り、リリース時の食い違いをなくす ([#38](https://github.com/Sh1n1230/security-checker/issues/38)) ([839f4ae](https://github.com/Sh1n1230/security-checker/commit/839f4aee8a6acc3a20506a9b0d572f8df001e610))


### Documentation

* リリースのたびにずれるバージョン表記をなくし、eval の状況を反映する ([#34](https://github.com/Sh1n1230/security-checker/issues/34)) ([07f9d53](https://github.com/Sh1n1230/security-checker/commit/07f9d53d8f10cb5591fa8a97eb789623dbaee47d))
