# 意思決定記録 (ADR)

「なぜそうなっているか」を後から辿れるようにするための記録です。
設計書 ([DESIGN.md](../DESIGN.md)) は「どうするか」、ADR は「なぜそれを選び、何を捨てたか」を書きます。

| # | タイトル | 状態 |
|---|---|---|
| [0001](0001-sarif-level-from-scanner-severity.md) | SARIF の level はスキャナ由来の重大度で決める | 採用 (2026-09-15) |
| [0002](0002-docs-language.md) | ドキュメントの正典言語は当面日本語 | 採用 (2026-09-15) |
| [0003](0003-bundled-presets.md) | 同梱プリセットは客観条件を満たすものだけ | 採用 (2026-09-15) |
| [0004](0004-fork-pr-rescan-instead-of-artifacts.md) | fork PR の publish 側は成果物を使わず、読むだけで検査し直す | 採用 (2026-10-04) |
| [0005](0005-composite-action-until-ghcr.md) | GHCR 公開までは composite action で配る | 採用 (2026-10-04) |
| [0006](0006-outside-diff-candidates-in-sarif.md) | diff の範囲外の候補も SARIF に note で残す | 採用 (2026-10-04) |
| [0007](0007-no-required-approvals-while-single-maintainer.md) | メンテナが 1 人の間は、マージに承認を必須にしない | 採用 (2026-10-19) |
| [0008](0008-baseline-secret-hash.md) | baseline の秘密は、候補 ID ではなく baseline のソルト付き要約で照合する | 採用 (2026-11-04) |
| [0009](0009-gate-on-sarif-level-only.md) | Code Scanning のゲートは SARIF の level だけで掛け、security-severity を付けない | 採用 (2026-11-04) |

新しい ADR は連番で足し、既存のものは書き換えずに「置き換えた」ことを新しい ADR に書きます。
