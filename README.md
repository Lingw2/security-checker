# security-checker

**English** | [日本語](README.ja.md)

[![CI](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Sh1n1230/security-checker/badge)](https://scorecard.dev/viewer/?uri=github.com/Sh1n1230/security-checker)
[![Release](https://img.shields.io/github/v/release/Sh1n1230/security-checker)](https://github.com/Sh1n1230/security-checker/releases)
[![License: MIT](https://img.shields.io/github/license/Sh1n1230/security-checker)](LICENSE)

An AI security review platform: it runs the usual scanners, then has **independent LLMs review each
finding as third-party auditors**, so you get fewer false positives without hiding real issues.

> **Status:** alpha. Phases P1–P5 of the [migration plan](docs/DESIGN.md#32-移行計画) are done;
> releases are published on GitHub only for now (install from git); PyPI comes later.
> The design docs are currently in Japanese ([ADR 0002](docs/adr/0002-docs-language.md)).

## What it is — and what it is not

- **It is** a reviewer. Scanners (semgrep, gitleaks, osv-scanner, trivy) report candidates; one or more
  LLM reviewers decide whether each candidate is a real, reachable vulnerability and explain why.
- **It does not modify your code.** Reviewers suggest a remediation; applying it is always your call.
- **It does not ask the LLM to hunt for bugs.** Findings come from deterministic scanners, so results are
  reproducible and auditable.
- **It is vendor neutral.** There is no default model and no "supported LLM" list. You pick what you
  already have — an HTTP endpoint in one of four API shapes, or any non-interactive command.

## Keep the AI that wrote the code away from the AI that reviews it

If the same model that helped you write a piece of code also judges whether it is safe, it tends to agree
with itself. security-checker lets you choose a reviewer that is *not* your development assistant, or
several of them, and makes their agreement — or disagreement — visible.

```text
  Developer's AI ──writes──► code ──scanners──► candidates ──► Reviewer AI(s) ──► findings
                                                              (independent)
```

When reviewers disagree, the finding is reported as **`review_required`** instead of being forced into a
yes/no answer. Split decisions are exactly what a human should look at.

## Try it in 60 seconds

```sh
uv tool install git+https://github.com/Sh1n1230/security-checker
security-checker scan .        # scanners only — nothing leaves your machine
security-checker init          # detect what you can use as a reviewer, write security-checker.yml
security-checker review . --dry-run    # see exactly what would be sent, without sending it
security-checker review .
```

`init` lists what is actually available in *your* environment (non-interactive CLIs, API key environment
variables). The README deliberately does not name a model: whatever we wrote here would become the de facto
recommendation.

## Results

| status | meaning | fails CI? |
|---|---|---|
| `confirmed` / `likely` | reviewers judge it a real issue | if severity ≥ `policy.fail_on` |
| **`review_required`** | reviewers disagree, or are not confident | no — but it is shown right after `confirmed` |
| `false_positive` | reviewers judge it not exploitable here | no (kept in `report.json`, hidden from PRs) |
| `inconclusive` / `error` / `not_reviewed` | no verdict | no — and never presented as "clean" |

Exit codes separate *"we found something"* (1) from *"the tool is broken"* (3): a failed scanner never
looks like a clean run.

`security-checker explain <id>` replays every reviewer's reasoning and every LLM call behind a verdict.

## GitHub Actions

```yaml
permissions:
  contents: read
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # sticky summary + inline comments
      security-events: write # SARIF upload to Code Scanning
    steps:
      - uses: actions/checkout@<SHA>
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Sh1n1230/security-checker@<SHA>
        env:
          YOUR_PROVIDER_API_KEY: ${{ secrets.YOUR_PROVIDER_API_KEY }}
```

On pull requests it reviews only candidates touching changed lines, keeps **one** sticky summary comment up
to date, never re-posts the same inline comment, and uploads SARIF under the fixed tool name
`security-checker`. Fork PRs are handled safely (scan only, no secrets; an optional `workflow_run` workflow
re-scans the PR code read-only with your trusted config). We never use `pull_request_target`.
See [docs/github-actions.md](docs/github-actions.md).

## Configuration

Everything has a default except reviewers. Start with one reviewer, add more, then a judge:

```yaml
reviewers:
  - name: r1
    transport: http
    dialect: openai_chat          # openai_chat | anthropic_messages | gemini_generate | ollama_chat
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: MY_API_KEY       # the variable name — plaintext keys are not accepted
  - name: r2
    transport: process            # any non-interactive command; no API key needed
    command: ["<your-command>", "--non-interactive", "--no-tools"]
aggregation:
  strategy: consensus             # consensus | weighted | judge
```

Reference: [docs/configuration.md](docs/configuration.md) ·
aggregation strategies: [docs/aggregation.md](docs/aggregation.md).

## Adding an LLM — three routes

1. **An HTTP endpoint that speaks a known API shape** → one config block. The shape (dialect), not the
   vendor, is what matters.
2. **A command that runs non-interactively and prints JSON** → one config block with `transport: process`.
3. **Anything else** → a small Python package registered via entry points, verified with the published
   contract tests (`security_checker.testing.ProviderContractTests`).

`security-checker providers check` verifies a new reviewer end to end (config, reachability, structured
output). See [docs/providers.md](docs/providers.md).

## How it works

```text
Scanners ─► normalize ─► suppress (baseline / ignore / annotations) ─► diff scope
        ─► context builder (code window, repo facts) ─► reviewers (rate / budget limited)
        ─► aggregation (consensus / weighted / judge) ─► policy ─► terminal / JSON / Markdown / SARIF / PR
```

## Accuracy

We measure whether LLM review actually helps, on a labelled dataset (100 hand-written cases, majority false
positives). **Recall is the primary metric** — reducing false positives is worthless if real issues get
dismissed — and `eval` fails if any true positive is missed. If multiple reviewers do not beat a single one,
we will say so. See [docs/evaluation.md](docs/evaluation.md).

## Security and privacy

`review` sends the flagged code and its surrounding context (not the whole repository) to the reviewers you
configured. Detected secret values are masked before they are stored or sent. `scan` sends nothing.
Details: [docs/security-model.md](docs/security-model.md).

## Exit codes

| code | meaning |
|---|---|
| 0 | no policy violation |
| 1 | policy violation (`fail_on` or above, or score below `min_score`) |
| 2 | configuration error — stops before anything is sent |
| 3 | execution error — with `strict` (default): a scanner failed, a reviewer was disabled, review stopped early, or candidates were left unreviewed |

"Found vulnerabilities" (1) and "the tool broke" (3) are never mixed. Per-command details:
[docs/exit-codes.md](docs/exit-codes.md).

## Host-audit scripts (contrib/host-audit/)

Standalone, read-only scripts (carried over from v1, independent of the Python package) that audit *your
machine and workflow* rather than a codebase. Each exits 1 when it finds a problem, so they fit cron or CI.

| script | what it checks |
|---|---|
| `audit_macos.sh` / `windows/audit_windows.ps1` | OS settings (FileVault / BitLocker, firewall, SIP / Defender, sharing) |
| `check_ports.sh` / `windows/check_ports.ps1` | listening ports and anything exposed beyond localhost |
| `check_permissions.sh [dir]` / `windows/check_permissions.ps1` | `~/.ssh` and credential file permissions, world-writable files |
| `check_shell_env.sh` / `windows/check_shell_env.ps1` | secrets leaked into shell history, dotfiles and environment variables |
| `check_git_history.sh <repo>` | secrets anywhere in git history, including deleted ones |
| `check_tls_cert.sh <domain>` / `windows/check_tls_cert.ps1` | certificate expiry and acceptance of TLS 1.0 / 1.1 |
| `check_updates.sh` / `windows/check_updates.ps1` | pending OS / package-manager updates and backup status |
| `install_hooks.sh [repo]` | installs git hooks: pre-commit secret scan, pre-push blocks direct and force pushes to protected branches |
| `run_all.sh` / `windows/run_all.ps1` | runs the environment checks above in one go |

## Development guardrails

Dangerous git operations are blocked in three layers, ordered by how hard they are to bypass:

| layer | applies to | bypass | where |
|---|---|---|---|
| 1. GitHub Ruleset | everyone, every tool (server side) | **none** | GitHub settings |
| 2. git hooks | every local operation, human or agent | `--no-verify` | `contrib/host-audit/hooks/` |
| 3. agent permission settings | that agent only | easily, by rephrasing the command | `.claude/settings.json` |

Blocking direct and force pushes to protected branches lives in layers 1 and 2 only — pattern-matching
command strings (layer 3) is trivially evaded by things like `git -C <path> push --force origin main`.
`.claude/settings.json` is declarations only and ships no executable hook scripts, since those would run on
the machine of anyone who clones and opens the repository.

## Claude Code skills (skills/)

Two model-agnostic skills let you ask for a check or a fix in plain language:

```sh
cp -r skills/security-check skills/security-fix ~/.claude/skills/
```

- **security-check** — runs `security-checker scan` / `review` and explains the results
- **security-fix** — prioritises the findings and walks through safe fixes

Automated checks cover only part of the picture; review authentication and authorisation design manually
with [checklist/CHECKLIST.md](checklist/CHECKLIST.md).

## Contributing / License

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and
[SECURITY.md](SECURITY.md) (**report vulnerabilities privately, not in public issues**). All documentation is
indexed in [docs/README.md](docs/README.md). Issues and PRs are welcome in English or Japanese. MIT licensed.

The original v1 (bash / PowerShell) was removed after v1.1.0; see the `v1.1.0` tag if you need it.
