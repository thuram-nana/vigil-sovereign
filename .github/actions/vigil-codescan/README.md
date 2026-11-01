# VIGIL code security scan — GitHub Action (W4)

A diff-scoped, **oracle-grounded** static security review for a pull request. It runs VIGIL's
deterministic code analysis (DAA) over the PR's changed files and annotates them with **FACT/LEAD-typed**
findings:

- **FACT** (`::error`) — VIGIL's single-region static oracle re-derived the property from the retained
  source region. Offline-re-verifiable.
- **LEAD** (`::warning`) — a DAA pattern matched but the oracle did not confirm it (a LEAD-only class, a
  non-Python file, or an oracle refusal). Surfaced honestly, **never** claimed oracle-verified.

This is a second trigger adapter into VIGIL's existing security job queue → authorized runner — the
**same** path the webhook uses. The scan runs **only** after the hard authorization gate allows the job,
so a repo with no provisioned `EngagementAuthority` is **refused, not scanned** (being "from CI" grants no
bypass).

## Usage

```yaml
# .github/workflows/security.yml (consumer)
on: pull_request
permissions:
  contents: read          # read-only; annotations/summary need no write token
jobs:
  vigil:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # REQUIRED — the three-dot PR diff needs the merge-base in local history
      - uses: ./.github/actions/vigil-codescan
        with:
          fail-on: high    # gate the build on oracle-confirmed FACTs at/above High; leads stay warnings
```

## Inputs

| input | default | meaning |
|---|---|---|
| `queue-root` | `.vigil-queue` | durable SecurityJob queue root (workspace-local is fine for one-shot CI) |
| `base-dir` | `.vigil-live` | engagement base dir holding the signed `<slug>.spine` |
| `fail-on` | `""` | fail (exit 1) on an **oracle-confirmed FACT** at/above this severity (`critical\|high\|medium\|low`); leads never break the build |
| `max-files` | `5000` | max files the analyzers scan |
| `python-version` | `3.13` | Python used to run VIGIL |

## What it does NOT do

- It does **not** post review comments or open PRs. CI output is limited to workflow-command annotations
  (`::error`/`::warning`) and the job summary — no GitHub write token is required. The gated review-comment
  / fix-PR legs live in `vigil pr-bot` (off by default, behind owner-signed grants + approval).
- It does **not** evade, exfiltrate, or scan third parties — it reads the PR's own changed files locally.

## Prerequisites / honest caveats

- **Authority**: the scan is refused unless an owner-signed `EngagementAuthority` is provisioned for the
  repo (the gate is the sole executor). This Action is the trigger; it never bypasses authorization.
- **Entitlement**: the FACT oracle needs the `DEEP_STATIC_ANALYSIS` capability provisioned, else the scan
  refuses under enforcement.
- **Not yet wired into a live workflow in this repo** — this is the reusable building block; enabling it on
  VIGIL's own PRs is a deploy decision (provision the authority + entitlement first), mirroring how
  `sigil serve-customer` / `serve-public` are shipped-but-not-auto-started.
