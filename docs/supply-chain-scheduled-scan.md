# Dependency-update automation and the daily supply-chain scan

_Slice W3-1 (#424). This document is true of the code as committed; the pin that keeps it true is
`integration/tests/test_dependency_automation.py`, which runs in the required
`integration two-env boundary (P5)` job._

## The gap this closes

The A14 supply-chain gate (`.github/workflows/supply-chain.yml`) runs only on push and pull request
to `main`. A vulnerability disclosed against a dependency that is already merged and already pinned
is therefore invisible until someone happens to open a pull request that touches a lock. Two new,
additive pieces close that window. Neither edits `ci.yml`, and neither is a merge-blocker — the A14
gate remains the blocking control on pull requests.

## 1. Dependency-update automation — `.github/dependabot.yml`

Dependabot watches all five ecosystems the repository actually contains and opens an attributable
pull request when an update is available:

| Ecosystem | Watched location(s) |
| --- | --- |
| `pip` | `/`, `/apps/sigil`, `/gateway`, `/integration`, `/engine/crucible`, `/engine/crucible/framework/v2`, `/packages/core/vigil_core` |
| `cargo` | `/apps/sigil/kernel` (the WARDEN Rust kernel) |
| `npm` | `/` (see note below) |
| `github-actions` | `/` (the pinned action SHAs in `.github/workflows/*`) |
| `docker` | `/gateway`, `/engine/crucible/framework/v2/aegis` |

Update pull requests are grouped (minor/patch batched) and scheduled weekly, to keep the noise low; a
security-relevant bump still surfaces the same day through the scan below.

**Deliberate exclusions.** The intentionally-vulnerable eval-corpus fixtures under
`engine/crucible/framework/v2/eval/corpus_apps/_cve/` are **not** watched — they must stay vulnerable
so the engine can prove it detects the CVE, and a "fix" pull request would break the corpus.
`vendor/` is quarantined third-party source and is likewise left alone.

**npm note (honest limit).** The `npm` entry is declared at the repository root so a production
`package.json` is watched the moment one lands. Today the repository ships no runtime npm project —
the only `package.json` is the excluded `st-2014-3744` eval fixture — so this entry is currently a
standing guard rather than an active watch.

## 2. The daily scan — `.github/workflows/scheduled-supply-chain-scan.yml`

A `schedule:` trigger runs the scan every day at 06:00 UTC (a `workflow_dispatch` allows a manual run,
with a `dry_run` input; it also runs on pull requests purely so its own change is visible green). It
scans the committed dependency tree with Trivy — the same version-and-sha256-pinned scanner, lock
file-patterns, and `.trivyignore` the A14 gate uses, so both agree on what is actionable — and when a
finding is at or above the threshold (`CRITICAL` today, to match A14's blocking policy; W3-9/#432
raises it) it **opens a GitHub issue** listing each vulnerability, its fixed version, and its
advisory. The issue-opening step is gated to the `schedule` (and non-dry-run manual) event, so a
pull-request run never creates an issue.

The decision — parse the report, filter by severity, build the issue title and body — lives in
`.github/scripts/supply_chain_scan.py` (pure standard library) precisely so it is testable without a
network or a Trivy binary. On a clean report it opens nothing; that is what keeps the scan from being
a gate that always fires.

**Advisory, by design.** This workflow is intentionally not in
`.github/required-status-checks.txt`. Its job is to watch over time and raise an issue, not to add a
second blocker on pull requests.

## Negative controls

Two, so a green result can never be a silently-broken scanner:

- **In the workflow.** Before the real scan, the job writes a fixture `requirements.txt` pinning a
  known-`CRITICAL` package to a temp directory *outside* the repository, scans it, and runs the real
  decision path in dry-run with `--expect-findings`. The step fails if that fixture produces no
  finding — proving the issue-opening path actually fires — while dry-run means no issue is created.
- **In the test.** `test_dependency_automation.py` feeds the decision script a clean report and a
  sub-threshold (HIGH-only) report and asserts it opens nothing, feeds a known-`CRITICAL` report and
  asserts it does, and feeds the config checkers a manifest missing an ecosystem / an update lacking a
  schedule / a workflow with no `schedule:` trigger and asserts each is rejected.
