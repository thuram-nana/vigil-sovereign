# W12-3 — Require review from Code Owners (CODEOWNERS across the tree)

Issue: [#492](https://github.com/thuram-nana/vigil-sovereign/issues/492) ·
Milestone: W12 — PROCESS HYGIENE.

## The defect this closes

CODEOWNERS assigns reviewers. The repository already had a root
[`.github/CODEOWNERS`](../../.github/CODEOWNERS) — the [W1-8] #417 work moved it out of the inert
nested `engine/crucible/.github/` location to a path GitHub actually reads — but its coverage of the
**security-critical trust domains** was partial, and nothing machine-checked it. A catch-all
`*  @thuram-nana` makes every path nominally "owned", which is exactly why a naive coverage check is
worthless: it passes vacuously. The real risk is a second maintainer being added to `*` and thereby
inheriting review authority over the veracity firewall, the egress gate, the supply-chain pins and the
governance policy itself — trust roots that must be **called out**, not inherited by accident.

## The decision

1. Give every security-critical trust domain its **own explicit CODEOWNERS rule** — more specific than
   the `*` catch-all, so it is the last matching rule and wins. Beyond the domains already listed
   (`verify/`, `veracity/`, `live/`, `gateway/`, `egress-guard/`, `workflows/`) this adds the
   governance surface itself (`/.github/`, `/tools/governance/`), supply-chain integrity
   (`/infra/supply-chain/`), the formal core-invariant models (`/formal/`), and the shared integrity
   substrate (`/packages/core/vigil_core/`).
2. Machine-check that coverage with a required-CI guard so the list cannot silently rot.
3. Document plainly what CODEOWNERS does and does not enforce today.

## What this does and does NOT enforce — and the one human/admin action still required

A CODEOWNERS file **requests** a review from the named owners. It becomes a **merge gate** only when
branch protection on `main` also has **"Require review from Code Owners"** enabled. That setting is a
repository-administration change made through the GitHub UI or the Administration API; it cannot be
turned on from inside the repository tree, so this slice does **not** claim it is on.

> **HUMAN/ADMIN ACTION (residual for #492):** In the `main` branch protection settings, enable
> *Require a pull request before merging* → *Require review from Code Owners* (with at least one
> required approval). Until then this file makes ownership explicit and requests the review; it does
> not by itself block a merge. Do not describe CODEOWNERS as a gate until that setting is on.

This is the same honesty discipline as the branch-protection token ([W0-1] #554) and signed commits
([W12-4] #493): everything code-side ships and is tested; the final flip is a deliberate operator step.

## The claim (registered in the claims registry, id `W12-3`)

<!-- CLAIM:W12-3 -->
> **Registered claim:** The repository-root CODEOWNERS lives where GitHub reads it, has a catch-all owner, and gives every security-critical trust-domain path its own explicit rule that is more specific than the catch-all, with a well-formed owner and a path that exists in the tree; a required-CI guard fails the build if any critical path falls back to the bare catch-all, if the catch-all is missing, if an owner token is malformed, or if a rule points at a path not in the tree.

## Why this is TRUE of the code

- [`.github/CODEOWNERS`](../../.github/CODEOWNERS) carries an explicit rule for each path in
  `_CRITICAL_PREFIXES`, each owned by a valid `@handle`.
- [`integration/tests/test_codeowners_coverage.py`](../../integration/tests/test_codeowners_coverage.py)
  is the guard. Its enforcing helper `codeowners_coverage_defects(text, repo_root)` returns the list of
  coverage defects; the positive test asserts the real CODEOWNERS has none. It reads files only (imports
  neither trust domain, sends no packet), so it runs in the required **integration two-env boundary
  (P5)** CI job, which collects the whole `integration/tests` tree.
- **Fails without the change.** On the tree before this slice, `/.github/`, `/tools/governance/`,
  `/infra/supply-chain/`, `/formal/` and `/packages/core/vigil_core/` had no explicit rule — they sat
  under the bare catch-all — so `test_root_codeowners_covers_every_critical_path` is red. Observed by
  `git stash push -- .github/CODEOWNERS` then running the file.
- **Negative control.** In the same run, `codeowners_coverage_defects` is fed CODEOWNERS text with a
  critical rule dropped, with no catch-all, with a malformed owner, and with a rule pointing at a
  nonexistent path — each must be reported — proving the gate is not a constant-pass no-op.

## Residual

- The **"Require review from Code Owners"** branch-protection flip (above) is the single human/admin
  action that turns this from a review *request* into a merge *gate*. Issue #492 stays open pending it.
