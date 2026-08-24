# Governance prep — the FOUR human/admin actions still required (#492, #493, #554, #653)

This slice (`gov-prep-492-493-554-653`) shipped every code-side, doc-side and test-side artifact for
four governance items to the government-deployment bar. Each item, however, has exactly one residual
that **cannot** be done from inside the repository — it needs a repository-administration flip, an org
secret, or physical/self-hosted infrastructure. Those four residuals are enumerated here so the
orchestrator/operator can action them deliberately. **All four issues stay OPEN pending these actions.**

Nothing below is claimed as done. The claims registered for these items describe only what the code
enforces now (the tooling, the tests, the scaffolds), never the admin flip.

| # | Issue | What shipped (code/doc/test) | The ONE human/admin action still required |
|---|-------|------------------------------|-------------------------------------------|
| 1 | **#492** (W12-3) Require review from Code Owners | Root `.github/CODEOWNERS` with an explicit owner for every security-critical trust domain; `integration/tests/test_codeowners_coverage.py` (required P5); `docs/decisions/W12-3-require-code-owner-review.md` | **Enable "Require review from Code Owners"** on the `main` branch-protection rule (Settings → Branches), with ≥1 required approval. Until then CODEOWNERS *requests* review; it does not *gate* a merge. |
| 2 | **#493** (W12-4) Enforce signed commits | `tools/governance/setup-commit-signing.sh` + `verify-commit-signing.sh` + `commit_signing.py` (the shared check); `integration/tests/test_commit_signing_setup.py` (required P5); `docs/decisions/W12-4-enforce-signed-commits.md` | **Enable "Require signed commits"** on the `main` branch-protection rule. NOTE: this **blocks unsigned pushes** the moment it is on, so roll it out only after every contributor/automation has configured signing — a deliberate operator choice. |
| 3 | **#554** (W0-1 residual) BRANCH_PROTECTION_TOKEN | Branch-protection compare logic extracted to `tools/governance/branch_protection_check.py` and called by `.github/workflows/branch-protection-verify.yml`; negative test `docs/tests/test_branch_protection_verify.py` (required briefing job); `docs/decisions/W0-1-branch-protection-token.md` | **Provision a fine-grained PAT with Administration:read** and add it as the repo secret **`BRANCH_PROTECTION_TOKEN`**. The live pin no-ops without it (the default `GITHUB_TOKEN` cannot read branch protection). Only after the secret exists may the pin be promoted to a required check. |
| 4 | **#653** (W3-7 residual) trivy strix-sandbox on self-hosted runner | Dormant scaffold `.github/workflows/strix-sandbox-image-scan.yml` (self-hosted `runs-on` + opt-in var, schedule/dispatch only, gateway threshold, advisory); shape guard `docs/tests/test_strix_sandbox_image_scan_workflow.py` (required briefing job); enumerated in `KNOWN_NONPR_ADVISORY`; `docs/SUPPLY-CHAIN.md` §4a | **Register a self-hosted / large runner** able to build the ~7GB Kali image (labels `[self-hosted, linux, x64, large]`) and set the repo variable `STRIX_SANDBOX_SCAN=enabled`. Until then the scaffold is cleanly skipped; the SBOM scan remains the PR-CI proof of the Strix layer. |

## How to close each issue after the action

1. **#492** — after enabling Require-Code-Owner-review, confirm the setting via
   `tools/governance/require-checks.sh` / the GitHub API, then close #492 noting the setting is live.
2. **#493** — after enabling Require-signed-commits (and confirming contributors are set up), close
   #493. `tools/governance/verify-commit-signing.sh` is the per-contributor readiness check.
3. **#554** — after adding `BRANCH_PROTECTION_TOKEN`, confirm the `branch-protection-verify` workflow
   arms (`armed=true`) and reports on PRs, then promote it via `require-checks.sh` and close #554.
4. **#653** — after registering the runner and setting `STRIX_SANDBOX_SCAN=enabled`, confirm one run of
   `strix-sandbox-image-scan.yml` builds and scans the image, then close #653.

## Why these are not faked closed

Each residual is an *authority* the repository does not hold: branch-protection settings and org secrets
are owned by a repository admin; a self-hosted runner is physical/cloud infrastructure. The honest
posture (see `AGENT-SHARED-CONSTRAINTS.md` → "Honesty on irreducible external dependencies") is to ship
everything code-side, prove it with required tests, and name the residual — which is exactly what the
four decision docs and the four registered claims do.
