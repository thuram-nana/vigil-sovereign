# W0-1 (residual) — BRANCH_PROTECTION_TOKEN and the branch-protection live-reality pin

Issue: [#554](https://github.com/thuram-nana/vigil-sovereign/issues/554) ·
Milestone: W0 — FOUNDATIONS (residual).

## Context

Three artifacts key on `.github/required-status-checks.txt`, the single source of truth for the `main`
branch's required checks:

1. `tools/governance/require-checks.sh` reads it to SET live branch protection (`--apply`);
2. `docs/tests/test_required_checks_canonical.py` proves the committed artifacts agree with each other,
   offline; and
3. `.github/workflows/branch-protection-verify.yml` reads the LIVE GitHub settings and fails if they
   drift from the committed policy — the pin that catches "someone turned protection off in the UI".

The offline test (2) proves the committed files are self-consistent. Only the live pin (3) can prove the
**actual** GitHub settings still match. This residual is about making (3) real and testable.

## The human/admin action this residual still needs

Reading branch protection requires the **"Administration: read"** permission. That is NOT a grantable
`GITHUB_TOKEN` permission scope, so the default token the workflow runs with **cannot** read branch
protection. The workflow therefore no-ops (`armed=false`) until a **fine-grained Personal Access Token
with Administration:read** is provided as the repository secret `BRANCH_PROTECTION_TOKEN`.

> **HUMAN/ADMIN ACTION (residual for #554):** Create a fine-grained PAT scoped to this repository with
> **Administration: read**, and add it as the repository secret **`BRANCH_PROTECTION_TOKEN`**. Until
> then the live pin is a clean no-op — it cannot verify anything — and MUST NOT be promoted to a
> required check (a required check that always no-ops still passes, but a required check that errors
> because it cannot read protection would block every PR). Promotion is a later, deliberate governance
> step via `tools/governance/require-checks.sh` once the secret exists and the job reports on PRs.

## The decision (what ships in this slice)

The comparison logic used to live inline in the workflow as a `python3 - <<'PY'` heredoc, where it could
never be unit-tested — the only way to exercise it was to run the workflow against a live repo with the
admin token. This slice **extracts it** to
[`tools/governance/branch_protection_check.py`](../../tools/governance/branch_protection_check.py)
(`compare_protection` + `load_canonical`) and points the workflow at that module, so the exact code the
job runs is now driven offline by a required test — **including the negative control the acceptance
criterion names**: dropping a required check from the committed policy makes the compare fail.

Nothing about the workflow's behaviour changes — it still no-ops without the token, still compares the
same four dimensions (contexts as a set, `strict`, force-pushes, deletions) — the logic simply became a
tested module instead of an untestable heredoc.

## Promotion prep — confirmed

The live pin's job name, **"branch protection matches the committed policy"**, is deliberately **NOT**
in `.github/required-status-checks.txt` (it would block every PR while it no-ops), and it is enumerated
in the `KNOWN_ADVISORY` ledger of `docs/tests/test_required_checks_canonical.py` with that exact reason.
`docs/tests/test_branch_protection_verify.py::test_verify_is_advisory_not_required_until_token_provisioned`
pins that it stays out of the required set until the token is provisioned.

## The claim (registered in the claims registry, id `W0-1-branch-protection-verify`)

<!-- CLAIM:W0-1-branch-protection-verify -->
> **Registered claim:** The branch-protection verify logic lives in a single tested module (`compare_protection`) that the workflow calls, and it detects when live GitHub branch protection drifts from the committed canonical policy — flagging a missing or extra required check, a non-strict rule, or allowed force-pushes/deletions — with a required offline test proving that dropping a required check from the committed policy makes the compare fail; the live pin itself stays advisory (deliberately not a required check) and no-ops until the fine-grained `BRANCH_PROTECTION_TOKEN` PAT with Administration:read is provisioned, which is a human/admin action.

## Why this is TRUE of the code

- [`tools/governance/branch_protection_check.py`](../../tools/governance/branch_protection_check.py)
  holds `compare_protection`; the workflow calls it by path (no inline copy remains).
- [`docs/tests/test_branch_protection_verify.py`](../tests/test_branch_protection_verify.py) drives it
  with a matching live body (no problems) and the drift cases, and asserts the workflow calls the module
  and that the inline heredoc is gone. It runs in the required **the briefing explains every agent and
  capability** CI job (`pytest docs/tests -q`).
- **Fails without the change.** On the pre-fix tree the workflow carried the inline heredoc, so
  `test_workflow_calls_the_extracted_module` is red (observed by `git stash` of the workflow), and
  without the module the test cannot import `compare_protection`.

## Residual

- Provisioning `BRANCH_PROTECTION_TOKEN` (above) is the single human/admin action that arms the live
  pin. Issue #554 stays open pending it.
