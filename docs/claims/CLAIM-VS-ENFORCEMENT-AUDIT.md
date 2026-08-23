# Claim-vs-enforcement audit — landing (W15-3 #395)

**What this is.** The claim-vs-enforcement audit asked, of every enforcement-flavoured claim in the
buyer- and reviewer-facing surfaces (README, AS-BUILT, POSTURE, CONTRIBUTING, SUPPLY-CHAIN, the in-app
Manual/Legal pages and the served remediation ladder): *is this true of the code?* Each claim was
classified **TRUE / SCOPED / FALSE / UNVERIFIABLE** against the source. The interim run produced **14
FALSE and 11 SCOPED** verdicts, filed as issues **[W0-5] #400 through [W0-14] #409**. This document
**lands** that audit: it records the load-bearing findings, the code reference that decided each, and —
crucially — the **current disposition** of each at the HEAD this document is committed on, because a
docs-truth audit is only useful if it is re-checked against the moving code rather than trusted as a
snapshot.

The durable machinery this folds into is the **claims registry** ([`registry.json`](registry.json),
W0-3 #398): every enforcement claim that survives resolves to a real enforcing symbol and a real proving
test, and the guard (`docs/tests/test_claims_registry.py`) fails the build if a registered claim loses its
backing or a doc marker loses its entry.

## A. FALSE families — and their disposition now

### A1. Branch protection / required checks (a claim family propagated into 11 files)

| Claim (as audited) | Verdict | Disposition NOW | Where |
|---|---|---|---|
| "Branch protection on `main` is live; a fixed set of required checks (the doc gave a specific count); force-push/deletion blocked; anyone can re-derive via `gh api …/branches/main/protection`." | **FALSE** at the audited HEAD (the protection object 404'd; every check was advisory). | **CLOSED.** The count is now stated honestly (see the protection table), with a committed source of truth and both an offline and a live check keying on it. Reviews and signed commits are explicitly marked **not enforced**, not claimed. | `docs/AS-BUILT.md:17-29`; `.github/required-status-checks.txt`; offline `docs/tests/test_required_checks_canonical.py`; live `.github/workflows/branch-protection-verify.yml` |

The remaining honesty risk here — a doc stating a required-check **count** that disagrees with the
canonical file — is pinned by `test_required_checks_canonical.py::test_doc_counts_match_canonical` across
every shipped `.md`. (This audit-landing PR additionally fixed a stale required-check count (13) in a `ci.yml`
comment, which the `.md`-only guard did not reach; it is now pinned by
`docs/tests/test_w16_std7_doc_drifts_corrected.py`.)

### A2. "TPM-anchored" — a display bug that manufactured a hardware claim

| Claim (as audited) | Verdict | Disposition NOW | Where |
|---|---|---|---|
| The CLI printed `(TPM-anchored)` for records because the branch keyed on `getattr(e, "grounded", False)` — a **string** field, always truthy — so every software-counter record was labelled "TPM-anchored". | **FALSE** (a `display-manufactures-evidence` drift). | **CLOSED.** The CLI now tests `getattr(e, "grounded", "") == "tpm"` and falls to `"software-chain"` otherwise; a comment records the exact bug it replaced. | `integration/vigil_integration/cli.py:1792-1796`; field type `attestation/models.py:57,82,107` |

## B. SCOPED verdicts

The 11 SCOPED verdicts are claims that are true only under a stated condition (an opt-in control
documented as a default, a capability true only on a configured host, etc.). They are tracked in the
filed issues (#400–#409) and, as each is reconciled, registered in [`registry.json`](registry.json) with
the honest `default` (`on`/`off`) and `failure_class` (`config-stated-as-code` /
`opt-in-stated-as-default` / `display-manufactures-evidence`) so a SCOPED claim can never be silently
re-documented as unconditional. The registry already carries examples of each class (e.g. `W10-8`
`opt-in-stated-as-default`, `REM-LADDER` `display-manufactures-evidence`).

## C. Honest residual (what this landing does NOT claim)

- This document lands the audit's **load-bearing** findings and their disposition. It does **not**
  reproduce a verbatim claim-by-claim classification of the full 137 KB README; that enumeration lives in
  the audit transcript referenced by #395 and in the per-claim issues #400–#409.
- Not every SCOPED claim has a `registry.json` entry **yet**. The registry is the destination; #400–#409
  track the remaining registrations. Adding one is mechanical (land the claim's marker + entry; the guard
  refuses an entry whose symbol or proving test does not resolve).
- The audit was run at an earlier HEAD; the two FALSE **families** above were re-verified as CLOSED at
  this HEAD. A SCOPED item not yet re-verified here keeps its filed-issue status until it is.
