# W13-9 — The reviewer readiness package is a VERIFIABLE ASSURANCE ARCHITECTURE, script-assembled and evidence-bound

Issue: [#502](https://github.com/thuram-nana/vigil-sovereign/issues/502) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme).
Depends on (as OPTIONAL, pending inputs): [#500] VSCP (the three client instruments) and
[#504] W14-2 legal counsel (`EXPORT.md`, the DPA). Neither is merged yet; this slice ships the
assembler and its gates now and flags those inputs as PENDING rather than fabricating them.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W13-9 -->
> The reviewer readiness package is ASSEMBLED by a script (`tools/reviewer-package/assemble.py`) from
> committed sources — `DATA-GROUND-TRUTH.md`, `PRIVACY.md`, `SECURITY.md`, the retention and
> incident-response policies, and `docs/claims/registry.json` — so it cannot be a hand-edited snapshot;
> every assurance statement it makes resolves to a claims-registry entry whose enforcing symbol is real
> and whose proving test exists and runs in a required CI job (removing that test makes the package build
> FAIL, so the package cannot outlive its evidence); inputs owned by not-yet-merged dependencies
> (`EXPORT.md` from #504 and the three client instruments from #500) are flagged as PENDING rather than
> fabricated; and the package is presented as a VERIFIABLE ASSURANCE ARCHITECTURE, never as a compliance
> accreditation or attestation — a build-time gate fails the build if any wording asserts certification.

This claim is TRUE of the code as of W13-9:

- **Script-assembled, not a snapshot** — `tools/reviewer-package/assemble.py::build_package` re-derives the
  package bytes from the tree on every run and writes to the gitignored `dist/reviewer-package/`. It records
  a SHA-256 digest over the embedded committed sources so a reviewer can confirm the package was produced
  from those exact bytes (this digest is reproducibility provenance, **not** a granted credential).
- **Pulls from the named committed sources** — `input_manifest()` lists `DATA-GROUND-TRUTH.md`, `PRIVACY.md`,
  `SECURITY.md`, the backup/DR retention record (`docs/decisions/W7-1-rpo-rto-objectives-and-drill.md`), the
  incident-response playbook (`engine/crucible/framework/playbooks/26-incident-response-pivot.md`) and
  `docs/claims/registry.json`. A required input that is absent raises `MissingRequiredInput` and fails the
  build.
- **Every claim is evidence-bound** — `build_package` resolves each id in `ASSURANCE_CLAIMS` through
  `resolve_claim`, which fails (`EvidenceMissing`) unless the registry entry exists, its `enforced_by`
  symbol is really defined (AST, no import), its `proved_by` test file and **every** named test function
  exist, and its `ci_job` is a **required** check in `.github/required-status-checks.txt`. **Deleting a
  proving test therefore fails the package build** — the pack cannot outlive its evidence.
- **No wording asserts certification** — `assert_no_certification_wording` scans the fully rendered package
  and raises `CertificationWordingError` on the `certify / certified / certifies / certification` family.
  The legitimate cryptographic word `certificate`/`certificates` (proof-carrying-finding certificates,
  evidence certificates) is word-boundary-excluded, so the package can still speak about signed evidence
  certificates while never asserting a compliance certification.
- **Pending inputs are flagged, never fabricated** — `EXPORT.md` (#504, legal counsel) and the three client
  instruments (#500, VSCP) are declared with `required=False` and a tracking issue. While their files are
  absent they render as **PENDING** in the package; once the dependency lands the files, the same manifest
  entry auto-embeds them. Nothing legal or client-facing is invented on their behalf.
- **A facade, not a second policy engine** — the package REFERENCES the existing controls (WARDEN tiers, the
  conjunctive and destruction gates, the signed charter, the `require_capability` entitlement layer, the
  hash-chained signed spine, offline re-verification, TPM sealing, m-of-n quorum) through their registry
  entries and re-runnable tests. `assemble.py` implements no gate, policy, or oracle of its own — it is an
  assembler over the assurance substrate, in the same spirit as `sovereign_bridge` being a facade over the
  gate chain ([W13-2] #495).

## The test that fails without this change (observed, not assumed)

`docs/tests/test_w13_9_reviewer_package.py` loads `tools/reviewer-package/assemble.py` and calls
`build_package()`. On a tree without W13-9 the module does not exist, so the test errors at collection;
with the module present but the `W13-9` registry entry absent, `build_package()` raises `EvidenceMissing`.
Both were observed on this tree while building the slice. The negative controls in the same run prove the
gates are not no-ops: removing a proving test from a scratch registry makes `resolve_claim` raise
`EvidenceMissing`, and feeding certification wording to `assert_no_certification_wording` raises
`CertificationWordingError`.

## Where the tests run — a required CI job

`docs/tests/test_w13_9_reviewer_package.py` reads files and imports only the standard library plus the
assembler module (itself stdlib-only), so it runs in the **required** `the briefing explains every agent
and capability` job (`pytest docs/tests -q`), the same job that runs the claims-registry guard. The
`W13-9` registry entry names that job, and `docs/tests/test_claims_registry.py` fails the build if the
entry ever stops resolving.

## Honest residual

The two client-facing dependencies are not yet merged: `EXPORT.md` (export-control classification, #504)
and the three client instruments (#500, VSCP). The assembler ships now and renders them as PENDING with
their issues; it will embed them without change once those deps land their files. This is the honest state,
recorded in both the package and the final report.

> **Registration:** this claim is entry `W13-9` in `docs/claims/registry.json`; the marker above is its
> `source` anchor.
