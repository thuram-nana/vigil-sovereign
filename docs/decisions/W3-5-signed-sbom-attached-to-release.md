# W3-5 — Every release carries a signed SBOM, retrievable independently of CI artifact retention

Issue: [#428](https://github.com/thuram-nana/vigil-sovereign/issues/428) ·
Milestone: W3 — SUPPLY CHAIN.

## The claim (registered in the claims registry, [W0-3] #398)

<!-- CLAIM:W3-5 -->
> Every release attaches a cosign-signed CycloneDX SBOM to the GitHub Release (durable, independent of CI artifact retention), and the released SBOM is cross-checked against its hash-pinned lock so an SBOM that omits a shipped component fails.

This claim is TRUE of the code as of W3-5.

## The defect

Before this slice the only bill of materials the product produced lived in a **90-day CI artifact**
(`a14-sbom-cyclonedx`, uploaded by `.github/workflows/supply-chain.yml`). It was never committed and
never attached to a release, so **a deployed artifact had no retrievable SBOM** once CI retention
lapsed — `supply-chain.yml:185-191` generated it, and it evaporated 90 days later.

## The fix

`.github/workflows/release.yml` (tag push only, `v*`) now, for each shipped dependency closure
(offense + sovereign — the product ships two, FATAL-2):

1. **Generates and cross-checks** the CycloneDX SBOM with the SAME mechanism the A14 gate runs on
   every PR — `engine/crucible/bin/verify-supply-chain.sh --sbom-out=…`. That script regenerates the
   SBOM from the hash-pinned lock and cross-checks it against the lock component-for-component, so an
   SBOM that dropped a shipped component fails *before* anything is signed.
2. **Signs** each SBOM with `cosign sign-blob` — the SAME keyless Sigstore primitive the release
   already uses for the wheel and sdist. This is deliberately **not a new signing scheme**: a
   `vigil_core` Ed25519/DSSE signature would require a long-lived signing key on the CI runner, which
   is exactly the property keyless OIDC signing exists to avoid. The SBOM travels with its own
   offline-verifiable `*.cosign.bundle` (certificate + signature + Rekor inclusion proof).
3. **Attaches** the signed SBOMs (and their bundles) to the **GitHub Release** with `gh release
   upload`. A release asset does not expire with CI artifact retention, so the bill of materials is
   retrievable for as long as the release exists — the durability the 90-day artifact never had.

The offline verifier `.github/scripts/verify-release-artifacts.sh` then re-runs the component
cross-check against the exact SBOM **bytes about to be attached** (via
`infra/supply-chain/sbom_crosscheck.py`), verifies each SBOM's cosign signature offline, and refuses a
release that carries no SBOM at all.

## The enforcement + its negative control

The cross-check is `infra/supply-chain/sbom_crosscheck.py::missing_components`: it returns every
locked component absent from the SBOM. A non-empty result fails the release. The negative control is
run in the same breath, in two places:

- `integration/tests/test_release_sbom.py::test_crosscheck_passes_a_complete_sbom_and_fails_an_incomplete_one`
  feeds it a complete SBOM (empty result) and the same SBOM with one component removed (that component
  is reported) — the omit-a-component acceptance criterion, on the enforcing function itself.
- `verify-release-artifacts.sh` drops a component from a copy of each attached SBOM and requires the
  cross-check to FAIL, so the release path cannot ship a green tick over an incomplete SBOM.

## Why the proving test is a required check, not the workflow

`release.yml` is tag-triggered, so it never reports on a pull request and cannot be a required check.
Its shape and the cross-check behaviour are asserted offline by `integration/tests/test_release_sbom.py`,
which runs in the required **integration two-env boundary (P5)** job on every PR — the same pattern
`test_release_provenance.py` uses for the W3-4 signing legs.

## Residual

The wheel that ships is `packages/core/vigil_core`; the SBOMs attached describe the offense and
sovereign dependency closures (the two locks), which is the bill of materials for the product's
Python surface. The editable `-e ./…` first-party members have no registry artifact and are covered
by the same hash-lock discipline, not by a separate per-member SBOM.
