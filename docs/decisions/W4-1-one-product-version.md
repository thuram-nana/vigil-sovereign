# W4-1 — One product version, asserted consistent across every first-party package

Issue: [#441](https://github.com/thuram-nana/vigil-sovereign/issues/441) ·
Milestone: W4 — RELEASE ENGINEERING.

## The defect this closes

VIGIL shipped six uncoordinated version numbers — `vigil-core` 0.1.0, `vigil-integration` 0.1.0,
`vigil-gateway` 0.1.0, `crucible` 2.0.0a1, `sigil` 0.9.0 and the WARDEN Rust kernel 0.9.0 — while
the repo root declared none at all. No single fact said "this is the version of the product", so a
package could drift and a release could not name a coherent number.

## The decision

There is now **one product version**, and it lives in exactly one place: the repo-root `VERSION`
file. Every first-party package's declared version is asserted equal to it. We chose the
ASSERT-CONSISTENCY branch (not build-time derivation) because it needs no per-backend plumbing
across the three build backends in the tree (hatchling, setuptools, cargo) and matches the repo's
existing offline-consistency-guard pattern under `docs/tests/`.

The single vendored third-party package, `vendor/strix` (`strix-agent`), is **excluded**: a
vendored dependency's version is upstream's fact, not the product's, and rewriting it would erase
attribution.

## The claim (registered in the claims registry — [W0-3] #398, id `W4-1`)

<!-- CLAIM:W4-1 -->
> **Registered claim (W0-3 #398):** The product version is declared once at the repo-root VERSION file and every first-party package's declared version is asserted equal to it in a required CI job, while the vendored third-party strix package keeps its own upstream version.

Why it is TRUE of the code:

- `VERSION` at the repo root holds the single product version (`0.1.0`).
- `docs/tests/test_product_version_consistency.py` reads every first-party package's declared
  version from its authoritative site — `[project].version` of the pyproject for the packaged
  Python distributions, the `__version__` attribute where the pyproject derives the version
  dynamically (sigil) or carries a runtime marker (crucible-v2), and `[package].version` of
  `Cargo.toml` for the WARDEN kernel — and asserts each equals the `VERSION` file.
- The pure helper `mismatched_versions(product, declared)` returns any package whose version
  disagrees; the negative-control tests feed it a deliberately-bumped map and assert it reports the
  divergence, so the gate is proven not to be a no-op.
- The test runs in the already-**required** `the briefing explains every agent and capability` CI
  job (`pytest docs/tests -q`), which reads files only and imports neither trust domain.

## Consequences

Bumping any first-party package version without bumping `VERSION` (or vice versa) turns the required
job RED. A coordinated release bumps `VERSION` and the package sites together.
