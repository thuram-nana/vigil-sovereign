# W2-4 — coverage is measured (line + branch) and ratcheted

Issue: [#421](https://github.com/thuram-nana/vigil-sovereign/issues/421) ·
Milestone: W2 — CODE QUALITY GATES.

## The claim (registered in the claims registry — [W0-3] #398, id `W2-4`)

<!-- CLAIM:W2-4 -->
> **Registered claim (W0-3 #398):** line and branch coverage of the vigil_core substrate are measured every CI run and gated by a committed ratchet floor: a drop below the floor fails CI.

## Why this exists

There was **no coverage measurement anywhere**. The "coverage guards" only proved a path *collected*
>0 tests (`pytest --collect-only`) — "a skipped proof and a passing proof are the same colour on a
dashboard." The project could not state what fraction of its security-critical code any test touches.

## What is TRUE of the code as of W2-4

- **Measurement.** The required `vigil_core — shared integrity substrate` CI job runs the
  `vigil_core` suite under `pytest-cov` with `--cov=vigil_core --cov-branch`, producing a
  machine-readable JSON + XML report and a human term report.
- **The floor.** `tools/coverage/coverage-thresholds.json` holds the committed per-package line and
  branch floors. `vigil_core` is gated at **line ≥ 85%, branch ≥ 75%** (measured baseline at this
  commit: line 85.16% / branch 75.42% over 273 tests).
- **The gate.** `tools/coverage/coverage_ratchet.py`'s `evaluate()` computes line/branch percentages
  from the report's raw counts and fails the build if either drops below its floor. Deleting a test
  that covers `vigil_core` drops measured coverage below the floor and reddens CI.
- **The artifact.** The coverage report is published as a CI artifact (`coverage-vigil_core`) each run.
- **Ratchet direction.** The floors are a committed high-water baseline. Raising a floor as coverage
  improves is a tightening (`coverage_ratchet.py update`); lowering one is an explicit, reviewable
  loosening.

## Honest limits — roll-out plan

This gate currently measures and floors the **`vigil_core`** package — the shared, security-critical
integrity substrate (signed hash-chain, canonical JSON, Ed25519 + threshold crypto, capability
tokens). The mechanism is generic (the thresholds file is keyed by package), but the other packages
(`vigil_integration`, `gateway`, `sigil`, and the offense `framework/v2`) are **not yet gated**; a
package with no entry in the thresholds file is not measured or floored. Extending measurement to
those packages — each in its own required job, with a measured baseline before a floor is set — is the
tracked follow-on. No floor is set for a package whose coverage has not been measured (a floor you
cannot measure is green-washing).

## Proof

`docs/tests/test_coverage_ratchet.py` (rides the required `the briefing explains every agent and
capability` job) exercises `evaluate()`'s line + branch controls in-process, checks the committed
floor is real and non-trivial, and asserts the CI job measures branch coverage, runs the ratchet
guard, and publishes the artifact.
