# W6-6 — ONE doctor, ONE shared check registry (both trust planes)

Issue: milestone W6, item W6-6 ·
Registered in the claims registry ([W0-3] #398, id `W6-6`).

`vigil doctor` (the offense / integration plane) and `sigil doctor` (the sovereign plane) used to be two
disjoint self-checks: no shared code, no shared idea of what "a failed control" means, and — for `sigil
doctor` — an exit code `make smoke` threw away with `|| true`. They now share ONE registry in
`vigil_core.doctor`, a pure-stdlib, namespace-pure package BOTH planes may import without dragging a
dependency across the two-env boundary (FATAL-2).

## The claim (registered in the claims registry — [W0-3] #398, id `W6-6`)

<!-- CLAIM:W6-6 -->
> **Registered claim (W0-3 #398):** `vigil doctor` and `sigil doctor` share ONE check registry in `vigil_core.doctor` — the same `REQUIRED_CONTROLS` production-posture spec, the same fail-closed, opt-in gate decision (`evaluate`), and the same exit roll-up (`overall_ok`) — so the two entry points can never drift on which controls are required, what counts as satisfied, or whether a failure flips the exit code; and the security-posture block documented in README.md is REGENERATED from that registry by a required CI guard, not authored by hand, so it cannot rot.

## Why this is TRUE of the code

- **One registry.** `vigil_core.doctor.REQUIRED_CONTROLS` is the single ordered spec of production-posture
  controls (control id, good-states, requirement text). `vigil_integration.doctor` imports it as
  `_PRODUCTION_GATE` (`_PRODUCTION_GATE is vigil_core.doctor.REQUIRED_CONTROLS` — the same object, not a
  copy), and `sigil doctor` reads the same spec, so neither can drift on which controls matter.
- **One decision.** `evaluate(...)` is the shared production-posture gate verdict: fail-closed (any control
  outside its good-set — `UNKNOWN` included — is unmet) and opt-in (inert unless the production posture is
  armed). Both entry points render the same JSON-safe verdict.
- **One exit roll-up.** `overall_ok(...)` turns each entry point's mix of checks into ONE honest exit code,
  so neither doctor can silently discard a failure again (`sigil doctor`'s `make smoke` line is de-`|| true`d).
- **The README block cannot rot.** `render_readme_posture_block()` regenerates the canonical
  PRODUCTION-posture-gate block from `REQUIRED_CONTROLS` + `evaluate` on a fixed misconfigured fixture,
  using the SAME `render_gate_block` formatter `vigil doctor` prints; the required CI guard
  `test_readme_posture_block_is_ci_regenerated_from_the_registry`
  (`integration/tests/test_doctor_consolidation.py`, run in the *integration two-env boundary (P5)* job)
  fails the build if README.md no longer contains that block verbatim.

## Proof

`integration/tests/test_doctor_consolidation.py` proves the integration entry point (the shared-registry
identity, `security_report()`, the honoured CLI exit, and the README-regeneration anti-rot guard);
`packages/core/vigil_core/tests/test_doctor.py` proves the registry / `evaluate` / `overall_ok` core; and
`apps/sigil/tests/test_doctor_consolidation.py` proves the sovereign entry point reads the same registry.
