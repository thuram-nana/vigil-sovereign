<!--
  VIGIL (vigil-sovereign) pull request. Every change reaches `main` ONLY through a reviewed pull
  request (see CONTRIBUTING.md). Fill this in honestly — the Maintainer reviews every PR against the
  project's doctrine, and the required status checks must be green before it can merge.
-->

## What this changes

<!-- One-paragraph summary. What and why. Link the issue(s): "Closes #NNN" for issues this fully resolves. -->

## Type

- [ ] Bug / production fix
- [ ] New capability (additive / opt-in, default-OFF)
- [ ] Docs / tests only
- [ ] Refactor (no behaviour change)

## Doctrine & safety checklist (required)

- [ ] **Authorized-use / defensive posture only.** No offensive capabilities the project
      deliberately excludes (see [`engine/crucible/DISCLAIMER.md`](../engine/crucible/DISCLAIMER.md)).
- [ ] **Prove-don't-guess, near-zero false positives.** Any new detection BLOCKS / promotes to a
      FACT only on a re-runnable oracle proof a benign input cannot trigger; otherwise it ships as a
      LEAD.
- [ ] **Two-env boundary intact (FATAL-2).** Offense/integration code does not import `sigil.*`;
      `framework` imports in sovereign-loaded modules stay function-local. `uiproxy.py` stays
      stdlib-only.
- [ ] **Determinism on any signed / decision path.** No wallclock or global RNG where a decision is
      signed or replayed.
- [ ] **Additive / opt-in.** New powers are default-OFF and gated fail-closed.
- [ ] **`make gate` stays byte-identical** where the engine benchmark applies; new `OracleKind`
      members stay OUT of the frozen `verify/verifier.py::_ALL_ORACLES`.
- [ ] **Tests included and green**, with a negative control for any new guard/gate, and any
      framework-dependent integration test listed in the offense leg of
      [`.github/workflows/ci.yml`](workflows/ci.yml).
- [ ] **Honest docs.** No overclaiming; limitations noted, and any product claim registered in the
      claims registry ([`docs/claims/`](../docs/claims/README.md)).

## Evidence

<!-- Paste the relevant test output (and the gate row if the benchmark applies). -->

```
# pytest summary / gate row here
```

## Residual / follow-ups

<!-- Anything only partially done, and the issue tracking it. "None" is a valid, honest answer. -->
