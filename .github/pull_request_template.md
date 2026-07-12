<!--
  CRUCIBLE pull request. All external changes reach `main` ONLY through a reviewed
  pull request. Fill this in honestly — the maintainer reviews every PR against the
  project's doctrine and the byte-identical benchmark gate.
-->

## What this changes

<!-- One-paragraph summary. What and why. -->

## Type

- [ ] Bug fix
- [ ] New capability (additive / opt-in)
- [ ] Docs / tests only
- [ ] Refactor (no behavior change)

## Doctrine & safety checklist (required)

- [ ] **Authorized-use / defensive only.** No detection-evasion, C2/persistence, full
      exploitation frameworks, credential-attack offense, identity-rotation, or
      unattended action on live/third-party hosts. (See [`DISCLAIMER.md`](../DISCLAIMER.md).)
- [ ] **Prove-don't-guess + near-zero false positives.** Any new detection BLOCKS /
      promotes to a FACT only on a re-runnable oracle proof a benign input cannot
      trigger; otherwise it ships as a LEAD.
- [ ] **`make gate` is byte-identical.** `python3 -m framework.v2 benchmark --gate
      --no-incumbents` still reports `crucible 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
      … | 853 | … | 9` and `gate: PASS`. New `OracleKind` members stay OUT of the
      frozen `verify/verifier.py::_ALL_ORACLES` (15).
- [ ] **Additive / opt-in.** New powers are default-OFF and gated fail-closed.
- [ ] **Tests included and green** (`pytest framework/v2 -q`), including an
      execution-verified benign corpus for any new detector.
- [ ] **Honest docs.** No overclaiming; limitations noted in [`V2-LIMITATIONS.md`](../V2-LIMITATIONS.md).

## Evidence

<!-- Paste the gate row and the relevant test output. -->

```
# make gate row + pytest summary here
```
