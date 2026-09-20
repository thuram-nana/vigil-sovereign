# Phase 3 (B10) — operator rate / User-Agent controls

## Context

The plan's offensive pillar calls for the scanner to "identify itself and respect an operator-set rate
ceiling" (B10). Grounding showed most of this was already true: the HTTP executor already sends a
**correlatable** User-Agent (`OBSIDIAN/1.0 (authorized owner-test <date>)`) and already **throttles** at a
per-posture rate (`_RATE_PROFILES`: TEST 0.2s, AUDIT 1.0s, EMULATE 5s+jitter), both derived from the charter
posture. What was missing was **operator control + visibility**: no way to tag the UA per run, no way to slow
a cautious first live run below the posture rate, and no surfaced view of the traffic a run will produce.

## Decision

Add two operator controls, read from the environment the engage child inherits, plus a read-only profile.

<!-- CLAIM:PHASE3-1 -->
A remote engagement's request rate can only be TIGHTENED by an operator-set minimum interval — the effective
rate floor is the maximum of the charter posture's floor and the operator's minimum, so the control can slow a
run but never make it faster than the posture mandates — and the scanner's correlatable User-Agent carries the
operator's identifier tag when one is set.

Concretely:
- `http_executor` reads `VIGIL_OPERATOR_ID` (appended to the correlatable UA) and
  `VIGIL_MIN_REQUEST_INTERVAL_S` (clamped to `[0, 3600]`, invalid/absent -> 0). `_sleep_for_rate_limit`
  computes `floor = max(posture_floor, operator_min)` — tighten-only.
- `console.actions._operator_traffic_controls` threads those to the engage child as env (sanitising the
  operator id against header injection) and returns a READ-ONLY `traffic_profile` (posture, effective UA,
  effective + posture rate floors, GET-only, single-use offense ceiling) that `launch_assessment` surfaces so
  the operator sees the traffic a run will produce before it runs.

## Honest scope

The UA already identifies the scanner and the posture already throttles — these controls are additive
operator control + visibility, not a new safety property, EXCEPT the tighten-only invariant above (an operator
cannot use them to speed a scan past the charter posture). GET-only and the single-use offense ceiling are
existing engine invariants shown read-only, not asserted as new here.
