# W9-4 — The production refuse-to-start gate is OPT-IN (documented as opt-in, not default)

Issue: milestone W9, item W9-4 ·
Registered in the claims registry ([W0-3] #398, id `W9-4`).

This record exists to address failure-mode **class (2)** the W0 plan names: *enforcement that ships opt-in
but is documented as default*. The gate below is real, but it is INERT unless the operator opts in, and the
registered claim says so in the same breath as the capability.

## The claim (registered in the claims registry — [W0-3] #398, id `W9-4`)

<!-- CLAIM:W9-4 -->
> **Registered claim (W0-3 #398):** The production refuse-to-start gate is OPT-IN: with VIGIL_POSTURE unset it is inert and never blocks a start, and only when VIGIL_POSTURE selects production does a start path refuse to run unless all five production preconditions hold, with an unknown control failing closed.

## Why this is TRUE of the code — and where it is opt-in

`evaluate_production_gate` (`integration/vigil_integration/doctor.py`):

- **Opt-in selector.** `production_posture()` returns the `VIGIL_POSTURE` value IFF it is `production` or
  `prod` (case-insensitive). Anything else — including unset — leaves the gate **not armed**: it reports
  `ok=True` and never flips an exit code. This is the point of the claim: the control is *documented as
  opt-in because it is opt-in*, not described as a default that silently holds.
- **When armed, it refuses on any unmet precondition.** With posture selecting production, a start path
  (`vigil up` / `vigil engage`) refuses unless ALL FIVE production preconditions hold. Each probe reads a
  REAL control.
- **Fail-closed on the unknown.** A control whose state cannot be determined is treated as NOT satisfied
  (`ok=False`), never assumed good — a missing/ambiguous decision is DENY.

## How it is verified

Pinned by `integration/tests/test_doctor_production_gate.py`, which runs in the required
**integration two-env boundary (P5)** CI job (sovereign leg). The suite includes:

- `test_gate_inert_when_posture_unset` — the opt-in claim's positive: unset ⇒ inert;
- `test_posture_selector_matches_production_and_prod_case_insensitively` — the selector;
- `test_gate_passes_when_all_five_satisfied` and `test_gate_refuses_each_condition_independently` — armed
  behaviour, each precondition load-bearing;
- `test_gate_fails_closed_when_a_control_is_unknown` — the fail-closed negative control;
- `test_cmd_up_refuses_in_production_and_never_calls_run_up` /
  `test_cmd_engage_refuses_in_production_before_importing_the_engine` — the start paths honour it.
