# W13-1 — The enforcement coverage matrix is measured by execution, not by grep

Issue: [#494](https://github.com/thuram-nana/vigil-sovereign/issues/494) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme). Blocks [W13-2] #495.

## The claim (to register in the claims registry, [W0-3] #398, once it lands)

> For each sensitive execution path VIGIL inventories, the gate of record it traverses is proven by
> **executing** the real gate — a line tracer records that the enforcing code actually ran — and a
> deliberately unauthorized action on that path is **refused** in the same run (the negative control).
> A path with no refusal proof is recorded as an **OPEN BYPASS**, never as covered. The matrix is a
> measurement facade over the existing gates; it adds no authorization logic of its own.

The claims registry (#398) is not present on this tree, so — as the repo's prior slices did (see
`docs/decisions/W5-1-*.md`) — this decision record + a doc-truth test (`test_committed_matrix_is_true_of_the_code`)
stand in for the registry entry. When #398 lands, register the claim above and link this record.

This claim is TRUE of the code as of W13-1.

## What ships

- **The measurement engine + inventory** — `integration/vigil_integration/enforcement_matrix.py`.
  - `traced_call(target_code, thunk)` installs a `sys.settrace` line tracer scoped by **code-object
    identity** to exactly one gate function, and returns the set of that function's line numbers that
    executed. A non-empty set is the execution marker: the gate-of-record function itself ran. The marker
    cannot be forged by a look-alike wrapper — the frame's `f_code` must **be** the gate's code object — so
    "grep says the deny branch exists" is not accepted as "the deny branch runs."
  - `CONTROLS` inventories the sensitive execution paths and the gate each traverses. Each row's
    `resolver` binds it to the LIVE, already-shipped gate; the resolvers contain **no policy logic** — they
    drive the real function and read its real return/raise. This honours the programme constraint that the
    sovereign bridge is a facade over existing gates, never a second policy engine.
  - `evaluate_control` runs each row's authorized and unauthorized probes under the tracer and classifies
    the row `COVERED` only when the gate's own code **traversed** and ALLOWed the authorized action AND
    traversed and REFUSED the unauthorized one. Missing/failing negative control, or an ungated authorized
    path, is `OPEN_BYPASS`. A gate not loadable in the current environment is `OFFENSE_LEG`, proven in the
    other CI leg — never silently counted as covered.

- **The artifact** — `docs/ENFORCEMENT-COVERAGE-MATRIX.md`, GENERATED from the registry
  (`render_matrix_markdown`), one row per sensitive path with its plane, gate of record, and negative
  control. It is regenerated and pinned by the test, so it stays true of the code.

- **The tests** — `integration/tests/test_enforcement_matrix.py` (runs in the required
  `integration two-env boundary (P5)` CI job):
  - `test_sovereign_gate_is_traversed_and_refuses[<id>]` — parametrized; for every sovereign-plane gate,
    the authorized action **traverses-and-allows** and the unauthorized action **traverses-and-refuses**,
    both measured by execution.
  - `test_entitlement_gate_is_traversed_and_refused` — the offense-plane `require_capability` gate; guarded
    by `pytest.importorskip("framework...")` so it runs in the offense leg (this file is on that leg's
    explicit run-list in `.github/workflows/ci.yml`, pinned by `test_ci_framework_tests_run_in_offense_leg.py`).
  - `test_no_open_bypasses_among_loadable_controls` — zero OPEN BYPASS (and zero unresolved gates) across
    every control loadable in this environment.
  - `test_matrix_flags_a_noop_gate_as_open_bypass` — **the negative control has teeth**: a synthetic gate
    that never refuses is recorded OPEN BYPASS, not COVERED. This is the test that FAILS on a tree whose
    gate has regressed to a no-op — the failure is observed, not assumed.
  - `test_core_gate_functions_are_all_rowed` — a NEW gate-decision function added to a clean core gate
    module (`vigil_core.gate` / `vigil_core.warden_tiers` / `vigil_core.hard_guardrail`) turns CI red until
    it is rowed or documented as a non-gate helper, so a new gate-of-record path cannot appear
    un-inventoried in the core.
  - `test_committed_matrix_is_true_of_the_code` — the committed artifact must equal the registry's render,
    so adding a sensitive path without its matrix row makes the artifact drift and turns CI red.

## The inventory as of W13-1 (7 gate-of-record paths)

| # | Path | Gate of record | Plane |
|---|------|----------------|-------|
| 1 | agent → tool bridge: tool-name → autonomy tier | `vigil_core.warden_tiers.classify/gate` | sovereign |
| 2 | offense tool call: A2-floor class gate | `vigil_integration.warden_gate.decide_tool` | sovereign |
| 3 | target-touching offense action: CRUCIBLE AND WARDEN | `vigil_core.gate.conjunctive_decide` | sovereign |
| 4 | destructive action: the m-of-n threshold conjunct | `vigil_core.gate.conjunctive_decide[destructive]` | sovereign |
| 5 | worker / adapter / proxy egress: the destination-IP floor | `vigil_gateway.denylist.is_egress_denied` | sovereign |
| 6 | any domain target: the categorical protected-domain floor | `vigil_core.hard_guardrail.assert_not_hard_blocked` | sovereign |
| 7 | gated offense subsystem entry (`require_capability()` sites) | `framework.v2.entitlement.require_capability` | offense |

All seven are `COVERED` by execution (the sovereign six in both integration legs, the offense one in the
offense leg). No OPEN BYPASS was found among them — every one has a live refusal proof.

## Honest scope (what this slice is, and is not)

- The inventory is the **gate-of-record layer** — the pure, shared authorization primitives every
  action-bearing edge composes. It is a real, measured baseline, but it is **not yet the full path
  inventory** the spec envisions (UI→proxy→console, the REST API, the CLI verb surface, per-worker retry
  and adapter seams, each mapped to the concrete gate its request traverses end-to-end). Extending
  `CONTROLS` to those request-level paths — where a genuine bypass is most likely to surface — is the
  natural next increment and is what [W13-2] #495 builds on.
- Because the inventory is the gate-of-record core (each gate has a shipped, tested refusal branch), **this
  slice found no OPEN BYPASS**, so there is no per-bypass issue to file yet (AC "every bypass the matrix
  finds is filed as its own issue"). The machinery to record and surface an OPEN BYPASS the moment a
  request-level path without a refusal proof is added is in place (`open_bypasses`, the OPEN_BYPASS status,
  and the failing guard); a discovered bypass is filed then. No bypass was fabricated to satisfy the AC.
- The core-gate "new path → red" guard (`test_core_gate_functions_are_all_rowed`) scans the three clean
  core gate modules. `warden_gate` / `denylist` / `entitlement` carry many helper functions, so they are
  pinned by resolver-resolvability (a rename/removal reddens the run) + the doc-truth artifact rather than
  a module scan; widening the scan to those modules is a follow-on.
