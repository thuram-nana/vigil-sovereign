# W13-2 — `sovereign_bridge` is a FACADE over the existing gates, never a second policy engine

Issue: [#495](https://github.com/thuram-nana/vigil-sovereign/issues/495) ·
Milestone: W13 — SOVEREIGN CONTROL PLANE (ANTIC programme) · Blocked by [W13-1] #494.

## The claim (register in the claims registry, [W0-3] #398)

> VIGIL exposes ONE unified authorization entry, `sovereign_bridge.authorize()`, that returns a
> **normalized** `ALLOW` / `DENY` / `QUEUE` verdict with a reason code, the deciding gate, and any
> capability the entitlement gate confirmed. It is a **facade**: it composes the ALREADY-EXISTING gate
> chain — the `conjunctive_gate` authority-of-record (kill-switch ∧ scope ∧ WARDEN ∧ m-of-n destruction),
> then the sovereignty LLM-egress gate, then the `require_capability()` entitlement gate — **in order**, and
> it adds **no policy of its own**. Every non-`ALLOW` verdict traces to an underlying gate (`denied_by` is a
> real gate in the chain). It is **fail-closed** (a gate that raises or returns an unrecognised verdict is a
> `DENY` attributed to that gate; the first non-`ALLOW` wins). A **production** deployment profile refuses
> `OBSERVE_ONLY` (production MUST `ENFORCE`), and there is **no `skip_security_checks`-equivalent flag**
> anywhere in the source that could turn the gate chain off.

This claim is TRUE of the code as of W13-2:

- **The facade** — `integration/vigil_integration/sovereign_bridge.py`. `compose_authorization()` is the pure
  core: it iterates the injected `Gate` list, calls `gate.decide(request)`, and returns based only on what
  each gate returns. It NEVER inspects the `request` to make a verdict — so the bridge is not a decision
  point. `authorize()` wraps it with the fail-closed construction guards.
- **No independent policy** — the invariant `effect is Effect.ALLOW  <=>  denied_by is None` holds; every
  non-`ALLOW` return sets `denied_by` to the deciding gate's name and carries that gate's own reason. Pinned
  by `test_every_non_allow_traces_to_a_real_gate_across_a_battery` (a 125-chain battery) and
  `test_facade_does_not_inspect_request_content_when_gates_allow` in
  `integration/tests/test_sovereign_bridge.py`.
- **Composes the REAL existing gates** — `build_offense_bridge()` wires: the authority leg to
  `conjunctive_gate.build_offense_gate` (the offense authority-of-record); the sovereignty leg to
  `live.think_claude.llm_egress_refusal` (kernel sovereignty tier); the entitlement leg to
  `framework.v2.entitlement.require_capability`. `framework` is imported LAZILY, inside functions.
  `integration/tests/test_sovereign_bridge_offense.py` drives a real `DENY` through EACH leg (AIR_GAPPED tier
  refuses a cloud backend; an enforced entitlement refuses an ungranted capability; an out-of-envelope
  authority refuses) with a permissive/ungoverned NEGATIVE CONTROL beside each, so no leg is a no-op.
- **Fail-closed** — a raising gate and an unrecognised verdict both `DENY` (attributed), the first non-`ALLOW`
  short-circuits, an empty chain is refused at construction, and unknown mode/profile strings raise. Pinned
  by the `fail-closed` and `NEGATIVE CONTROLS` sections of `test_sovereign_bridge.py`.
- **Production rejects `OBSERVE_ONLY`** — `_validate_config()` raises when
  `profile in _PRODUCTION_PROFILES and mode is OBSERVE_ONLY`; `test_production_profile_rejects_observe_only`
  pins it. `OBSERVE_ONLY` is permitted only for staging/development and records the true verdict without
  blocking (`SovereignDecision.blocks()` is False), so a deployment can measure before it flips to `ENFORCE`.
- **No `skip_security_checks`-equivalent flag** — `test_no_skip_security_checks_equivalent_flag_anywhere_in_source`
  parses every source file under `integration/vigil_integration`, `packages/core/vigil_core` and
  `gateway/vigil_gateway` with `ast` and asserts no function argument, assignment target, attribute, or
  keyword name normalizes to a security-bypass fragment (`skipsecuritychecks`, `bypassgate`, `disablewarden`,
  …). It is AST-based, so this document's own prose naming the forbidden flag does not trip it.

## The test that fails without this change (observed, not assumed)

`integration/tests/test_sovereign_bridge.py` imports `vigil_integration.sovereign_bridge` at module scope. On
a tree without W13-2 that module does not exist, so the whole file ERRORs at collection. Observed on this very
tree by moving the module aside:

```
$ mv integration/vigil_integration/sovereign_bridge.py /tmp/ ; \
  PYTHONPATH=integration:gateway .venv-sovereign/bin/python -m pytest -q integration/tests/test_sovereign_bridge.py
E   ModuleNotFoundError: No module named 'vigil_integration.sovereign_bridge'
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.32s
```

Restoring the module returns the suite to green (18 passed).

## Where the tests run — a required CI job

Both test files live under `integration/tests/`, which is executed by the **required** check
`integration two-env boundary (P5)` (`required-status-checks.txt`):

- `test_sovereign_bridge.py` is framework-free and runs in that job's SOVEREIGN leg.
- `test_sovereign_bridge_offense.py` imports `framework` behind an `importorskip`, so it runs in that job's
  OFFENSE leg and is listed there explicitly in `.github/workflows/ci.yml` (the
  `test_ci_framework_tests_run_in_offense_leg` guard fails the build if it is not).

## FATAL-2 (the two-env boundary)

The composition core imports nothing but stdlib, so `sovereign_bridge` loads in BOTH processes exactly like
`vigil_core.gate`. The offense wiring imports `framework` lazily. `integration/tests/test_two_env_boundary.py`
names `vigil_integration.sovereign_bridge` in its in-process probe and asserts `framework` / `strix` are not
in `sys.modules` after importing it; `test_sovereign_bridge.py::test_import_is_two_env_clean` re-proves it in
an isolated subprocess so the property holds even under the offense venv.

## Relationship to W13-1 (#494)

W13-1 builds the enforcement-coverage matrix that inventories every sensitive path and the gate it actually
traverses. `sovereign_bridge` is the single composed entry those paths converge on. This slice ships the
facade and its delegation/fail-closed proofs; wiring each sensitive execution path to call `authorize()` at
its entry is tracked by W13-1's matrix and the downstream W13-3…W13-6 slices, which this facade unblocks.

> **Registration:** fold this claim into the claims registry when [W0-3] #398 lands; until then this decision
> record is the source of truth for the claim.
