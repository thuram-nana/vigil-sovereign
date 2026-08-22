# Enforcement coverage matrix — gate-of-record LAYER, measured by execution (W13-1)

GENERATED, DO NOT EDIT BY HAND. Regenerated and pinned by `integration/tests/test_enforcement_matrix.py`.

**What this matrix proves — and what it does NOT.** It measures the GATE-OF-RECORD LAYER: the shared authorization primitives that the sensitive actions below depend on. For each row it RUNS the real gate FUNCTION under a line tracer (`vigil_integration.enforcement_matrix`) with SYNTHESIZED inputs, and asserts by execution that the primitive traversed-and-ALLOWed an authorized action and traversed-and-REFUSED a deliberately unauthorized one (the negative control). It does NOT drive a real end-to-end request path: the *Sensitive action* column names the action that depends on the gate, but the proof is that the SHARED GATE refuses — not that the named call site (the worker / adapter / proxy egress call, the agent→tool bridge, …) actually reaches the gate. The *Proof scope* column records this: every shipped row is proven at `gate function` scope. Wiring a gate into a specific call site is a SEPARATE claim, not measured here. A gate with no refusal proof is an OPEN BYPASS, not covered.

| # | Sensitive action (depends on the gate) | Plane | Gate of record | Proof scope | Negative control |
|---|----------------------------------------|-------|----------------|-------------|------------------|
| 1 | agent → tool bridge: every tool-name is classified to an autonomy tier (danger-first, fail-closed to A3) before it may auto-run | sovereign | `vigil_core.warden_tiers.classify/gate` | gate function | yes |
| 2 | offense tool call: the raise-only A2 floor gate decides auto / queue-for-owner-approval / deny by tool class | sovereign | `vigil_integration.warden_gate.decide_tool` | gate function | yes |
| 3 | every target-touching offense action: CRUCIBLE-authority AND WARDEN, first-failure-wins, fail-closed | sovereign | `vigil_core.gate.conjunctive_decide` | gate function | yes |
| 4 | destructive / irreversible action: the extra m-of-n threshold conjunct — no wired gate is a fail-closed DENY even when WARDEN would auto-allow the class | sovereign | `vigil_core.gate.conjunctive_decide[destructive]` | gate function | yes |
| 5 | worker / adapter / proxy egress: the destination-IP floor (metadata / link-local / loopback / private) that no charter scope can lift | sovereign | `vigil_gateway.denylist.is_egress_denied` | gate function | yes |
| 6 | any domain target the agent proposes: the categorical government / military / educational / intergovernmental scope floor, evaluated before the charter | sovereign | `vigil_core.hard_guardrail.assert_not_hard_blocked` | gate function | yes |
| 7 | gated offense subsystem entry (active-recon / exploit / deep-static / evasion): the entitlement gate wired at require_capability() sites | offense | `framework.v2.entitlement.require_capability` | gate function | yes |

Planes: a `sovereign` row's gate loads without the offense engine and is proven by execution in BOTH integration CI legs; the `offense` row's gate (`require_capability`) needs `framework`, so its execution proof runs only in the offense leg (FATAL-2 two-env boundary).
