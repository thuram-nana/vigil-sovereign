# Enforcement coverage matrix — measured by execution (W13-1)

GENERATED, DO NOT EDIT BY HAND. Regenerated and pinned by `integration/tests/test_enforcement_matrix.py`. Each row is a sensitive execution path and the gate of record it traverses; the row is proven by RUNNING the real gate under a line tracer (`vigil_integration.enforcement_matrix`), asserting the enforcing code executed on an authorized action (ALLOW) and that a deliberately unauthorized action is REFUSED (the negative control). A path with no refusal proof is an OPEN BYPASS, not covered.

| # | Sensitive execution path | Plane | Gate of record | Negative control |
|---|--------------------------|-------|----------------|------------------|
| 1 | agent → tool bridge: every tool-name is classified to an autonomy tier (danger-first, fail-closed to A3) before it may auto-run | sovereign | `vigil_core.warden_tiers.classify/gate` | yes |
| 2 | offense tool call: the raise-only A2 floor gate decides auto / queue-for-owner-approval / deny by tool class | sovereign | `vigil_integration.warden_gate.decide_tool` | yes |
| 3 | every target-touching offense action: CRUCIBLE-authority AND WARDEN, first-failure-wins, fail-closed | sovereign | `vigil_core.gate.conjunctive_decide` | yes |
| 4 | destructive / irreversible action: the extra m-of-n threshold conjunct — no wired gate is a fail-closed DENY even when WARDEN would auto-allow the class | sovereign | `vigil_core.gate.conjunctive_decide[destructive]` | yes |
| 5 | worker / adapter / proxy egress: the destination-IP floor (metadata / link-local / loopback / private) that no charter scope can lift | sovereign | `vigil_gateway.denylist.is_egress_denied` | yes |
| 6 | any domain target the agent proposes: the categorical government / military / educational / intergovernmental scope floor, evaluated before the charter | sovereign | `vigil_core.hard_guardrail.assert_not_hard_blocked` | yes |
| 7 | gated offense subsystem entry (active-recon / exploit / deep-static / evasion): the entitlement gate wired at require_capability() sites | offense | `framework.v2.entitlement.require_capability` | yes |

Planes: a `sovereign` row's gate loads without the offense engine and is proven by execution in BOTH integration CI legs; the `offense` row's gate (`require_capability`) needs `framework`, so its execution proof runs only in the offense leg (FATAL-2 two-env boundary).
