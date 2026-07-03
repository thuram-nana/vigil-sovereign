# knowledge/ — the Technique Knowledge Graph

Techniques as **machine-checkable planning operators**. This is the join that
turns intel into action: an ATT&CK/CAPEC/CWE entry is prose a human reads; the
path engine needs a move it can *check* against the graph and *chain* into the
next one. `knowledge` reifies each technique as a STRIPS-style operator whose
preconditions and effects speak the world-model's own vocabulary — so an
operator plugs straight into `worldmodel` derivation with no translation layer.

## Why bespoke (ATT&CK is not enough)

ATT&CK/CAPEC give *loose hints*: a tactic, a paragraph, some detection prose.
What they do **not** give is a machine-checkable pre/post-condition. "Adversary
uses valid accounts" cannot be evaluated against a graph; it has no typed
precondition ("a CREDENTIAL VALID_ON a PRINCIPAL") and no typed effect ("assert
CAN_ASSUME"). Without those, a planner cannot decide *whether the technique
applies here* or *what becomes true if it fires* — so it cannot chain. The gap
analysis called this out: intel that can't be executed is a library, not a
plan. So the operator schema is ours, it is small, and its vocabulary is
`worldmodel.NodeKind` / `EdgeKind` / node attrs — an operator **is** an
interaction rule with a technique label and detection metadata.

## The shape

```
Operator
  id, name, technique_ref[str]   # ATT&CK / CAPEC / CWE ids — the intel provenance
  preconditions: [Predicate]     # typed conditions over the world-model
  effects:       [Effect]        # typed edge/attr assertions (capability gained)
  detection_signals: [str]       # what a defender/oracle would observe
  oracle_kind: verify.OracleKind # the deterministic oracle that CONFIRMS it fired

Predicate  (four decidable kinds)
  NODE_KIND       focus node is of a kind
  NODE_ATTR       focus attr satisfies an op (eq/ne/exists/absent/in/truthy/falsy)
  INCIDENT_EDGE   focus has an edge (dir, kind) to a node of a kind  [capture_as]
  GRAPH_HAS_NODE  a node of a kind exists globally                   [capture_as]

Effect
  ASSERT_EDGE  src_role -> dst_role of edge_kind   (a boundary crossed)
  SET_ATTR     target_role.attr = value            (a fact learned)
```

Effect endpoints are named by **role**, not node id. `apply` resolves roles
against a *binding*: the `focus` node, whatever the preconditions `capture_as`,
and any caller-seeded roles (e.g. the `actor` principal a technique acts *as*,
or the `resource` a grant targets). This is how a precondition ("this CREDENTIAL
is VALID_ON that PRINCIPAL") feeds the endpoint of an effect edge.

## The bridge into derivation

```python
from framework.v2.knowledge import match, apply, derive, saturate, CATALOG

binding = match(op, world, focus_node, seed={"actor": "attacker"})  # None if N/A
if binding:
    apply(op, world, binding, seq=100)   # asserts effects, provenance="operator:<id>"
```

- `applicable(op, world, focus) -> bool` — do the preconditions hold here?
- `match(...) -> Binding | None` — applicable + the captured/seeded role bindings.
- `apply(op, world, binding, seq)` — assert the effects. Every derived edge/attr
  carries `provenance="operator:<id>"`, `first_seen=last_seen=seq`, the effect's
  confidence, and (on edges) the technique refs + detection signals — so a
  derived edge is **self-explaining**: the path engine's provenance chain names
  the technique that produced each hop.
- `derive(...)` — match + apply in one.
- `saturate(catalog, world, seq_start, seeds=...)` — forward-chain the whole
  catalog to a **fixpoint**. Effects are monotonic (the graph only accretes), so
  it converges; re-running on a converged graph asserts nothing new.

Determinism is inherited from the world-model: evaluation only *reads* the
graph, and every asserted fact takes a caller-supplied monotonic **sequence
int** — never a clock, never randomness. Same inputs, same derived facts, same
bytes.

## The seed catalog (6 operators, spanning classes)

| id | class | technique_ref | oracle |
|---|---|---|---|
| `unauth-endpoint-read` | IDOR / BOLA | T1190, CWE-639/284, CAPEC-1 | achieved-state |
| `credential-reuse` | valid accounts | T1078, CWE-522/287, CAPEC-560 | achieved-state |
| `token-replay` | session/token replay | T1550.001, CWE-384/613, CAPEC-60 | achieved-state |
| `ssrf-internal-reach` | SSRF pivot | CWE-918, CAPEC-664, T1090 | oob-callback |
| `role-assumption` | IAM privilege escalation | T1548, T1078.004, CWE-269, CAPEC-233 | achieved-state |
| `deserialization-to-code-exec` | insecure deserialization | CWE-502, T1059/1203, CAPEC-586 | oob-callback |

These are **abstract planning operators, not exploits**. Each states what must
be true, what capability it grants, and how a defender would see it. There are
no payloads anywhere in this module.

Two of them deliberately **chain**: `credential-reuse` asserts a `CAN_ASSUME`
edge, which is exactly `role-assumption`'s precondition. Forward-chaining walks
credential theft into cloud privilege the way a real operator would —
intel → move → new edge → next move → a path to the crown jewel that did not
exist before.

## What this unlocks

The load-bearing test (`tests/test_catalog.py`): a world where the attacker can
reach an endpoint and the endpoint queries a datastore, but — restricted to
reachability edges — no path connects attacker to datastore. Firing
`unauth-endpoint-read` asserts the missing `REACHABLE_FROM` edge across the
broken auth boundary, and `worldmodel.query.find_paths` **now returns the path**,
with its final hop's provenance pointing back at the technique. That is the
whole point: the planner can chain because techniques became operators.

## Files

| Module | Purpose |
|---|---|
| `models.py` | `Operator`, `Predicate`, `Effect` + the `PredicateKind`/`EffectKind`/`AttrOp`/`Direction` vocab. Pure validated shapes; `extra='forbid'`. |
| `operators.py` | `applicable` / `match` / `apply` / `derive` / `saturate` — evaluate preconditions and assert effects into a `WorldModel`. `OperatorError` on wiring faults. |
| `catalog.py` | the 6 hand-authored technique operators; `CATALOG`, `by_id`, `by_technique`. |
| `tests/` | attr-op semantics, precondition gating, capture/seed bindings, effect provenance, the path-unlock integration, the chain, and saturate determinism. |

## Status

Seed + tests only this wave. The planner consumes `saturate` to expand the
reachable surface before querying paths, and the verify layer confirms a fired
operator via its `oracle_kind` — both are additive wire-ups in a later wave.
Nothing here reaches back into the planner or verify (no import cycle; it
imports *from* `worldmodel` and the `OracleKind` enum only).
