# worldmodel/ — WMS, the World-Model Substrate

The backbone the reasoning layers were missing: one persistent, typed
attack-graph that survives a restart and answers *"given what we have
observed, what is now reachable, and by what explainable route?"*

Recon writes hosts and services into it. Intake writes web surface and
findings. Identity and cloud work write principals, credentials,
sessions, and IAM grants. The planner (future wave) reads paths out of
it to decide where to push next; the verify layer (future wave) reads a
path's provenance chain to decide whether it believes it. Everything
touches the same graph, so a lead discovered on the web surface and a
credential recovered from a datastore end up as two edges in one place
instead of two facts in two agents' heads.

## Why bespoke

No off-the-shelf graph schema spans web + identity + cloud *and* carries
per-fact provenance and confidence. Attack graphs in the literature are
either network-reachability only (no IAM, no web routes) or IAM-only (no
network, no findings). BloodHound models AD identity; a CSPM tool models
cloud IAM; a web crawler models routes — none of them model the *chain
across all three*, which is exactly where real compromise lives (an
`ENDPOINT` leaks a `CREDENTIAL` that is `VALID_ON` a `PRINCIPAL` that
`CAN_ASSUME` a `CLOUD_RESOURCE` fronting a `DATASTORE`). So the schema is
ours, and it is deliberately small.

## The two non-negotiables

1. **Every fact carries provenance + confidence.** `provenance` is the
   id of the event/observation that asserted the node or edge;
   `confidence` is a belief in `[0, 1]`. A path is only as strong as its
   weakest edge (`Path.min_confidence`), and every hop traces back to
   what made the framework believe it (`Path.provenance_chain`). This is
   what turns an attack path from an oracle's assertion into something
   the operator can audit.

2. **Time is a monotonic sequence int, never a wallclock.** Callers pass
   their own event counter as `first_seen` / `last_seen`. The graph
   never reads the clock, so upsert-merge, ordering, and every query are
   deterministic and replayable — the same inputs always produce the
   same bytes and the same paths.

## Upsert-merge

`add_node` / `add_edge` are idempotent. Re-asserting a node id (or an
`(src, dst, kind)` edge triple) from a fresh observation *refines* the
fact rather than duplicating it:

- `attrs` merge — incoming keys overlay, keys not re-asserted are kept;
- `confidence` reconciles to the **max** — re-observing never lowers
  belief, and the higher-confidence assertion donates its provenance so
  the surviving pointer names the strongest evidence;
- the seen-window widens — `first_seen = min`, `last_seen = max`.

## Files

| Module | Purpose |
|---|---|
| `models.py` | `NodeKind` / `EdgeKind` enums; `Node`, `Edge` (both provenance + confidence + monotonic seen ints); `Path` (query result carrying `min_confidence` and `provenance_chain`). |
| `graph.py` | `WorldModel` — dict-of-dicts typed multigraph. `add_node` / `add_edge` upsert-merge, `neighbors`, `nodes_of_kind`, `edges_of_kind`, `reachable`. `WorldModelError` on integrity violations. |
| `store.py` | `to_json` / `from_json` (+ `save` / `load`) — deterministic, diffable JSON snapshots; edge→node integrity enforced on load. |
| `query.py` | `find_paths(src, dst, kinds, max_hops)` — bounded, cycle-safe simple-path enumeration; `crown_jewel_paths(src, datastore_kind)` — reachable data stores from a foothold. |
| `tests/` | upsert-merge, reachability, path enumeration (no-path + cycle), JSON round-trip. |

## Shape

```
NodeKind:  HOST · SERVICE · ENDPOINT · WEBAPP · DATASTORE ·
           CLOUD_RESOURCE · NETWORK_SEGMENT · PRINCIPAL ·
           CREDENTIAL · SESSION · CONTROL · FINDING

EdgeKind:  REACHABLE_FROM · TRUSTS_FOR · HAS_GRANT · MEMBER_OF ·
           CAN_ASSUME · VALID_ON · AUTHENTICATES_TO · SESSION_ON ·
           CONTROL_PROTECTS · EVIDENCES
```

## Use

```python
from framework.v2.worldmodel import (
    WorldModel, Node, Edge, NodeKind, EdgeKind,
    find_paths, crown_jewel_paths, to_json, from_json,
)

wm = WorldModel()
wm.add_node(Node(id="foothold", kind=NodeKind.HOST,
                 provenance="obs-1", confidence=1.0,
                 first_seen=1, last_seen=1))
wm.add_node(Node(id="db", kind=NodeKind.DATASTORE,
                 provenance="obs-2", confidence=0.9,
                 first_seen=2, last_seen=2))
wm.add_edge(Edge(src="foothold", dst="db", kind=EdgeKind.REACHABLE_FROM,
                 provenance="obs-3", confidence=0.8,
                 first_seen=3, last_seen=3))

paths = find_paths(wm, "foothold", "db")
print(paths[0].min_confidence, paths[0].provenance_chain)

snapshot = to_json(wm)           # deterministic, diffable
wm2 = from_json(snapshot)        # survives a restart
```

## Status

Substrate + tests only this wave. The planner and verify layers consume
it in a later wave; nothing here reaches back into them (no import
cycle, by design).
