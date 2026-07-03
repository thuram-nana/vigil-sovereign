"""
worldmodel — the persistent, typed attack-graph substrate.

Every other reasoning layer eventually asks the same question: *given
what we have observed, what is now reachable, and by what explainable
route?* The world-model is where that state lives — a directed, typed
multigraph of hosts, services, web surface, datastores, cloud resources,
identities, credentials, sessions, controls, and findings, wired
together by reachability and trust edges. Every node and edge carries
provenance (what asserted it) and confidence (how much we believe it),
so a path the planner proposes is auditable hop-by-hop rather than an
oracle's say-so.

This wave ships the substrate and its tests only. The planner / verify
layers consume it in a future wave; nothing here reaches back into them.

Public surface (import from here, not from submodules):

    from framework.v2.worldmodel import (
        NodeKind, EdgeKind, Node, Edge, Path,
        WorldModel, WorldModelError,
        find_paths, crown_jewel_paths,
        to_json, from_json, save, load,
    )

Design notes:

- Time is a caller-supplied monotonic **sequence int**, never a
  wallclock. The graph never reads the clock, so every merge, ordering,
  and query is deterministic and replayable.
- add_node / add_edge are idempotent upserts: attrs merge, confidence
  reconciles to the max, the seen-window widens. Re-observing a fact
  refines it; it never duplicates or forgets it.
- All queries are bounded (max_hops) and simple-path (cycle-safe).
"""

from __future__ import annotations

from .graph import WorldModel, WorldModelError
from .models import Edge, EdgeKind, Node, NodeKind, Path
from .query import crown_jewel_paths, find_paths
from .store import (
    from_dict,
    from_json,
    load,
    save,
    to_dict,
    to_json,
)

__all__ = [
    # models
    "NodeKind",
    "EdgeKind",
    "Node",
    "Edge",
    "Path",
    # graph
    "WorldModel",
    "WorldModelError",
    # query
    "find_paths",
    "crown_jewel_paths",
    # store
    "to_dict",
    "to_json",
    "from_dict",
    "from_json",
    "save",
    "load",
]
