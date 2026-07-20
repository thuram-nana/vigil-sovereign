"""
worldmodel.query — bounded path queries over the attack-graph.

The planner and verify layers (future waves) don't want the raw
adjacency — they want answers: *from this foothold, what simple paths
reach that crown jewel, and how confident is each hop?* This module
provides those answers as `Path` objects that carry their own provenance
chain and weakest-link confidence.

Every query here is **bounded** — `max_hops` caps path length and simple-
path semantics (no repeated node) guarantees termination even on a
cyclic graph. Enumeration order is deterministic, driven by the graph's
sorted adjacency, so results are stable across runs and exact in tests.
"""

from __future__ import annotations

from collections.abc import Iterable

from .graph import WorldModel
from .models import Edge, EdgeKind, NodeKind, Path

DEFAULT_MAX_HOPS = 6


def find_paths(
    model: WorldModel,
    src: str,
    dst: str,
    edge_kinds: Iterable[EdgeKind] | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> list[Path]:
    """Enumerate all simple paths (no repeated node) from `src` to `dst`
    following only edges of the given kinds (any kind when None), up to
    `max_hops` edges. Returns `Path` objects in deterministic order,
    shortest paths first then by traversal order.

    Empty list when: src or dst is absent, no path exists, or src == dst
    (self-paths are not attack paths). Bounded and cycle-safe."""
    if max_hops < 1:
        raise ValueError("max_hops must be >= 1")
    if src == dst:
        return []
    if not model.has_node(src) or not model.has_node(dst):
        return []

    results: list[Path] = []
    visited: set[str] = {src}
    trail: list[Edge] = []

    def _dfs(current: str) -> None:
        if len(trail) >= max_hops:
            return
        for edge in model.out_edges(current, edge_kinds):
            nxt = edge.dst
            if nxt == dst:
                results.append(Path(edges=[*trail, edge]))
                continue
            if nxt in visited:
                continue
            visited.add(nxt)
            trail.append(edge)
            _dfs(nxt)
            trail.pop()
            visited.discard(nxt)

    _dfs(src)
    # Shortest paths first; ties keep deterministic discovery order.
    results.sort(key=lambda p: p.hops)
    return results


def crown_jewel_paths(
    model: WorldModel,
    src: str,
    datastore_kind: NodeKind = NodeKind.DATASTORE,
    edge_kinds: Iterable[EdgeKind] | None = None,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> dict[str, list[Path]]:
    """From foothold `src`, enumerate the simple paths that reach each
    crown-jewel node (every node of `datastore_kind`). Returns a mapping
    of crown-jewel node id -> its reachable paths, including jewels with
    an empty list so the caller sees which are *not* reachable.

    This is the archetypal question the planner asks: given where I stand,
    which data stores can I reach and by what explainable route."""
    jewels = model.nodes_of_kind(datastore_kind)
    return {
        jewel.id: find_paths(model, src, jewel.id, edge_kinds, max_hops)
        for jewel in jewels
    }
