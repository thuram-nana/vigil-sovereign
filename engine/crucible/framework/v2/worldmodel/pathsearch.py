"""
worldmodel.pathsearch — objective-directed, ranked, explainable attack paths.

``query.find_paths`` enumerates *every* simple path up to a hop bound —
exhaustive, but it drowns the operator in routes and has no notion of
which one an attacker would actually take. This module is the planner's
real interface: it asks the objective-directed questions and returns them
*ranked*.

  * :func:`shortest_paths` — Yen's algorithm for the ``k`` shortest simple
    paths from a source to a specific target (fewest hops first).

  * :func:`best_paths` — the ``k`` best routes from a foothold to *any*
    crown-jewel node (any node whose kind is in ``objective_kinds``),
    ranked by a caller-supplied ``weight_fn``. The default weight is
    ``-log(confidence)`` so that minimising total weight maximises the
    product of edge confidences: the highest-confidence route wins. Every
    result is a :class:`~.models.Path`, so it carries ``min_confidence``
    (its weakest link) and ``provenance_chain`` (auditable hop-by-hop).

  * :func:`choke_points` — the BloodHound-style remediation output: the
    edges that gate the most source→objective routes. Ranked by how many
    crown jewels a single edge's removal disconnects (exact 1-cut / bridge
    detection), then by betweenness over the enumerated shortest paths.

Everything here is **read-only** on the world-model (nothing is mutated,
so it is safe to run concurrently with derivation) and **deterministic**:
Dijkstra relaxes neighbours in the graph's sorted adjacency order and all
ties break on the edge-key tuple, so the same graph always yields the same
ranked paths. Run :func:`derive` first if you want planning to see the
graph's inferred consequences, not only its raw observations.
"""

from __future__ import annotations

import heapq
import math
from collections import deque
from collections.abc import Callable, Iterable

from pydantic import BaseModel, ConfigDict, Field

from .graph import WorldModel
from .models import Edge, EdgeKind, NodeKind, Path

# A weight_fn maps an edge to a **non-negative** traversal cost. Dijkstra
# requires non-negativity; the default satisfies it because confidence <= 1.
WeightFn = Callable[[Edge], float]

_EdgeList = list[Edge]
_EdgeKey = tuple[str, str, str]

DEFAULT_CHOKE_K = 8


def default_weight(edge: Edge) -> float:
    """``-log(confidence)`` — the default edge cost. Summed over a path it
    equals ``-log(product of confidences)``, so the minimum-weight path is
    the maximum-confidence path. A zero-confidence edge costs ``inf`` (it
    is effectively unusable)."""
    c = edge.confidence
    if c <= 0.0:
        return math.inf
    return -math.log(c)


def unit_weight(edge: Edge) -> float:
    """Every edge costs 1 — minimising total weight minimises hop count."""
    return 1.0


def lcb_weight(z: float = 1.0) -> WeightFn:
    """A risk-averse weight: ``-log(belief lower-credible-bound)``. Where
    ``default_weight`` ranks by the confidence point estimate, this ranks by the
    *evidence-discounted* belief, so a high-mean but thinly-evidenced (high-
    variance) edge costs MORE than a slightly-lower-mean but proven one — the
    planner prefers routes it has actually corroborated. Non-negative (the LCB is
    in [0, 1]); a zero-LCB edge costs ``inf`` (unusable until it earns evidence).

    Returns a ``WeightFn`` to hand to :func:`best_paths` / :func:`shortest_paths`;
    ``z`` sets how conservative the bound is (1.0 ~= a one-sigma lower bound)."""
    def _weight(edge: Edge) -> float:
        lcb = edge.belief_lcb(z)
        if lcb <= 0.0:
            return math.inf
        return -math.log(lcb)
    return _weight


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _path_nodes(edges: _EdgeList) -> list[str]:
    return [edges[0].src] + [e.dst for e in edges]


def _path_sig(edges: _EdgeList) -> tuple[_EdgeKey, ...]:
    """A hashable identity for a path (its ordered edge keys) for dedup."""
    return tuple(e.key for e in edges)


def _total_weight(edges: _EdgeList, weight: WeightFn) -> float:
    return math.fsum(weight(e) for e in edges)


# ---------------------------------------------------------------------------
# Dijkstra (single shortest simple path, with Yen's exclusions)
# ---------------------------------------------------------------------------


def _dijkstra(
    world: WorldModel,
    src: str,
    dst: str,
    weight: WeightFn,
    edge_kinds: Iterable[EdgeKind] | None,
    removed_edges: set[_EdgeKey],
    removed_nodes: set[str],
) -> _EdgeList | None:
    """Minimum-weight simple path ``src`` -> ``dst`` as a list of edges, or
    ``None`` if none exists. Skips any edge in ``removed_edges`` and any
    node in ``removed_nodes`` (Yen's spur machinery). Non-negative weights
    only; ``inf``-weight edges are treated as absent."""
    if src == dst:
        return []
    if not world.has_node(src) or not world.has_node(dst):
        return None

    dist: dict[str, float] = {src: 0.0}
    pred: dict[str, Edge] = {}
    visited: set[str] = set()
    # Heap ordered by (distance, node id) so ties break deterministically.
    heap: list[tuple[float, str]] = [(0.0, src)]

    while heap:
        d, u = heapq.heappop(heap)
        if u in visited:
            continue
        visited.add(u)
        if u == dst:
            break
        for edge in world.out_edges(u, edge_kinds):  # sorted adjacency
            v = edge.dst
            if v in removed_nodes or v in visited:
                continue
            if edge.key in removed_edges:
                continue
            w = weight(edge)
            if not math.isfinite(w):
                continue
            nd = d + w
            if v not in dist or nd < dist[v]:
                dist[v] = nd
                pred[v] = edge
                heapq.heappush(heap, (nd, v))

    if dst not in dist:
        return None
    # Reconstruct.
    path: _EdgeList = []
    cur = dst
    while cur != src:
        edge = pred[cur]
        path.append(edge)
        cur = edge.src
    path.reverse()
    return path


# ---------------------------------------------------------------------------
# Yen's k-shortest simple paths
# ---------------------------------------------------------------------------


def _yen(
    world: WorldModel,
    src: str,
    dst: str,
    weight: WeightFn,
    edge_kinds: Iterable[EdgeKind] | None,
    k: int,
) -> list[_EdgeList]:
    """The ``k`` lowest-weight *simple* paths ``src`` -> ``dst``, ascending
    by total weight (ties break on the edge-key tuple). Returns fewer than
    ``k`` when the graph has fewer distinct simple paths."""
    first = _dijkstra(world, src, dst, weight, edge_kinds, set(), set())
    if not first:  # None, or empty (src == dst)
        return []

    accepted: list[_EdgeList] = [first]
    accepted_sigs: set[tuple[_EdgeKey, ...]] = {_path_sig(first)}
    # Candidate heap keyed by (weight, sig) — sig alone disambiguates any
    # two distinct paths, so heap entries never compare Edge objects.
    candidates: list[tuple[float, tuple[_EdgeKey, ...], _EdgeList]] = []
    candidate_sigs: set[tuple[_EdgeKey, ...]] = set()

    while len(accepted) < k:
        prev = accepted[-1]
        prev_nodes = _path_nodes(prev)

        for i in range(len(prev)):
            spur_node = prev_nodes[i]
            root_edges = prev[:i]
            root_nodes = prev_nodes[: i + 1]

            removed_edges: set[_EdgeKey] = set()
            for p in accepted:
                if len(p) > i and _path_nodes(p)[: i + 1] == root_nodes:
                    removed_edges.add(p[i].key)
            # Forbid revisiting any node already on the root path (keeps
            # the concatenated path simple).
            removed_nodes = set(prev_nodes[:i])

            spur = _dijkstra(
                world, spur_node, dst, weight, edge_kinds, removed_edges, removed_nodes
            )
            if spur is None:
                continue
            total = root_edges + spur
            sig = _path_sig(total)
            if sig in accepted_sigs or sig in candidate_sigs:
                continue
            heapq.heappush(candidates, (_total_weight(total, weight), sig, total))
            candidate_sigs.add(sig)

        if not candidates:
            break
        _, sig, best = heapq.heappop(candidates)
        candidate_sigs.discard(sig)
        accepted.append(best)
        accepted_sigs.add(sig)

    return accepted[:k]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def shortest_paths(
    world: WorldModel,
    src: str,
    dst: str,
    edge_kinds: Iterable[EdgeKind] | None = None,
    k: int = 1,
) -> list[Path]:
    """The ``k`` shortest simple paths (fewest hops) from ``src`` to ``dst``,
    following only edges of ``edge_kinds`` (any kind when ``None``). Paths
    are distinct and returned shortest-first. Empty when ``src == dst``,
    either endpoint is absent, or no path exists."""
    if k < 1:
        raise ValueError("k must be >= 1")
    if src == dst or not world.has_node(src) or not world.has_node(dst):
        return []
    return [Path(edges=p) for p in _yen(world, src, dst, unit_weight, edge_kinds, k)]


def best_paths(
    world: WorldModel,
    src: str,
    objective_kinds: Iterable[NodeKind],
    weight_fn: WeightFn | None = None,
    k: int = 1,
    *,
    edge_kinds: Iterable[EdgeKind] | None = None,
) -> list[Path]:
    """The ``k`` best routes from ``src`` to *any* crown-jewel node (a node
    whose kind is in ``objective_kinds``), ranked by ``weight_fn`` (default
    :func:`default_weight` = ``-log(confidence)``, so the highest-confidence
    route ranks first). ``weight_fn`` must be non-negative.

    Returns :class:`~.models.Path` objects — inspect ``min_confidence`` and
    ``provenance_chain`` on each. The global top ``k`` across all objectives
    is exact: it is drawn from the per-objective ``k``-best unions, and every
    path ends at exactly one objective."""
    if k < 1:
        raise ValueError("k must be >= 1")
    weight = weight_fn or default_weight
    if not world.has_node(src):
        return []

    objectives: set[str] = set()
    for kind in objective_kinds:
        for node in world.nodes_of_kind(kind):
            objectives.add(node.id)
    objectives.discard(src)

    ranked: list[tuple[float, tuple[_EdgeKey, ...], _EdgeList]] = []
    for oid in sorted(objectives):
        for p in _yen(world, src, oid, weight, edge_kinds, k):
            ranked.append((_total_weight(p, weight), _path_sig(p), p))
    ranked.sort(key=lambda t: (t[0], t[1]))
    return [Path(edges=p) for _, _, p in ranked[:k]]


class ChokePoint(BaseModel):
    """One edge weighed as a remediation target on the source→objective
    routes. ``betweenness`` counts how many of the enumerated shortest
    paths traverse it; ``disconnects`` lists the objective node ids that
    become unreachable from the source if this single edge is removed, and
    ``is_bridge`` is true iff that list is non-empty. Cutting a bridge is a
    guaranteed win; a high-betweenness non-bridge is the best single lever
    when no 1-cut exists."""

    model_config = ConfigDict(extra="forbid")

    edge: Edge
    betweenness: int = Field(ge=0)
    disconnects: list[str] = Field(default_factory=list)
    is_bridge: bool = False


def _reaches(
    world: WorldModel,
    src: str,
    dst: str,
    edge_kinds: Iterable[EdgeKind] | None,
    excluded: set[_EdgeKey],
) -> bool:
    """BFS: is ``dst`` reachable from ``src`` over ``edge_kinds`` when the
    edges in ``excluded`` are removed? Read-only (never mutates world)."""
    if src == dst:
        return True
    seen: set[str] = {src}
    queue: deque[str] = deque([src])
    while queue:
        cur = queue.popleft()
        for edge in world.out_edges(cur, edge_kinds):
            if edge.key in excluded:
                continue
            nxt = edge.dst
            if nxt == dst:
                return True
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return False


def choke_points(
    world: WorldModel,
    src: str,
    objective_kinds: Iterable[NodeKind],
    *,
    edge_kinds: Iterable[EdgeKind] | None = None,
    k: int = DEFAULT_CHOKE_K,
) -> list[ChokePoint]:
    """Rank the edges whose removal most damages ``src``'s access to the
    crown jewels (nodes of ``objective_kinds``) — the remediation view.

    Method (bounded and read-only): enumerate up to ``k`` shortest simple
    paths from ``src`` to each reachable objective (repeated-shortest-path),
    count edge betweenness over that union, then for each edge on any route
    test — by a single reachability BFS with that edge removed — how many
    objectives it *alone* gates (exact 1-cut / bridge detection). Results
    are sorted by objectives-disconnected desc, then betweenness desc, then
    edge key, so the top entry is the strongest single remediation lever.
    Returns ``[]`` when no objective is reachable."""
    if k < 1:
        raise ValueError("k must be >= 1")

    objectives: list[str] = []
    seen_obj: set[str] = set()
    for kind in objective_kinds:
        for node in world.nodes_of_kind(kind):
            if node.id != src and node.id not in seen_obj:
                seen_obj.add(node.id)
                objectives.append(node.id)
    objectives.sort()

    betweenness: dict[_EdgeKey, int] = {}
    edge_by_key: dict[_EdgeKey, Edge] = {}
    reachable_objs: list[str] = []
    for oid in objectives:
        paths = _yen(world, src, oid, unit_weight, edge_kinds, k)
        if paths:
            reachable_objs.append(oid)
        for p in paths:
            for edge in p:
                betweenness[edge.key] = betweenness.get(edge.key, 0) + 1
                edge_by_key[edge.key] = edge

    results: list[ChokePoint] = []
    for key, edge in edge_by_key.items():
        disconnects = [
            oid
            for oid in reachable_objs
            if not _reaches(world, src, oid, edge_kinds, {key})
        ]
        results.append(
            ChokePoint(
                edge=edge,
                betweenness=betweenness[key],
                disconnects=disconnects,
                is_bridge=bool(disconnects),
            )
        )
    results.sort(key=lambda c: (-len(c.disconnects), -c.betweenness, c.edge.key))
    return results
