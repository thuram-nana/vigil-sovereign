"""
worldmodel.graph — the in-memory typed attack-graph.

WorldModel is a directed, typed multigraph. Nodes are keyed by id;
edges are keyed by the triple (src, dst, kind), so the same relationship
re-asserted from a new observation *upserts* rather than duplicating.

Adjacency is a plain dict-of-dicts — no external graph library — held in
two directions so both forward reachability and reverse ("who can reach
me?") queries are O(degree):

    _out[src][dst][kind] -> Edge      # outgoing
    _in[dst][src][kind]  -> Edge      # incoming (same Edge object)

Upsert semantics (add_node / add_edge) are the load-bearing behaviour:

  - attrs merge  — incoming keys overlay existing, keys not re-asserted
    are retained (the graph accretes knowledge, never forgets it);
  - confidence reconciles to the **max** — re-observing a fact never
    lowers belief in it; the higher-confidence assertion also donates
    its provenance, so the surviving provenance points at the strongest
    evidence (ties: the incoming assertion wins, keeping provenance
    fresh);
  - first_seen = min, last_seen = max of the two sequence ints.

All sequence numbers are caller-supplied monotonic ints; the graph never
reads a wallclock, so every operation is deterministic and replayable.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Iterator

from ..common.errors import CrucibleError
from .models import Edge, EdgeKind, Node, NodeKind


class WorldModelError(CrucibleError):
    """Recoverable world-model error — e.g. an edge referencing a node
    that is not present. The world-model records observations; it makes
    no trust decision, so this is a plain CrucibleError, never an
    EthicsViolation."""


class WorldModel:
    """A typed attack-graph. Construct empty, then accrete facts."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        # kind is stored by its str value so keys are JSON-friendly.
        self._out: dict[str, dict[str, dict[str, Edge]]] = {}
        self._in: dict[str, dict[str, dict[str, Edge]]] = {}

    # -- nodes --------------------------------------------------------------

    def add_node(self, node: Node) -> Node:
        """Idempotent upsert. If a node with this id exists, merge attrs,
        reconcile confidence to the max, widen the seen-window, and adopt
        the higher-confidence assertion's provenance. Returns the stored
        node (the merged one on upsert). Kind may not change once set."""
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            self._out.setdefault(node.id, {})
            self._in.setdefault(node.id, {})
            return node
        if existing.kind != node.kind:
            raise WorldModelError(
                f"node {node.id!r} kind conflict: "
                f"{existing.kind.value} != {node.kind.value}"
            )
        merged_attrs = dict(existing.attrs)
        merged_attrs.update(node.attrs)
        # max confidence wins; on a tie the incoming assertion donates
        # provenance so the surviving pointer stays fresh.
        if node.confidence >= existing.confidence:
            provenance, confidence = node.provenance, node.confidence
        else:
            provenance, confidence = existing.provenance, existing.confidence
        merged = existing.model_copy(
            update={
                "attrs": merged_attrs,
                "confidence": confidence,
                "provenance": provenance,
                "first_seen": min(existing.first_seen, node.first_seen),
                "last_seen": max(existing.last_seen, node.last_seen),
            }
        )
        self._nodes[node.id] = merged
        return merged

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def nodes_of_kind(self, kind: NodeKind) -> list[Node]:
        """All nodes of a kind, in deterministic (id-sorted) order."""
        return [n for _, n in sorted(self._nodes.items()) if n.kind == kind]

    def all_nodes(self) -> list[Node]:
        return [self._nodes[k] for k in sorted(self._nodes)]

    # -- edges --------------------------------------------------------------

    def add_edge(self, edge: Edge) -> Edge:
        """Idempotent upsert keyed by (src, dst, kind). Both endpoints
        must already be present (add their nodes first). Merge semantics
        mirror add_node. Returns the stored (merged) edge."""
        if edge.src not in self._nodes:
            raise WorldModelError(f"edge references unknown src node {edge.src!r}")
        if edge.dst not in self._nodes:
            raise WorldModelError(f"edge references unknown dst node {edge.dst!r}")
        kv = edge.kind.value
        existing = self._out.get(edge.src, {}).get(edge.dst, {}).get(kv)
        if existing is not None:
            merged_attrs = dict(existing.attrs)
            merged_attrs.update(edge.attrs)
            if edge.confidence >= existing.confidence:
                provenance, confidence = edge.provenance, edge.confidence
            else:
                provenance, confidence = existing.provenance, existing.confidence
            stored = existing.model_copy(
                update={
                    "attrs": merged_attrs,
                    "confidence": confidence,
                    "provenance": provenance,
                    "first_seen": min(existing.first_seen, edge.first_seen),
                    "last_seen": max(existing.last_seen, edge.last_seen),
                }
            )
        else:
            stored = edge
        self._out.setdefault(edge.src, {}).setdefault(edge.dst, {})[kv] = stored
        self._in.setdefault(edge.dst, {}).setdefault(edge.src, {})[kv] = stored
        return stored

    def get_edge(self, src: str, dst: str, kind: EdgeKind) -> Edge | None:
        return self._out.get(src, {}).get(dst, {}).get(kind.value)

    def edges_of_kind(self, kind: EdgeKind) -> list[Edge]:
        """All edges of a kind, in deterministic (src, dst)-sorted order."""
        out: list[Edge] = []
        for src in sorted(self._out):
            for dst in sorted(self._out[src]):
                edge = self._out[src][dst].get(kind.value)
                if edge is not None:
                    out.append(edge)
        return out

    def all_edges(self) -> list[Edge]:
        """Every edge, in deterministic (src, dst, kind)-sorted order."""
        out: list[Edge] = []
        for src in sorted(self._out):
            for dst in sorted(self._out[src]):
                for kv in sorted(self._out[src][dst]):
                    out.append(self._out[src][dst][kv])
        return out

    # -- traversal ----------------------------------------------------------

    def neighbors(
        self,
        node_id: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
        *,
        incoming: bool = False,
    ) -> list[Edge]:
        """Outgoing edges from `node_id` (or incoming when incoming=True),
        optionally filtered to a set of edge kinds. Deterministic order.
        Unknown node -> empty list (traversal is total, not partial)."""
        allowed = {k.value for k in edge_kinds} if edge_kinds is not None else None
        adj = self._in if incoming else self._out
        buckets = adj.get(node_id, {})
        out: list[Edge] = []
        for other in sorted(buckets):
            for kv in sorted(buckets[other]):
                if allowed is None or kv in allowed:
                    out.append(buckets[other][kv])
        return out

    def reachable(
        self,
        src: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
    ) -> set[str]:
        """Set of node ids reachable from `src` by following edges of the
        given kinds (any kind when None). Excludes `src` itself unless a
        cycle returns to it. Unknown `src` -> empty set. BFS; each node
        visited once, so cycles terminate."""
        if src not in self._nodes:
            return set()
        allowed = {k.value for k in edge_kinds} if edge_kinds is not None else None
        # `src` enters `seen` only if a cycle routes back to it; that
        # signal is intentionally preserved.
        seen: set[str] = set()
        queue: deque[str] = deque([src])
        while queue:
            cur = queue.popleft()
            for dst, kinds in self._out.get(cur, {}).items():
                if allowed is not None and not (allowed & kinds.keys()):
                    continue
                if dst not in seen:
                    seen.add(dst)
                    queue.append(dst)
        return seen

    def out_edges(
        self,
        node_id: str,
        edge_kinds: Iterable[EdgeKind] | None = None,
    ) -> Iterator[Edge]:
        """Iterator over outgoing edges (deterministic order). Used by the
        query layer's path enumeration."""
        yield from self.neighbors(node_id, edge_kinds)

    # -- sizing -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(
            len(kinds)
            for dsts in self._out.values()
            for kinds in dsts.values()
        )
