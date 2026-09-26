"""ORDER IDENTITY for the graph order indexes (#828).

`WorldModel`'s deterministic readers (`all_nodes`, `nodes_of_kind`, `all_edges`,
`edges_of_kind`, `neighbors`) used to re-`sorted()` the whole node dict /
adjacency dict on EVERY call. They are now served from maintained sorted
buckets. Those sorts existed ONLY to pin iteration order, so the index is only
allowed to be a speed-up if it is **verdict-byte-identical**: every reader must
return the SAME sequence, element for element, as the pre-index code.

This module proves that directly rather than by inference:

  * `_ref_*` below are the pre-change reader bodies, copied VERBATIM from
    graph.py at base 838e0b42. They read only `_nodes` / `_out` / `_in`, the
    same base structures the indexed readers derive from, so they compute the
    honest "what the old code would have returned" answer for whatever state
    the graph is actually in.
  * `_assert_same` compares by `id()`, i.e. the exact same Python objects in
    the exact same positions — strictly stronger than `==` on the models.
  * The comparison is driven through MUTATION sequences (insert / upsert /
    edge upsert / remove / re-add / self-loop, in several insertion orders,
    with reads interleaved between writes), because a stale index rots on
    mutation, not on a freshly built graph.

If an index change ever shifts iteration order by one element, these fail.
"""

from __future__ import annotations

import random

import pytest

from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind

# --------------------------------------------------------------------------
# the pre-index reader bodies, verbatim from base 838e0b42
# --------------------------------------------------------------------------


def _ref_all_nodes(w: WorldModel) -> list[Node]:
    return [w._nodes[k] for k in sorted(w._nodes)]


def _ref_nodes_of_kind(w: WorldModel, kind) -> list[Node]:
    return [n for _, n in sorted(w._nodes.items()) if n.kind == kind]


def _ref_all_edges(w: WorldModel) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            for kv in sorted(w._out[src][dst]):
                out.append(w._out[src][dst][kv])
    return out


def _ref_edges_of_kind(w: WorldModel, kind: EdgeKind) -> list[Edge]:
    out: list[Edge] = []
    for src in sorted(w._out):
        for dst in sorted(w._out[src]):
            edge = w._out[src][dst].get(kind.value)
            if edge is not None:
                out.append(edge)
    return out


def _ref_neighbors(w: WorldModel, node_id: str, edge_kinds=None,
                   *, incoming: bool = False) -> list[Edge]:
    allowed = {k.value for k in edge_kinds} if edge_kinds is not None else None
    adj = w._in if incoming else w._out
    buckets = adj.get(node_id, {})
    out: list[Edge] = []
    for other in sorted(buckets):
        for kv in sorted(buckets[other]):
            if allowed is None or kv in allowed:
                out.append(buckets[other][kv])
    return out


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_NODE_KINDS = [NodeKind.HOST, NodeKind.SERVICE, NodeKind.ENDPOINT,
               NodeKind.PRINCIPAL, NodeKind.CREDENTIAL, NodeKind.FINDING]
_EDGE_KINDS = [EdgeKind.REACHABLE_FROM, EdgeKind.TRUSTS_FOR, EdgeKind.HAS_GRANT,
               EdgeKind.CAN_ASSUME, EdgeKind.EVIDENCES]


def _node(nid: str, kind: NodeKind = NodeKind.HOST, *, conf: float = 0.5,
          seq: int = 1) -> Node:
    return Node(id=nid, kind=kind, provenance="obs", confidence=conf,
                first_seen=seq, last_seen=seq)


def _edge(src: str, dst: str, kind: EdgeKind = EdgeKind.REACHABLE_FROM, *,
          conf: float = 0.5, seq: int = 1) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance="obs-e",
                confidence=conf, first_seen=seq, last_seen=seq)


def _assert_same(label: str, fast: list, ref: list) -> None:
    """Element-for-element object identity — strictly stronger than `==`."""
    assert [id(x) for x in fast] == [id(x) for x in ref], (
        f"{label}: indexed reader diverged from the pre-index order\n"
        f"  indexed: {[getattr(x, 'id', None) or (x.src, x.dst, x.kind.value) for x in fast]}\n"
        f"  pre-idx: {[getattr(x, 'id', None) or (x.src, x.dst, x.kind.value) for x in ref]}"
    )


def _assert_every_reader_identical(w: WorldModel, step: str) -> None:
    """Every deterministic reader, against its pre-index twin, at one instant."""
    w._assert_index_consistent()
    _assert_same(f"{step}: all_nodes", w.all_nodes(), _ref_all_nodes(w))
    _assert_same(f"{step}: all_edges", w.all_edges(), _ref_all_edges(w))
    for nk in _NODE_KINDS:
        _assert_same(f"{step}: nodes_of_kind({nk.value})",
                     w.nodes_of_kind(nk), _ref_nodes_of_kind(w, nk))
        # a str-enum member and its bare value must resolve the same way the
        # old `n.kind == kind` comparison did
        _assert_same(f"{step}: nodes_of_kind({nk.value!r} as str)",
                     w.nodes_of_kind(nk.value), _ref_nodes_of_kind(w, nk.value))
    for ek in _EDGE_KINDS:
        _assert_same(f"{step}: edges_of_kind({ek.value})",
                     w.edges_of_kind(ek), _ref_edges_of_kind(w, ek))
    for nid in sorted(w._nodes) + ["absent-node"]:
        for incoming in (False, True):
            _assert_same(f"{step}: neighbors({nid}, incoming={incoming})",
                         w.neighbors(nid, incoming=incoming),
                         _ref_neighbors(w, nid, incoming=incoming))
            for kinds in ([EdgeKind.REACHABLE_FROM],
                          [EdgeKind.TRUSTS_FOR, EdgeKind.HAS_GRANT],
                          []):
                _assert_same(
                    f"{step}: neighbors({nid}, {[k.value for k in kinds]}, "
                    f"incoming={incoming})",
                    w.neighbors(nid, kinds, incoming=incoming),
                    _ref_neighbors(w, nid, kinds, incoming=incoming),
                )


# --------------------------------------------------------------------------
# 1. hand-built adversarial mutation sequence
# --------------------------------------------------------------------------


def test_order_identity_through_a_hostile_mutation_sequence() -> None:
    """Descending inserts (every append lands out of order), reads interleaved
    between writes (so the lazy sort fires mid-stream), upserts, removals,
    re-adds, and a self-loop."""
    w = WorldModel()

    # descending ids -> every append is out of order -> the bucket is always dirty
    for i in reversed(range(12)):
        w.add_node(_node(f"n{i:02d}", _NODE_KINDS[i % len(_NODE_KINDS)], seq=i + 1))
        _assert_every_reader_identical(w, f"desc-insert n{i:02d}")

    # edges, also descending, interleaved with reads
    for i in reversed(range(11)):
        w.add_edge(_edge(f"n{i:02d}", f"n{i + 1:02d}", _EDGE_KINDS[i % len(_EDGE_KINDS)],
                         seq=i + 1))
        _assert_every_reader_identical(w, f"desc-edge n{i:02d}")

    # a second kind on an existing (src, dst) pair, out of kind order
    w.add_edge(_edge("n00", "n01", EdgeKind.TRUSTS_FOR, seq=50))
    w.add_edge(_edge("n00", "n01", EdgeKind.CAN_ASSUME, seq=51))
    w.add_edge(_edge("n00", "n01", EdgeKind.EVIDENCES, seq=52))
    w.add_edge(_edge("n00", "n01", EdgeKind.HAS_GRANT, seq=53))
    _assert_every_reader_identical(w, "multi-kind bucket")

    # upserts: same ids re-asserted, must not duplicate or reorder anything
    for i in range(12):
        w.add_node(_node(f"n{i:02d}", _NODE_KINDS[i % len(_NODE_KINDS)],
                         conf=0.9, seq=100 + i))
    w.add_edge(_edge("n00", "n01", EdgeKind.TRUSTS_FOR, conf=0.95, seq=120))
    _assert_every_reader_identical(w, "upserts")

    # a self-loop, then remove the node that carries it
    w.add_edge(_edge("n05", "n05", EdgeKind.REACHABLE_FROM, seq=130))
    w.add_edge(_edge("n05", "n05", EdgeKind.OWNS, seq=131))
    _assert_every_reader_identical(w, "self-loop added")

    # removals from the middle, from the ends, and of an absent node
    assert w.remove_node("absent") is False
    _assert_every_reader_identical(w, "remove absent")
    for nid in ("n05", "n00", "n11", "n07"):
        assert w.remove_node(nid) is True
        _assert_every_reader_identical(w, f"removed {nid}")

    # re-add removed nodes and their edges — the index must come back clean
    for nid in ("n07", "n00", "n05"):
        w.add_node(_node(nid, NodeKind.DATASTORE, seq=200))
        _assert_every_reader_identical(w, f"re-added {nid}")
    w.add_edge(_edge("n05", "n00", EdgeKind.HOLDS, seq=201))
    w.add_edge(_edge("n00", "n07", EdgeKind.OWNS, seq=202))
    w.add_edge(_edge("n05", "n05", EdgeKind.REACHABLE_FROM, seq=203))
    _assert_every_reader_identical(w, "re-added edges")

    # drain the graph entirely
    for nid in sorted(w._nodes, reverse=True):
        w.remove_node(nid)
    _assert_every_reader_identical(w, "drained")
    assert w.all_nodes() == [] and w.all_edges() == []


# --------------------------------------------------------------------------
# 2. randomised mutation workload
# --------------------------------------------------------------------------


@pytest.mark.parametrize("seed", [0, 1, 2, 3, 7, 11, 13, 29, 101, 997])
def test_order_identity_under_a_randomised_mutation_workload(seed: int) -> None:
    rng = random.Random(seed)
    w = WorldModel()
    pool = [f"x{i:03d}" for i in range(24)]
    live: list[str] = []

    for step in range(220):
        roll = rng.random()
        if roll < 0.34 or not live:
            nid = rng.choice(pool)                       # new OR upsert
            kind = (w._nodes[nid].kind if nid in w._nodes
                    else rng.choice(_NODE_KINDS))        # kind may not change
            w.add_node(_node(nid, kind, conf=rng.random(), seq=step + 1))
            if nid not in live:
                live.append(nid)
        elif roll < 0.80:
            src, dst = rng.choice(live), rng.choice(live)  # self-loops included
            w.add_edge(_edge(src, dst, rng.choice(_EDGE_KINDS),
                             conf=rng.random(), seq=step + 1))
        else:
            nid = rng.choice(live)
            assert w.remove_node(nid) is True
            live.remove(nid)

        # read on EVERY step: the lazy bucket normalisation must interleave
        # with writes without ever losing a key or shifting one
        if step % 7 == 0 or step > 200:
            _assert_every_reader_identical(w, f"seed={seed} step={step}")

    _assert_every_reader_identical(w, f"seed={seed} final")


# --------------------------------------------------------------------------
# 3. insertion-order invariance
# --------------------------------------------------------------------------


def _build(order_nodes, order_edges) -> WorldModel:
    w = WorldModel()
    for nid, kind in order_nodes:
        w.add_node(_node(nid, kind, seq=1))
    for src, dst, kind in order_edges:
        w.add_edge(_edge(src, dst, kind, seq=1))
    return w


def _shape(w: WorldModel) -> dict:
    """Everything the readers promise ORDER over, as plain keys."""
    return {
        "all_nodes": [n.id for n in w.all_nodes()],
        "all_edges": [(e.src, e.dst, e.kind.value) for e in w.all_edges()],
        "by_node_kind": {k.value: [n.id for n in w.nodes_of_kind(k)]
                         for k in _NODE_KINDS},
        "by_edge_kind": {k.value: [(e.src, e.dst) for e in w.edges_of_kind(k)]
                         for k in _EDGE_KINDS},
        "out": {nid: [(e.src, e.dst, e.kind.value) for e in w.neighbors(nid)]
                for nid in sorted(w._nodes)},
        "in": {nid: [(e.src, e.dst, e.kind.value)
                     for e in w.neighbors(nid, incoming=True)]
               for nid in sorted(w._nodes)},
        "filtered": {nid: [(e.src, e.dst, e.kind.value)
                           for e in w.neighbors(nid, [EdgeKind.REACHABLE_FROM,
                                                      EdgeKind.CAN_ASSUME])]
                     for nid in sorted(w._nodes)},
    }


def test_insertion_order_does_not_change_iteration_order() -> None:
    """The same logical graph built in 24 different insertion orders must read
    back in ONE order — the sorted one. An index that leaked insertion order
    would show up here."""
    nodes = [(f"h{i:02d}", _NODE_KINDS[i % len(_NODE_KINDS)]) for i in range(14)]
    edges = [(f"h{i:02d}", f"h{(i * 5 + 3) % 14:02d}",
              _EDGE_KINDS[i % len(_EDGE_KINDS)]) for i in range(14)]
    edges += [("h03", "h09", EdgeKind.TRUSTS_FOR), ("h03", "h09", EdgeKind.OWNS),
              ("h03", "h09", EdgeKind.CAN_ASSUME), ("h07", "h07", EdgeKind.HOLDS)]

    baseline = _shape(_build(nodes, edges))
    # the reference order, computed the pre-index way, on the baseline graph
    ref = _build(nodes, edges)
    assert baseline["all_nodes"] == [n.id for n in _ref_all_nodes(ref)]
    assert baseline["all_edges"] == [(e.src, e.dst, e.kind.value)
                                     for e in _ref_all_edges(ref)]

    rng = random.Random(4242)
    for trial in range(24):
        n2, e2 = list(nodes), list(edges)
        rng.shuffle(n2)
        rng.shuffle(e2)
        # edges may only be added once both endpoints exist; nodes all go first
        w = _build(n2, e2)
        w._assert_index_consistent()
        assert _shape(w) == baseline, f"insertion order {trial} changed read order"


def test_removal_and_readd_order_matches_a_fresh_build() -> None:
    """Build, churn (remove + re-add in a different order), and land on exactly
    the read order of a graph that was never churned."""
    nodes = [(f"k{i:02d}", _NODE_KINDS[i % len(_NODE_KINDS)]) for i in range(10)]
    edges = [(f"k{i:02d}", f"k{(i * 3 + 1) % 10:02d}",
              _EDGE_KINDS[i % len(_EDGE_KINDS)]) for i in range(10)]
    fresh = _shape(_build(nodes, edges))

    churned = _build(nodes, edges)
    for nid in ("k04", "k00", "k09", "k02"):
        churned.remove_node(nid)
        churned._assert_index_consistent()
    # re-add in reverse, so every append lands out of order
    for nid, kind in reversed([nk for nk in nodes if nk[0] in
                               ("k04", "k00", "k09", "k02")]):
        churned.add_node(_node(nid, kind, seq=1))
    for src, dst, kind in reversed(edges):
        churned.add_edge(_edge(src, dst, kind, seq=1))
    churned._assert_index_consistent()
    assert _shape(churned) == fresh


# --------------------------------------------------------------------------
# 4. reader purity: a read must not change what the next read returns
# --------------------------------------------------------------------------


def test_reads_are_idempotent_and_do_not_disturb_each_other() -> None:
    """The lazy normalisation mutates internal buckets on read. That must be
    invisible: repeated reads, and reads in any interleaving, return the same
    sequence."""
    w = WorldModel()
    for i in reversed(range(16)):
        w.add_node(_node(f"z{i:02d}", _NODE_KINDS[i % len(_NODE_KINDS)], seq=i + 1))
    for i in reversed(range(15)):
        w.add_edge(_edge(f"z{i:02d}", f"z{i + 1:02d}",
                         _EDGE_KINDS[i % len(_EDGE_KINDS)], seq=i + 1))

    first = _shape(w)
    for _ in range(3):
        assert _shape(w) == first
    # and in a different reader order, on a graph whose buckets start dirty again
    w.add_node(_node("z00", _NODE_KINDS[0], conf=0.99, seq=400))
    w.add_edge(_edge("z15", "z00", EdgeKind.OWNS, seq=401))
    a = w.neighbors("z00")
    b = w.all_edges()
    c = w.nodes_of_kind(NodeKind.HOST)
    d = w.all_nodes()
    assert [id(x) for x in w.neighbors("z00")] == [id(x) for x in a]
    assert [id(x) for x in w.all_edges()] == [id(x) for x in b]
    assert [id(x) for x in w.nodes_of_kind(NodeKind.HOST)] == [id(x) for x in c]
    assert [id(x) for x in w.all_nodes()] == [id(x) for x in d]
    _assert_every_reader_identical(w, "reader purity")


def test_nodes_of_kind_misses_a_non_kind_exactly_as_the_old_filter_did() -> None:
    w = WorldModel()
    w.add_node(_node("a", NodeKind.HOST))
    w.add_node(_node("b", NodeKind.SERVICE))
    assert w.nodes_of_kind("not-a-kind") == _ref_nodes_of_kind(w, "not-a-kind") == []
    assert w.nodes_of_kind(NodeKind.DATASTORE) == []
    assert [n.id for n in w.nodes_of_kind("host")] == ["a"]
    assert [n.id for n in w.nodes_of_kind(NodeKind.HOST)] == ["a"]
