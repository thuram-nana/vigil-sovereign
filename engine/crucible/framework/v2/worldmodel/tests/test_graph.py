"""Tests for worldmodel.graph — upsert-merge, adjacency, reachability."""

from __future__ import annotations

import pytest

from ..graph import WorldModel, WorldModelError
from ..models import Edge, EdgeKind, Node, NodeKind


def _node(node_id: str, kind: NodeKind = NodeKind.HOST, *, prov: str = "obs",
          conf: float = 1.0, first: int = 1, last: int = 1) -> Node:
    return Node(id=node_id, kind=kind, provenance=prov, confidence=conf,
                first_seen=first, last_seen=last)


def _edge(src: str, dst: str, kind: EdgeKind = EdgeKind.REACHABLE_FROM, *,
          prov: str = "obs-e", conf: float = 1.0, first: int = 1,
          last: int = 1, attrs: dict | None = None) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance=prov, confidence=conf,
                first_seen=first, last_seen=last, attrs=attrs or {})


def test_add_node_then_get() -> None:
    wm = WorldModel()
    wm.add_node(_node("h1"))
    assert wm.has_node("h1")
    assert wm.get_node("h1").kind == NodeKind.HOST
    assert wm.node_count == 1


def test_node_upsert_merges_attrs_and_reconciles_confidence() -> None:
    wm = WorldModel()
    wm.add_node(Node(id="h1", kind=NodeKind.HOST, attrs={"ip": "10.0.0.1"},
                     provenance="obs-A", confidence=0.6, first_seen=2, last_seen=2))
    merged = wm.add_node(Node(id="h1", kind=NodeKind.HOST,
                              attrs={"os": "linux"}, provenance="obs-B",
                              confidence=0.9, first_seen=5, last_seen=5))
    # attrs accreted, not replaced
    assert merged.attrs == {"ip": "10.0.0.1", "os": "linux"}
    # confidence rose to the max; provenance follows the stronger evidence
    assert merged.confidence == 0.9
    assert merged.provenance == "obs-B"
    # seen-window widened
    assert merged.first_seen == 2
    assert merged.last_seen == 5
    assert wm.node_count == 1


def test_node_upsert_lower_confidence_keeps_higher() -> None:
    wm = WorldModel()
    wm.add_node(_node("h1", conf=0.8, prov="strong"))
    merged = wm.add_node(_node("h1", conf=0.3, prov="weak"))
    assert merged.confidence == 0.8
    assert merged.provenance == "strong"   # belief never lowered


def test_node_kind_conflict_rejected() -> None:
    wm = WorldModel()
    wm.add_node(_node("x", NodeKind.HOST))
    with pytest.raises(WorldModelError):
        wm.add_node(_node("x", NodeKind.DATASTORE))


def test_add_edge_requires_endpoints() -> None:
    wm = WorldModel()
    wm.add_node(_node("a"))
    with pytest.raises(WorldModelError):
        wm.add_edge(_edge("a", "missing"))
    with pytest.raises(WorldModelError):
        wm.add_edge(_edge("missing", "a"))


def test_edge_upsert_merges_on_triple() -> None:
    wm = WorldModel()
    wm.add_node(_node("a"))
    wm.add_node(_node("b"))
    wm.add_edge(_edge("a", "b", conf=0.5, prov="e1", attrs={"port": 22}))
    merged = wm.add_edge(_edge("a", "b", conf=0.7, prov="e2",
                               attrs={"proto": "ssh"}, first=3, last=3))
    assert wm.edge_count == 1
    assert merged.confidence == 0.7
    assert merged.provenance == "e2"
    assert merged.attrs == {"port": 22, "proto": "ssh"}
    assert merged.last_seen == 3


def test_multigraph_distinct_kinds_coexist() -> None:
    wm = WorldModel()
    wm.add_node(_node("a"))
    wm.add_node(_node("b"))
    wm.add_edge(_edge("a", "b", EdgeKind.REACHABLE_FROM))
    wm.add_edge(_edge("a", "b", EdgeKind.TRUSTS_FOR))
    assert wm.edge_count == 2
    assert wm.get_edge("a", "b", EdgeKind.REACHABLE_FROM) is not None
    assert wm.get_edge("a", "b", EdgeKind.TRUSTS_FOR) is not None


def test_nodes_and_edges_of_kind_are_sorted() -> None:
    wm = WorldModel()
    for nid in ("h2", "h1", "h3"):
        wm.add_node(_node(nid))
    wm.add_node(_node("d1", NodeKind.DATASTORE))
    assert [n.id for n in wm.nodes_of_kind(NodeKind.HOST)] == ["h1", "h2", "h3"]
    assert [n.id for n in wm.nodes_of_kind(NodeKind.DATASTORE)] == ["d1"]


def test_neighbors_incoming_and_outgoing_with_filter() -> None:
    wm = WorldModel()
    for n in ("a", "b", "c"):
        wm.add_node(_node(n))
    wm.add_edge(_edge("a", "b", EdgeKind.REACHABLE_FROM))
    wm.add_edge(_edge("a", "c", EdgeKind.TRUSTS_FOR))
    wm.add_edge(_edge("c", "a", EdgeKind.REACHABLE_FROM))
    out = wm.neighbors("a")
    assert {e.dst for e in out} == {"b", "c"}
    out_reach = wm.neighbors("a", [EdgeKind.REACHABLE_FROM])
    assert [e.dst for e in out_reach] == ["b"]
    inc = wm.neighbors("a", incoming=True)
    assert [e.src for e in inc] == ["c"]


def test_reachable_linear() -> None:
    wm = WorldModel()
    for n in ("a", "b", "c", "d"):
        wm.add_node(_node(n))
    wm.add_edge(_edge("a", "b"))
    wm.add_edge(_edge("b", "c"))
    wm.add_edge(_edge("c", "d"))
    assert wm.reachable("a") == {"b", "c", "d"}
    assert wm.reachable("c") == {"d"}


def test_reachable_respects_edge_kind_filter() -> None:
    wm = WorldModel()
    for n in ("a", "b", "c"):
        wm.add_node(_node(n))
    wm.add_edge(_edge("a", "b", EdgeKind.REACHABLE_FROM))
    wm.add_edge(_edge("b", "c", EdgeKind.TRUSTS_FOR))
    # only REACHABLE_FROM: cannot cross the TRUSTS_FOR hop
    assert wm.reachable("a", [EdgeKind.REACHABLE_FROM]) == {"b"}
    assert wm.reachable("a", [EdgeKind.REACHABLE_FROM, EdgeKind.TRUSTS_FOR]) == {"b", "c"}


def test_reachable_terminates_on_cycle() -> None:
    wm = WorldModel()
    for n in ("a", "b", "c"):
        wm.add_node(_node(n))
    wm.add_edge(_edge("a", "b"))
    wm.add_edge(_edge("b", "c"))
    wm.add_edge(_edge("c", "a"))   # cycle back to start
    reach = wm.reachable("a")
    assert reach == {"a", "b", "c"}   # cycle returns to a, so a is in the set


def test_reachable_unknown_source_empty() -> None:
    wm = WorldModel()
    assert wm.reachable("nope") == set()
