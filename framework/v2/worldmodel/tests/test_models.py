"""Tests for worldmodel.models — validation of the pure data shapes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ..models import Edge, EdgeKind, Node, NodeKind, Path


def _node(node_id: str, kind: NodeKind = NodeKind.HOST) -> Node:
    return Node(id=node_id, kind=kind, provenance="obs-1", confidence=1.0,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind = EdgeKind.REACHABLE_FROM,
          conf: float = 1.0, prov: str = "obs-e") -> Edge:
    return Edge(src=src, dst=dst, kind=kind, provenance=prov, confidence=conf,
                first_seen=1, last_seen=1)


def test_node_requires_provenance() -> None:
    with pytest.raises(ValidationError):
        Node(id="h", kind=NodeKind.HOST, provenance="", confidence=1.0,
             first_seen=1, last_seen=1)


def test_confidence_bounds_enforced() -> None:
    with pytest.raises(ValidationError):
        _edge("a", "b", conf=1.5)
    with pytest.raises(ValidationError):
        _edge("a", "b", conf=-0.1)


def test_last_seen_before_first_seen_rejected() -> None:
    with pytest.raises(ValidationError):
        Node(id="h", kind=NodeKind.HOST, provenance="o", confidence=1.0,
             first_seen=5, last_seen=2)
    with pytest.raises(ValidationError):
        Edge(src="a", dst="b", kind=EdgeKind.REACHABLE_FROM, provenance="o",
             confidence=1.0, first_seen=5, last_seen=2)


def test_edge_key_triple() -> None:
    e = _edge("a", "b", EdgeKind.CAN_ASSUME)
    assert e.key == ("a", "b", "can_assume")


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        Node(id="h", kind=NodeKind.HOST, provenance="o", confidence=1.0,
             first_seen=1, last_seen=1, bogus="x")


def test_path_derived_properties() -> None:
    e1 = _edge("a", "b", conf=0.9, prov="p1")
    e2 = _edge("b", "c", conf=0.4, prov="p2")
    p = Path(edges=[e1, e2])
    assert p.nodes == ["a", "b", "c"]
    assert p.min_confidence == 0.4      # weakest link
    assert p.provenance_chain == ["p1", "p2"]
    assert p.hops == 2


def test_path_requires_at_least_one_edge() -> None:
    with pytest.raises(ValidationError):
        Path(edges=[])
