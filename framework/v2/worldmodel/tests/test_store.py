"""Tests for worldmodel.store — deterministic JSON round-trip."""

from __future__ import annotations

import pytest

from ..graph import WorldModel, WorldModelError
from ..models import Edge, EdgeKind, Node, NodeKind
from ..store import from_json, load, save, to_dict, to_json


def _sample() -> WorldModel:
    wm = WorldModel()
    wm.add_node(Node(id="foothold", kind=NodeKind.HOST, attrs={"ip": "10.0.0.1"},
                     provenance="obs-1", confidence=1.0, first_seen=1, last_seen=3))
    wm.add_node(Node(id="p1", kind=NodeKind.PRINCIPAL, provenance="obs-2",
                     confidence=0.8, first_seen=2, last_seen=2))
    wm.add_node(Node(id="db", kind=NodeKind.DATASTORE, provenance="obs-3",
                     confidence=0.9, first_seen=3, last_seen=3))
    wm.add_edge(Edge(src="foothold", dst="p1", kind=EdgeKind.AUTHENTICATES_TO,
                     provenance="e-1", confidence=0.7, first_seen=4, last_seen=4,
                     attrs={"method": "basic"}))
    wm.add_edge(Edge(src="p1", dst="db", kind=EdgeKind.HAS_GRANT,
                     provenance="e-2", confidence=0.6, first_seen=5, last_seen=5))
    return wm


def test_round_trip_preserves_everything() -> None:
    wm = _sample()
    wm2 = from_json(to_json(wm))
    assert wm2.node_count == wm.node_count
    assert wm2.edge_count == wm.edge_count
    n = wm2.get_node("foothold")
    assert n.attrs == {"ip": "10.0.0.1"}
    assert n.last_seen == 3
    e = wm2.get_edge("foothold", "p1", EdgeKind.AUTHENTICATES_TO)
    assert e.confidence == 0.7
    assert e.attrs == {"method": "basic"}


def test_serialisation_is_deterministic() -> None:
    # Same graph built in a different insertion order -> identical bytes.
    wm_a = _sample()
    wm_b = WorldModel()
    wm_b.add_node(Node(id="db", kind=NodeKind.DATASTORE, provenance="obs-3",
                       confidence=0.9, first_seen=3, last_seen=3))
    wm_b.add_node(Node(id="foothold", kind=NodeKind.HOST, attrs={"ip": "10.0.0.1"},
                       provenance="obs-1", confidence=1.0, first_seen=1, last_seen=3))
    wm_b.add_node(Node(id="p1", kind=NodeKind.PRINCIPAL, provenance="obs-2",
                       confidence=0.8, first_seen=2, last_seen=2))
    wm_b.add_edge(Edge(src="p1", dst="db", kind=EdgeKind.HAS_GRANT,
                       provenance="e-2", confidence=0.6, first_seen=5, last_seen=5))
    wm_b.add_edge(Edge(src="foothold", dst="p1", kind=EdgeKind.AUTHENTICATES_TO,
                       provenance="e-1", confidence=0.7, first_seen=4, last_seen=4,
                       attrs={"method": "basic"}))
    assert to_json(wm_a) == to_json(wm_b)


def test_to_dict_shape() -> None:
    d = to_dict(_sample())
    assert d["schema_version"] == 1
    assert [n["id"] for n in d["nodes"]] == ["db", "foothold", "p1"]  # id-sorted
    assert len(d["edges"]) == 2


def test_save_and_load(tmp_path) -> None:
    wm = _sample()
    p = tmp_path / "sub" / "wm.json"
    save(wm, p)
    assert p.is_file()
    wm2 = load(p)
    assert wm2.edge_count == 2


def test_load_missing_file_errors(tmp_path) -> None:
    with pytest.raises(WorldModelError):
        load(tmp_path / "nope.json")


def test_from_json_rejects_bad_json() -> None:
    with pytest.raises(WorldModelError):
        from_json("{not json")


def test_from_json_rejects_wrong_schema_version() -> None:
    with pytest.raises(WorldModelError):
        from_json('{"schema_version": 999, "nodes": [], "edges": []}')


def test_from_json_rejects_edge_to_missing_node() -> None:
    # Edge references a dst node that is not in the document.
    doc = (
        '{"schema_version": 1, "nodes": ['
        '{"id": "a", "kind": "host", "attrs": {}, "provenance": "o",'
        ' "confidence": 1.0, "first_seen": 1, "last_seen": 1}], '
        '"edges": [{"src": "a", "dst": "ghost", "kind": "reachable_from",'
        ' "attrs": {}, "provenance": "e", "confidence": 1.0,'
        ' "first_seen": 1, "last_seen": 1}]}'
    )
    with pytest.raises(WorldModelError):
        from_json(doc)


def test_from_json_rejects_malformed_record() -> None:
    # confidence out of bounds -> validation error surfaced as WorldModelError
    doc = (
        '{"schema_version": 1, "nodes": ['
        '{"id": "a", "kind": "host", "attrs": {}, "provenance": "o",'
        ' "confidence": 5.0, "first_seen": 1, "last_seen": 1}], "edges": []}'
    )
    with pytest.raises(WorldModelError):
        from_json(doc)
