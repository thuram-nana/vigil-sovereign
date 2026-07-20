"""Tests for worldmodel.query — bounded simple-path enumeration."""

from __future__ import annotations

import pytest

from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind
from ..query import crown_jewel_paths, find_paths


def _wm(nodes: dict[str, NodeKind], edges: list[tuple[str, str, EdgeKind, float]]) -> WorldModel:
    wm = WorldModel()
    for nid, kind in nodes.items():
        wm.add_node(Node(id=nid, kind=kind, provenance=f"n-{nid}",
                         confidence=1.0, first_seen=1, last_seen=1))
    for i, (s, d, k, c) in enumerate(edges):
        wm.add_edge(Edge(src=s, dst=d, kind=k, provenance=f"e-{i}",
                         confidence=c, first_seen=1, last_seen=1))
    return wm


R = EdgeKind.REACHABLE_FROM
T = EdgeKind.TRUSTS_FOR


def test_find_paths_single_path() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
             [("a", "b", R, 0.9), ("b", "c", R, 0.5)])
    paths = find_paths(wm, "a", "c")
    assert len(paths) == 1
    p = paths[0]
    assert p.nodes == ["a", "b", "c"]
    assert p.min_confidence == 0.5
    assert p.provenance_chain == ["e-0", "e-1"]


def test_find_paths_multiple_sorted_shortest_first() -> None:
    # a->c direct, and a->b->c : two paths, shortest first
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("a", "c", R, 1.0)],
    )
    paths = find_paths(wm, "a", "c")
    assert len(paths) == 2
    assert paths[0].hops == 1        # direct first
    assert paths[1].hops == 2


def test_find_paths_no_path() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
             [("a", "b", R, 1.0)])   # nothing reaches c
    assert find_paths(wm, "a", "c") == []


def test_find_paths_respects_edge_kind_filter() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
             [("a", "b", R, 1.0), ("b", "c", T, 1.0)])
    assert find_paths(wm, "a", "c", [R]) == []            # blocked at T hop
    assert len(find_paths(wm, "a", "c", [R, T])) == 1


def test_find_paths_bounded_by_max_hops() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "d": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("c", "d", R, 1.0)],
    )
    assert find_paths(wm, "a", "d", max_hops=2) == []     # needs 3 hops
    assert len(find_paths(wm, "a", "d", max_hops=3)) == 1


def test_find_paths_cycle_does_not_hang_and_stays_simple() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "j": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("c", "a", R, 1.0),
         ("c", "j", R, 1.0)],
    )
    paths = find_paths(wm, "a", "j")
    assert len(paths) == 1
    # simple path: no node repeats
    assert paths[0].nodes == ["a", "b", "c", "j"]


def test_find_paths_self_source_dest_empty() -> None:
    wm = _wm({"a": NodeKind.HOST}, [])
    assert find_paths(wm, "a", "a") == []


def test_find_paths_unknown_endpoint_empty() -> None:
    wm = _wm({"a": NodeKind.HOST}, [])
    assert find_paths(wm, "a", "ghost") == []
    assert find_paths(wm, "ghost", "a") == []


def test_find_paths_zero_max_hops_rejected() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.DATASTORE}, [("a", "b", R, 1.0)])
    with pytest.raises(ValueError):
        find_paths(wm, "a", "b", max_hops=0)


def test_crown_jewel_paths_maps_all_datastores() -> None:
    wm = _wm(
        {"foothold": NodeKind.HOST, "mid": NodeKind.PRINCIPAL,
         "db1": NodeKind.DATASTORE, "db2": NodeKind.DATASTORE},
        [("foothold", "mid", R, 0.9), ("mid", "db1", R, 0.7)],
    )
    jewels = crown_jewel_paths(wm, "foothold")
    assert set(jewels) == {"db1", "db2"}
    assert len(jewels["db1"]) == 1              # reachable
    assert jewels["db1"][0].min_confidence == 0.7
    assert jewels["db2"] == []                  # present but unreachable
