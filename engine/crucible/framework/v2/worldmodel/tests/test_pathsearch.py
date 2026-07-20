"""Tests for worldmodel.pathsearch — ranked, explainable attack paths."""

from __future__ import annotations

import math

import pytest

from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind
from ..pathsearch import (
    ChokePoint,
    best_paths,
    choke_points,
    default_weight,
    shortest_paths,
)

R = EdgeKind.REACHABLE_FROM
T = EdgeKind.TRUSTS_FOR


def _wm(
    nodes: dict[str, NodeKind],
    edges: list[tuple[str, str, EdgeKind, float]],
) -> WorldModel:
    wm = WorldModel()
    for nid, kind in nodes.items():
        wm.add_node(
            Node(id=nid, kind=kind, provenance=f"n-{nid}", confidence=1.0,
                 first_seen=1, last_seen=1)
        )
    for i, (s, d, k, c) in enumerate(edges):
        wm.add_edge(
            Edge(src=s, dst=d, kind=k, provenance=f"e-{i}", confidence=c,
                 first_seen=1, last_seen=1)
        )
    return wm


# -- shortest_paths (Yen) ----------------------------------------------------


def test_shortest_paths_single() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 0.9), ("b", "c", R, 0.5)],
    )
    paths = shortest_paths(wm, "a", "c")
    assert len(paths) == 1
    assert paths[0].nodes == ["a", "b", "c"]


def test_shortest_paths_k_ordered_and_distinct() -> None:
    # a->d direct (1 hop); a->b->d and a->c->d (2 hops each).
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "d": NodeKind.DATASTORE},
        [("a", "d", R, 1.0), ("a", "b", R, 1.0), ("b", "d", R, 1.0),
         ("a", "c", R, 1.0), ("c", "d", R, 1.0)],
    )
    paths = shortest_paths(wm, "a", "d", k=5)
    assert len(paths) == 3                              # exactly 3 simple paths
    hops = [p.hops for p in paths]
    assert hops == sorted(hops)                         # ascending by length
    assert hops[0] == 1                                 # direct route first
    sigs = {tuple(p.nodes) for p in paths}
    assert len(sigs) == 3                               # all distinct


def test_shortest_paths_respects_edge_kind_filter() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", T, 1.0)],
    )
    assert shortest_paths(wm, "a", "c", edge_kinds=[R]) == []
    assert len(shortest_paths(wm, "a", "c", edge_kinds=[R, T])) == 1


def test_shortest_paths_no_path_and_self() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.DATASTORE}, [])
    assert shortest_paths(wm, "a", "b") == []
    assert shortest_paths(wm, "a", "a") == []
    assert shortest_paths(wm, "a", "ghost") == []


def test_shortest_paths_cycle_stays_simple() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "j": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("c", "a", R, 1.0),
         ("c", "j", R, 1.0)],
    )
    paths = shortest_paths(wm, "a", "j", k=5)
    assert len(paths) == 1
    assert paths[0].nodes == ["a", "b", "c", "j"]       # no node repeats


def test_shortest_paths_bad_k() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.DATASTORE}, [("a", "b", R, 1.0)])
    with pytest.raises(ValueError):
        shortest_paths(wm, "a", "b", k=0)


# -- best_paths (confidence-ranked) ------------------------------------------


def test_best_paths_picks_highest_confidence_route() -> None:
    # Two routes a->jewel: high-confidence 2-hop beats a low-confidence
    # 1-hop, because default weight ranks by product of confidence.
    wm = _wm(
        {"a": NodeKind.HOST, "m": NodeKind.HOST, "jewel": NodeKind.DATASTORE},
        [("a", "jewel", R, 0.2),                        # direct but weak
         ("a", "m", R, 0.99), ("m", "jewel", R, 0.99)], # longer but strong
    )
    paths = best_paths(wm, "a", [NodeKind.DATASTORE], k=2)
    assert len(paths) == 2
    assert paths[0].nodes == ["a", "m", "jewel"]        # strong route wins
    assert paths[0].min_confidence == pytest.approx(0.99)
    assert paths[1].nodes == ["a", "jewel"]


def test_best_paths_reaches_any_objective_kind() -> None:
    # Two crown jewels of different kinds; best_paths ranks routes to either.
    wm = _wm(
        {"a": NodeKind.HOST, "db": NodeKind.DATASTORE, "cr": NodeKind.CLOUD_RESOURCE},
        [("a", "db", R, 0.5), ("a", "cr", R, 0.9)],
    )
    paths = best_paths(wm, "a", [NodeKind.DATASTORE, NodeKind.CLOUD_RESOURCE], k=2)
    assert [p.nodes[-1] for p in paths] == ["cr", "db"]  # higher-conf first


def test_best_paths_provenance_chain_is_auditable() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "m": NodeKind.HOST, "j": NodeKind.DATASTORE},
        [("a", "m", R, 0.8), ("m", "j", R, 0.7)],
    )
    p = best_paths(wm, "a", [NodeKind.DATASTORE])[0]
    assert p.provenance_chain == ["e-0", "e-1"]
    assert p.min_confidence == pytest.approx(0.7)


def test_best_paths_custom_weight_fn() -> None:
    # Weight = hop count -> shortest wins regardless of confidence.
    wm = _wm(
        {"a": NodeKind.HOST, "m": NodeKind.HOST, "j": NodeKind.DATASTORE},
        [("a", "j", R, 0.2), ("a", "m", R, 0.99), ("m", "j", R, 0.99)],
    )
    p = best_paths(wm, "a", [NodeKind.DATASTORE], weight_fn=lambda e: 1.0)[0]
    assert p.nodes == ["a", "j"]                        # fewest hops now wins


def test_best_paths_no_objective_or_unreachable() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.HOST}, [("a", "b", R, 1.0)])
    assert best_paths(wm, "a", [NodeKind.DATASTORE]) == []   # no jewels at all
    wm2 = _wm({"a": NodeKind.HOST, "j": NodeKind.DATASTORE}, [])
    assert best_paths(wm2, "a", [NodeKind.DATASTORE]) == []  # jewel unreachable


def test_default_weight_matches_neg_log() -> None:
    e = Edge(src="a", dst="b", kind=R, provenance="p", confidence=0.5,
             first_seen=1, last_seen=1)
    assert default_weight(e) == pytest.approx(-math.log(0.5))
    z = e.model_copy(update={"confidence": 0.0})
    assert default_weight(z) == math.inf


# -- choke_points ------------------------------------------------------------


def test_choke_points_finds_true_bottleneck() -> None:
    # Diamond that funnels through a single edge g->j:
    #   a -> b -> g -> j
    #   a -> c -> g -> j
    # g->j is the only edge into the jewel: its removal disconnects it.
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "g": NodeKind.HOST, "j": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("a", "c", R, 1.0),
         ("b", "g", R, 1.0), ("c", "g", R, 1.0), ("g", "j", R, 1.0)],
    )
    chokes = choke_points(wm, "a", [NodeKind.DATASTORE])
    assert isinstance(chokes[0], ChokePoint)
    top = chokes[0]
    assert (top.edge.src, top.edge.dst) == ("g", "j")   # the true cut
    assert top.is_bridge is True
    assert top.disconnects == ["j"]


def test_choke_points_ranks_bridge_above_non_bridge() -> None:
    # a->b (bridge, sole route to left jewel j1) and a parallel-redundant
    # region to j2. The bridge must rank first.
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST,
         "x": NodeKind.HOST, "y": NodeKind.HOST,
         "j1": NodeKind.DATASTORE, "j2": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "j1", R, 1.0),
         ("a", "x", R, 1.0), ("a", "y", R, 1.0),
         ("x", "j2", R, 1.0), ("y", "j2", R, 1.0)],
    )
    chokes = choke_points(wm, "a", [NodeKind.DATASTORE])
    assert chokes[0].is_bridge is True
    assert "j1" in chokes[0].disconnects
    # j2 has two disjoint routes -> no single edge is its bridge.
    for c in chokes:
        assert "j2" not in c.disconnects


def test_choke_points_no_reachable_objective() -> None:
    wm = _wm({"a": NodeKind.HOST, "j": NodeKind.DATASTORE}, [])
    assert choke_points(wm, "a", [NodeKind.DATASTORE]) == []


def test_choke_points_betweenness_counts_shared_edge() -> None:
    # Both routes to j share the a->g edge -> betweenness 2 on it.
    wm = _wm(
        {"a": NodeKind.HOST, "g": NodeKind.HOST, "p": NodeKind.HOST,
         "q": NodeKind.HOST, "j": NodeKind.DATASTORE},
        [("a", "g", R, 1.0), ("g", "p", R, 1.0), ("g", "q", R, 1.0),
         ("p", "j", R, 1.0), ("q", "j", R, 1.0)],
    )
    chokes = choke_points(wm, "a", [NodeKind.DATASTORE], k=5)
    by_key = {(c.edge.src, c.edge.dst): c for c in chokes}
    assert by_key[("a", "g")].betweenness == 2          # on both routes
    assert by_key[("a", "g")].is_bridge is True         # sole exit from a
