"""
Forward blast-radius predictor (`predict_action_blast_radius`) — the FORWARD sibling of
`what_if_remediate`. These tests pin the two properties M4.2 rests on:

  * CORRECTNESS: opening an edge that (directly or via a chain) reaches a crown jewel yields a HIGH
    incremental blast; a benign edge (dead-end, or to an already-reachable jewel, or to a node of a
    filtered edge-kind) yields ~0.
  * READ-ONLY: the predictor never mutates the world, and `before` is exactly `world.reachable`, so
    `after ⊇ before` and the incremental blast is always ≥ 0.

Every positive has a safe-negative control beside it — a benign-edge case measured the same way — so
the test cannot pass by always reporting a non-zero blast.
"""

from __future__ import annotations

from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.impact import (
    ForwardBlastResult,
    ImpactModel,
    _reachable_augmented,
    predict_action_blast_radius,
)
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind

_EK = EdgeKind.REACHABLE_FROM


def _n(world: WorldModel, nid: str, kind: NodeKind) -> None:
    world.add_node(Node(id=nid, kind=kind, provenance="test", confidence=1.0,
                        first_seen=1, last_seen=1))


def _e(world: WorldModel, src: str, dst: str) -> tuple[str, str, str]:
    return world.add_edge(Edge(src=src, dst=dst, kind=_EK, provenance="test",
                               confidence=1.0, first_seen=1, last_seen=1)).key


def _world() -> WorldModel:
    """attacker reaches ONLY datastore:public directly. The high-value crown jewel sits behind gw
    (gw -> crown), with NO attacker -> gw edge, so crown is unreachable until an action opens one.
    crown2 has no real inbound at all (reached only by a chain of opened edges); island/relay/ghost
    are dead-ends for the safe-negative controls."""
    w = WorldModel()
    for nid, k in [
        ("host:attacker", NodeKind.HOST), ("host:gw", NodeKind.HOST),
        ("host:island", NodeKind.HOST), ("host:relay", NodeKind.HOST),
        ("datastore:crown", NodeKind.DATASTORE), ("datastore:public", NodeKind.DATASTORE),
        ("datastore:crown2", NodeKind.DATASTORE),
    ]:
        _n(w, nid, k)
    _e(w, "host:gw", "datastore:crown")          # gw reaches the crown jewel ...
    _e(w, "host:attacker", "datastore:public")   # ... but the attacker only reaches public today
    return w


def _impact() -> ImpactModel:
    return ImpactModel(nodes={"datastore:crown": 100.0, "datastore:public": 1.0,
                              "datastore:crown2": 50.0}, default=1.0)


_OBJ = [NodeKind.DATASTORE]


# --- correctness: a high-impact open vs its safe-negative controls -----------------------------

def test_opening_edge_to_gateway_opens_the_crown_jewel() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "host:gw")], _OBJ, edge_kinds=[_EK], impact=m)
    assert isinstance(r, ForwardBlastResult)
    assert r.newly_reachable_jewels == ["datastore:crown"]     # reached via the opened hop + real gw->crown
    assert r.incremental_blast == 100.0
    assert r.already_reachable_jewels == ["datastore:public"]  # the baseline is carried separately
    assert r.baseline_blast == 1.0
    assert r.action_src == "host:attacker"
    assert r.opened_edges == ["host:attacker --> host:gw"]


def test_benign_dead_end_edge_opens_nothing() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "host:island")], _OBJ, edge_kinds=[_EK], impact=m)
    assert r.newly_reachable_jewels == []
    assert r.incremental_blast == 0.0
    assert r.baseline_blast == 1.0   # the baseline is unchanged


def test_edge_to_an_already_reachable_jewel_is_zero_incremental() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "datastore:public")], _OBJ, edge_kinds=[_EK], impact=m)
    assert r.newly_reachable_jewels == []       # public was already reachable — not INCREMENTAL
    assert r.incremental_blast == 0.0


def test_opened_edges_chain_through_a_hypothetical_intermediate() -> None:
    """Two opened edges form a chain (attacker -> relay -> crown2); the augmented BFS must follow an
    opened edge out of a node reached only by another opened edge."""
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker",
        [("host:attacker", "host:relay"), ("host:relay", "datastore:crown2")],
        _OBJ, edge_kinds=[_EK], impact=m)
    assert r.newly_reachable_jewels == ["datastore:crown2"]
    assert r.incremental_blast == 50.0


def test_opened_edge_to_an_unknown_node_is_a_dead_end() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "host:ghost")], _OBJ, edge_kinds=[_EK], impact=m)
    assert r.newly_reachable_jewels == []    # ghost is not in the graph and has no out-edges
    assert r.incremental_blast == 0.0


def test_no_opened_edges_is_a_zero_blast_noop() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(w, "host:attacker", [], _OBJ, edge_kinds=[_EK], impact=m)
    assert r.opened_edges == []
    assert r.newly_reachable_jewels == []
    assert r.incremental_blast == 0.0
    assert r.already_reachable_jewels == ["datastore:public"]


# --- the impact model is honoured --------------------------------------------------------------

def test_uniform_impact_counts_each_opened_jewel_as_one() -> None:
    w = _world()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "host:gw")], _OBJ, edge_kinds=[_EK])  # default uniform
    assert r.newly_reachable_jewels == ["datastore:crown"]
    assert r.incremental_blast == 1.0      # uniform: the crown is worth 1.0, not 100.0


def test_incremental_blast_sums_multiple_opened_jewels() -> None:
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker",
        [("host:attacker", "host:gw"), ("host:attacker", "datastore:crown2")],
        _OBJ, edge_kinds=[_EK], impact=m)
    assert r.newly_reachable_jewels == ["datastore:crown", "datastore:crown2"]
    assert r.incremental_blast == 150.0    # 100 (crown via gw) + 50 (crown2 direct)


# --- edge-kind scoping applies to the REAL edges reached from an opened hop ---------------------

def test_edge_kind_filter_scopes_the_real_downstream_hops() -> None:
    """Opening attacker -> gw cannot reach the crown when the traversal is scoped to an edge-kind the
    real gw -> crown edge does not carry: the opened hop is followed, but the real downstream edge is
    filtered out, so no jewel opens. This proves the filter is actually applied to the real graph."""
    w, m = _world(), _impact()
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "host:gw")], _OBJ,
        edge_kinds=[EdgeKind.CAN_ASSUME], impact=m)   # no CAN_ASSUME edges exist
    assert r.newly_reachable_jewels == []
    assert r.incremental_blast == 0.0


# --- read-only + the before/after invariant ----------------------------------------------------

def test_predictor_never_mutates_the_world() -> None:
    w, m = _world(), _impact()
    nodes_before, edges_before = w.node_count, w.edge_count
    predict_action_blast_radius(
        w, "host:attacker",
        [("host:attacker", "host:gw"), ("host:relay", "datastore:crown2")],
        _OBJ, edge_kinds=[_EK], impact=m)
    assert (w.node_count, w.edge_count) == (nodes_before, edges_before)


def test_before_equals_world_reachable_and_opening_only_grows_it() -> None:
    """Fidelity + monotonicity: with no opened edges the augmented BFS is exactly `world.reachable`,
    and adding opened edges can only ENLARGE the reachable set — so the incremental blast is ≥ 0."""
    w = _world()
    base = _reachable_augmented(w, "host:attacker", [_EK], {})
    assert base == w.reachable("host:attacker", [_EK])
    grown = _reachable_augmented(w, "host:attacker", [_EK], {"host:attacker": ["host:gw"]})
    assert base <= grown and "datastore:crown" in grown and "datastore:crown" not in base


def test_incremental_blast_is_never_negative_even_for_a_redundant_open() -> None:
    w, m = _world(), _impact()
    # opening an edge that leads only to already-reachable territory
    r = predict_action_blast_radius(
        w, "host:attacker", [("host:attacker", "datastore:public")], _OBJ, edge_kinds=[_EK], impact=m)
    assert r.incremental_blast >= 0.0 and r.incremental_blast == 0.0
