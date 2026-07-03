"""Tests for worldmodel.derivation — monotone forward-chaining to a fixpoint."""

from __future__ import annotations

import pytest

from ..derivation import (
    ASSUME_VIA_VALID_CREDENTIAL,
    DEFAULT_RULES,
    TRANSITIVE_REACHABILITY,
    EdgePattern,
    InteractionRule,
    NodeConstraint,
    derive,
)
from ..graph import WorldModel
from ..models import Edge, EdgeKind, Node, NodeKind

R = EdgeKind.REACHABLE_FROM
V = EdgeKind.VALID_ON
CA = EdgeKind.CAN_ASSUME


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


# -- transitive reachability -------------------------------------------------


def test_transitive_chain_derives_single_edge() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 0.9), ("b", "c", R, 0.5)],
    )
    res = derive(wm, [TRANSITIVE_REACHABILITY], seq=10)
    keys = {(e.src, e.dst) for e in res.derived}
    assert keys == {("a", "c")}                       # exactly one derived edge
    edge = wm.get_edge("a", "c", R)
    assert edge is not None
    assert edge.provenance == "derived:transitive_reachability"
    assert edge.confidence == pytest.approx(0.45)     # 0.9 * 0.5
    assert edge.first_seen == 10 and edge.last_seen == 10


def test_transitive_reaches_fixpoint_over_longer_chain() -> None:
    # a -> b -> c -> d ; closure adds a-c, a-d, b-d (3 new edges, no more)
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "d": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("c", "d", R, 1.0)],
    )
    res = derive(wm, [TRANSITIVE_REACHABILITY], seq=1)
    derived = {(e.src, e.dst) for e in res.derived}
    assert derived == {("a", "c"), ("a", "d"), ("b", "d")}


def test_derive_does_not_over_derive_or_touch_observed() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 0.9), ("b", "c", R, 0.5)],
    )
    before = wm.edge_count
    derive(wm, [TRANSITIVE_REACHABILITY], seq=1)
    assert wm.edge_count == before + 1                # only a->c added
    # Observed edges keep their original provenance/confidence.
    assert wm.get_edge("a", "b", R).provenance == "e-0"
    assert wm.get_edge("b", "c", R).confidence == 0.5


def test_no_self_loop_derived_on_cycle() -> None:
    # a <-> b cycle: closure must not assert reflexive a->a / b->b.
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST},
        [("a", "b", R, 0.9), ("b", "a", R, 0.9)],
    )
    res = derive(wm, [TRANSITIVE_REACHABILITY], seq=1)
    for e in res.derived:
        assert e.src != e.dst
    assert wm.get_edge("a", "a", R) is None
    assert wm.get_edge("b", "b", R) is None


def test_allow_self_loop_rule_permits_reflexive() -> None:
    rule = TRANSITIVE_REACHABILITY.model_copy(update={"allow_self_loop": True})
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST},
        [("a", "b", R, 0.9), ("b", "a", R, 0.9)],
    )
    derive(wm, [rule], seq=1)
    assert wm.get_edge("a", "a", R) is not None


# -- credential / assume rule + node constraints -----------------------------


def test_assume_via_valid_credential() -> None:
    wm = _wm(
        {"host": NodeKind.HOST, "svc": NodeKind.PRINCIPAL, "key": NodeKind.CREDENTIAL},
        [("host", "svc", R, 0.9), ("key", "svc", V, 0.8)],
    )
    res = derive(wm, [ASSUME_VIA_VALID_CREDENTIAL], seq=5)
    edge = wm.get_edge("host", "svc", CA)
    assert edge is not None
    assert edge.confidence == pytest.approx(0.72)     # 0.9 * 0.8
    assert edge.provenance == "derived:assume_via_valid_credential"
    assert [(e.src, e.dst) for e in res.derived] == [("host", "svc")]


def test_node_kind_constraint_blocks_wrong_kind() -> None:
    # 'svc' is reachable and has a VALID_ON edge, but it is a HOST, not a
    # PRINCIPAL, so the constraint must refuse to fire.
    wm = _wm(
        {"host": NodeKind.HOST, "svc": NodeKind.HOST, "key": NodeKind.CREDENTIAL},
        [("host", "svc", R, 0.9), ("key", "svc", V, 0.8)],
    )
    res = derive(wm, [ASSUME_VIA_VALID_CREDENTIAL], seq=1)
    assert res.derived == []
    assert wm.get_edge("host", "svc", CA) is None


def test_attr_constraint_matches_only_when_present() -> None:
    rule = InteractionRule(
        name="prod_only",
        premises=[EdgePattern(src="X", dst="Y", kind=R)],
        conclusion=EdgePattern(src="X", dst="Y", kind=CA),
        where={"Y": NodeConstraint(kind=NodeKind.PRINCIPAL, attrs={"env": "prod"})},
    )
    wm = WorldModel()
    wm.add_node(Node(id="h", kind=NodeKind.HOST, provenance="n", confidence=1.0,
                     first_seen=1, last_seen=1))
    wm.add_node(Node(id="p", kind=NodeKind.PRINCIPAL, attrs={"env": "prod"},
                     provenance="n", confidence=1.0, first_seen=1, last_seen=1))
    wm.add_node(Node(id="q", kind=NodeKind.PRINCIPAL, attrs={"env": "dev"},
                     provenance="n", confidence=1.0, first_seen=1, last_seen=1))
    wm.add_edge(Edge(src="h", dst="p", kind=R, provenance="e", confidence=1.0,
                     first_seen=1, last_seen=1))
    wm.add_edge(Edge(src="h", dst="q", kind=R, provenance="e", confidence=1.0,
                     first_seen=1, last_seen=1))
    derive(wm, [rule], seq=1)
    assert wm.get_edge("h", "p", CA) is not None       # prod matches
    assert wm.get_edge("h", "q", CA) is None            # dev filtered out


# -- fixpoint / determinism / guards -----------------------------------------


def test_iterations_prove_fixpoint_and_are_deterministic() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0)],
    )
    r1 = derive(wm, [TRANSITIVE_REACHABILITY], seq=1)
    # Re-running on the now-closed graph is a no-op fixpoint.
    r2 = derive(wm, [TRANSITIVE_REACHABILITY], seq=1)
    assert r2.iterations == 1                           # first round makes no change
    assert r1.iterations >= 2


def test_empty_run_reports_one_iteration_and_nothing() -> None:
    wm = _wm({"a": NodeKind.HOST, "b": NodeKind.HOST}, [])
    res = derive(wm, DEFAULT_RULES, seq=1)
    assert res.derived == []
    assert res.iterations == 1


def test_max_iters_caps_rounds() -> None:
    wm = _wm(
        {"a": NodeKind.HOST, "b": NodeKind.HOST, "c": NodeKind.HOST,
         "d": NodeKind.DATASTORE},
        [("a", "b", R, 1.0), ("b", "c", R, 1.0), ("c", "d", R, 1.0)],
    )
    res = derive(wm, [TRANSITIVE_REACHABILITY], seq=1, max_iters=1)
    assert res.iterations == 1                          # stopped early


def test_bad_args_rejected() -> None:
    wm = _wm({"a": NodeKind.HOST}, [])
    with pytest.raises(ValueError):
        derive(wm, [], seq=1, max_iters=0)
    with pytest.raises(ValueError):
        derive(wm, [], seq=-1)


def test_rule_with_unbound_conclusion_var_rejected() -> None:
    with pytest.raises(ValueError):
        InteractionRule(
            name="bad",
            premises=[EdgePattern(src="X", dst="Y", kind=R)],
            conclusion=EdgePattern(src="X", dst="Z", kind=R),   # Z unbound
        )
