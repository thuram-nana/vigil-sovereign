"""Tests for knowledge.operators — evaluation and effect assertion."""

from __future__ import annotations

import pytest

from ...worldmodel.graph import WorldModel
from ...worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ..models import (
    AttrOp,
    Direction,
    Effect,
    EffectKind,
    Operator,
    Predicate,
    PredicateKind,
)
from ..operators import (
    OperatorError,
    applicable,
    apply,
    derive,
    match,
)


def _node(wm: WorldModel, nid: str, kind: NodeKind, **attrs: object) -> Node:
    return wm.add_node(Node(id=nid, kind=kind, attrs=dict(attrs),
                            provenance=f"obs-{nid}", confidence=1.0,
                            first_seen=1, last_seen=1))


def _edge(wm: WorldModel, s: str, d: str, k: EdgeKind, **attrs: object) -> Edge:
    return wm.add_edge(Edge(src=s, dst=d, kind=k, attrs=dict(attrs),
                            provenance=f"obs-{s}-{d}", confidence=1.0,
                            first_seen=1, last_seen=1))


# -- attr op semantics ------------------------------------------------------


def test_falsy_matches_missing_and_false() -> None:
    wm = WorldModel()
    ep_unset = _node(wm, "ep1", NodeKind.ENDPOINT)
    ep_false = _node(wm, "ep2", NodeKind.ENDPOINT, auth=False)
    ep_true = _node(wm, "ep3", NodeKind.ENDPOINT, auth=True)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[Predicate(kind=PredicateKind.NODE_ATTR, attr="auth", op=AttrOp.FALSY)],
        effects=[Effect(kind=EffectKind.SET_ATTR, attr="hit", value=True)],
    )
    assert applicable(op, wm, ep_unset) is True
    assert applicable(op, wm, ep_false) is True
    assert applicable(op, wm, ep_true) is False


def test_eq_on_missing_attr_fails_closed() -> None:
    wm = WorldModel()
    ep = _node(wm, "ep", NodeKind.ENDPOINT)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[Predicate(kind=PredicateKind.NODE_ATTR, attr="auth",
                                 op=AttrOp.EQ, value=False)],
        effects=[Effect(kind=EffectKind.SET_ATTR, attr="hit", value=True)],
    )
    assert applicable(op, wm, ep) is False


# -- applicable gates on world state ---------------------------------------


def test_applicable_gates_on_incident_edge() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    _node(wm, "p", NodeKind.PRINCIPAL)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[
            Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                      direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                      capture_as="principal"),
        ],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                        src_role="actor", dst_role="principal")],
    )
    # no VALID_ON edge yet -> not applicable
    assert applicable(op, wm, cred) is False
    _edge(wm, "cred", "p", EdgeKind.VALID_ON)
    assert applicable(op, wm, cred) is True


def test_incident_edge_direction_and_kind_filter() -> None:
    wm = WorldModel()
    host = _node(wm, "h", NodeKind.HOST)
    ep = _node(wm, "ep", NodeKind.ENDPOINT)
    # host -> ep REACHABLE_FROM : this is an *incoming* edge to ep from a HOST
    _edge(wm, "h", "ep", EdgeKind.REACHABLE_FROM)
    p_in = Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                     direction=Direction.IN, other_kind=NodeKind.HOST, capture_as="host")
    p_out = Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                      direction=Direction.OUT, other_kind=NodeKind.HOST)
    caps: dict[str, str] = {}
    from ..operators import _predicate_ok  # internal, but worth asserting directly
    assert _predicate_ok(wm, ep, p_in, caps) is True
    assert caps["host"] == "h"
    assert _predicate_ok(wm, ep, p_out, {}) is False
    assert host.id == "h"


# -- match captures roles ---------------------------------------------------


def test_match_captures_and_seeds() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    _node(wm, "victim", NodeKind.PRINCIPAL)
    _node(wm, "attacker", NodeKind.PRINCIPAL)
    _edge(wm, "cred", "victim", EdgeKind.VALID_ON)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[
            Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                      direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                      capture_as="principal"),
        ],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                        src_role="actor", dst_role="principal")],
    )
    binding = match(op, wm, cred, seed={"actor": "attacker"})
    assert binding == {"focus": "cred", "principal": "victim", "actor": "attacker"}


def test_match_rejects_phantom_seed() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    _node(wm, "victim", NodeKind.PRINCIPAL)
    _edge(wm, "cred", "victim", EdgeKind.VALID_ON)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                                 direction=Direction.OUT, capture_as="principal")],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                        src_role="actor", dst_role="principal")],
    )
    with pytest.raises(OperatorError):
        match(op, wm, cred, seed={"actor": "ghost"})


def test_match_returns_none_when_not_applicable() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.PRINCIPAL)],
        effects=[Effect(kind=EffectKind.SET_ATTR, attr="hit", value=True)],
    )
    assert match(op, wm, cred) is None


# -- apply asserts effects with operator provenance ------------------------


def test_apply_asserts_edge_with_provenance_and_metadata() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    _node(wm, "victim", NodeKind.PRINCIPAL)
    _node(wm, "attacker", NodeKind.PRINCIPAL)
    _edge(wm, "cred", "victim", EdgeKind.VALID_ON)
    op = Operator(
        id="credential-reuse", name="t", technique_ref=["T1078", "CWE-522"],
        detection_signals=["reused secret"],
        preconditions=[
            Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.CREDENTIAL),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                      direction=Direction.OUT, other_kind=NodeKind.PRINCIPAL,
                      capture_as="principal"),
        ],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                        src_role="actor", dst_role="principal", confidence=0.75,
                        edge_attrs={"via": "reuse"})],
    )
    binding = match(op, wm, cred, seed={"actor": "attacker"})
    applied = apply(op, wm, binding, seq=10)
    assert len(applied) == 1
    edge = wm.get_edge("attacker", "victim", EdgeKind.CAN_ASSUME)
    assert edge is not None
    assert edge.provenance == "operator:credential-reuse"
    assert edge.confidence == 0.75
    assert edge.first_seen == 10 and edge.last_seen == 10
    assert edge.attrs["via"] == "reuse"
    assert edge.attrs["technique"] == "credential-reuse"
    assert edge.attrs["technique_ref"] == ["T1078", "CWE-522"]
    assert edge.attrs["detection_signals"] == ["reused secret"]


def test_apply_set_attr_effect_merges_on_existing_node() -> None:
    wm = WorldModel()
    host = _node(wm, "h", NodeKind.HOST, os="linux")
    op = Operator(
        id="rce", name="t", technique_ref=["CWE-502"],
        preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST)],
        effects=[Effect(kind=EffectKind.SET_ATTR, target_role="focus",
                        attr="code_exec", value=True, confidence=0.7)],
    )
    apply(op, wm, {"focus": host.id}, seq=5)
    stored = wm.get_node("h")
    assert stored.attrs == {"os": "linux", "code_exec": True}  # merged, not replaced
    # observation confidence 1.0 outranks the effect's 0.7, so the world-model
    # keeps the stronger provenance — the attr is learned, belief is not lowered
    assert stored.provenance == "obs-h"


def test_apply_unbound_role_raises() -> None:
    wm = WorldModel()
    cred = _node(wm, "cred", NodeKind.CREDENTIAL)
    _node(wm, "victim", NodeKind.PRINCIPAL)
    _edge(wm, "cred", "victim", EdgeKind.VALID_ON)
    op = Operator(
        id="t", name="t", technique_ref=["X"],
        preconditions=[Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.VALID_ON,
                                 direction=Direction.OUT, capture_as="principal")],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.CAN_ASSUME,
                        src_role="actor", dst_role="principal")],
    )
    binding = match(op, wm, cred)  # no actor seeded
    with pytest.raises(OperatorError):
        apply(op, wm, binding, seq=1)


def test_apply_is_idempotent_upsert() -> None:
    wm = WorldModel()
    host = _node(wm, "h", NodeKind.HOST)
    op = Operator(
        id="rce", name="t", technique_ref=["CWE-502"],
        preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST)],
        effects=[Effect(kind=EffectKind.SET_ATTR, attr="code_exec", value=True)],
    )
    derive(op, wm, host, seq=1)
    derive(op, wm, host, seq=2)
    assert wm.get_node("h").attrs["code_exec"] is True
    assert wm.node_count == 1
