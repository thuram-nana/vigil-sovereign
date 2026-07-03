"""
Attacker state — persistent, chainable (Wave 5, item A).

The world-model must hold what the attacker has ACHIEVED (owned assets, held
credentials, reached services) as typed facts that (1) survive persistence and
(2) enable follow-on derivation — the chaining a flat finding list cannot do.

The load-bearing test records a primitive's postcondition (credential obtained),
reloads the graph from `store`, shows the state survived, and shows it unlocks a
derived follow-on edge (attacker OWNS the target the credential is valid on).
"""

from __future__ import annotations

from framework.v2.worldmodel import store
from framework.v2.worldmodel.attacker import ATTACKER_ID, ATTACKER_RULES, AttackerState
from framework.v2.worldmodel.derivation import derive
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind


def _node(nid: str, kind: NodeKind) -> Node:
    return Node(id=nid, kind=kind, attrs={}, provenance="obs:1",
                confidence=0.9, first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind, conf: float) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, attrs={}, provenance="obs:1",
                confidence=conf, first_seen=1, last_seen=1)


def test_attacker_state_persists_and_unlocks_followon() -> None:
    w = WorldModel()
    # A credential C that is valid on target principal T.
    w.add_node(_node("T", NodeKind.PRINCIPAL))
    w.add_node(_node("C", NodeKind.CREDENTIAL))
    w.add_edge(_edge("C", "T", EdgeKind.VALID_ON, 0.8))

    # Record the postcondition of a confirmed primitive: the credential is held.
    atk = AttackerState(w)
    atk.hold("C", seq=2)
    assert atk.held() == ["C"]
    assert atk.owned() == [], "no OWNS yet — that must be derived, not asserted"

    # Persist and reload: the attacker state is graph-native, so it round-trips.
    reloaded = store.from_json(store.to_json(w))
    assert AttackerState(reloaded).held() == ["C"], "attacker state must survive persistence"

    # Derivation over the reloaded world unlocks the follow-on edge.
    derive(reloaded, ATTACKER_RULES, seq=3)
    assert AttackerState(reloaded).owned() == ["T"], (
        "held credential valid on T must derive attacker OWNS T"
    )

    # The follow-on is explainable and confidence-tracked, not asserted.
    owns = reloaded.get_edge(ATTACKER_ID, "T", EdgeKind.OWNS)
    assert owns is not None and owns.provenance.startswith("derived:")
    # confidence = product of HOLDS (1.0) and VALID_ON (0.8).
    assert abs(owns.confidence - 0.8) < 1e-9


def test_reach_follows_from_owned_host() -> None:
    w = WorldModel()
    w.add_node(_node("H", NodeKind.HOST))
    w.add_node(_node("S", NodeKind.SERVICE))
    # S is reachable from H.
    w.add_edge(_edge("H", "S", EdgeKind.REACHABLE_FROM, 0.9))

    atk = AttackerState(w)
    atk.own("H", seq=1)
    derive(w, ATTACKER_RULES, seq=2)

    assert "S" in AttackerState(w).reached(), "owning H must reach what's reachable from H"


def test_no_postcondition_no_derived_ownership() -> None:
    # Without the recorded 'held' postcondition, the same graph derives nothing —
    # the attacker state is what unlocks the chain, not the raw topology.
    w = WorldModel()
    w.add_node(_node("T", NodeKind.PRINCIPAL))
    w.add_node(_node("C", NodeKind.CREDENTIAL))
    w.add_edge(_edge("C", "T", EdgeKind.VALID_ON, 0.8))

    derive(w, ATTACKER_RULES, seq=1)
    # No attacker node, no HOLDS -> no OWNS.
    assert w.get_edge(ATTACKER_ID, "T", EdgeKind.OWNS) is None
