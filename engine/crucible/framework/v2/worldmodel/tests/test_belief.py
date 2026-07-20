"""
Wave 8 — the Bayesian belief layer.

Alongside the scalar confidence (still reconciled by max, for back-compat), each
node/edge carries a Beta(alpha, beta) belief that accumulates corroboration and
refutation. Re-observing a FAILED fact LOWERS belief_mean — which max-confidence
can never express — and the risk-averse pathsearch weight prefers proven
(low-variance) routes over thinly-evidenced ones.
"""

from __future__ import annotations

from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind
from framework.v2.worldmodel.pathsearch import best_paths, default_weight, lcb_weight


def _node(nid: str, conf: float = 1.0, seq: int = 0) -> Node:
    return Node(id=nid, kind=NodeKind.HOST, provenance="test", confidence=conf,
                first_seen=seq, last_seen=seq)


def test_corroboration_raises_mean_and_shrinks_variance() -> None:
    w = WorldModel()
    w.add_node(_node("h", conf=0.8, seq=0))
    m1 = w.get_node("h").belief_mean
    sd1 = w.get_node("h").belief_sd
    w.add_node(_node("h", conf=0.9, seq=1))  # corroborated
    w.add_node(_node("h", conf=0.9, seq=2))  # corroborated again
    n = w.get_node("h")
    assert n.belief_mean > m1
    assert n.belief_sd < sd1  # more evidence -> tighter belief


def test_refutation_lowers_belief_even_though_confidence_cannot() -> None:
    w = WorldModel()
    w.add_node(_node("h", conf=0.9, seq=0))
    before = w.get_node("h").belief_mean
    w.add_node(_node("h", conf=0.0, seq=1))  # re-observed and FAILED
    after = w.get_node("h")
    assert after.belief_mean < before          # belief dropped
    assert after.confidence == 0.9             # but scalar confidence is unchanged (max)


def test_confidence_still_reconciles_by_max() -> None:
    w = WorldModel()
    w.add_node(_node("h", conf=0.5, seq=0))
    w.add_node(_node("h", conf=0.7, seq=1))
    w.add_node(_node("h", conf=0.6, seq=2))
    assert w.get_node("h").confidence == 0.7  # regression guard: unchanged behaviour


def _edge(src: str, dst: str, conf: float, alpha: float, beta: float) -> Edge:
    return Edge(src=src, dst=dst, kind=EdgeKind.REACHABLE_FROM, provenance="t",
                confidence=conf, alpha=alpha, beta=beta, first_seen=0, last_seen=0)


def test_lcb_weight_prefers_the_better_evidenced_of_equal_mean_routes() -> None:
    # two one-hop routes from src to two crown jewels, equal belief MEAN but
    # different variance: proven (many observations) vs thin (few).
    w = WorldModel()
    for nid in ("src", "proven", "thin"):
        w.add_node(Node(id=nid, kind=NodeKind.HOST, provenance="t", first_seen=0, last_seen=0))
    # proven: Beta(20,20) mean 0.5, tight. thin: Beta(1,1) mean 0.5, wide.
    w.add_edge(_edge("src", "proven", 0.5, 20.0, 20.0))
    w.add_edge(_edge("src", "thin", 0.5, 1.0, 1.0))

    paths = best_paths(w, "src", objective_kinds={NodeKind.HOST}, weight_fn=lcb_weight(1.0), k=2)
    dests = [p.edges[-1].dst for p in paths]
    assert dests and dests[0] == "proven"  # the better-evidenced route ranks first


def test_ranking_degrades_to_current_behaviour_under_certainty() -> None:
    # when everything is certain (confidence 1.0), the default confidence-weighted
    # ranking is exactly as before — belief is additive, not disruptive.
    w = WorldModel()
    for nid in ("src", "a", "b"):
        w.add_node(Node(id=nid, kind=NodeKind.HOST, provenance="t", confidence=1.0, first_seen=0, last_seen=0))
    w.add_edge(_edge("src", "a", 1.0, 1.0, 1.0))
    w.add_edge(_edge("src", "b", 1.0, 1.0, 1.0))
    paths = best_paths(w, "src", objective_kinds={NodeKind.HOST}, weight_fn=default_weight, k=2)
    assert len(paths) == 2  # both reachable, unchanged
