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


# ===========================================================================
# M2.1 — the WORKLIST/DELTA saturate must be BYTE-IDENTICAL to the full rescan.
#
# saturate() is a worklist rewrite of the (retained) full-rescan reference
# _saturate_full(). The contract is pure perf: the SAME saturated graph (every
# node/edge field, incl. first_seen/last_seen and the Beta belief alpha/beta),
# the SAME seen closure, and the SAME returned derivations in the SAME order —
# while making STRICTLY FEWER derive() calls. These tests differential-diff the
# two over fixture AND random graphs, exercise the multi-hop under-saturation
# trap explicitly, and prove the derive-count win with a counting control.
# ===========================================================================

import random as _random

from .. import operators as _opmod
from ..catalog import CATALOG
from ..catalog_ext import EXTENDED_CATALOG
from ..operators import _saturate_full, saturate


def _seen_of(wm: WorldModel) -> set:
    """Reconstruct saturate's `seen` closure from a graph: one signature per
    edge (src,dst,kind) and node (id, sorted-attr-names) — the exact shape
    _signature() produces."""
    s: set = set()
    for e in wm.all_edges():
        s.add(("E", e.src, e.dst, e.kind.value))
    for n in wm.all_nodes():
        s.add(("N", n.id, ",".join(sorted(n.attrs))))
    return s


def _applied_norm(applied: list) -> list:
    # Applied is a light record; compare its operator id + the stored (pydantic)
    # edge/node, which deep-compare EVERY field — attrs, confidence, alpha/beta,
    # first_seen/last_seen, provenance, grounding.
    return [(a.operator_id, a.edge, a.node) for a in applied]


def _assert_identical(build, ops, *, seeds=None, seq_start=1000, max_rounds=16):
    """Run _saturate_full and saturate on two freshly-built copies of the SAME
    world; assert the saturated graph + returned derivations are byte-identical.
    Returns (full_world, full_applied) for callers that assert on the closure."""
    w_full = build()
    w_wl = build()
    # the two inputs must start identical (guards the builder itself)
    assert w_full.all_nodes() == w_wl.all_nodes()
    assert w_full.all_edges() == w_wl.all_edges()

    a_full = _saturate_full(ops, w_full, seq_start, seeds=seeds, max_rounds=max_rounds)
    a_wl = saturate(ops, w_wl, seq_start, seeds=seeds, max_rounds=max_rounds)

    # the saturated graph — every node/edge field, incl. Beta belief + seq windows
    assert w_wl.all_nodes() == w_full.all_nodes()
    assert w_wl.all_edges() == w_full.all_edges()
    # the seen closure
    assert _seen_of(w_wl) == _seen_of(w_full)
    # the returned derivation record — same facts, same order, same first-fire snapshot
    assert _applied_norm(a_wl) == _applied_norm(a_full)
    return w_full, a_full


def _count_derivations(fn, build, ops, *, seeds=None, seq_start=1000, monkeypatch=None):
    """Run `fn` (saturate or _saturate_full) and return (#derive-calls, world).
    Patches the module-global `derive` both functions call, so the count is the
    number of (op,node) match attempts — the 'derivation count' the win is in."""
    real = _opmod.derive
    n = [0]

    def counting(*a, **k):
        n[0] += 1
        return real(*a, **k)

    monkeypatch.setattr(_opmod, "derive", counting)
    try:
        w = build()
        n[0] = 0
        fn(ops, w, seq_start, seeds=seeds)
        return n[0], w
    finally:
        monkeypatch.setattr(_opmod, "derive", real)


# -- fixture 1: the REAL catalog, a rich multi-round / multi-hop closure --------


def _real_catalog_world() -> WorldModel:
    wm = WorldModel()

    def N(i, k, **a):
        wm.add_node(Node(id=i, kind=k, attrs=dict(a), provenance=f"obs-{i}",
                         confidence=1.0, first_seen=1, last_seen=1))

    def E(s, d, k, **a):
        wm.add_edge(Edge(src=s, dst=d, kind=k, attrs=dict(a), provenance=f"obs-{s}-{d}",
                         confidence=1.0, first_seen=1, last_seen=1))

    N("attacker", NodeKind.PRINCIPAL)
    N("ep_idor", NodeKind.ENDPOINT, auth=False)
    N("ds_main", NodeKind.DATASTORE)
    N("cred_in_ds", NodeKind.CREDENTIAL)
    N("ep_ssrf", NodeKind.ENDPOINT, fetches_url=True)
    N("cr_internal", NodeKind.CLOUD_RESOURCE, internal=True)
    N("cred_leak", NodeKind.CREDENTIAL, exposed=True)
    N("p_victim", NodeKind.PRINCIPAL)
    N("res_jewel", NodeKind.CLOUD_RESOURCE)
    N("ep_deser", NodeKind.ENDPOINT, deserializes_untrusted=True)
    N("h_a", NodeKind.HOST)
    N("h_b", NodeKind.HOST)
    N("h_c", NodeKind.HOST)
    N("s_replay", NodeKind.SESSION, client_bound=False, expired=False)
    N("wa_main", NodeKind.WEBAPP)
    N("s_leak", NodeKind.SESSION, leaked=True)
    N("wa_theft", NodeKind.WEBAPP)

    E("ep_idor", "ds_main", EdgeKind.TRUSTS_FOR)            # unauth-endpoint-read
    E("ds_main", "cred_in_ds", EdgeKind.REACHABLE_FROM)     # datastore-secret-extraction (OUT->cred)
    E("cred_in_ds", "p_victim", EdgeKind.VALID_ON)          # credential-reuse
    E("cred_leak", "p_victim", EdgeKind.VALID_ON)           # credential-reuse / -leak-capture
    E("h_a", "ep_deser", EdgeKind.REACHABLE_FROM)           # deserialization (host runs the ep)
    E("h_a", "h_b", EdgeKind.REACHABLE_FROM)                # lateral-pivot h_a -> h_b
    E("h_b", "h_c", EdgeKind.REACHABLE_FROM)                # lateral-pivot h_b -> h_c
    E("s_replay", "wa_main", EdgeKind.SESSION_ON)           # token-replay
    E("s_leak", "wa_theft", EdgeKind.SESSION_ON)            # session-theft-takeover
    return wm


def test_saturate_worklist_matches_full_on_real_catalog() -> None:
    ops = [*CATALOG, *EXTENDED_CATALOG]
    seeds = {op.id: {"actor": "attacker", "resource": "res_jewel"} for op in ops}
    w_full, a_full = _assert_identical(_real_catalog_world, ops, seeds=seeds)

    # non-vacuous: the deep chains actually fired (so the multi-round / multi-hop /
    # SET_ATTR / GRAPH_HAS_NODE-attr paths are genuinely exercised).
    assert w_full.get_edge("attacker", "h_c", EdgeKind.OWNS) is not None     # 2-hop pivot
    assert w_full.get_edge("attacker", "res_jewel", EdgeKind.HAS_GRANT) is not None  # cred->role
    assert w_full.get_edge("ep_ssrf", "cr_internal", EdgeKind.REACHABLE_FROM) is not None  # ssrf (graph_has_node attr)
    assert w_full.get_edge("attacker", "wa_theft", EdgeKind.AUTHENTICATES_TO) is not None  # token leak->theft
    assert w_full.get_node("h_a").attrs.get("code_exec") is True            # SET_ATTR fired
    assert len(a_full) > 8


# -- fixture 2: SET_ATTR reverse-order chain (a node touched early, a late
#    derivation that transitively depends on it) ---------------------------------


def _attr_chain_ops() -> list:
    H = NodeKind.HOST

    def step(i):
        return Operator(
            id=f"step{i}", name=f"step{i}", technique_ref=["X"],
            preconditions=[
                Predicate(kind=PredicateKind.NODE_KIND, node_kind=H),
                Predicate(kind=PredicateKind.NODE_ATTR, attr=f"step{i - 1}", op=AttrOp.TRUTHY),
            ],
            effects=[Effect(kind=EffectKind.SET_ATTR, attr=f"step{i}", value=True)],
        )

    # REVERSE of the dependency order -> one new attr per round (forces >=3 rounds),
    # and step3 (last round) depends on step1 (first round) on n0 touched early.
    return [step(3), step(2), step(1)]


def _attr_chain_world() -> WorldModel:
    wm = WorldModel()
    wm.add_node(Node(id="n0", kind=NodeKind.HOST, attrs={"step0": True},
                     provenance="obs-n0", confidence=1.0, first_seen=1, last_seen=1))
    return wm


def test_saturate_worklist_matches_full_attr_chain_trap() -> None:
    ops = _attr_chain_ops()
    w_full, a_full = _assert_identical(_attr_chain_world, ops)
    # the chain fully propagated across rounds
    attrs = w_full.get_node("n0").attrs
    assert attrs == {"step0": True, "step1": True, "step2": True, "step3": True}
    # three NEW node-attr signatures. first_seen is pinned to the node's original
    # window (min => 1), so the multi-round proof is in last_seen: each hop's
    # first-fire snapshot carries a STRICTLY LATER seq than the one before it.
    nodes = [a.node for a in a_full if a.node is not None]
    assert len(nodes) == 3
    ls = [n.last_seen for n in nodes]
    assert ls[0] < ls[1] < ls[2]


# -- fixture 3: EDGE-based reverse-order multi-hop pivot trap --------------------


def _pivot_trap_ops() -> list:
    return [Operator(
        id="pivot", name="pivot", technique_ref=["X"],
        preconditions=[
            Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.OWNS,
                      direction=Direction.IN, other_kind=NodeKind.PRINCIPAL, capture_as="owner"),
            Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=EdgeKind.REACHABLE_FROM,
                      direction=Direction.OUT, other_kind=NodeKind.HOST, capture_as="peer"),
        ],
        effects=[Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=EdgeKind.OWNS,
                        src_role="owner", dst_role="peer")],
    )]


def _pivot_trap_world() -> WorldModel:
    wm = WorldModel()

    def N(i, k):
        wm.add_node(Node(id=i, kind=k, provenance=f"obs-{i}", confidence=1.0,
                         first_seen=1, last_seen=1))

    def E(s, d, k):
        wm.add_edge(Edge(src=s, dst=d, kind=k, provenance=f"obs-{s}-{d}",
                         confidence=1.0, first_seen=1, last_seen=1))

    N("p", NodeKind.PRINCIPAL)
    for h in ("h0", "h1", "h2", "h3"):
        N(h, NodeKind.HOST)
    E("p", "h3", EdgeKind.OWNS)                # attacker starts owning h3 (highest id)
    E("h3", "h2", EdgeKind.REACHABLE_FROM)     # reach chain runs DOWN the id order ->
    E("h2", "h1", EdgeKind.REACHABLE_FROM)     # one OWNS edge per round (reverse of
    E("h1", "h0", EdgeKind.REACHABLE_FROM)     # the id-sorted focus scan)
    return wm


def test_saturate_worklist_matches_full_edge_multihop_trap() -> None:
    ops = _pivot_trap_ops()
    w_full, _ = _assert_identical(_pivot_trap_world, ops)
    # the pivot walked the whole chain to the deepest host
    for h in ("h2", "h1", "h0"):
        assert w_full.get_edge("p", h, EdgeKind.OWNS) is not None
    # derived hop-by-hop across rounds: first_seen strictly increases down the chain
    fs2 = w_full.get_edge("p", "h2", EdgeKind.OWNS).first_seen
    fs1 = w_full.get_edge("p", "h1", EdgeKind.OWNS).first_seen
    fs0 = w_full.get_edge("p", "h0", EdgeKind.OWNS).first_seen
    assert fs2 < fs1 < fs0


# -- fixture 4: a value-overwrite that produces NO new signature must NOT extend
#    the fixpoint — the worklist must not OVER-saturate relative to the rescan ----


def test_saturate_worklist_does_not_oversaturate_on_value_overwrite() -> None:
    H = NodeKind.HOST
    read_v = Operator(id="readv", name="readv", technique_ref=["X"],
                      preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=H),
                                     Predicate(kind=PredicateKind.NODE_ATTR, attr="v",
                                               op=AttrOp.EQ, value=7)],
                      effects=[Effect(kind=EffectKind.SET_ATTR, attr="hit", value=True)])
    set_v = Operator(id="setv", name="setv", technique_ref=["X"],
                     preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=H),
                                    Predicate(kind=PredicateKind.NODE_ATTR, attr="trigger",
                                              op=AttrOp.TRUTHY)],
                     effects=[Effect(kind=EffectKind.SET_ATTR, attr="v", value=7)])
    ops = [read_v, set_v]   # reader first

    def build() -> WorldModel:
        wm = WorldModel()
        # v is an EXISTING key (value 3) -> set_v changes its VALUE to 7 but adds
        # no new attr-key, so the node signature is unchanged: round_new stays 0 and
        # the loop breaks before readv ever sees v==7. The rescan does this; the
        # worklist must reproduce it exactly (dirtying readv, then DROPPING it on break).
        wm.add_node(Node(id="n0", kind=H, attrs={"trigger": True, "v": 3},
                         provenance="obs-n0", confidence=1.0, first_seen=1, last_seen=1))
        return wm

    w_full, a_full = _assert_identical(build, ops)
    assert w_full.get_node("n0").attrs["v"] == 7       # the value WAS overwritten
    assert "hit" not in w_full.get_node("n0").attrs    # but readv did NOT fire (no over-saturation)
    assert a_full == []                                # no NEW signature -> nothing returned


# -- the perf win: STRICTLY FEWER derivations on a synthetic-N graph ------------


def _perf_synth_ops(length: int) -> list:
    H = NodeKind.HOST
    out = []
    for i in range(length, 0, -1):   # reverse order -> length+1 rounds to converge
        out.append(Operator(
            id=f"pstep{i}", name=f"pstep{i}", technique_ref=["X"],
            preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=H),
                           Predicate(kind=PredicateKind.NODE_ATTR, attr=f"s{i - 1}", op=AttrOp.TRUTHY)],
            effects=[Effect(kind=EffectKind.SET_ATTR, attr=f"s{i}", value=True)]))
    return out


def _perf_synth_world(n_inert: int, active: bool) -> WorldModel:
    wm = WorldModel()
    if active:
        wm.add_node(Node(id="active", kind=NodeKind.HOST, attrs={"s0": True},
                         provenance="o", confidence=1.0, first_seen=1, last_seen=1))
    # many INERT hosts: candidates of every step op (NODE_KIND HOST) that re-FAIL
    # the s{i-1} precondition every round. The rescan re-probes them each round;
    # the worklist probes them once (round 0), never dirtied again.
    for i in range(n_inert):
        wm.add_node(Node(id=f"inert_{i:03d}", kind=NodeKind.HOST, attrs={},
                         provenance="o", confidence=1.0, first_seen=1, last_seen=1))
    return wm


def test_saturate_worklist_strictly_fewer_derivations(monkeypatch) -> None:
    ops = _perf_synth_ops(5)                       # 5 ops, ~6 rounds on the active chain

    def build():
        return _perf_synth_world(n_inert=60, active=True)

    full_n, w_full = _count_derivations(_saturate_full, build, ops, monkeypatch=monkeypatch)
    wl_n, w_wl = _count_derivations(saturate, build, ops, monkeypatch=monkeypatch)

    assert full_n > 0 and wl_n > 0
    assert wl_n < full_n                           # the win, measured as a derivation count
    # and the win is byte-identical: same saturated graph despite fewer derivations
    assert w_wl.all_nodes() == w_full.all_nodes()
    assert w_wl.all_edges() == w_full.all_edges()
    # the active chain really did run multiple rounds (else "fewer" would be trivial)
    assert w_full.get_node("active").attrs == {f"s{i}": True for i in range(6)}


def test_saturate_worklist_equal_derivations_when_single_sweep(monkeypatch) -> None:
    # Control: with NO derivable facts the fixpoint is one sweep; the worklist's
    # mandatory first sweep scans exactly what the rescan does -> EQUAL counts (the
    # worklist earns its win only by skipping LATER re-scans, never the first one).
    ops = _perf_synth_ops(5)

    def build():
        return _perf_synth_world(n_inert=40, active=False)

    full_n, w_full = _count_derivations(_saturate_full, build, ops, monkeypatch=monkeypatch)
    wl_n, w_wl = _count_derivations(saturate, build, ops, monkeypatch=monkeypatch)
    assert full_n > 0
    assert wl_n == full_n
    assert w_wl.all_nodes() == w_full.all_nodes()


# -- negative control: the differential comparator actually BITES ---------------


def test_differential_comparator_detects_a_difference() -> None:
    # Prove _assert_identical's equality checks are not vacuous: the SAME rescan at
    # a different seq_start yields a DIFFERENT graph (first_seen/last_seen shift), so
    # the all_nodes()/all_edges() equality the byte-identity tests rely on is False.
    ops = _attr_chain_ops()
    w_a = _attr_chain_world()
    w_b = _attr_chain_world()
    _saturate_full(ops, w_a, 1000)
    _saturate_full(ops, w_b, 9000)
    assert w_a.all_nodes() != w_b.all_nodes()      # seq windows differ -> not equal
    # sanity: they agree on structure (same attr keys) — only the seq windows differ,
    # which is exactly the dimension byte-identity must (and does) pin down.
    assert _seen_of(w_a) == _seen_of(w_b)


# -- the strongest guard: random graphs + random operators ----------------------


def _rand_world_and_ops(rng: _random.Random):
    node_kinds = [NodeKind.HOST, NodeKind.ENDPOINT, NodeKind.PRINCIPAL, NodeKind.DATASTORE,
                  NodeKind.CREDENTIAL, NodeKind.SESSION, NodeKind.WEBAPP, NodeKind.CLOUD_RESOURCE]
    edge_kinds = [EdgeKind.REACHABLE_FROM, EdgeKind.VALID_ON, EdgeKind.CAN_ASSUME, EdgeKind.OWNS,
                  EdgeKind.HOLDS, EdgeKind.SESSION_ON, EdgeKind.TRUSTS_FOR, EdgeKind.HAS_GRANT]
    attr_names = ["a", "b", "c"]
    ids = [f"n{i}" for i in range(rng.randint(3, 8))] + ["attacker"]
    nodes = []
    for nid in ids:
        kind = NodeKind.PRINCIPAL if nid == "attacker" else rng.choice(node_kinds)
        attrs = {an: rng.choice([True, False]) for an in attr_names if rng.random() < 0.5}
        nodes.append((nid, kind, attrs))
    edges = [(rng.choice(ids), rng.choice(ids), rng.choice(edge_kinds))
             for _ in range(rng.randint(2, 10))]

    ops = []
    for oi in range(rng.randint(2, 5)):
        preconds: list = []
        captures: list = []
        if rng.random() < 0.7:
            preconds.append(Predicate(kind=PredicateKind.NODE_KIND, node_kind=rng.choice(node_kinds)))
        for _ in range(rng.randint(0, 2)):
            preconds.append(Predicate(kind=PredicateKind.NODE_ATTR, attr=rng.choice(attr_names),
                                      op=rng.choice([AttrOp.TRUTHY, AttrOp.FALSY,
                                                     AttrOp.EXISTS, AttrOp.ABSENT])))
        for _ in range(rng.randint(0, 2)):
            cap = None
            if rng.random() < 0.6:
                cap = f"c{oi}_{len(captures)}"
                captures.append(cap)
            preconds.append(Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=rng.choice(edge_kinds),
                                      direction=rng.choice([Direction.OUT, Direction.IN, Direction.EITHER]),
                                      other_kind=(rng.choice(node_kinds) if rng.random() < 0.5 else None),
                                      capture_as=cap))
        if rng.random() < 0.4:   # exercise the global GRAPH_HAS_NODE read (attr + kind-only)
            cap = None
            if rng.random() < 0.5:
                cap = f"g{oi}_{len(captures)}"
                captures.append(cap)
            if rng.random() < 0.6:
                preconds.append(Predicate(kind=PredicateKind.GRAPH_HAS_NODE, node_kind=rng.choice(node_kinds),
                                          attr=rng.choice(attr_names), op=AttrOp.TRUTHY, capture_as=cap))
            else:
                preconds.append(Predicate(kind=PredicateKind.GRAPH_HAS_NODE,
                                          node_kind=rng.choice(node_kinds), capture_as=cap))
        if not preconds:
            preconds.append(Predicate(kind=PredicateKind.NODE_KIND, node_kind=rng.choice(node_kinds)))

        roles = ["focus", "actor"] + captures   # every one is bound whenever the op matches
        effects: list = []
        for _ in range(rng.randint(1, 2)):
            if rng.random() < 0.65:
                effects.append(Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=rng.choice(edge_kinds),
                                      src_role=rng.choice(roles), dst_role=rng.choice(roles)))
            else:
                effects.append(Effect(kind=EffectKind.SET_ATTR, target_role=rng.choice(roles),
                                      attr=rng.choice(attr_names + ["x", "y"]),
                                      value=rng.choice([True, 1, 2])))
        ops.append(Operator(id=f"op{oi}", name=f"op{oi}", technique_ref=["X"],
                            preconditions=preconds, effects=effects))

    def build() -> WorldModel:
        wm = WorldModel()
        for nid, kind, attrs in nodes:
            wm.add_node(Node(id=nid, kind=kind, attrs=dict(attrs), provenance=f"obs-{nid}",
                             confidence=1.0, first_seen=1, last_seen=1))
        for s, d, k in edges:
            wm.add_edge(Edge(src=s, dst=d, kind=k, provenance=f"obs-{s}-{d}",
                             confidence=1.0, first_seen=1, last_seen=1))
        return wm

    seeds = {op.id: {"actor": "attacker"} for op in ops}
    return build, ops, seeds


def test_saturate_worklist_matches_full_random(monkeypatch) -> None:
    trials = 200
    with_derivations = 0
    strictly_fewer = 0
    total_full = 0
    for seed in range(trials):
        rng = _random.Random(seed)
        build, ops, seeds = _rand_world_and_ops(rng)
        # byte-identity on this random config
        _, a_full = _assert_identical(build, ops, seeds=seeds)
        if a_full:
            with_derivations += 1
        # and the worklist NEVER does more derivations than the rescan (and usually
        # fewer). Counting monkeypatches derive; restore it before the next diff.
        full_n, _ = _count_derivations(_saturate_full, build, ops, seeds=seeds, monkeypatch=monkeypatch)
        wl_n, _ = _count_derivations(saturate, build, ops, seeds=seeds, monkeypatch=monkeypatch)
        assert wl_n <= full_n, f"seed {seed}: worklist did MORE derivations ({wl_n} > {full_n})"
        total_full += full_n
        if wl_n < full_n:
            strictly_fewer += 1

    # coverage: the random suite must actually exercise derivation + the win, else
    # the byte-identity assertions above are passing on empty closures.
    assert with_derivations >= trials // 3, f"only {with_derivations}/{trials} trials derived anything"
    assert strictly_fewer >= 1, "no random trial showed the worklist doing fewer derivations"
    assert total_full > 500


# ===========================================================================
# M2.1 regression guard — the VALUE-SENSITIVE / NON-MONOTONIC differential.
#
# The suite above used only presence AttrOps (EXISTS/ABSENT/TRUTHY/FALSY) and a
# TRUTHY-only GRAPH_HAS_NODE. That distribution MISSED the defect a red-pen later
# found: _saturate_full reads a focus NODE_ATTR from the per-operator-pass SNAPSHOT
# (stale within a pass), but a pre-fix worklist re-fetched the focus live and so saw
# an operator's OWN in-pass SET_ATTR — flipping a value-sensitive EQ/NE/IN or a
# presence toggle, which lost a derived edge and inflated Beta belief. This generator
# is the exact one the red-pen used (value-sensitive NODE_ATTR, non-monotonic
# GRAPH_HAS_NODE, a `resource` seed, truncated max_rounds). Its seeds 55 and 3303
# reproduce two named counterexamples byte-for-byte; the 2-node PoC is hand-built.
# Keep this generator pinned — it is the differential distribution that BITES.
# ===========================================================================

_VS_NODE_KINDS = [NodeKind.HOST, NodeKind.ENDPOINT, NodeKind.PRINCIPAL, NodeKind.DATASTORE,
                  NodeKind.CREDENTIAL, NodeKind.SESSION, NodeKind.WEBAPP, NodeKind.CLOUD_RESOURCE]
_VS_EDGE_KINDS = [EdgeKind.REACHABLE_FROM, EdgeKind.VALID_ON, EdgeKind.CAN_ASSUME, EdgeKind.OWNS,
                  EdgeKind.HOLDS, EdgeKind.SESSION_ON, EdgeKind.TRUSTS_FOR, EdgeKind.HAS_GRANT]
_VS_ATTRS = ["a", "b", "c", "d"]
_VS_VALUES = [True, False, 0, 1, 2, "x"]


def _rand_cfg_value_sensitive(rng: _random.Random):
    """The red-pen's adversarial generator, pinned verbatim: value-sensitive NODE_ATTR
    (EQ/NE/IN as well as presence ops), non-monotonic GRAPH_HAS_NODE (ABSENT/FALSY),
    INCIDENT_EDGE + GRAPH_HAS_NODE captures, and a seeded `resource` role. Returns
    (build, ops, seeds). The RNG call order is load-bearing: it fixes the graphs at
    seeds 55 and 3303 that two named counterexamples live on."""
    ids = [f"n{i}" for i in range(rng.randint(3, 10))] + ["attacker", "resource"]
    nodes = []
    for nid in ids:
        if nid == "attacker":
            kind = NodeKind.PRINCIPAL
        elif nid == "resource":
            kind = NodeKind.CLOUD_RESOURCE
        else:
            kind = rng.choice(_VS_NODE_KINDS)
        attrs = {an: rng.choice(_VS_VALUES) for an in _VS_ATTRS if rng.random() < 0.5}
        nodes.append((nid, kind, attrs))
    edges = [(rng.choice(ids), rng.choice(ids), rng.choice(_VS_EDGE_KINDS))
             for _ in range(rng.randint(2, 14))]
    ops = []
    for oi in range(rng.randint(2, 6)):
        pre: list = []
        caps: list = []
        if rng.random() < 0.7:
            pre.append(Predicate(kind=PredicateKind.NODE_KIND, node_kind=rng.choice(_VS_NODE_KINDS)))
        for _ in range(rng.randint(0, 3)):
            op_ = rng.choice([AttrOp.EQ, AttrOp.NE, AttrOp.IN, AttrOp.EXISTS,
                              AttrOp.ABSENT, AttrOp.TRUTHY, AttrOp.FALSY])
            val = rng.sample(_VS_VALUES, rng.randint(1, 3)) if op_ is AttrOp.IN else rng.choice(_VS_VALUES)
            pre.append(Predicate(kind=PredicateKind.NODE_ATTR, attr=rng.choice(_VS_ATTRS), op=op_, value=val))
        for _ in range(rng.randint(0, 2)):
            cap = None
            if rng.random() < 0.6:
                cap = f"c{oi}_{len(caps)}"; caps.append(cap)
            pre.append(Predicate(kind=PredicateKind.INCIDENT_EDGE, edge_kind=rng.choice(_VS_EDGE_KINDS),
                                 direction=rng.choice([Direction.OUT, Direction.IN, Direction.EITHER]),
                                 other_kind=(rng.choice(_VS_NODE_KINDS) if rng.random() < 0.5 else None),
                                 capture_as=cap))
        if rng.random() < 0.5:
            cap = None
            if rng.random() < 0.5:
                cap = f"g{oi}_{len(caps)}"; caps.append(cap)
            if rng.random() < 0.7:
                gop = rng.choice([AttrOp.EQ, AttrOp.ABSENT, AttrOp.FALSY, AttrOp.TRUTHY, AttrOp.EXISTS])
                pre.append(Predicate(kind=PredicateKind.GRAPH_HAS_NODE, node_kind=rng.choice(_VS_NODE_KINDS),
                                     attr=rng.choice(_VS_ATTRS), op=gop, value=rng.choice(_VS_VALUES), capture_as=cap))
            else:
                pre.append(Predicate(kind=PredicateKind.GRAPH_HAS_NODE,
                                     node_kind=rng.choice(_VS_NODE_KINDS), capture_as=cap))
        if not pre:
            pre.append(Predicate(kind=PredicateKind.NODE_KIND, node_kind=rng.choice(_VS_NODE_KINDS)))
        roles = ["focus", "actor", "resource"] + caps
        effs: list = []
        for _ in range(rng.randint(1, 3)):
            if rng.random() < 0.6:
                effs.append(Effect(kind=EffectKind.ASSERT_EDGE, edge_kind=rng.choice(_VS_EDGE_KINDS),
                                   src_role=rng.choice(roles), dst_role=rng.choice(roles)))
            else:
                effs.append(Effect(kind=EffectKind.SET_ATTR, target_role=rng.choice(roles),
                                   attr=rng.choice(_VS_ATTRS), value=rng.choice(_VS_VALUES)))
        ops.append(Operator(id=f"op{oi}", name=f"op{oi}", technique_ref=["X"],
                            preconditions=pre, effects=effs))

    def build() -> WorldModel:
        wm = WorldModel()
        for nid, kind, attrs in nodes:
            wm.add_node(Node(id=nid, kind=kind, attrs=dict(attrs), provenance=f"obs-{nid}",
                             confidence=1.0, first_seen=1, last_seen=1))
        for s, d, k in edges:
            wm.add_edge(Edge(src=s, dst=d, kind=k, provenance=f"obs-{s}-{d}",
                             confidence=1.0, first_seen=1, last_seen=1))
        return wm

    seeds = {op.id: {"actor": "attacker", "resource": "resource"} for op in ops}
    return build, ops, seeds


def test_saturate_worklist_matches_full_value_sensitive_random(monkeypatch) -> None:
    # A few hundred seeded graphs from the adversarial distribution, each at FULL and
    # TRUNCATED max_rounds (the truncation regime is where a one-round-late derivation
    # shows up as a lost fact). Byte-identity on every one; the worklist never does more
    # derivations than the rescan.
    trials = 300
    derived = 0
    strictly_fewer = 0
    for seed in range(trials):
        build, ops, seeds = _rand_cfg_value_sensitive(_random.Random(seed))
        for mr in (1, 3, 16):
            _, a_full = _assert_identical(build, ops, seeds=seeds, max_rounds=mr)
            if a_full:
                derived += 1
        full_n, _ = _count_derivations(_saturate_full, build, ops, seeds=seeds, monkeypatch=monkeypatch)
        wl_n, _ = _count_derivations(saturate, build, ops, seeds=seeds, monkeypatch=monkeypatch)
        assert wl_n <= full_n, f"seed {seed}: worklist did MORE derivations ({wl_n} > {full_n})"
        if wl_n < full_n:
            strictly_fewer += 1
    # non-vacuity: this distribution really derives, and really shows the win. (Many
    # small random graphs converge in one sweep — no later rounds to save — so the
    # strictly-fewer rate is well below 1; the floor only proves the win is common.)
    assert derived >= trials, f"only {derived} derived-nonempty across {trials} seeds x 3 rounds"
    assert strictly_fewer >= trials // 5, f"worklist rarely won: {strictly_fewer}/{trials}"


def test_saturate_regression_poc_set_attr_own_later_focus() -> None:
    # Named counterexample 1 (the 2-node / 1-operator PoC). An operator whose effect
    # SET_ATTRs a LATER-sorted candidate focus (z_tgt) of its own NODE_ATTR precond.
    # Pre-fix, the worklist re-fetched z_tgt live, saw the fresh `a`, and re-fired its
    # own effect -> z_tgt Beta belief alpha/beta = 4.0/3.0 instead of the rescan's
    # 3.5/2.5. Now byte-identical (the stale per-pass snapshot hides the in-pass write).
    op = Operator(id="op", name="op", technique_ref=["X"],
                  preconditions=[Predicate(kind=PredicateKind.NODE_KIND, node_kind=NodeKind.HOST),
                                 Predicate(kind=PredicateKind.NODE_ATTR, attr="a", op=AttrOp.EXISTS)],
                  effects=[Effect(kind=EffectKind.SET_ATTR, target_role="late", attr="a",
                                  value=1, confidence=0.5)])

    def build() -> WorldModel:
        wm = WorldModel()
        wm.add_node(Node(id="a_src", kind=NodeKind.HOST, attrs={"a": 0},
                         provenance="obs", confidence=1.0, first_seen=1, last_seen=1))
        wm.add_node(Node(id="z_tgt", kind=NodeKind.HOST, attrs={},
                         provenance="obs", confidence=1.0, first_seen=1, last_seen=1))
        return wm

    w_full, _ = _assert_identical(build, [op], seeds={"op": {"late": "z_tgt"}})
    z = w_full.get_node("z_tgt")
    assert z.attrs == {"a": 1}
    assert (z.alpha, z.beta) == (3.5, 2.5)   # the rescan's belief, now matched exactly


def test_saturate_regression_redpen_seed55_mr1() -> None:
    # Named counterexample 2: seed=55, max_rounds=1 (diverged on node 'resource').
    build, ops, seeds = _rand_cfg_value_sensitive(_random.Random(55))
    w_full, _ = _assert_identical(build, ops, seeds=seeds, max_rounds=1)
    assert w_full.get_node("resource") is not None


def test_saturate_regression_redpen_seed3303_mr4() -> None:
    # Named counterexample 3: seed=3303, max_rounds=4 — a MISSED derived edge
    # ('n2','n2','trusts_for'), an outright lost fact pre-fix.
    build, ops, seeds = _rand_cfg_value_sensitive(_random.Random(3303))
    w_full, _ = _assert_identical(build, ops, seeds=seeds, max_rounds=4)
    assert w_full.get_edge("n2", "n2", EdgeKind.TRUSTS_FOR) is not None
