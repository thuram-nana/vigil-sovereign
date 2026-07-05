"""
Applicable-operator query over world-model state (Wave 5, item B).

The technique catalog already reifies each TTP as an operator with typed
preconditions/effects and ATT&CK/CWE/CAPEC cross-refs. This closes the query the
planner actually asks: given a world-model state S, *which operators' preconditions
are satisfied* — the applicable set it can chain from. `applicable_operators` is
that read-only query.

The test builds a state S that satisfies exactly two of the six catalog operators
and asserts the applicable set is exactly those two.
"""

from __future__ import annotations

from framework.v2.knowledge import CATALOG, applicable_operators, by_technique
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import Edge, EdgeKind, Node, NodeKind


def _node(nid: str, kind: NodeKind, **attrs: object) -> Node:
    return Node(id=nid, kind=kind, attrs=dict(attrs), provenance="obs", confidence=0.9,
                first_seen=1, last_seen=1)


def _edge(src: str, dst: str, kind: EdgeKind) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, attrs={}, provenance="obs", confidence=0.9,
                first_seen=1, last_seen=1)


def _state_S() -> WorldModel:
    """A world state satisfying exactly two operators:
      * unauth-endpoint-read — an ENDPOINT (auth falsy) TRUSTS_FOR a DATASTORE
      * credential-reuse      — a CREDENTIAL VALID_ON a PRINCIPAL
    and none of the other four (no SSRF url-fetch, no session, no assumable role,
    no deserialization sink)."""
    w = WorldModel()
    w.add_node(_node("ep", NodeKind.ENDPOINT, auth=False))
    w.add_node(_node("ds", NodeKind.DATASTORE))
    w.add_edge(_edge("ep", "ds", EdgeKind.TRUSTS_FOR))
    w.add_node(_node("cred", NodeKind.CREDENTIAL))
    w.add_node(_node("prin", NodeKind.PRINCIPAL))
    w.add_edge(_edge("cred", "prin", EdgeKind.VALID_ON))
    return w


def test_applicable_set_matches_world_state() -> None:
    w = _state_S()
    ids = {op.id for op in applicable_operators(w, CATALOG)}
    assert ids == {"unauth-endpoint-read", "credential-reuse"}, ids


def test_query_is_read_only() -> None:
    w = _state_S()
    before = (w.node_count, w.edge_count)
    applicable_operators(w, CATALOG)
    assert (w.node_count, w.edge_count) == before, "the query must assert nothing"


def test_empty_world_has_no_applicable_operators() -> None:
    assert applicable_operators(WorldModel(), CATALOG) == []


def test_focus_kinds_scopes_the_scan() -> None:
    w = _state_S()
    ids = {
        op.id
        for op in applicable_operators(w, CATALOG, focus_kinds=[NodeKind.CREDENTIAL])
    }
    assert ids == {"credential-reuse"}, "focus_kinds must restrict which nodes are tried"


def test_operators_carry_resolvable_cross_references() -> None:
    op = next(o for o in CATALOG if o.id == "credential-reuse")
    assert "T1078" in op.technique_ref
    assert any(r.startswith("CWE-") for r in op.technique_ref)
    assert any(r.startswith("CAPEC-") for r in op.technique_ref)
    # the cross-reference is queryable both ways
    assert op in by_technique("T1078")
