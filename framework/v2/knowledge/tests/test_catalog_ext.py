"""Tests for knowledge.catalog_ext — the extended operators and their load-
bearing claim: each new operator picks up a base-catalog effect as a precondition
and drives the escalation one or two hops further, and the combined catalog
forward-chains those hops to a fixpoint without over-deriving.

Every escalation is exercised through `saturate([*CATALOG, *EXTENDED_CATALOG])`
so the *composition* is what is under test, not an operator in isolation."""

from __future__ import annotations

import pytest

from ...verify.models import OracleKind
from ...worldmodel.graph import WorldModel
from ...worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ...worldmodel.store import to_json
from ..catalog import CATALOG
from ..catalog_ext import (
    CREDENTIAL_LEAK_CAPTURE,
    DATASTORE_SECRET_EXTRACTION,
    EXTENDED_CATALOG,
    FINDING_PRECONDITIONS,
    HOST_TAKEOVER,
    LATERAL_PIVOT,
    SESSION_THEFT_TAKEOVER,
    TOKEN_LEAK_CAPTURE,
    by_id_ext,
)
from ..models import AttrOp, PredicateKind
from ..operators import saturate

ATTACKER = "attacker"


def _n(wm: WorldModel, nid: str, kind: NodeKind, **attrs: object) -> Node:
    return wm.add_node(Node(id=nid, kind=kind, attrs=dict(attrs),
                            provenance=f"obs-{nid}", confidence=0.9,
                            first_seen=1, last_seen=1))


def _e(wm: WorldModel, s: str, d: str, k: EdgeKind, **attrs: object) -> Edge:
    return wm.add_edge(Edge(src=s, dst=d, kind=k, attrs=dict(attrs),
                            provenance=f"obs-{s}-{d}", confidence=0.9,
                            first_seen=1, last_seen=1))


ALL = (*CATALOG, *EXTENDED_CATALOG)


# ---------------------------------------------------------------------------
# registry / well-formedness
# ---------------------------------------------------------------------------


def test_extended_catalog_shape_and_disjoint_ids() -> None:
    assert len(EXTENDED_CATALOG) == 6
    ext_ids = [op.id for op in EXTENDED_CATALOG]
    assert len(set(ext_ids)) == 6
    base_ids = {op.id for op in CATALOG}
    assert base_ids.isdisjoint(ext_ids)  # no id collisions when composed
    assert by_id_ext("host-takeover") is HOST_TAKEOVER
    with pytest.raises(KeyError):
        by_id_ext("no-such-op")


def test_every_extended_operator_is_well_formed() -> None:
    """Every effect role must be resolvable from focus + captured roles, or be
    an intentionally caller-seeded role (actor / resource) — same contract the
    base catalog holds itself to."""
    seeded = {"actor", "resource"}
    for op in EXTENDED_CATALOG:
        resolvable = {"focus"} | op.captured_roles | seeded
        missing = op.effect_roles - resolvable
        assert not missing, f"{op.id} has unbindable effect roles: {missing}"
        assert op.oracle_kind in set(OracleKind)
        assert op.technique_ref  # intel provenance present


def test_finding_preconditions_reference_real_operator_attrs() -> None:
    """The direct node-attr markers FINDING_PRECONDITIONS can stamp must each be
    a NODE_ATTR precondition some operator actually reads — otherwise the mapping
    would promise an unlock that never fires."""
    assert FINDING_PRECONDITIONS  # non-empty
    for bug_class, overlay in FINDING_PRECONDITIONS.items():
        assert isinstance(bug_class, str) and isinstance(overlay, dict)

    checked_attrs = {
        p.attr
        for op in ALL
        for p in op.preconditions
        if p.kind is PredicateKind.NODE_ATTR and p.op is AttrOp.TRUTHY
    }
    direct_markers = {"exposed", "code_exec", "leaked",
                      "deserializes_untrusted", "fetches_url"}
    assert direct_markers <= checked_attrs
    # every direct marker is used by at least one finding mapping
    used = {a for ov in FINDING_PRECONDITIONS.values() for a in ov}
    assert direct_markers <= used


# ---------------------------------------------------------------------------
# chain A: unauth-endpoint-read (base) -> datastore-secret-extraction (ext)
# ---------------------------------------------------------------------------


def test_chain_datastore_read_to_credential_hold() -> None:
    """A broken-authz endpoint fronting a datastore (base op) makes the store
    reachable; datastore-secret-extraction then harvests a credential stored in
    it into the attacker's HOLDS state. The read primitive becomes credential
    access — across two catalogs."""
    wm = WorldModel()
    _n(wm, ATTACKER, NodeKind.PRINCIPAL)
    _n(wm, "ep", NodeKind.ENDPOINT, auth=False)
    _n(wm, "db", NodeKind.DATASTORE)
    _n(wm, "cred", NodeKind.CREDENTIAL)
    _e(wm, ATTACKER, "ep", EdgeKind.REACHABLE_FROM)        # network reach to route
    _e(wm, "ep", "db", EdgeKind.TRUSTS_FOR, purpose="query")  # app-tier link
    _e(wm, "db", "cred", EdgeKind.REACHABLE_FROM)          # the store holds a secret

    # over-derive control: a datastore with a stored secret but NO inbound reach
    _n(wm, "db_iso", NodeKind.DATASTORE)
    _n(wm, "cred_iso", NodeKind.CREDENTIAL)
    _e(wm, "db_iso", "cred_iso", EdgeKind.REACHABLE_FROM)

    seeds = {"datastore-secret-extraction": {"actor": ATTACKER}}
    saturate(ALL, wm, seq_start=100, seeds=seeds)

    # base op fired: the store is now reachable through the broken endpoint
    assert wm.get_edge("ep", "db", EdgeKind.REACHABLE_FROM) is not None
    # ext op fired off that reach: the credential is held
    held = wm.get_edge(ATTACKER, "cred", EdgeKind.HOLDS)
    assert held is not None
    assert held.provenance == "operator:datastore-secret-extraction"
    # did not over-derive: the unreached store's secret is NOT held
    assert wm.get_edge(ATTACKER, "cred_iso", EdgeKind.HOLDS) is None


# ---------------------------------------------------------------------------
# chain B: deserialization-to-code-exec (base) -> host-takeover -> lateral-pivot
# ---------------------------------------------------------------------------


def test_chain_code_exec_to_lateral_pivot() -> None:
    """Deserialization RCE (base) leaves a foothold + code_exec on host1;
    host-takeover promotes that to OWNS host1; lateral-pivot walks the internal
    REACHABLE_FROM edge to OWNS host2. Three operators, two catalogs, one chain."""
    wm = WorldModel()
    _n(wm, ATTACKER, NodeKind.PRINCIPAL)
    _n(wm, "ep", NodeKind.ENDPOINT, deserializes_untrusted=True)
    _n(wm, "host1", NodeKind.HOST)
    _n(wm, "host2", NodeKind.HOST)
    _e(wm, "host1", "ep", EdgeKind.REACHABLE_FROM)   # host1 runs the service
    _e(wm, "host1", "host2", EdgeKind.REACHABLE_FROM)  # internal peer reachable

    # over-derive controls
    _n(wm, "host_iso", NodeKind.HOST)                # isolated, no exec, unreached
    _n(wm, "host_unowned", NodeKind.HOST)
    _n(wm, "host_peer", NodeKind.HOST)
    _e(wm, "host_unowned", "host_peer", EdgeKind.REACHABLE_FROM)  # from an UNOWNED host

    seeds = {"deserialization-to-code-exec": {"actor": ATTACKER}}
    saturate(ALL, wm, seq_start=200, seeds=seeds)

    # base op fired
    assert wm.get_node("host1").attrs.get("code_exec") is True
    assert wm.get_edge(ATTACKER, "host1", EdgeKind.SESSION_ON) is not None
    # host-takeover fired
    owns1 = wm.get_edge(ATTACKER, "host1", EdgeKind.OWNS)
    assert owns1 is not None and owns1.provenance == "operator:host-takeover"
    # lateral-pivot fired
    owns2 = wm.get_edge(ATTACKER, "host2", EdgeKind.OWNS)
    assert owns2 is not None and owns2.provenance == "operator:lateral-pivot"
    # did not over-derive: isolated host and a peer of an UNOWNED host stay clean
    assert wm.get_edge(ATTACKER, "host_iso", EdgeKind.OWNS) is None
    assert wm.get_edge(ATTACKER, "host_peer", EdgeKind.OWNS) is None


def test_lateral_pivot_walks_multiple_hops() -> None:
    """lateral-pivot re-applies to each newly owned host, so a chain of
    REACHABLE_FROM edges is walked hop by hop to the fixpoint."""
    wm = WorldModel()
    _n(wm, ATTACKER, NodeKind.PRINCIPAL)
    for h in ("h0", "h1", "h2", "h3"):
        _n(wm, h, NodeKind.HOST)
    _e(wm, "h0", "h1", EdgeKind.REACHABLE_FROM)
    _e(wm, "h1", "h2", EdgeKind.REACHABLE_FROM)
    _e(wm, "h2", "h3", EdgeKind.REACHABLE_FROM)
    # seed the foothold directly: attacker already owns h0
    _e(wm, ATTACKER, "h0", EdgeKind.OWNS)

    saturate(ALL, wm, seq_start=300, seeds={})

    for h in ("h1", "h2", "h3"):
        assert wm.get_edge(ATTACKER, h, EdgeKind.OWNS) is not None, h


# ---------------------------------------------------------------------------
# chain C: credential-leak-capture (ext) -> role-assumption (base)
# ---------------------------------------------------------------------------


def test_chain_credential_leak_to_role_grant() -> None:
    """An exposed credential VALID_ON an admin lets credential-leak-capture assert
    CAN_ASSUME, which role-assumption (base) turns into HAS_GRANT over the crown
    jewel. Extended op unlocks a base op."""
    wm = WorldModel()
    _n(wm, ATTACKER, NodeKind.PRINCIPAL)
    _n(wm, "cred", NodeKind.CREDENTIAL, exposed=True)
    _n(wm, "admin", NodeKind.PRINCIPAL)
    _n(wm, "vault", NodeKind.CLOUD_RESOURCE)
    _e(wm, "cred", "admin", EdgeKind.VALID_ON)
    _e(wm, "admin", "vault", EdgeKind.HAS_GRANT, level="admin")

    # over-derive control: a credential that is NOT exposed
    _n(wm, "cred_safe", NodeKind.CREDENTIAL)
    _n(wm, "svc", NodeKind.PRINCIPAL)
    _e(wm, "cred_safe", "svc", EdgeKind.VALID_ON)

    seeds = {
        "credential-leak-capture": {"actor": ATTACKER},
        "credential-reuse": {"actor": ATTACKER},
        "role-assumption": {"resource": "vault"},
    }
    saturate(ALL, wm, seq_start=400, seeds=seeds)

    assert wm.get_edge(ATTACKER, "cred", EdgeKind.HOLDS) is not None
    assert wm.get_edge(ATTACKER, "admin", EdgeKind.CAN_ASSUME) is not None
    grant = wm.get_edge(ATTACKER, "vault", EdgeKind.HAS_GRANT)
    assert grant is not None and grant.provenance == "operator:role-assumption"
    # did not over-derive: the non-exposed credential is not captured as leaked
    assert wm.get_edge(ATTACKER, "cred_safe", EdgeKind.HOLDS) is None


# ---------------------------------------------------------------------------
# chain D: token-leak-capture (ext) -> session-theft-takeover (ext)
# ---------------------------------------------------------------------------


def test_chain_token_leak_to_account_takeover() -> None:
    """A leaked session token is HELD by token-leak-capture, then session-theft-
    takeover authenticates the attacker to the webapp the session runs on —
    account takeover with a stolen session, no credential."""
    wm = WorldModel()
    _n(wm, ATTACKER, NodeKind.PRINCIPAL)
    # client_bound=True keeps the base token-replay op from also matching here,
    # isolating the leak->takeover path under test.
    _n(wm, "sess", NodeKind.SESSION, leaked=True, client_bound=True)
    _n(wm, "app", NodeKind.WEBAPP)
    _e(wm, "sess", "app", EdgeKind.SESSION_ON)

    # over-derive control: a session that was NOT leaked
    _n(wm, "sess_safe", NodeKind.SESSION, client_bound=True)
    _e(wm, "sess_safe", "app", EdgeKind.SESSION_ON)

    seeds = {"token-leak-capture": {"actor": ATTACKER}}
    saturate(ALL, wm, seq_start=500, seeds=seeds)

    assert wm.get_edge(ATTACKER, "sess", EdgeKind.HOLDS) is not None
    auth = wm.get_edge(ATTACKER, "app", EdgeKind.AUTHENTICATES_TO)
    assert auth is not None and auth.provenance == "operator:session-theft-takeover"
    # did not over-derive: the un-leaked session is neither held nor a takeover source
    assert wm.get_edge(ATTACKER, "sess_safe", EdgeKind.HOLDS) is None


# ---------------------------------------------------------------------------
# determinism / fixpoint
# ---------------------------------------------------------------------------


def test_composed_saturate_is_deterministic_and_converges() -> None:
    """Running the combined catalog twice on identical worlds yields byte-identical
    graphs, and a second pass over the converged graph asserts nothing new."""
    def build() -> WorldModel:
        wm = WorldModel()
        _n(wm, ATTACKER, NodeKind.PRINCIPAL)
        _n(wm, "ep", NodeKind.ENDPOINT, deserializes_untrusted=True)
        _n(wm, "host1", NodeKind.HOST)
        _n(wm, "host2", NodeKind.HOST)
        _e(wm, "host1", "ep", EdgeKind.REACHABLE_FROM)
        _e(wm, "host1", "host2", EdgeKind.REACHABLE_FROM)
        _n(wm, "cred", NodeKind.CREDENTIAL, exposed=True)
        _n(wm, "admin", NodeKind.PRINCIPAL)
        _n(wm, "vault", NodeKind.CLOUD_RESOURCE)
        _e(wm, "cred", "admin", EdgeKind.VALID_ON)
        _e(wm, "admin", "vault", EdgeKind.HAS_GRANT)
        return wm

    seeds = {
        "deserialization-to-code-exec": {"actor": ATTACKER},
        "credential-leak-capture": {"actor": ATTACKER},
        "credential-reuse": {"actor": ATTACKER},
        "role-assumption": {"resource": "vault"},
    }
    wm1 = build()
    applied1 = saturate(ALL, wm1, seq_start=1000, seeds=seeds)
    assert applied1  # the chains did fire

    wm2 = build()
    saturate(ALL, wm2, seq_start=1000, seeds=seeds)
    assert to_json(wm1) == to_json(wm2)  # deterministic

    applied3 = saturate(ALL, wm1, seq_start=9000, seeds=seeds)
    assert applied3 == []  # already at fixpoint
