"""Tests for knowledge.catalog — the seed operators and the load-bearing
claim: a catalog operator drives world-model derivation to unlock a downstream
path the path engine could not find before."""

from __future__ import annotations

import pytest

from ...verify.models import OracleKind
from ...worldmodel.graph import WorldModel
from ...worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ...worldmodel.query import find_paths
from ..catalog import (
    CATALOG,
    CREDENTIAL_REUSE,
    ROLE_ASSUMPTION,
    UNAUTH_ENDPOINT_READ,
    by_id,
    by_technique,
)
from ..operators import apply, derive, match, saturate


def _n(wm: WorldModel, nid: str, kind: NodeKind, **attrs: object) -> Node:
    return wm.add_node(Node(id=nid, kind=kind, attrs=dict(attrs),
                            provenance=f"obs-{nid}", confidence=0.9,
                            first_seen=1, last_seen=1))


def _e(wm: WorldModel, s: str, d: str, k: EdgeKind, **attrs: object) -> Edge:
    return wm.add_edge(Edge(src=s, dst=d, kind=k, attrs=dict(attrs),
                            provenance=f"obs-{s}-{d}", confidence=0.9,
                            first_seen=1, last_seen=1))


# -- registry ---------------------------------------------------------------


def test_catalog_has_six_operators_unique_ids() -> None:
    assert len(CATALOG) == 6
    ids = [op.id for op in CATALOG]
    assert len(set(ids)) == 6


def test_by_id_and_by_technique() -> None:
    assert by_id("credential-reuse") is CREDENTIAL_REUSE
    with pytest.raises(KeyError):
        by_id("no-such-op")
    # T1078 tags credential-reuse; CWE-502 tags the deserialization operator
    assert CREDENTIAL_REUSE in by_technique("T1078")
    assert by_technique("CWE-502")[0].id == "deserialization-to-code-exec"
    assert by_technique("nonexistent") == []


def test_every_catalog_operator_is_well_formed() -> None:
    """Every effect role must be resolvable from focus + captured roles, or be
    an intentionally caller-seeded role (actor / resource). A catalog operator
    whose effect referenced a role nothing could ever bind would be a latent
    wiring bug."""
    seeded = {"actor", "resource"}
    for op in CATALOG:
        resolvable = {"focus"} | op.captured_roles | seeded
        missing = op.effect_roles - resolvable
        assert not missing, f"{op.id} has unbindable effect roles: {missing}"
        assert op.oracle_kind in set(OracleKind)


# -- the load-bearing integration: operator unlocks a downstream path -------


def test_unauth_endpoint_read_unlocks_datastore_path() -> None:
    """attacker -> ENDPOINT (REACHABLE_FROM) and ENDPOINT -> DATASTORE
    (TRUSTS_FOR, an app-tier link). Restricted to REACHABLE_FROM traversal the
    attacker cannot reach the datastore. Firing unauth-endpoint-read asserts the
    missing REACHABLE_FROM edge across the broken auth boundary, and the path
    engine now finds attacker -> ep -> db."""
    wm = WorldModel()
    _n(wm, "attacker", NodeKind.PRINCIPAL)
    ep = _n(wm, "ep", NodeKind.ENDPOINT, auth=False)
    _n(wm, "db", NodeKind.DATASTORE)
    _e(wm, "attacker", "ep", EdgeKind.REACHABLE_FROM)   # network reach to the route
    _e(wm, "ep", "db", EdgeKind.TRUSTS_FOR, purpose="query")  # structural, not attacker-reach

    reach = [EdgeKind.REACHABLE_FROM]
    assert find_paths(wm, "attacker", "db", edge_kinds=reach) == []  # blocked

    changes = derive(UNAUTH_ENDPOINT_READ, wm, ep, seq=100)
    assert changes is not None and len(changes) == 1

    paths = find_paths(wm, "attacker", "db", edge_kinds=reach)
    assert len(paths) == 1
    assert paths[0].nodes == ["attacker", "ep", "db"]
    # the unlocking hop is explainable back to the technique
    assert paths[0].edges[-1].provenance == "operator:unauth-endpoint-read"
    assert paths[0].edges[-1].attrs["technique_ref"] == UNAUTH_ENDPOINT_READ.technique_ref


def test_credential_reuse_then_role_assumption_chains() -> None:
    """Two operators chain: credential-reuse asserts CAN_ASSUME, which is
    role-assumption's precondition; role-assumption then asserts HAS_GRANT over
    the crown-jewel resource. This is the planner chain the gap analysis wanted:
    intel -> move -> new edge -> next move."""
    wm = WorldModel()
    _n(wm, "attacker", NodeKind.PRINCIPAL)
    cred = _n(wm, "cred", NodeKind.CREDENTIAL)
    _n(wm, "admin", NodeKind.PRINCIPAL)          # principal the cred is valid on
    _n(wm, "vault", NodeKind.CLOUD_RESOURCE)     # crown jewel the admin can reach
    _e(wm, "cred", "admin", EdgeKind.VALID_ON)
    _e(wm, "admin", "vault", EdgeKind.HAS_GRANT, level="read")

    # Step 1: credential-reuse -> attacker CAN_ASSUME admin
    b1 = match(CREDENTIAL_REUSE, wm, cred, seed={"actor": "attacker"})
    assert b1 is not None
    apply(CREDENTIAL_REUSE, wm, b1, seq=200)
    assert wm.get_edge("attacker", "admin", EdgeKind.CAN_ASSUME) is not None

    # Step 2: role-assumption now applies to the attacker principal (its
    # precondition CAN_ASSUME->PRINCIPAL is freshly satisfied by step 1).
    attacker_node = wm.get_node("attacker")
    b2 = match(ROLE_ASSUMPTION, wm, attacker_node, seed={"resource": "vault"})
    assert b2 is not None
    assert b2["role"] == "admin"        # captured from the CAN_ASSUME edge
    apply(ROLE_ASSUMPTION, wm, b2, seq=201)

    grant = wm.get_edge("attacker", "vault", EdgeKind.HAS_GRANT)
    assert grant is not None
    assert grant.provenance == "operator:role-assumption"


def test_saturate_reaches_fixpoint_and_is_deterministic() -> None:
    """saturate forward-chains the whole catalog to a fixpoint. Running it twice
    on identical worlds yields byte-identical graphs (deterministic derivation),
    and a second saturate over the converged graph asserts nothing new."""
    def build() -> WorldModel:
        wm = WorldModel()
        _n(wm, "attacker", NodeKind.PRINCIPAL)
        cred = _n(wm, "cred", NodeKind.CREDENTIAL)
        _n(wm, "admin", NodeKind.PRINCIPAL)
        _n(wm, "vault", NodeKind.CLOUD_RESOURCE)
        _e(wm, "cred", "admin", EdgeKind.VALID_ON)
        _e(wm, "admin", "vault", EdgeKind.HAS_GRANT, level="read")
        return wm

    seeds = {
        "credential-reuse": {"actor": "attacker"},
        "role-assumption": {"resource": "vault"},
    }
    wm1 = build()
    applied1 = saturate(CATALOG, wm1, seq_start=1000, seeds=seeds)
    # both new edges discovered: CAN_ASSUME then HAS_GRANT
    kinds = sorted(a.edge.kind.value for a in applied1 if a.edge is not None)
    assert "can_assume" in kinds and "has_grant" in kinds

    from ...worldmodel.store import to_json
    wm2 = build()
    saturate(CATALOG, wm2, seq_start=1000, seeds=seeds)
    assert to_json(wm1) == to_json(wm2)  # deterministic

    # already at fixpoint -> nothing new
    applied3 = saturate(CATALOG, wm1, seq_start=5000, seeds=seeds)
    assert applied3 == []
