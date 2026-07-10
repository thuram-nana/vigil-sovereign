"""
Tests for Wave 5a — the policy-path (IAM privilege-path) oracle.

A cloud sensor's "over-privileged / can reach R" is an OBSERVATION; it becomes a FACT only when a REAL
IAM grant path re-derives over the retained policy graph. These cover the pure oracle (judge a retained
policy graph), the access lattice (a read grant does not prove a write request), the FindingContext
carrier + verifier routing, offline re-verification (the retained JSON-safe graph re-confirms with no
cloud), and the ``verify.policy_path`` graph builder + confirm helper — plus the honest negatives
(a benign config, a broken chain, a malformed graph) that must NOT confirm.
"""

from __future__ import annotations

import json

import pytest

from framework.v2.verify import (
    OracleVerifier,
    build_policy_graph,
    confirm_privilege_path,
    policy_path_context,
    policy_path_oracle,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.policy_path import privilege_path_query
from framework.v2.verify.reverify import reverify_context

# A small policy: dev CAN_ASSUME admin; dev MEMBER_OF eng; admin HAS_GRANT read over customer-data;
# eng HAS_GRANT read over logs. So dev reaches customer-data (via assume) and logs (via membership).
_INV = {
    "principals": [
        {"id": "role/dev", "kind": "role", "can_assume": ["role/admin"], "member_of": ["group/eng"]},
        {"id": "role/admin", "kind": "role"},
    ],
    "resources": [
        {"id": "s3/customer-data", "kind": "datastore", "sensitive": True,
         "grants": [{"principal": "role/admin", "access": "read"}]},
        {"id": "s3/logs", "kind": "datastore",
         "grants": [{"principal": "group/eng", "access": "read"}]},
    ],
}


def _graph() -> dict:
    return build_policy_graph(_INV)


# ---- the pure oracle -------------------------------------------------------


def test_oracle_fires_on_a_real_assume_chain_grant() -> None:
    sig = policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/customer-data"))
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["grant_holder"] == "role/admin" and sig.observed["hops"] >= 1
    assert "role/dev" in sig.evidence and "s3/customer-data" in sig.evidence


def test_oracle_fires_via_group_membership() -> None:
    sig = policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/logs"))
    assert sig.fired and sig.observed["grant_holder"] == "group/eng"


def test_oracle_fires_on_a_direct_grant_zero_hops() -> None:
    sig = policy_path_oracle(privilege_path_query(_graph(), "role/admin", "s3/customer-data"))
    assert sig.fired and sig.observed["hops"] == 0   # admin holds the grant directly


@pytest.mark.parametrize("principal,resource", [
    ("role/nobody", "s3/customer-data"),   # principal not in graph
    ("role/admin", "s3/logs"),             # admin has no path to logs
    ("group/eng", "s3/customer-data"),     # eng cannot reach customer-data
])
def test_oracle_does_not_fire_without_a_real_path(principal: str, resource: str) -> None:
    assert policy_path_oracle(privilege_path_query(_graph(), principal, resource)).fired is False


def test_access_lattice_a_read_grant_does_not_prove_a_write_request() -> None:
    # admin holds only READ over customer-data — a WRITE/ADMIN request must NOT confirm (conservative).
    assert policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/customer-data", "write")).fired is False
    assert policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/customer-data", "admin")).fired is False
    # but a READ (or unspecified "any") request is granted by the read grant.
    assert policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/customer-data", "read")).fired is True
    assert policy_path_oracle(privilege_path_query(_graph(), "role/dev", "s3/customer-data", "")).fired is True


def test_admin_grant_dominates_a_read_request() -> None:
    inv = {"principals": [{"id": "p"}],
           "resources": [{"id": "r", "grants": [{"principal": "p", "access": "admin"}]}]}
    g = build_policy_graph(inv)
    assert policy_path_oracle(privilege_path_query(g, "p", "r", "read")).fired is True
    assert policy_path_oracle(privilege_path_query(g, "p", "r", "write")).fired is True


@pytest.mark.parametrize("bad", ["not a mapping", {}, {"principal": "p"}, {"resource": "r"},
                                 {"principal": "", "resource": "r"}])
def test_oracle_total_on_malformed_input(bad) -> None:
    assert policy_path_oracle(bad).fired is False


def test_oracle_is_deterministic() -> None:
    q = privilege_path_query(_graph(), "role/dev", "s3/customer-data")
    a, b = policy_path_oracle(q), policy_path_oracle(q)
    assert a.fired == b.fired and a.confidence == b.confidence and a.observed == b.observed


def test_oracle_terminates_on_a_cyclic_assume_graph() -> None:
    # a <-> b assume cycle with no grant: BFS must terminate and not confirm.
    inv = {"principals": [{"id": "a", "can_assume": ["b"]}, {"id": "b", "can_assume": ["a"]}],
           "resources": [{"id": "r", "grants": [{"principal": "c", "access": "read"}]}]}
    assert policy_path_oracle(privilege_path_query(build_policy_graph(inv), "a", "r")).fired is False


# ---- verifier routing + FindingContext carrier -----------------------------


def test_privilege_path_routes_to_the_policy_oracle() -> None:
    res = OracleVerifier().confirm(
        {"bug_class": "privilege_path", "policy": privilege_path_query(_graph(), "role/dev", "s3/customer-data")})
    assert res.confirmed and res.bug_class == "privilege_path"


def test_alias_bug_classes_route_to_the_policy_oracle() -> None:
    for bc in ("iam_privesc", "over_privileged", "excessive-permissions", "iam privilege escalation"):
        res = OracleVerifier().confirm(
            {"bug_class": bc, "policy": privilege_path_query(_graph(), "role/dev", "s3/customer-data")})
        assert res.confirmed, bc


def test_finding_context_carries_the_policy_graph_to_the_verifier() -> None:
    ctx = FindingContext.from_policy_graph(privilege_path_query(_graph(), "role/dev", "s3/logs"))
    vctx = ctx.to_verifier_context()
    assert vctx["bug_class"] == "privilege_path" and "policy" in vctx
    assert OracleVerifier().confirm(vctx).confirmed


def test_a_benign_query_does_not_confirm_through_the_verifier() -> None:
    res = confirm_privilege_path(_graph(), "role/nobody", "s3/customer-data")
    assert not res.confirmed


# ---- offline re-verification (prove-don't-guess: re-execute over retained evidence) ----


def test_confirmed_path_reverifies_offline_from_its_retained_graph() -> None:
    oracle_context = policy_path_context(_graph(), "role/dev", "s3/customer-data")
    json.dumps(oracle_context)   # the retained context is JSON-serialisable (enables offline re-verify)
    r = reverify_context(oracle_context, bug_class="privilege_path")
    assert r.reproduced and r.ok and r.confirmed_by == "policy_path"


def test_a_non_firing_context_reverifies_as_not_reproduced() -> None:
    ctx = policy_path_context(_graph(), "role/nobody", "s3/customer-data")
    r = reverify_context(ctx, bug_class="privilege_path")
    assert not r.reproduced


# ---- the graph builder -----------------------------------------------------


def test_build_policy_graph_is_total_and_deterministic() -> None:
    assert build_policy_graph("garbage")["grants"] == []
    assert build_policy_graph({}) == {"principals": [], "resources": [], "grants": [], "assume": [], "member_of": []}
    # deterministic (sorted) regardless of input principal/resource ordering
    a = build_policy_graph(_INV)
    shuffled = {"principals": list(reversed(_INV["principals"])),
                "resources": list(reversed(_INV["resources"]))}
    assert build_policy_graph(shuffled) == a


def test_build_policy_graph_lowercases_ids_like_from_cloud() -> None:
    g = build_policy_graph({"principals": [{"id": "Role/DEV", "can_assume": ["Role/ADMIN"]}],
                            "resources": [{"id": "S3/Data", "grants": [{"principal": "Role/ADMIN", "access": "READ"}]}]})
    assert {"src": "role/dev", "dst": "role/admin"} in g["assume"]
    assert g["grants"][0]["principal"] == "role/admin" and g["grants"][0]["resource"] == "s3/data"
