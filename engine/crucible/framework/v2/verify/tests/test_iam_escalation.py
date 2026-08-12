"""E2 (BUILD-PLAN §E2) — the IAM privilege-escalation PRIMITIVE oracle, its soundness core, and the
mutation-verified near-zero-FP controls that make each anti-overclaim guard LOAD-BEARING.

The oracle is the ACHIEVED-ESCALATION dual of ``policy_path_oracle`` (mere reachability): it fires ONLY when
retained IAM statements grant a base principal an UNCONDITIONAL escalation primitive from a FIXED set that
STRICTLY increases what it can reach — an EXPLICIT differential of the base vs escalation-closed BFS closures.
Every control below breaks ONE field (-> LEAD) then repairs it (-> FACT), so the control cannot silently rot.
"""

from __future__ import annotations

import copy
import random

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import (
    _IAM_ESCALATION_PRIMITIVES,
    _iam_build_adj_grants,
    _iam_reaches,
    iam_escalation_oracle,
    policy_path_oracle,
)


def _base_fact() -> dict:
    """A minimal genuine escalation: role/dev cannot reach s3/crown-jewels, role/admin holds admin over it,
    and dev holds the trust-rewrite primitive (sts:AssumeRole + iam:UpdateAssumeRolePolicy) on role/admin."""
    return {
        "base_principal": "role/dev", "target_resource": "s3/crown-jewels", "target_access": "admin",
        "graph": {"grants": [{"principal": "role/admin", "resource": "s3/crown-jewels", "access": "admin"}],
                  "assume": [], "member_of": []},
        "escalation": {"primitive": "assume_role_trust_rewrite", "via": "role/admin",
                       "statements": [{"effect": "Allow",
                                       "action": ["sts:AssumeRole", "iam:UpdateAssumeRolePolicy"],
                                       "resource": ["role/admin"]}]},
    }


def test_the_base_fact_fires_at_high_confidence():
    s = iam_escalation_oracle(_base_fact())
    assert s.fired is True and s.confidence == 0.95
    assert s.kind == OracleKind.IAM_ESCALATION_PRIMITIVE
    assert s.observed["primitive"] == "assume_role_trust_rewrite"
    assert s.observed["family"] == "grant_gain"


def test_every_fixed_primitive_can_fire_and_the_set_is_closed():
    # each of the FIVE fixed primitives, over a graph where `via` holds the target grant.
    caps = {
        "assume_role_trust_rewrite": _base_fact(),
        "pass_role_to_compute": {
            "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
            "graph": {"grants": [{"principal": "role/ec2", "resource": "s3/crown", "access": "admin"}]},
            "escalation": {"primitive": "pass_role_to_compute", "via": "role/ec2", "statements": [
                {"effect": "Allow", "action": ["iam:PassRole"], "resource": ["role/ec2"]},
                {"effect": "Allow", "action": ["ec2:RunInstances"], "resource": ["*"]}]}},
        "attach_user_policy": {
            "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
            "graph": {"grants": []},
            "escalation": {"primitive": "attach_user_policy", "via": "user/dev", "statements": [
                {"effect": "Allow", "action": ["iam:AttachUserPolicy"], "resource": ["user/dev"]}]}},
        "add_user_to_group": {
            "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
            "graph": {"grants": [{"principal": "group/admins", "resource": "s3/crown", "access": "admin"}]},
            "escalation": {"primitive": "add_user_to_group", "via": "group/admins", "statements": [
                {"effect": "Allow", "action": ["iam:AddUserToGroup"], "resource": ["group/admins"]}]}},
        "create_access_key": {
            "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
            "graph": {"grants": [{"principal": "user/admin", "resource": "s3/crown", "access": "admin"}]},
            "escalation": {"primitive": "create_access_key", "via": "user/admin", "statements": [
                {"effect": "Allow", "action": ["iam:CreateAccessKey"], "resource": ["user/admin"]}]}},
    }
    assert set(caps) == set(_IAM_ESCALATION_PRIMITIVES), "test must cover exactly the fixed primitive set"
    for name, cap in caps.items():
        assert iam_escalation_oracle(cap).fired is True, f"{name} should fire"

    # an unknown primitive synthesizes NO edge (the set is closed).
    unk = copy.deepcopy(_base_fact())
    unk["escalation"]["primitive"] = "iam:DeleteUser"
    s = iam_escalation_oracle(unk)
    assert s.fired is False and s.observed["reason"] == "unknown_primitive"


# ---------------------------------------------------------------------------
# #2 — the base/escalation closures share the LITERAL policy_path search, proven by DIFFERENTIAL equivalence
# over random graphs (rather than refactoring the shipping oracle, which would risk the byte-identical gate).
# ---------------------------------------------------------------------------


def test_iam_reaches_is_byte_equivalent_to_policy_path_oracle():
    rng = random.Random(1234)
    prins = ["role/dev", "role/admin", "group/eng", "user/x", "role/ops", "group/sec"]
    res = ["s3/data", "s3/crown", "kms/k1", "ddb/t"]
    acc = ["", "read", "write", "admin", "list"]
    for _ in range(3000):
        grants = [{"principal": rng.choice(prins), "resource": rng.choice(res), "access": rng.choice(acc)}
                  for _ in range(rng.randint(0, 4))]
        assume = [{"src": rng.choice(prins), "dst": rng.choice(prins)} for _ in range(rng.randint(0, 3))]
        member = [{"src": rng.choice(prins), "dst": rng.choice(prins)} for _ in range(rng.randint(0, 3))]
        graph = {"grants": grants, "assume": assume, "member_of": member}
        start, target, req = rng.choice(prins), rng.choice(res), rng.choice(acc)
        pp = policy_path_oracle({"principal": start, "resource": target, "access": req, **graph}).fired
        adj, gr = _iam_build_adj_grants(graph)
        assert _iam_reaches(adj, gr, start.lower(), target.lower(), req) == pp


# ---------------------------------------------------------------------------
# #1 — strict-gain BASE ASYMMETRY: a direct identity-policy Allow that already reaches the target (not a
# coarse resource-grant edge) is folded into the base closure, so it reads as NO gain (mutation-verified).
# ---------------------------------------------------------------------------


def test_direct_identity_reach_is_folded_into_base_and_suppresses_the_fire():
    cap = _base_fact()
    cap["target_access"] = "write"
    # dev already has s3 write on the target directly (same service) -> base reaches it -> NOT a strict gain.
    cap["escalation"]["statements"].append(
        {"effect": "Allow", "action": ["s3:PutObject", "s3:GetObject"], "resource": ["s3/crown-jewels"]})
    s = iam_escalation_oracle(cap)
    assert s.fired is False and s.observed["reason"] == "no_strict_gain_already_reachable"
    # REPAIR: remove the direct-reach statement -> the escalation is again a strict gain -> FACT.
    cap["escalation"]["statements"] = cap["escalation"]["statements"][:1]
    assert iam_escalation_oracle(cap).fired is True


def test_a_cross_service_identity_allow_does_not_fold_as_reach_over_the_target():
    # dev has iam:* (admin over the IAM service) but the target is an s3 resource -> the fold must NOT count
    # iam:* as reaching s3 (else attach-policy escalations would be impossible). This is the absurdity guard.
    cap = {
        "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
        "graph": {"grants": []},
        "escalation": {"primitive": "attach_user_policy", "via": "user/dev", "statements": [
            {"effect": "Allow", "action": ["iam:*"], "resource": ["*"]}]}}
    assert iam_escalation_oracle(cap).fired is True   # iam:* does NOT fold as s3 reach; attach-policy fires


def test_already_reachable_via_an_existing_assume_edge_is_not_escalation():
    cap = _base_fact()
    cap["graph"]["assume"] = [{"src": "role/dev", "dst": "role/admin"}]   # dev can already assume admin
    s = iam_escalation_oracle(cap)
    assert s.fired is False and s.observed["reason"] == "no_strict_gain_already_reachable"
    cap["graph"]["assume"] = []
    assert iam_escalation_oracle(cap).fired is True


# ---------------------------------------------------------------------------
# #4 — trust-rewrite requires sts:AssumeRole too (UpdateAssumeRolePolicy alone is a FALSE edge); PassRole
# requires the compute run-action pairing (mutation-verified).
# ---------------------------------------------------------------------------


def test_trust_rewrite_without_sts_assume_role_does_not_fire():
    cap = _base_fact()
    cap["escalation"]["statements"][0]["action"] = ["iam:UpdateAssumeRolePolicy"]   # drop sts:AssumeRole
    s = iam_escalation_oracle(cap)
    assert s.fired is False and s.observed["reason"] == "action_not_unconditionally_allowed"
    cap["escalation"]["statements"][0]["action"] = ["sts:AssumeRole", "iam:UpdateAssumeRolePolicy"]
    assert iam_escalation_oracle(cap).fired is True


def test_pass_role_without_a_compute_run_action_does_not_fire():
    cap = {
        "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
        "graph": {"grants": [{"principal": "role/ec2", "resource": "s3/crown", "access": "admin"}]},
        "escalation": {"primitive": "pass_role_to_compute", "via": "role/ec2", "statements": [
            {"effect": "Allow", "action": ["iam:PassRole"], "resource": ["role/ec2"]}]}}
    s = iam_escalation_oracle(cap)
    assert s.fired is False   # PassRole alone is not an escalation
    cap["escalation"]["statements"].append({"effect": "Allow", "action": ["ec2:RunInstances"], "resource": ["*"]})
    assert iam_escalation_oracle(cap).fired is True


def test_pass_role_run_action_denied_by_a_resource_scoped_deny_stays_a_lead():
    # In-loop red-pen fix: the PassRole run-action leg is checked "anywhere" (its compute resource — an
    # instance/function — is unknown), so its DENY check must be resource-agnostic too. A Deny on the run
    # action SCOPED to instances (`Deny ec2:RunInstances Resource=instance/*`) genuinely blocks the launch,
    # so it must SUPPRESS the FACT even though it does not cover the passed role. Before the fix this minted
    # a false FACT (the deny was checked only over `via`, which an instance-scoped deny does not cover).
    cap = {
        "base_principal": "user/dev", "target_resource": "s3/crown", "target_access": "admin",
        "graph": {"grants": [{"principal": "role/ec2", "resource": "s3/crown", "access": "admin"}]},
        "escalation": {"primitive": "pass_role_to_compute", "via": "role/ec2", "statements": [
            {"effect": "Allow", "action": ["iam:PassRole"], "resource": ["role/ec2"]},
            {"effect": "Allow", "action": ["ec2:RunInstances"], "resource": ["*"]},
            {"effect": "Deny", "action": ["ec2:RunInstances"],
             "resource": ["arn:aws:ec2:*:*:instance/*"]}]}}
    assert iam_escalation_oracle(cap).fired is False   # the launch is denied -> not an achievable escalation
    # remove the run-action Deny -> the escalation is unblocked -> FACT (the Deny was load-bearing)
    cap["escalation"]["statements"] = cap["escalation"]["statements"][:2]
    assert iam_escalation_oracle(cap).fired is True
    # a Deny on a DIFFERENT action must NOT over-suppress (the fix is precise, not a blanket any-deny gate)
    cap["escalation"]["statements"].append(
        {"effect": "Deny", "action": ["ec2:TerminateInstances"], "resource": ["*"]})
    assert iam_escalation_oracle(cap).fired is True


# ---------------------------------------------------------------------------
# The FP-trap battery: Condition, NotAction (Allow), explicit Deny, Deny-via-NotAction guardrail (#3),
# permissions boundary, SCP, resource-wildcard-excludes-target. Each -> LEAD, then repaired -> FACT.
# ---------------------------------------------------------------------------


def test_a_condition_on_the_granting_statement_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["statements"][0]["condition"] = {"StringEquals": {"aws:username": "dev"}}
    assert iam_escalation_oracle(cap).fired is False
    del cap["escalation"]["statements"][0]["condition"]
    assert iam_escalation_oracle(cap).fired is True


def test_a_notaction_allow_is_ambiguous_and_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["statements"][0]["not_action"] = ["s3:GetObject"]
    assert iam_escalation_oracle(cap).fired is False
    del cap["escalation"]["statements"][0]["not_action"]
    assert iam_escalation_oracle(cap).fired is True


def test_an_explicit_deny_takes_precedence_and_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["statements"].append(
        {"effect": "Deny", "action": ["sts:AssumeRole"], "resource": ["role/admin"]})
    assert iam_escalation_oracle(cap).fired is False
    cap["escalation"]["statements"] = cap["escalation"]["statements"][:1]
    assert iam_escalation_oracle(cap).fired is True


def test_a_deny_via_notaction_guardrail_suppresses_the_edge_fail_closed():
    # #3: a "deny everything EXCEPT an allow-list" org guardrail (a Deny with NotAction, no Action field)
    # must suppress the candidate edge — sts:AssumeRole is NOT in the NotAction exception, so it is denied.
    cap = _base_fact()
    cap["escalation"]["statements"].append(
        {"effect": "Deny", "not_action": ["s3:GetObject", "s3:ListBucket"], "resource": ["*"]})
    assert iam_escalation_oracle(cap).fired is False
    # REPAIR: exempt the escalation actions from the guardrail's NotAction -> no longer denied -> FACT.
    cap["escalation"]["statements"][-1]["not_action"] = ["sts:AssumeRole", "iam:UpdateAssumeRolePolicy"]
    assert iam_escalation_oracle(cap).fired is True


def test_a_restricting_permissions_boundary_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["boundary"] = {"statements": [
        {"effect": "Allow", "action": ["s3:GetObject"], "resource": ["*"]}]}   # does NOT allow the primitive
    assert iam_escalation_oracle(cap).fired is False
    cap["escalation"]["boundary"]["statements"] = [
        {"effect": "Allow", "action": ["sts:*", "iam:*"], "resource": ["*"]}]   # now permits it
    assert iam_escalation_oracle(cap).fired is True


def test_a_restricting_scp_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["scp"] = {"statements": [
        {"effect": "Deny", "action": ["sts:AssumeRole"], "resource": ["*"]}]}
    assert iam_escalation_oracle(cap).fired is False
    cap["escalation"]["scp"] = {"statements": [
        {"effect": "Allow", "action": ["*"], "resource": ["*"]}]}
    assert iam_escalation_oracle(cap).fired is True


def test_a_resource_wildcard_that_excludes_the_target_stays_a_lead():
    cap = _base_fact()
    cap["escalation"]["statements"][0]["resource"] = ["role/dev-*"]   # excludes role/admin
    assert iam_escalation_oracle(cap).fired is False
    cap["escalation"]["statements"][0]["resource"] = ["role/*"]       # now covers role/admin
    assert iam_escalation_oracle(cap).fired is True


def test_the_synthesized_edge_must_actually_reach_the_target():
    cap = _base_fact()
    cap["graph"]["grants"] = []   # role/admin holds no grant over the target -> assuming it reaches nothing
    s = iam_escalation_oracle(cap)
    assert s.fired is False and s.observed["reason"] == "edge_does_not_reach_target"


# ---------------------------------------------------------------------------
# #6 — glob case / normalization: the resource glob and the graph node identity use the SAME lowercasing,
# so a mixed-case capture resolves to the SAME node the graph uses.
# ---------------------------------------------------------------------------


def test_mixed_case_ids_normalize_consistently_across_glob_and_graph():
    cap = {
        "base_principal": "Role/Dev", "target_resource": "S3/Crown-Jewels", "target_access": "admin",
        "graph": {"grants": [{"principal": "role/Admin", "resource": "s3/crown-jewels", "access": "admin"}]},
        "escalation": {"primitive": "assume_role_trust_rewrite", "via": "ROLE/admin", "statements": [
            {"effect": "Allow", "action": ["STS:AssumeRole", "IAM:UpdateAssumeRolePolicy"],
             "resource": ["Role/Adm*"]}]}}   # a mixed-case glob that must match the lowercased via role/admin
    s = iam_escalation_oracle(cap)
    assert s.fired is True
    assert s.observed["via"] == "role/admin" and s.observed["base_principal"] == "role/dev"


def test_malformed_captures_never_raise_and_never_fire():
    for bad in (None, "x", 123, [], {}, {"base_principal": "x"}, {"target_resource": "y"},
                {"base_principal": "a", "target_resource": "b"},
                {"base_principal": "a", "target_resource": "b", "escalation": "not-a-dict"}):
        s = iam_escalation_oracle(bad)
        assert s.fired is False and s.confidence == 0.0
