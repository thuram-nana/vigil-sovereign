"""E4 TIER-2 — end-to-end OFFLINE wiring of the K8s dangerous-VERB / default-SA verb-grant capability.

A retained capture (a binding + the SEPARATELY-retained role_object its roleRef names) flows:
capture -> confirm(k8s_rbac_verb_grant oracle) -> admit(FACT over the registered
`k8s_exploit.rbac.dangerous_verb_grant` branch) -> signed D2 certificate -> OFFLINE re-verify (which re-fires
the oracle) -> veracity-firewall claim-grounding. The cert binding and the firewall re-execution engage
AUTOMATICALLY (both generic over any finding carrying an `oracle_context`), so this proves the whole offline
path with FIXTURE captures, zero cluster calls.

The near-zero-FP subject gate is exercised END-TO-END here, not just at the oracle: the most common
LEGITIMATE delegation (the namespace-default ServiceAccount bound to an `admin`-like role granting Secrets
get/list/watch in a namespace) must be admitted as a LEAD with NO certificate, and repairing it to an
unambiguous grant must produce a FACT — so the gate is load-bearing through the admission path too.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (the producer's framework imports are function-local) is asserted in test_two_env_boundary.py.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.k8s_rbac_grant")   # mint/reverify require the offense engine

from vigil_integration.live.k8s_rbac_grant_verify import grant_verify

_RBAC = "rbac.authorization.k8s.io"
_ANON_USER = {"kind": "User", "name": "system:anonymous", "namespace": "", "api_group": _RBAC}
_DEFAULT_SA = {"kind": "ServiceAccount", "name": "default", "namespace": "default", "api_group": ""}
_FULL_WILDCARD = {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}
_ADMIN_LIKE = {"verbs": ["get", "list", "watch", "create"], "resources": ["secrets", "pods"],
               "apiGroups": ["", "apps"]}

# an anonymous subject bound to a CUSTOM role whose PARSED rules grant cluster-admin-equivalent power.
_ANON_WILDCARD = {
    "check_id": "clusterrolebinding:anon-wild",
    "binding": {"kind": "ClusterRoleBinding", "namespace": "", "name": "anon-wild",
                "subjects": [_ANON_USER],
                "role_ref": {"name": "custom-superuser", "kind": "ClusterRole", "api_group": _RBAC}},
    "role_object": {"name": "custom-superuser", "kind": "ClusterRole", "api_group": _RBAC, "namespace": "",
                    "rules": [_FULL_WILDCARD], "rules_source": "live_clusterrole_get"},
}

# THE legitimate delegation the review flagged: default:default -> an admin-like role, in a NAMESPACE.
_LEGIT_NAMESPACE_OWNER = {
    "check_id": "rolebinding:default/ns-owner",
    "binding": {"kind": "RoleBinding", "namespace": "default", "name": "ns-owner",
                "subjects": [_DEFAULT_SA],
                "role_ref": {"name": "admin", "kind": "ClusterRole", "api_group": _RBAC}},
    "role_object": {"name": "admin", "kind": "ClusterRole", "api_group": _RBAC, "namespace": "",
                    "rules": [_ADMIN_LIKE], "rules_source": "live_clusterrole_get"},
}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def test_anonymous_dangerous_grant_mints_a_fact_that_reverifies_offline():
    signers, tr = _signers_and_trust()
    r = grant_verify(_ANON_WILDCARD, engagement_slug="e4t2test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None

    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E4-TIER-2 FACT must re-verify offline from its certificate"


def test_a_tampered_role_rule_fails_reverification():
    signers, tr = _signers_and_trust()
    r = grant_verify(_ANON_WILDCARD, engagement_slug="e4t2test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    # demote the role's rules to something harmless in the retained proof
    bad["k8s_rbac_grant_control"]["role_object"]["rules"] = [
        {"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}]
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a demoted rule set must fail re-verification (the firewall demotes it)"


def test_the_legitimate_namespace_owner_delegation_is_never_a_fact_mutation_verified():
    # The near-zero-FP gate, proven THROUGH the admission path: default:default bound to an admin-like role
    # (Secrets get/list/watch) in a namespace is the single most common legitimate RBAC delegation and must
    # be a LEAD with NO certificate.
    signers, _ = _signers_and_trust()
    r = grant_verify(_LEGIT_NAMESPACE_OWNER, engagement_slug="e4t2test", signers=signers)
    assert r.is_fact is False and r.verdict in ("LEAD", "INCONCLUSIVE"), r.reason
    assert r.certificate is None

    # REPAIR 1 — the same rules bound to an ANONYMOUS subject is unambiguous -> FACT.
    anon = copy.deepcopy(_LEGIT_NAMESPACE_OWNER)
    anon["binding"]["subjects"] = [_ANON_USER]
    assert grant_verify(anon, engagement_slug="e4t2test", signers=signers).is_fact is True

    # REPAIR 2 — default:default on a genuine */*/* ClusterRoleBinding is unambiguous -> FACT.
    wild = copy.deepcopy(_ANON_WILDCARD)
    wild["binding"]["subjects"] = [_DEFAULT_SA]
    assert grant_verify(wild, engagement_slug="e4t2test", signers=signers).is_fact is True


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"binding": {}}, {"role_object": {}}, {"binding": {"subjects": []}},
                None, "x", 123, []):
        r = grant_verify(bad, engagement_slug="e4t2test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
