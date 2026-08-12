"""E4 (part B) — end-to-end OFFLINE wiring of the anonymous-privileged K8s-RBAC capability (rbac_verify).

A retained live RBAC-binding capture flows: capture -> confirm(k8s_workload_posture oracle) -> admit(FACT
over the registered `k8s_exploit.rbac.anonymous_privileged_binding` branch) -> signed D2 certificate ->
OFFLINE re-verify (which re-fires the oracle) -> veracity-firewall claim-grounding. The D2 cert binding and
the firewall re-execution engage AUTOMATICALLY (both are generic over any finding carrying an
`oracle_context`), so this proves the whole offline path with FIXTURE captures, zero cluster calls. The
oracle itself is the EXISTING, red-penned k8s_workload_posture oracle (reused, not rebuilt) — E4's flagship
confirmation core; this slice adds only the LIVE-capture producer + branch + world-model projection.

The near-zero-FP discrimination is MUTATION-VERIFIED as load-bearing: each single-field break of the firing
capture drops it to a LEAD (a ServiceAccount merely NAMED system:anonymous — the default-SA case, TIER-2
territory; an anonymous binding to a non-dangerous role; a namespaced Role merely NAMED cluster-admin), and
restoring the field returns it to a FACT — so a non-FACT is proven caused by the break, never a vacuous pass.

Mint/reverify need the offense engine, so these importorskip framework and run in the offense (crucible) leg.
FATAL-2 (rbac_verify's framework imports are function-local; the module co-loads no framework at import) is
asserted separately in test_two_env_boundary.py.
"""
import copy

import pytest

pytest.importorskip("framework.v2.verify.k8s_workload_posture")   # mint/reverify require the offense engine

from vigil_integration.live.k8s_rbac_verify import rbac_verify

# A live ClusterRoleBinding whose RETAINED raw subjects + roleRef bind cluster-admin to the anonymous USER
# (system:anonymous is a User; system:unauthenticated is a Group — the two real reserved anonymous principals).
_ANON_ADMIN = {
    "resource_kind": "clusterrolebinding",
    "name": "anonymous-cluster-admin",
    "subjects": [{"kind": "User", "name": "system:anonymous", "namespace": "",
                  "api_group": "rbac.authorization.k8s.io"}],
    "role": "cluster-admin",
    "role_kind": "ClusterRole",
    "role_apigroup": "rbac.authorization.k8s.io",
}


def _signers_and_trust():
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    kp = generate_keypair()
    signers = [("gov0", kp.private_key_b64)]
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])
    return signers, tr


def test_anonymous_cluster_admin_binding_mints_a_fact_that_reverifies_offline():
    signers, tr = _signers_and_trust()

    r = rbac_verify(_ANON_ADMIN, engagement_slug="e4test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", r.reason
    assert r.certificate is not None and r.certificate.signed is not None
    assert r.finding_ref.startswith("k8s:") or r.finding_ref  # a stable finding ref was minted

    # the D2 cert re-verifies OFFLINE — re-fires the oracle (reproduction) AND routes each fact sentence
    # through the veracity firewall (claim-grounding). Both engage with no wiring of their own.
    from framework.v2.evidence.certify import verify_certificate
    v = verify_certificate(r.certificate.signed, oracle_context=r.oracle_context, trust_root=tr)
    assert v.ok is True, "a minted E4 FACT must re-verify offline from its certificate"


@pytest.mark.parametrize("subjects", [
    # the Group system:unauthenticated — the OTHER real anonymous principal.
    [{"kind": "Group", "name": "system:unauthenticated", "namespace": "",
      "api_group": "rbac.authorization.k8s.io"}],
    # a legacy STRING subject: a live-read RBAC sensor may emit the reserved name directly (the cluster is
    # authority) — the oracle accepts the bare reserved name.
    ["system:anonymous"],
])
def test_other_real_anonymous_principals_also_fact(subjects):
    signers, _ = _signers_and_trust()
    cap = copy.deepcopy(_ANON_ADMIN)
    cap["subjects"] = subjects
    r = rbac_verify(cap, engagement_slug="e4test", signers=signers)
    assert r.is_fact is True and r.verdict == "FACT", (subjects, r.reason)


@pytest.mark.parametrize("break_reason,mutate", [
    # NOT anonymous — a ServiceAccount merely NAMED system:anonymous is a DIFFERENT principal (a default/named
    # SA bound to cluster-admin is the TIER-2 case; it must NOT fire this anonymous-only branch).
    ("named-SA subject is not the anonymous principal",
     lambda c: c["subjects"][0].update({"kind": "ServiceAccount", "api_group": ""})),
    # NOT anonymous — the typed anonymous principal REQUIRES the RBAC apiGroup (an unvalidated manifest omits it).
    ("typed anonymous subject without the RBAC apiGroup",
     lambda c: c["subjects"][0].update({"api_group": ""})),
    # NOT anonymous — a Group named system:anonymous is the WRONG type (anonymous is a User; the Group principal
    # is system:unauthenticated) — exact type+name discrimination.
    ("Group named system:anonymous is the wrong type",
     lambda c: c["subjects"][0].update({"kind": "Group"})),
    # NOT dangerous — anonymous bound to a benign built-in role (view) is surfaced as a LEAD, never a FACT.
    ("anonymous bound to a non-dangerous role",
     lambda c: c.update({"role": "view"})),
    # NOT dangerous — a namespaced Role merely NAMED cluster-admin is not the powerful BUILT-IN ClusterRole.
    ("namespaced Role merely NAMED cluster-admin",
     lambda c: c.update({"role_kind": "Role"})),
    # NOT dangerous — a custom role in a non-RBAC apiGroup named cluster-admin is not the built-in.
    ("custom apiGroup role named cluster-admin",
     lambda c: c.update({"role_apigroup": "example.com"})),
    # the benign built-in anonymous binding every cluster ships (system:public-info-viewer) — role not dangerous.
    ("benign built-in public-info-viewer binding",
     lambda c: c.update({"role": "system:public-info-viewer"})),
])
def test_mutation_verified_only_a_true_anonymous_privileged_binding_is_a_fact(break_reason, mutate):
    signers, _ = _signers_and_trust()
    broken = copy.deepcopy(_ANON_ADMIN)
    mutate(broken)
    r = rbac_verify(broken, engagement_slug="e4test", signers=signers)
    assert r.is_fact is False and r.verdict in ("LEAD", "INCONCLUSIVE"), f"{break_reason}: {r.reason}"
    assert r.certificate is None, break_reason
    # restore -> FACT (proves the non-FACT was CAUSED by the break, not a vacuous always-LEAD path)
    assert rbac_verify(_ANON_ADMIN, engagement_slug="e4test", signers=signers).is_fact is True


def test_a_tampered_oracle_context_fails_reverification():
    signers, tr = _signers_and_trust()
    r = rbac_verify(_ANON_ADMIN, engagement_slug="e4test", signers=signers)
    assert r.is_fact

    from framework.v2.evidence.certify import verify_certificate
    bad = copy.deepcopy(r.oracle_context)
    # demote the bound role to a benign one in the retained proof — the firewall must reject the tampered claim
    bad["k8s_workload_control"]["achieved_state"]["role"] = "view"
    v = verify_certificate(r.certificate.signed, oracle_context=bad, trust_root=tr)
    assert v.ok is False, "a demoted binding must fail re-verification (the firewall demotes it)"


def test_the_capture_is_secret_safe_a_stray_kubeconfig_token_is_not_retained():
    # The runner fingerprints-and-discards the kubeconfig bearer token; even if a careless caller left one on
    # the capture, the canonical reducer retains ONLY the RBAC binding metadata, so no token reaches the cert.
    signers, _ = _signers_and_trust()
    cap = copy.deepcopy(_ANON_ADMIN)
    cap["auth_token"] = "eyJhbGciOiJSUzI1NiJ9.KUBECONFIG_BEARER_TOKEN_SECRET"
    r = rbac_verify(cap, engagement_slug="e4test", signers=signers)
    assert r.is_fact is True
    assert "KUBECONFIG_BEARER_TOKEN_SECRET" not in str(r.oracle_context)


def test_a_malformed_capture_never_raises_and_is_not_a_fact():
    signers, _ = _signers_and_trust()
    for bad in ({}, {"subjects": []}, {"role": "cluster-admin"}, {"subjects": [{}], "role": ""},
                None, "x", 123, []):
        r = rbac_verify(bad, engagement_slug="e4test", signers=signers)
        assert r.is_fact is False, f"a malformed capture must never be a FACT: {bad!r}"
        assert r.certificate is None
