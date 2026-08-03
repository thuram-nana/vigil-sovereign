"""
C2·K8s — the live-cluster k8s-RBAC posture oracle (an anonymous-privileged RBAC binding -> FACT), and its
substrate alignment (T4a).

A live RBAC read is a THIRD-PARTY collector's say-so — a LEAD. The k8s-workload-posture oracle promotes it
to a FACT ONLY when the RETAINED binding proves a CONCRETE insecure achieved state: an ANONYMOUS subject
(system:anonymous / system:unauthenticated) bound to a genuinely DANGEROUS built-in ClusterRole
(cluster-admin / admin / edit). A benign binding (the built-in system:public-info-viewer, an anonymous
binding to a non-dangerous/custom role, a namespaced Role merely NAMED "admin", a binding with no anonymous
subject) does NOT fire — near-zero false positives. The confirmed fact re-verifies offline from its
retained context.

Unlike its former bespoke wiring (a DIRECT oracle call projecting a fact with the fake ``oracle_kind=
"k8s_workload"``), this oracle now routes through the standard ``confirm`` -> ``verifier._run`` substrate
as its own real ``OracleKind.K8S_WORKLOAD_POSTURE`` — so it carries a distinct ``oracle_version`` and its
fact RE-VERIFIES through the ``oracle_version`` reverify registry, exactly like every sibling posture oracle.
"""

from __future__ import annotations

from framework.v2.verify import (
    confirm_k8s_workload_posture,
    k8s_workload_posture_context,
    k8s_workload_posture_oracle,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracle_version import oracle_version
from framework.v2.verify.reverify import reverify_context
from framework.v2.verify.verifier import _ALL_ORACLES, OracleVerifier

# A live ClusterRoleBinding whose retained raw subjects + role grant cluster-admin to system:anonymous.
_ANON_ADMIN = {
    "check_id": "binding:/anon-admin", "resource_kind": "clusterrolebinding", "name": "anon-admin",
    "achieved_state": {
        "subjects": ["system:anonymous"], "role": "cluster-admin",
        "role_kind": "ClusterRole", "role_apigroup": "rbac.authorization.k8s.io"},
}

# A benign, namespaced binding to a non-dangerous role — the honest LEAD that must NOT be promoted.
_BENIGN_NAMESPACED = {
    "check_id": "binding:default/anon-view", "resource_kind": "rolebinding", "name": "anon-view",
    "namespace": "default",
    "achieved_state": {"subjects": ["system:unauthenticated"], "role": "view"},
}


# ---- the oracle fires ONLY on a proven anonymous-privileged binding ---------


def test_oracle_signal_carries_the_new_kind() -> None:
    sig = k8s_workload_posture_oracle(_ANON_ADMIN)
    assert sig.fired and sig.confidence >= 0.7
    # the odd-one-out is fixed: the signal now carries its OWN kind, not K8S_POSTURE
    assert sig.kind is OracleKind.K8S_WORKLOAD_POSTURE
    assert sig.kind is not OracleKind.K8S_POSTURE
    assert sig.observed["rule"] == "anonymous_privileged_binding"


def test_confirm_via_seam_fires_on_anonymous_cluster_admin() -> None:
    result = confirm_k8s_workload_posture(_ANON_ADMIN)
    assert result.confirmed
    top = max(result.confirming_signals, key=lambda s: s.confidence)
    assert top.kind is OracleKind.K8S_WORKLOAD_POSTURE


def test_confirm_via_seam_and_verifier_agree() -> None:
    assert OracleVerifier().confirm(k8s_workload_posture_context(_ANON_ADMIN)).confirmed


# ---- the oracle does NOT fire on a benign / unprovable binding --------------


def test_benign_namespaced_binding_does_not_fire() -> None:
    assert not confirm_k8s_workload_posture(_BENIGN_NAMESPACED).confirmed


def test_namespaced_role_named_admin_is_not_the_builtin_and_does_not_fire() -> None:
    # a custom namespaced Role merely NAMED "admin" is NOT the powerful built-in ClusterRole
    ctl = {"check_id": "binding:ns/x", "resource_kind": "rolebinding", "name": "x",
           "achieved_state": {"subjects": ["system:anonymous"], "role": "admin",
                              "role_kind": "Role", "role_apigroup": "rbac.authorization.k8s.io"}}
    assert not confirm_k8s_workload_posture(ctl).confirmed


def test_no_anonymous_subject_does_not_fire() -> None:
    ctl = {"check_id": "binding:/svc", "name": "svc",
           "achieved_state": {"subjects": ["alice", "system:serviceaccount:x:y"], "role": "cluster-admin"}}
    assert not confirm_k8s_workload_posture(ctl).confirmed


def test_malformed_and_empty_do_not_fire() -> None:
    for junk in ({}, {"achieved_state": {}}, {"achieved_state": {"subjects": "x", "role": 5}}):
        assert not confirm_k8s_workload_posture(junk).confirmed


# ---- routing + the frozen-fallback invariant --------------------------------


def test_routes_via_verifier_and_kind_is_out_of_the_frozen_fallback() -> None:
    v = OracleVerifier()
    assert v.oracles_for("k8s_workload_misconfiguration") == (OracleKind.K8S_WORKLOAD_POSTURE,)
    assert v.oracles_for("k8s_workload_posture") == (OracleKind.K8S_WORKLOAD_POSTURE,)   # alias folds
    assert v.oracles_for("anonymous_rbac_binding") == (OracleKind.K8S_WORKLOAD_POSTURE,)  # alias folds
    # the NEW kind is reachable ONLY via its explicit row — never the unknown-class fallback
    assert OracleKind.K8S_WORKLOAD_POSTURE not in _ALL_ORACLES
    assert OracleKind.K8S_WORKLOAD_POSTURE not in v.oracles_for("some_unknown_class")
    # the gate-stability invariant: the frozen fallback set is still EXACTLY 15
    assert len(_ALL_ORACLES) == 15


def test_kube_bench_k8s_posture_row_is_untouched() -> None:
    # the sibling kube-bench class still routes to its OWN, distinct kind — not collided with the new one
    v = OracleVerifier()
    assert v.oracles_for("k8s_misconfiguration") == (OracleKind.K8S_POSTURE,)
    assert OracleKind.K8S_POSTURE is not OracleKind.K8S_WORKLOAD_POSTURE


# ---- oracle_version: distinct, non-colliding identities ---------------------


def test_two_k8s_oracles_have_distinct_versions() -> None:
    vw = oracle_version(OracleKind.K8S_WORKLOAD_POSTURE)
    vk = oracle_version(OracleKind.K8S_POSTURE)
    assert vw.startswith("sha256:") and vk.startswith("sha256:")
    assert vw != vk                                   # distinct oracle bodies -> distinct versions
    assert vw == oracle_version("k8s_workload_posture")   # enum == str value, stable


# ---- offline re-verification (prove-don't-guess) ----------------------------


def test_confirmed_posture_reverifies_offline_from_its_retained_context() -> None:
    oracle_context = k8s_workload_posture_context(_ANON_ADMIN)
    # no cluster, no trust in the collector — re-run the pure oracle over the retained binding
    r = reverify_context(oracle_context, bug_class="k8s_workload_misconfiguration")
    assert r.reproduced and r.ok
    assert r.confirmed_by == OracleKind.K8S_WORKLOAD_POSTURE.value


def test_reverify_matches_the_claimed_certificate() -> None:
    oracle_context = k8s_workload_posture_context(_ANON_ADMIN)
    r = reverify_context(
        oracle_context, bug_class="k8s_workload_misconfiguration",
        claimed_confirmed_by=OracleKind.K8S_WORKLOAD_POSTURE.value, claimed_confidence=0.9)
    assert r.reproduced and r.matches_claim is True


def test_benign_binding_does_not_reverify() -> None:
    r = reverify_context(k8s_workload_posture_context(_BENIGN_NAMESPACED),
                         bug_class="k8s_workload_misconfiguration")
    assert not r.reproduced


# ---- the adapter retains only structural fields -----------------------------


def test_adapter_builder_retains_only_structural_fields() -> None:
    ctx = FindingContext.from_k8s_workload_control({**_ANON_ADMIN, "noise": "verbose collector prose"})
    emitted = ctx.to_verifier_context()
    assert "k8s_workload_control" in emitted
    wl = emitted["k8s_workload_control"]
    assert "noise" not in wl                          # non-structural fields are NOT laundered in
    assert wl["check_id"] == "binding:/anon-admin"
    assert wl["achieved_state"]["role"] == "cluster-admin"
    assert wl["achieved_state"]["subjects"] == ["system:anonymous"]
