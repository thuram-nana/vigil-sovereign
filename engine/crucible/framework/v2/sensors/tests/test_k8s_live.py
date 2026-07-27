"""
Phase C2 · K8s — LIVE read-only Kubernetes workload/RBAC posture collector (sensors.k8s_live) + its new
achieved-state oracle (verify.oracles.k8s_workload_posture_oracle).

Near-zero-FP by construction: the collector emits a control ONLY for an EXPLICIT insecure achieved state
(a privileged container / a host-network pod / an RBAC binding to system:anonymous|system:unauthenticated),
and the oracle fires ONLY on that explicit state — a benign workload mints nothing and promotes nothing.
"""

from __future__ import annotations

from types import SimpleNamespace

from framework.v2.sensors.k8s_live import (
    K8sLiveSensor,
    k8s_workload_controls,
    k8s_workload_observations,
)
from framework.v2.verify.oracles import k8s_workload_posture_oracle


# --- the new achieved-state oracle: fires only on an EXPLICIT insecure state ---


def test_oracle_fires_on_each_explicit_insecure_state():
    for state, rule in (({"privileged": True}, "privileged_container"),
                        ({"host_network": True}, "host_network"),
                        ({"anonymous_subject": True}, "anonymous_rbac_subject")):
        sig = k8s_workload_posture_oracle({"check_id": "x", "achieved_state": state})
        assert sig.fired and sig.confidence == 0.9 and sig.observed["rule"] == rule


def test_oracle_does_not_fire_on_benign_or_unknown():
    for state in ({}, {"privileged": False}, {"host_network": False}, {"anonymous_subject": False},
                  {"privileged": None}, {"privileged": "maybe"}):
        assert not k8s_workload_posture_oracle({"check_id": "x", "achieved_state": state}).fired
    assert not k8s_workload_posture_oracle("garbage").fired                    # non-mapping → non-fire, no raise
    assert not k8s_workload_posture_oracle({}).fired


def test_oracle_rule_order_privileged_wins():
    sig = k8s_workload_posture_oracle({"achieved_state": {"privileged": True, "host_network": True}})
    assert sig.observed["rule"] == "privileged_container"                      # fixed order, deterministic


# --- the collector translators (pure) ------------------------------------------


def test_pod_controls_only_for_insecure_pods():
    pods = [{"name": "priv", "namespace": "ns", "privileged": True, "host_network": False},
            {"name": "hostnet", "namespace": "ns", "privileged": False, "host_network": True},
            {"name": "both", "namespace": "kube-system", "privileged": True, "host_network": True},
            {"name": "benign", "namespace": "ns", "privileged": False, "host_network": False}]
    controls = k8s_workload_controls(pods=pods)
    ids = {c["check_id"] for c in controls}
    assert "pod:ns/priv:privileged" in ids
    assert "pod:ns/hostnet:hostnetwork" in ids
    assert "pod:kube-system/both:privileged" in ids and "pod:kube-system/both:hostnetwork" in ids
    assert not any("benign" in i for i in ids)                                 # a hardened pod emits nothing


def test_binding_controls_only_for_anonymous_subjects():
    bindings = [{"name": "anon", "role": "cluster-admin", "subjects": ["system:anonymous"]},
                {"name": "unauth", "namespace": "ns", "role": "view", "subjects": ["system:unauthenticated"]},
                {"name": "named", "role": "cluster-admin", "subjects": ["alice", "system:serviceaccount:x:y"]}]
    controls = k8s_workload_controls(bindings=bindings)
    ids = {c["check_id"] for c in controls}
    assert "binding:/anon" in ids and "binding:ns/unauth" in ids
    assert not any("named" in i for i in ids)                                  # a named-subject binding is not anon


def test_controls_totality():
    assert k8s_workload_controls(pods="x", bindings=7) == []                   # non-iterable → total
    assert k8s_workload_controls(pods=[7, {"name": ""}], bindings=[None]) == []


# --- observations (LEADS) + the oracle promotes them ---------------------------


def test_observations_are_leads_keyed_per_control():
    controls = k8s_workload_controls(pods=[{"name": "p", "namespace": "ns", "privileged": True}])
    obs = k8s_workload_observations(controls, seq=1)
    assert len(obs) == 1 and obs[0].subject.key == "k8s-workload:pod:ns/p:privileged"
    assert obs[0].attrs.get("privileged") is True                             # achieved state rides in attrs


# --- egress + fail-closed run + fusion wiring ----------------------------------


def test_egress_from_in_cluster_env(monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.delenv("KUBECONFIG", raising=False)
    assert K8sLiveSensor().egress_hosts == ("10.0.0.1",)


def test_egress_empty_when_no_config(monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("KUBECONFIG", raising=False)
    assert K8sLiveSensor().egress_hosts == ()                                  # coincides with the run() no-op


def test_run_fail_closed_without_kubernetes_client(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    r = K8sLiveSensor().run({}, SimpleNamespace())
    assert r.ok is False and "kubernetes" in r.note and "fail-closed" in r.note.lower()


def test_k8s_live_wired_into_fusion():
    from framework.v2.engage_fusion import _LIVE_SENSORS, _fusion_registry
    from framework.v2.entitlement.models import Capability
    assert "k8s_live" in _LIVE_SENSORS
    s = _fusion_registry().get("k8s_live")
    assert isinstance(s, K8sLiveSensor) and s.tier == "T2" and s.capability == Capability.ACTIVE_RECON


def test_k8s_live_controls_promote_through_reverify():
    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import EdgeKind, GROUNDING_GROUNDED

    controls = k8s_workload_controls(
        pods=[{"name": "p", "namespace": "ns", "privileged": True, "host_network": False},
              {"name": "ok", "namespace": "ns", "privileged": False, "host_network": False}],
        bindings=[{"name": "anon", "role": "cluster-admin", "subjects": ["system:anonymous"]}])
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"controls": controls}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("k8s_live", {}), res, seq=3, slug="alpha")
    assert promoted == 2                                                       # privileged pod + anon binding
    priv = world.get_node("finding:k8s_workload:k8s-workload:pod:ns/p:privileged")
    assert priv is not None and priv.grounding == GROUNDING_GROUNDED
    assert world.get_edge("finding:k8s_workload:k8s-workload:pod:ns/p:privileged",
                          "control:k8s-workload:pod:ns/p:privileged", EdgeKind.EVIDENCES) is not None
    assert world.get_node("finding:k8s_workload:k8s-workload:binding:/anon") is not None
    # the benign pod promoted nothing
    assert not any(n.id.startswith("finding:k8s_workload:") and "ns/ok" in n.id for n in world.all_nodes())
