"""
Phase C2 · K8s — LIVE read-only Kubernetes RBAC posture collector (sensors.k8s_live) + its new
achieved-state oracle (verify.oracles.k8s_workload_posture_oracle).

Near-zero-FP the hard way (the first cut over-promoted and was BLOCKed): the ONE confirmed FACT is an
ANONYMOUS subject (system:anonymous / system:unauthenticated) bound to a genuinely DANGEROUS built-in role
(cluster-admin / admin / edit). The built-in system:public-info-viewer binding to system:unauthenticated —
present in EVERY cluster — must mint NOTHING; privileged/host-network pods are leads, not facts (deferred).
"""

from __future__ import annotations

from types import SimpleNamespace

from framework.v2.sensors.k8s_live import (
    K8sLiveSensor,
    k8s_workload_controls,
    k8s_workload_observations,
)
from framework.v2.verify.oracles import k8s_workload_posture_oracle


def _binding(name, role, subjects, namespace="", role_kind="ClusterRole",
             role_apigroup="rbac.authorization.k8s.io"):
    return {"name": name, "namespace": namespace, "role": role, "subjects": subjects,
            "role_kind": role_kind, "role_apigroup": role_apigroup}


# --- the new oracle: re-derives (anonymous ∧ dangerous-role) from the RAW binding ---


def test_oracle_fires_on_anonymous_dangerous_role():
    for role in ("cluster-admin", "admin", "edit", "Cluster-Admin"):
        sig = k8s_workload_posture_oracle(
            {"check_id": "b", "achieved_state": {"subjects": ["system:unauthenticated"], "role": role}})
        assert sig.fired and sig.confidence == 0.9 and sig.observed["rule"] == "anonymous_privileged_binding"
    # system:anonymous too
    assert k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["alice", "system:anonymous"], "role": "cluster-admin"}}).fired


def test_oracle_does_not_fire_on_benign_or_non_dangerous():
    # THE critical negative control: the built-in public-info-viewer binding present on EVERY cluster
    assert not k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["system:authenticated", "system:unauthenticated"],
                            "role": "system:public-info-viewer"}}).fired
    # anonymous bound to a NON-dangerous / custom role → not a fact (a lead)
    assert not k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["system:unauthenticated"], "role": "view"}}).fired
    assert not k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["system:anonymous"], "role": "my-custom-role"}}).fired
    # dangerous role bound to a NAMED (authenticated) subject → not anonymous → not a fact
    assert not k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["alice", "system:serviceaccount:x:y"], "role": "cluster-admin"}}).fired
    # LOW regression: a CUSTOM namespaced Role merely NAMED "edit" is not the powerful built-in ClusterRole
    assert not k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["system:anonymous"], "role": "edit",
                            "role_kind": "Role", "role_apigroup": "rbac.authorization.k8s.io"}}).fired
    assert not k8s_workload_posture_oracle(          # a non-RBAC apiGroup is likewise not the built-in
        {"achieved_state": {"subjects": ["system:anonymous"], "role": "admin",
                            "role_kind": "ClusterRole", "role_apigroup": "example.com"}}).fired
    # but the genuine built-in ClusterRole DOES fire
    assert k8s_workload_posture_oracle(
        {"achieved_state": {"subjects": ["system:anonymous"], "role": "cluster-admin",
                            "role_kind": "ClusterRole", "role_apigroup": "rbac.authorization.k8s.io"}}).fired
    # malformed / absent
    assert not k8s_workload_posture_oracle("garbage").fired
    assert not k8s_workload_posture_oracle({"achieved_state": {"subjects": "x", "role": 5}}).fired
    assert not k8s_workload_posture_oracle({}).fired


# --- the collector translators (pure): only anon bindings, excluding the benign default ---


def test_binding_controls_exclude_the_benign_default():
    bindings = [
        _binding("system:public-info-viewer", "system:public-info-viewer",
                 ["system:authenticated", "system:unauthenticated"]),      # benign default → excluded
        _binding("anon-admin", "cluster-admin", ["system:anonymous"]),     # critical → control
        _binding("anon-view", "view", ["system:unauthenticated"], namespace="ns"),  # anon+non-dangerous → control (lead)
        _binding("named-admin", "cluster-admin", ["alice"]),               # not anonymous → excluded
    ]
    ids = {c["check_id"] for c in k8s_workload_controls(bindings=bindings)}
    assert "binding:/anon-admin" in ids and "binding:ns/anon-view" in ids
    assert "binding:/system:public-info-viewer" not in ids                 # the every-cluster default: NO control
    assert not any("named-admin" in i for i in ids)


def test_a_default_cluster_mints_and_promotes_nothing():
    # the BLOCK regression, proven end-to-end: a fully benign default cluster (only the public-info-viewer
    # binding) yields NO controls, NO observations, and NO facts.
    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel

    default_only = [_binding("system:public-info-viewer", "system:public-info-viewer",
                             ["system:authenticated", "system:unauthenticated"])]
    controls = k8s_workload_controls(bindings=default_only)
    assert controls == []
    assert k8s_workload_observations(controls, seq=1) == []
    world = WorldModel()
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"controls": controls}))
    assert _reverify(world, FusionTask("k8s_live", {}), res, seq=1, slug="alpha") == 0
    assert not any(n.id.startswith("finding:k8s_workload:") for n in world.all_nodes())


def test_controls_totality():
    assert k8s_workload_controls(bindings=7) == []
    assert k8s_workload_controls(bindings=[7, {"name": ""}, {"name": "x", "subjects": "y"}]) == []


def test_observations_are_leads_keyed_per_control():
    controls = k8s_workload_controls(bindings=[_binding("anon-admin", "cluster-admin", ["system:anonymous"])])
    obs = k8s_workload_observations(controls, seq=1)
    assert len(obs) == 1 and obs[0].subject.key == "k8s-workload:binding:/anon-admin"
    assert obs[0].attrs.get("role") == "cluster-admin" and obs[0].attrs.get("anonymous_subject") == "system:anonymous"


# --- egress robustness + fail-closed run + fusion wiring ------------------------


def test_egress_from_in_cluster_env(monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.delenv("KUBECONFIG", raising=False)
    assert K8sLiveSensor().egress_hosts == ("10.0.0.1",)


def test_egress_from_kubeconfig_file(tmp_path, monkeypatch):
    kc = tmp_path / "kubeconfig"
    kc.write_text("apiVersion: v1\ncurrent-context: c\ncontexts:\n- name: c\n  context:\n    cluster: cl\n"
                  "clusters:\n- name: cl\n  cluster:\n    server: https://api.my-cluster.example:6443\n",
                  encoding="utf-8")
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setenv("KUBECONFIG", f"{kc}{__import__('os').pathsep}/nonexistent")   # multi-path, first wins
    assert K8sLiveSensor().egress_hosts == ("api.my-cluster.example",)


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


def test_anonymous_cluster_admin_promotes_through_reverify():
    from framework.v2.engage_fusion import FusionTask, _reverify
    from framework.v2.worldmodel.graph import WorldModel
    from framework.v2.worldmodel.models import EdgeKind, GROUNDING_GROUNDED

    controls = k8s_workload_controls(bindings=[
        _binding("anon-admin", "cluster-admin", ["system:anonymous"]),      # critical → FACT
        _binding("anon-view", "view", ["system:unauthenticated"])])        # anon+non-dangerous → LEAD only
    res = SimpleNamespace(ok=True, result=SimpleNamespace(output={"controls": controls}))
    world = WorldModel()
    promoted = _reverify(world, FusionTask("k8s_live", {}), res, seq=3, slug="alpha")
    assert promoted == 1                                                    # only the anonymous cluster-admin
    fid = "finding:k8s_workload:k8s-workload:binding:/anon-admin"
    node = world.get_node(fid)
    assert node is not None and node.grounding == GROUNDING_GROUNDED
    assert world.get_edge(fid, "control:k8s-workload:binding:/anon-admin", EdgeKind.EVIDENCES) is not None
    assert world.get_node("finding:k8s_workload:k8s-workload:binding:/anon-view") is None   # the lead is not a fact
