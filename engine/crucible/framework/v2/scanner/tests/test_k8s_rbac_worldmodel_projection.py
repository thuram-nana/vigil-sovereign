"""E4 (part B) — a confirmed anonymous-privileged K8s-RBAC binding projects into the attack graph.

A confirmed `k8s_workload_misconfiguration` finding must project the E4 achieved effect: an UNAUTHENTICATED
subject bound to cluster-admin. Unlike an IMDS/secret capture, NO credential is HELD — reaching the
kube-apiserver IS cluster-admin — so the projection mints the cluster control-plane (a crown CLOUD_RESOURCE)
and the secret store (a crown DATASTORE) chained by TRUSTS_FOR from the reached endpoint, and best_paths must
yield the attacker -> endpoint -> cluster -> secrets crown-jewel route.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _k8s_finding(param: str = "anon") -> AuditFinding:
    return AuditFinding(check_id="k8s_workload_misconfiguration", bug_class="k8s_workload_misconfiguration",
                        insertion_point=f"k8s:rbac:{param}", param=param, confidence=0.9,
                        confirmed_by="k8s_workload_posture")


def test_anonymous_privileged_binding_projects_a_crown_jewel_route() -> None:
    report = ScanReport(target="http://t/", active_findings=[_k8s_finding("anon")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    world = result.world

    ep = "endpoint:anon"
    cluster, secrets = f"cluster:{ep}", f"secrets:{ep}"

    cn = world.get_node(cluster)
    assert cn is not None and cn.kind == NodeKind.CLOUD_RESOURCE, "the cluster control-plane must be minted"
    assert cn.attrs.get("anonymous_cluster_admin") is True
    sn = world.get_node(secrets)
    assert sn is not None and sn.kind == NodeKind.DATASTORE, "the cluster secret store must be minted"

    # NO credential is HELD — the achieved effect is unauthenticated, so reaching the surface hands over the
    # resource behind it (the idor/bola topology), NOT a HOLDS(credential) chain.
    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.TRUSTS_FOR and e.src == ep and e.dst == cluster for e in edges), \
        "reaching the anonymous-bound API server must grant the cluster control-plane"
    assert any(e.kind == EdgeKind.TRUSTS_FOR and e.src == cluster and e.dst == secrets for e in edges), \
        "cluster-admin must reach the secret store"
    assert not any(e.kind == EdgeKind.HOLDS for e in edges), \
        "the anonymous case holds NO credential (that is E1/E5, not E4)"

    # the achieved-effect crown-jewel route must be discoverable: attacker -> endpoint -> cluster -> secrets.
    assert result.attack_paths, "a confirmed anonymous-cluster-admin binding must yield an attack path"
    assert any(secrets in {s.dst for s in p.steps} for p in result.attack_paths), \
        "a projected path must reach the cluster secret store (crown jewel)"


def test_a_demoted_finding_grants_no_topology_when_reverified() -> None:
    # populate_worldmodel with verify=True mints a finding's derivatives ONLY if its proof re-fires; a k8s
    # finding carrying no re-firing oracle_context must grant NOTHING (no cluster/secrets nodes).
    report = ScanReport(target="http://t/", active_findings=[_k8s_finding("stale")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report, verify=True)
    ep = "endpoint:stale"
    assert result.world.get_node(f"cluster:{ep}") is None, \
        "a finding whose proof does not re-fire must project no cluster control-plane"
    assert result.world.get_node(f"secrets:{ep}") is None


def test_a_non_k8s_finding_does_not_mint_the_k8s_topology() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("cluster:endpoint:id") is None
    assert result.world.get_node("secrets:endpoint:id") is None
