"""E4 TIER-2 — a confirmed dangerous-verb RBAC grant projects into the attack graph.

The achieved effect matches TIER-1's shape rather than E1/E5's: the granted subject (system:anonymous, the
namespace-default ServiceAccount, or system:authenticated) holds NO credential, so reaching the kube-apiserver
AS that subject IS the grant. The projection therefore mints the cluster control-plane (a crown
CLOUD_RESOURCE) and the secret store (a crown DATASTORE) chained by TRUSTS_FOR from the reached endpoint —
the idor/bola datastore topology, NOT the credential-HOLD chain.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _grant_finding(param: str = "rbacgrant") -> AuditFinding:
    return AuditFinding(check_id="k8s_rbac_privilege_grant", bug_class="k8s_rbac_privilege_grant",
                        insertion_point=f"k8s:rbac:{param}", param=param, confidence=0.9,
                        confirmed_by="k8s_rbac_verb_grant")


def test_a_confirmed_verb_grant_projects_a_crown_jewel_route() -> None:
    report = ScanReport(target="http://t/", active_findings=[_grant_finding("rbacgrant")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    world = result.world

    ep = "endpoint:rbacgrant"
    cluster, secrets = f"cluster:{ep}", f"secrets:{ep}"

    cn = world.get_node(cluster)
    assert cn is not None and cn.kind == NodeKind.CLOUD_RESOURCE, "the cluster control-plane must be minted"
    assert cn.attrs.get("dangerous_rbac_grant") is True
    sn = world.get_node(secrets)
    assert sn is not None and sn.kind == NodeKind.DATASTORE, "the cluster secret store must be minted"

    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.TRUSTS_FOR and e.src == ep and e.dst == cluster for e in edges), \
        "reaching the API server as the granted subject must grant the control-plane"
    assert any(e.kind == EdgeKind.TRUSTS_FOR and e.src == cluster and e.dst == secrets for e in edges), \
        "the dangerous grant must reach the secret store"
    assert not any(e.kind == EdgeKind.HOLDS for e in edges), \
        "the granted subject holds NO credential (that is E1/E5, not E4)"

    assert result.attack_paths, "a confirmed dangerous verb-grant must yield an attack path"
    assert any(secrets in {s.dst for s in p.steps} for p in result.attack_paths), \
        "a projected path must reach the cluster secret store (crown jewel)"


def test_a_demoted_finding_grants_no_topology_when_reverified() -> None:
    # verify=True mints a finding's derivatives ONLY if its retained proof re-fires; a finding carrying no
    # re-firing oracle_context must grant NOTHING.
    report = ScanReport(target="http://t/", active_findings=[_grant_finding("stale")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report, verify=True)
    ep = "endpoint:stale"
    assert result.world.get_node(f"cluster:{ep}") is None, \
        "a finding whose proof does not re-fire must project no cluster control-plane"
    assert result.world.get_node(f"secrets:{ep}") is None


def test_a_non_e4t2_finding_does_not_mint_the_grant_topology() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("cluster:endpoint:id") is None
    assert result.world.get_node("secrets:endpoint:id") is None
