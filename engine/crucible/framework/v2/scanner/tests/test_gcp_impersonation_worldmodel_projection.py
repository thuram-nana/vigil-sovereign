"""E3 — a confirmed GCP service-account impersonation projects into the attack graph.

A confirmed `gcp_sa_impersonation` finding must project the E3 achieved effect: the attacker HOLDS a minted
short-lived token proven VALID as the target service-account B, which chains (OWN_VIA_HELD_CREDENTIAL:
HOLDS(cred) + VALID_ON(cred->principal) => OWNS(principal)) to ownership of B — the same achieved-effect
topology as an IMDS/secret capture, seeded by a confirmed impersonation token.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _impersonation_finding(param: str = "sa") -> AuditFinding:
    return AuditFinding(check_id="gcp_sa_impersonation", bug_class="gcp_sa_impersonation",
                        insertion_point=f"query_value:{param}", param=param, confidence=0.95,
                        confirmed_by="gcp_sa_impersonation")


def test_impersonation_projects_a_held_credential_that_chains_to_ownership() -> None:
    report = ScanReport(target="http://t/", active_findings=[_impersonation_finding("sa")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    world = result.world

    ep = "endpoint:sa"
    cred, principal = f"credential:gcp-impersonation:{ep}", f"principal:gcp-impersonation:{ep}"

    cn = world.get_node(cred)
    assert cn is not None and cn.kind == NodeKind.CREDENTIAL and cn.attrs.get("source") == "gcp-impersonation"
    assert world.get_node(principal) is not None

    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.HOLDS and e.src == "attacker:self" and e.dst == cred for e in edges), \
        "the attacker must HOLD the confirmed-valid minted impersonation token"
    assert any(e.kind == EdgeKind.VALID_ON and e.src == cred and e.dst == principal for e in edges), \
        "the impersonation token must be VALID_ON the target-SA principal"

    # CHAIN-READY: the projected edges are exactly the premises of OWN_VIA_HELD_CREDENTIAL; applying that
    # derivation rule yields the achieved-effect OWNS(attacker -> principal) — ownership of the target SA.
    from framework.v2.worldmodel.attacker import ATTACKER_RULES
    from framework.v2.worldmodel.derivation import derive
    derive(world, ATTACKER_RULES, seq=10_000)
    assert any(e.kind == EdgeKind.OWNS and e.src == "attacker:self" and e.dst == principal
               for e in world.all_edges()), \
        "the held, valid impersonation token must chain (OWN_VIA_HELD_CREDENTIAL) to ownership of the target SA"


def test_a_non_refiring_finding_under_verify_grants_nothing() -> None:
    # Under verify=True the projection mints the E3 topology ONLY if the finding's retained proof re-fires
    # NOW. A finding carrying no re-verifiable oracle_context must grant the attacker nothing.
    report = ScanReport(target="http://t/", active_findings=[_impersonation_finding("sa")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report, verify=True)
    assert result.world.get_node("credential:gcp-impersonation:endpoint:sa") is None


def test_a_non_e3_finding_does_not_mint_the_impersonation_topology() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("credential:gcp-impersonation:endpoint:id") is None
