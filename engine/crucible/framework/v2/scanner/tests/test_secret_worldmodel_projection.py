"""E5 (part B) — a confirmed exposed-secret validity projects into the attack graph.

A confirmed `secret_credential_validity` finding must project the E5 achieved effect: the attacker HOLDS a
leaked credential proven VALID, which chains (OWN_VIA_HELD_CREDENTIAL: HOLDS(cred) + VALID_ON(cred->principal)
=> OWNS(principal)) to account takeover — the same achieved-effect topology as an IMDS capture.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _secret_finding(param: str = "token") -> AuditFinding:
    return AuditFinding(check_id="secret_credential_validity", bug_class="secret_credential_validity",
                        insertion_point=f"query_value:{param}", param=param, confidence=0.95,
                        confirmed_by="secret_credential_validity")


def test_secret_validity_projects_a_held_credential_that_chains_to_ownership() -> None:
    report = ScanReport(target="http://t/", active_findings=[_secret_finding("token")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    world = result.world

    ep = "endpoint:token"
    cred, principal = f"credential:secret:{ep}", f"principal:secret:{ep}"

    cn = world.get_node(cred)
    assert cn is not None and cn.kind == NodeKind.CREDENTIAL and cn.attrs.get("source") == "exposed-secret"
    assert world.get_node(principal) is not None

    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.HOLDS and e.src == "attacker:self" and e.dst == cred for e in edges), \
        "the attacker must HOLD the confirmed-valid exposed credential"
    assert any(e.kind == EdgeKind.VALID_ON and e.src == cred and e.dst == principal for e in edges), \
        "the exposed credential must be VALID_ON its principal"

    # CHAIN-READY: the projected edges are exactly the premises of OWN_VIA_HELD_CREDENTIAL; applying that
    # derivation rule yields the achieved-effect OWNS(attacker -> principal) — account takeover.
    from framework.v2.worldmodel.attacker import ATTACKER_RULES
    from framework.v2.worldmodel.derivation import derive
    derive(world, ATTACKER_RULES, seq=10_000)
    assert any(e.kind == EdgeKind.OWNS and e.src == "attacker:self" and e.dst == principal
               for e in world.all_edges()), \
        "the held, valid exposed credential must chain (OWN_VIA_HELD_CREDENTIAL) to ownership of the principal"


def test_a_non_secret_finding_does_not_mint_the_secret_topology() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("credential:secret:endpoint:id") is None
