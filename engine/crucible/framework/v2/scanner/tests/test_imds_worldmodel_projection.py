"""E1-Slice3 — the confirmed IMDS credential-capture projects into the attack graph.

A confirmed `imds_credential_capture` finding must project the E1 achieved effect: the attacker HOLDS a cloud
credential proven valid by a confirming call, which chains (OWN_VIA_HELD_CREDENTIAL: HOLDS(cred) +
VALID_ON(cred->principal) => OWNS(principal)) to account takeover. This is the world-model/attack-path half
the E1 oracle's STATUS listed as blocking work.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _imds_finding(param: str = "token") -> AuditFinding:
    return AuditFinding(check_id="imds_credential_capture", bug_class="imds_credential_capture",
                        insertion_point=f"query_value:{param}", param=param, confidence=0.95,
                        confirmed_by="imds_credential_capture")


def test_imds_capture_projects_a_held_credential_that_chains_to_ownership() -> None:
    report = ScanReport(target="http://t/", active_findings=[_imds_finding("token")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    world = result.world

    ep = "endpoint:token"
    cred, principal = f"credential:imds:{ep}", f"principal:imds:{ep}"

    # the achieved-effect topology: a confirmed metadata credential + its principal
    cn = world.get_node(cred)
    assert cn is not None and cn.kind == NodeKind.CREDENTIAL and cn.attrs.get("source") == "instance-metadata"
    assert world.get_node(principal) is not None

    edges = list(world.all_edges())
    # the attacker HOLDS the captured credential
    assert any(e.kind == EdgeKind.HOLDS and e.src == "attacker:self" and e.dst == cred for e in edges), \
        "the attacker must HOLD the confirmed metadata credential"
    # VALID_ON(cred -> principal) so the held credential is usable
    assert any(e.kind == EdgeKind.VALID_ON and e.src == cred and e.dst == principal for e in edges), \
        "the captured credential must be VALID_ON its principal"

    # CHAIN-READY: the projected edges are exactly the premises of OWN_VIA_HELD_CREDENTIAL
    # (HOLDS(A,C) + VALID_ON(C,T) with C a CREDENTIAL => OWNS(A,T)). Applying that derivation rule directly
    # over the projected graph yields the achieved-effect OWNS(attacker -> principal) — account takeover —
    # proving the projection has the right shape to chain (the orchestrator runs the technique CATALOG here;
    # the ATTACKER_RULES derivation is a separate, existing composition point, exercised directly below).
    from framework.v2.worldmodel.attacker import ATTACKER_RULES
    from framework.v2.worldmodel.derivation import derive
    derive(world, ATTACKER_RULES, seq=10_000)   # forward-chain the achieved-effect rule (mutates in place)
    assert any(e.kind == EdgeKind.OWNS and e.src == "attacker:self" and e.dst == principal
               for e in world.all_edges()), \
        "the held, valid metadata credential must chain (OWN_VIA_HELD_CREDENTIAL) to ownership of the principal"


def test_a_non_imds_finding_does_not_mint_the_imds_topology() -> None:
    # control: the imds projection is keyed on the bug_class, so an unrelated finding mints no imds nodes.
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("credential:imds:endpoint:id") is None
