"""E2 (BUILD-PLAN §E2) — a confirmed IAM privilege-escalation PRIMITIVE projects into the attack graph.

The projection branches on the primitive FAMILY (read from the finding's retained capture):

  * grant_gain (trust-rewrite / PassRole / attach-policy / add-to-group) — mints the base PRINCIPAL + the
    escalated CLOUD_RESOURCE, a HAS_GRANT strict-gain edge, and records the attacker's OWNS over the resource.
  * credential_mint (create-credential-for-target) — mints a CREDENTIAL + PRINCIPAL + VALID_ON and the
    attacker HOLDS the credential, which chains (OWN_VIA_HELD_CREDENTIAL) to OWNS the principal.

A finding whose bug_class is not E2 mints none of this topology.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _finding(primitive: str, param: str) -> AuditFinding:
    return AuditFinding(
        check_id="iam_escalation_primitive", bug_class="iam_escalation_primitive",
        insertion_point=f"iam:{primitive}:{param}", param=param, confidence=0.95,
        confirmed_by="iam_escalation_primitive",
        oracle_context={"iam_escalation_capture": {"escalation": {"primitive": primitive}}})


def _run(finding: AuditFinding):
    report = ScanReport(target="http://t/", active_findings=[finding])
    return AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)


def test_grant_gain_projects_a_strict_gain_grant_and_attacker_ownership() -> None:
    world = _run(_finding("assume_role_trust_rewrite", "base")).world
    ep = "endpoint:base"
    base, resource = f"principal:iam-esc-base:{ep}", f"resource:iam-esc-target:{ep}"

    bn, rn = world.get_node(base), world.get_node(resource)
    assert bn is not None and bn.kind == NodeKind.PRINCIPAL
    assert rn is not None and rn.kind == NodeKind.CLOUD_RESOURCE and rn.attrs.get("escalated") is True

    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.HAS_GRANT and e.src == base and e.dst == resource for e in edges), \
        "the base principal must hold the strict-gain grant over the escalated resource"
    assert any(e.kind == EdgeKind.OWNS and e.src == "attacker:self" and e.dst == resource for e in edges), \
        "the attacker (having reached the escalation-capable base) must OWN the escalated resource"


def test_credential_mint_projects_a_held_credential_that_chains_to_ownership() -> None:
    world = _run(_finding("create_access_key", "tok")).world
    ep = "endpoint:tok"
    cred, principal = f"credential:iam-escalation:{ep}", f"principal:iam-escalation:{ep}"

    cn = world.get_node(cred)
    assert cn is not None and cn.kind == NodeKind.CREDENTIAL and cn.attrs.get("source") == "iam-escalation-mint"
    assert world.get_node(principal) is not None

    edges = list(world.all_edges())
    assert any(e.kind == EdgeKind.HOLDS and e.src == "attacker:self" and e.dst == cred for e in edges), \
        "the attacker must HOLD the credential minted for the target"
    assert any(e.kind == EdgeKind.VALID_ON and e.src == cred and e.dst == principal for e in edges), \
        "the minted credential must be VALID_ON its principal"

    # CHAIN-READY: the projected edges are exactly the premises of OWN_VIA_HELD_CREDENTIAL.
    from framework.v2.worldmodel.attacker import ATTACKER_RULES
    from framework.v2.worldmodel.derivation import derive
    derive(world, ATTACKER_RULES, seq=10_000)
    assert any(e.kind == EdgeKind.OWNS and e.src == "attacker:self" and e.dst == principal
               for e in world.all_edges()), \
        "the held, minted credential must chain (OWN_VIA_HELD_CREDENTIAL) to ownership of the principal"


def test_an_unreadable_primitive_falls_back_to_the_grant_gain_model() -> None:
    # a finding carrying no readable primitive still projects the (general) grant_gain topology, never crashes.
    f = AuditFinding(check_id="iam_escalation_primitive", bug_class="iam_escalation_primitive",
                     insertion_point="iam:x", param="p", confidence=0.9, confirmed_by="iam_escalation_primitive")
    world = _run(f).world
    assert world.get_node("resource:iam-esc-target:endpoint:p") is not None


def test_a_non_e2_finding_does_not_mint_the_escalation_topology() -> None:
    report = ScanReport(target="http://t/", active_findings=[
        AuditFinding(check_id="idor", bug_class="idor", insertion_point="query_value:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state")])
    result = AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report)
    assert result.world.get_node("resource:iam-esc-target:endpoint:id") is None
    assert result.world.get_node("credential:iam-escalation:endpoint:id") is None
