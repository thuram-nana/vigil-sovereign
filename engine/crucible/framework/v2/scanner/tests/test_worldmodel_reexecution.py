"""
TRUTHENOVATION T1 — the world-model is a UNIVERSAL veracity choke point.

``populate_worldmodel`` (campaign.py) must RE-EXECUTE each finding's retained proof before it
writes a FINDING node: a node earns an ``oracle:``-provenance (the tier the graph reads back as a
proven fact) ONLY if its ``oracle_context`` re-fires NOW. A finding recorded ``confirmed`` whose
proof no longer reproduces is written with a DOWNGRADED ``demoted:``-provenance that classifies
UNGROUNDED, so the world-model can never carry an ``oracle:`` FACT node whose proof does not
re-fire. Recon/ENDPOINT nodes are untouched — they are not oracle-proven facts.

The findings here are synthetic (fast, deterministic): a REAL firing FindingContext built via
``confirm_finding`` for the fact, and a non-divergent context for the stale/tampered case, mirroring
``veracity/tests/test_finding_admission.py``.
"""

from __future__ import annotations

from framework.v2.scanner.campaign import ScanReport, populate_worldmodel
from framework.v2.scanner.engine import AuditFinding
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import (
    GROUNDING_GROUNDED,
    EdgeKind,
    NodeKind,
    classify_provenance,
)

_BASE = {"status": 200, "body": "No results."}
_DIVERGENT = {"status": 200, "body": "id=1 alice user\nid=2 bob admin\nid=3 carol user"}
_DISC = {"dimensions": ["status", "length", "lexical"]}


def _ctx(mutated: dict) -> dict:
    return FindingContext.from_http_responses(
        _BASE, mutated, bug_class="boolean_sqli", discriminator=_DISC).model_dump(mode="json")


def _finding(param: str, ctx: dict) -> AuditFinding:
    """A serialized AuditFinding whose confirmed_by/confidence come from the REAL oracle re-fire
    over ``ctx`` (so the recorded metadata matches what reverification produces)."""
    c = confirm_finding(finding={"bug_class": "boolean_sqli"},
                        context=FindingContext.model_validate(ctx))
    return AuditFinding(
        check_id="s1", bug_class="boolean_sqli", insertion_point=f"query:{param}", param=param,
        confidence=c.confidence if c else 0.5,
        confirmed_by=c.confirmed_by.value if c else "differential_response",
        oracle_context=ctx,
    )


def _finding_node(world: WorldModel, param: str):
    return world.get_node(f"finding:boolean_sqli:query:{param}")


def test_refiring_finding_node_keeps_oracle_provenance() -> None:
    # a finding whose retained proof RE-FIRES → oracle: provenance, classified as a grounded fact.
    report = ScanReport(target="http://t/", active_findings=[_finding("good", _ctx(_DIVERGENT))])
    world = WorldModel()
    populate_worldmodel(report, world, seq=1)

    n = _finding_node(world, "good")
    assert n is not None
    assert n.provenance.startswith("oracle:")
    assert n.grounding == GROUNDING_GROUNDED == "grounded"
    assert n.attrs.get("bug_class") == "boolean_sqli"
    assert n.attrs.get("confirmed_by") == "differential_response"
    assert "grounding" not in n.attrs  # a fact carries no demoted marker
    # the EVIDENCES edge to its endpoint is grounded too
    ev = world.get_edge(n.id, "endpoint:good", EdgeKind.EVIDENCES)
    assert ev is not None and ev.provenance.startswith("oracle:") and ev.grounding == "grounded"


def test_nonrefiring_finding_node_is_demoted_and_not_grounded() -> None:
    # recorded confirmed (real confirmed_by/confidence), but the retained context is NON-divergent
    # → the oracle does NOT re-fire → the node is demoted, NOT a grounded fact.
    stale = AuditFinding(
        check_id="s1", bug_class="boolean_sqli", insertion_point="query:stale", param="stale",
        confidence=0.9, confirmed_by="differential_response", oracle_context=_ctx(_BASE))
    report = ScanReport(target="http://t/", active_findings=[stale])
    world = WorldModel()
    populate_worldmodel(report, world, seq=1)

    n = _finding_node(world, "stale")
    assert n is not None
    assert n.provenance.startswith("demoted:")
    assert n.grounding != "grounded"            # NOT read back as a fact
    assert classify_provenance(n.provenance) != GROUNDING_GROUNDED
    assert n.attrs.get("grounding") == "demoted"  # queryable marker: proof did not re-fire
    # the EVIDENCES edge is downgraded the same way
    ev = world.get_edge(n.id, "endpoint:stale", EdgeKind.EVIDENCES)
    assert ev is not None and ev.provenance.startswith("demoted:") and ev.grounding != "grounded"


def test_tampered_evidence_finding_is_demoted() -> None:
    # a genuine firing context whose retained MUTATED response was altered to match the baseline
    # (divergence removed) — the classic tampered-certificate case — must demote, never stay a fact.
    ctx = _ctx(_DIVERGENT)
    ctx["mutated"] = dict(ctx["baseline"])   # tamper: kill the divergence the oracle keyed on
    tampered = AuditFinding(
        check_id="s1", bug_class="boolean_sqli", insertion_point="query:evil", param="evil",
        confidence=0.9, confirmed_by="differential_response", oracle_context=ctx)
    world = WorldModel()
    populate_worldmodel(ScanReport(target="http://t/", active_findings=[tampered]), world, seq=1)
    n = _finding_node(world, "evil")
    assert n is not None and n.provenance.startswith("demoted:") and n.grounding != "grounded"


def test_finding_with_no_retained_proof_is_demoted() -> None:
    # oracle_context is None → nothing to re-fire → demoted (fail-closed), never a fact.
    f = AuditFinding(check_id="s1", bug_class="idor", insertion_point="query:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state", oracle_context=None)
    world = WorldModel()
    populate_worldmodel(ScanReport(target="http://t/", active_findings=[f]), world, seq=1)
    n = world.get_node("finding:idor:query:id")
    assert n is not None and n.provenance.startswith("demoted:") and n.grounding != "grounded"


def _chain(report: ScanReport, *, verify: bool):
    """Run the full attack-graph projection (populate_worldmodel + chain_findings) the console
    ``/api/worldmodel/`` endpoint rebuilds from a stored report. ``verify=True`` mirrors the
    console/stored-projection boundary (re-execute each finding's proof)."""
    from framework.v2.scanner.orchestrator import AutonomousCampaign
    return AutonomousCampaign(lambda req: {"status": 200, "body": ""}).chain_findings(report, verify=verify)


def test_refiring_finding_spawns_grounded_attack_derivatives_under_verify() -> None:
    # under verify=True (the stored-projection boundary), a re-firing finding STILL grants a
    # grounded attacker capability — the T1 gate must not over-skip a legitimate fact's derivatives.
    report = ScanReport(target="http://t/", active_findings=[_finding("good", _ctx(_DIVERGENT))])
    world = _chain(report, verify=True).world
    grounded = [e for e in world.all_edges()
                if e.provenance.startswith("finding:") and e.grounding == GROUNDING_GROUNDED]
    assert grounded, "a re-firing finding must still spawn a grounded attacker capability under verify"


def test_nonrefiring_finding_spawns_no_grounded_derivatives_or_paths_under_verify() -> None:
    # RED-PEN BLOCK-1 regression: at the stored-projection boundary (verify=True — what the console
    # /api/worldmodel handler passes), a recorded-confirmed finding whose retained proof does NOT
    # re-fire must grant the attacker NOTHING — no grounded finding:-provenance reach/topology edge
    # or node, and no attack path. (The demoted finding node itself is still recorded by
    # populate_worldmodel as UNGROUNDED; it just spawns no attacker capability.)
    f = AuditFinding(check_id="s1", bug_class="idor", insertion_point="query:id", param="id",
                     confidence=0.9, confirmed_by="achieved_state", oracle_context=None)
    result = _chain(ScanReport(target="http://t/", active_findings=[f]), verify=True)
    world = result.world
    grounded_edges = [e for e in world.all_edges()
                      if e.provenance.startswith("finding:") and e.grounding == GROUNDING_GROUNDED]
    grounded_nodes = [n for n in world.all_nodes()
                      if n.kind != NodeKind.ENDPOINT and n.provenance.startswith("finding:")
                      and n.grounding == GROUNDING_GROUNDED]
    assert grounded_edges == [], "a non-re-firing finding spawned a grounded attack-graph edge"
    assert grounded_nodes == [], "a non-re-firing finding spawned a grounded topology node"
    assert result.attack_paths == [], "a non-re-firing finding yielded an attack path"


def test_endpoint_nodes_are_unaffected() -> None:
    # the ENDPOINT (recon surface) node keeps its scan: provenance whether or not the finding is a
    # fact — recon nodes are legitimately not oracle-proven and must not be touched by the T1 gate.
    report = ScanReport(target="http://t/", active_findings=[
        _finding("good", _ctx(_DIVERGENT)),
        AuditFinding(check_id="s1", bug_class="boolean_sqli", insertion_point="query:stale",
                     param="stale", confidence=0.9, confirmed_by="differential_response",
                     oracle_context=_ctx(_BASE)),
    ])
    world = WorldModel()
    populate_worldmodel(report, world, seq=1)
    for param in ("good", "stale"):
        ep = world.get_node(f"endpoint:{param}")
        assert ep is not None
        assert ep.provenance == "scan:http://t/"
        assert not ep.provenance.startswith(("oracle:", "demoted:"))
