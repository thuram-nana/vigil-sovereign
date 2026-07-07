"""
Intelligence Engine ↔ live loop integration.

Pins the seams that wire the engine into engage/scan/planner without loosening the
doctrine: intel assets and attack facts coexist on ONE world-model with disjoint id
namespaces and a non-inverting monotonic clock; scan-observed surface becomes
asset-tier Observations (never attack-tier); VOI ordering doesn't change WHAT offline
recon resolves; and gated predictions become goal-tree leaves the planner can NEVER
auto-claim.
"""

from __future__ import annotations

from pathlib import Path

from framework.v2.intel.collectors import DEFAULT_COLLECTORS
from framework.v2.intel.from_scan import observations_from_report
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.planner import ReconPlanner
from framework.v2.intel.project import project_observation
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.transport import FixtureTransport
from framework.v2.planner.seed import seed_tree
from framework.v2.scanner.engine import AuditFinding
from framework.v2.scanner.campaign import ScanReport
from framework.v2.scanner.fingerprint import Fingerprint, TechMatch
from framework.v2.scanner.orchestrator import AutonomousCampaign
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import NodeKind

_FIX = Path(__file__).resolve().parents[1] / "collectors" / "fixtures"


def _report(target="https://app.example.com/", *, finding=True, fp=True) -> ScanReport:
    findings = []
    if finding:
        findings.append(AuditFinding(
            check_id="ssrf-1", bug_class="ssrf", insertion_point="query", param="url",
            endpoint="https://app.example.com/fetch", confidence=0.9, confirmed_by="oracle"))
    fingerprint = Fingerprint(matches=[TechMatch(name="nginx", category="server", confidence=0.8)]) if fp else None
    return ScanReport(target=target, active_findings=findings, fingerprint=fingerprint)


# ---- adapter: scan surface → asset-tier Observations ------------------------


def test_from_scan_mints_asset_tier_only() -> None:
    obs = observations_from_report(_report(), seq=0)
    ids = {o.subject.node_id for o in obs} | {o.object.node_id for o in obs if o.object}
    assert "domain:app.example.com" in ids
    assert any(o.object and o.object.node_id == "application:nginx" for o in obs)  # RUNS edge
    # strictly asset tier — never collides with the attack graph's endpoint:/finding:
    assert all(not i.startswith(("endpoint:", "finding:")) for i in ids)


def test_from_scan_ingests_into_worldmodel() -> None:
    world = WorldModel()
    ing = IntelIngest(world)
    ing.ingest(observations_from_report(_report(), seq=0))
    n = world.get_node("domain:app.example.com")
    # self-observed target is well-believed (a couple of observations sit above the 0.5
    # prior; belief saturates slowly by design — corroboration never runs to certainty).
    assert n is not None and n.belief_mean > 0.65 and n.confidence == 1.0


# ---- shared world-model: intel + attack coexist, clock never inverts --------


def test_chain_findings_accretes_onto_shared_intel_world() -> None:
    world = WorldModel()
    # intel recon already put an asset on the graph at a low seq
    ing = IntelIngest(world)
    ing.ingest(observations_from_report(_report(), seq=0))
    hw = ing.high_water()

    auto = AutonomousCampaign(_no_send).chain_findings(_report(), world=world, seq_base=hw + 1)
    assert auto.world is world                                  # same instance
    assert world.get_node("domain:app.example.com") is not None  # intel asset survives
    ep = world.get_node("endpoint:url")
    assert ep is not None                                        # attack fact accreted
    assert ep.first_seen >= hw + 1                              # projected ABOVE the recon band


def test_chain_findings_default_is_unchanged() -> None:
    # world=None / seq_base=1 reproduces standalone behaviour exactly
    auto = AutonomousCampaign(_no_send).chain_findings(_report())
    ep = auto.world.get_node("endpoint:url")
    assert ep is not None and ep.first_seen == 1


def _no_send(_request):
    raise RuntimeError("must not send")


# ---- VOI ordering doesn't change WHAT offline recon resolves ----------------


def test_run_collectors_voi_order_preserves_result() -> None:
    seeds = [canonicalize(NodeKind.DOMAIN, "company.com")]
    plain = IntelIngest(WorldModel()).run_collectors(
        seeds, list(DEFAULT_COLLECTORS), FixtureTransport(_FIX), max_depth=2)
    voi = IntelIngest(WorldModel()).run_collectors(
        seeds, list(DEFAULT_COLLECTORS), FixtureTransport(_FIX), max_depth=2,
        planner=ReconPlanner(list(DEFAULT_COLLECTORS)))
    assert {e.canonical_id for e in plain.entities} == {e.canonical_id for e in voi.entities}
    assert any(e.owned_by for e in voi.entities)


# ---- goal-tree seeding: entities dispatchable, predictions GATED ------------


class _FakeMember:
    def __init__(self, kind, key):
        self.kind = kind
        self.node_id = f"{kind.value}:{key}"
        self.key = key


class _FakeEntity:
    def __init__(self, key):
        self.members = [_FakeMember(NodeKind.DOMAIN, key)]


class _FakePrediction:
    def __init__(self, key, prior=0.4):
        self.node_id = f"domain:{key}"
        self.prior = prior
        self.rationale = f"sibling {key}"


def test_seed_tree_entities_become_dispatchable_surfaces() -> None:
    tree = seed_tree(archetype_slug="generic-web", target_url="https://api.co/",
                     entities=[_FakeEntity("api.co")])
    surfaces = {n.surface for n in tree.nodes.values() if n.is_leaf()}
    assert "https://api.co" in surfaces          # real asset → dispatchable URL surface


def test_seed_tree_predictions_are_gated_and_never_claimed() -> None:
    preds = [_FakePrediction("staging.api.co"), _FakePrediction("dev.api.co")]
    tree = seed_tree(archetype_slug="generic-web", target_url="https://api.co/", predictions=preds)
    pred_leaves = [n for n in tree.nodes.values()
                   if n.is_leaf() and n.bug_class == "asset-existence"]
    assert len(pred_leaves) == 2
    assert all(n.status == "deferred" for n in pred_leaves)          # born deferred
    # ALL three planner selectors only consider open/claimed leaves (they share
    # open_leaves()), so a prediction is NEVER auto-claimed and NEVER dispatched.
    for selector in (tree.best_open_leaf, tree.best_open_leaf_voi):
        for _ in range(30):
            leaf = selector()
            if leaf is None:
                break
            assert leaf.bug_class != "asset-existence"
            tree.mark_status(leaf.id, "failed")
    assert all(n.status == "deferred" for n in pred_leaves)          # still gated after draining
    # open_leaves() (the shared filter) never yields a deferred prediction
    assert all(l.bug_class != "asset-existence" for l in tree.open_leaves())


def test_seed_tree_prediction_surface_is_not_a_dispatchable_url() -> None:
    tree = seed_tree(archetype_slug="generic-web", predictions=[_FakePrediction("x.api.co")])
    pred = next(n for n in tree.nodes.values() if n.bug_class == "asset-existence")
    # kind:key, not https:// — even if un-deferred it wouldn't be dispatched without a URL
    assert pred.surface == "domain:x.api.co" and not pred.surface.startswith("http")
