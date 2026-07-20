"""
Intel reasoning core — canonicalization, the Observation, fusion, and the projection
keystone. The properties that make it "reason, not collect": belief that RISES on
corroboration and FALLS on refutation, fusion that saturates without runaway, and
"unknown stays unknown" for worthless sources.
"""

from __future__ import annotations

from framework.v2.intel.fuse import fuse_observations
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.project import observation_to_evidence, project_observation
from framework.v2.intel.refs import ArtifactTier, canonicalize
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import NodeKind
from framework.v2.worldmodel.store import from_json, to_json


def _dobs(source, rel=Reliability.A, cred=Credibility.C1, conf=0.9,
          pol=Polarity.AFFIRMS, seq=1, dom="api.acme.com"):
    return Observation(
        obs_id=f"{source}-{seq}", source=source, source_kind=IntelSourceKind.DNS,
        subject=canonicalize(NodeKind.DOMAIN, dom),
        source_reliability=SourceReliability(reliability=rel, credibility=cred),
        confidence=conf, polarity=pol, seq=seq)


# ---- canonicalization --------------------------------------------------------


def test_canonicalize_normalizes_and_is_idempotent() -> None:
    assert canonicalize(NodeKind.DOMAIN, "API.Acme.COM.").node_id == "domain:api.acme.com"
    assert canonicalize(NodeKind.ASN, "as 64501").node_id == "asn:AS64501"
    assert canonicalize(NodeKind.NETBLOCK, "10.15.4.7/24").node_id == "netblock:10.15.4.0/24"
    assert canonicalize(NodeKind.HOST, "10.0.0.1").node_id == "host:10.0.0.1"
    r = canonicalize(NodeKind.DOMAIN, "api.acme.com")
    assert canonicalize(NodeKind.DOMAIN, r.key).node_id == r.node_id  # idempotent


def test_entity_ref_tiers() -> None:
    assert canonicalize(NodeKind.HOST, "10.0.0.1").tier is ArtifactTier.ASSET
    assert canonicalize(NodeKind.ASN, "AS1").tier is ArtifactTier.OWNER
    assert canonicalize(NodeKind.DOMAIN, "x.com").is_asset_tier


def test_source_reliability_weight() -> None:
    assert SourceReliability(reliability=Reliability.A, credibility=Credibility.C1).weight() == 1.0
    assert SourceReliability(reliability=Reliability.F, credibility=Credibility.C6).weight() == 0.0  # unjudgeable
    assert SourceReliability(calibrated_prior=0.7).weight() == 0.7


# ---- fusion ------------------------------------------------------------------


def test_fusion_corroboration_saturates_without_runaway() -> None:
    one = fuse_observations([_dobs("a")]).belief_mean
    three = fuse_observations([_dobs("a", seq=1), _dobs("b", seq=2), _dobs("c", seq=3)]).belief_mean
    assert three > one
    assert three < 0.99   # saturates (noisy-OR), never runs to certainty on 3 obs


def test_fusion_contested_lands_at_half() -> None:
    fb = fuse_observations([_dobs("a", seq=1), _dobs("b", pol=Polarity.REFUTES, seq=2)])
    assert abs(fb.belief_mean - 0.5) < 0.05 and fb.contested


def test_fusion_worthless_source_is_unknown() -> None:
    fb = fuse_observations([_dobs("x", rel=Reliability.F, cred=Credibility.C6)])
    assert abs(fb.belief_mean - 0.5) < 1e-9 and fb.effective_n == 0.0  # unknown stays unknown


def test_fusion_dedupes_per_source() -> None:
    # one source repeating itself is not independent corroboration
    repeated = fuse_observations([_dobs("a", seq=1), _dobs("a", seq=2), _dobs("a", seq=3)])
    single = fuse_observations([_dobs("a", seq=3)])
    assert abs(repeated.belief_mean - single.belief_mean) < 1e-9


def test_fusion_rejects_mixed_claims() -> None:
    import pytest
    with pytest.raises(ValueError, match="distinct claims"):
        fuse_observations([_dobs("a", dom="api.acme.com"), _dobs("b", dom="other.acme.com")])


# ---- the projection keystone -------------------------------------------------


def test_projection_belief_rises_on_corroboration_and_falls_on_refutation() -> None:
    w = WorldModel()
    assert project_observation(w, _dobs("ct", seq=1)) is True
    b1 = w.get_node("domain:api.acme.com").belief_mean
    project_observation(w, _dobs("dns", seq=2))
    b2 = w.get_node("domain:api.acme.com").belief_mean
    project_observation(w, _dobs("recheck", pol=Polarity.REFUTES, seq=3))
    b3 = w.get_node("domain:api.acme.com").belief_mean
    assert b2 > b1, "corroboration must raise belief"
    assert b3 < b2, "refutation must lower belief (max-confidence cannot)"


def test_projection_drops_worthless_source() -> None:
    w = WorldModel()
    assert project_observation(w, _dobs("x", rel=Reliability.F, cred=Credibility.C6)) is False
    assert w.node_count == 0  # unknown stays unknown — nothing entered the graph


def test_projection_is_order_independent() -> None:
    obs = [_dobs("a", seq=1), _dobs("b", conf=0.7, seq=2), _dobs("c", conf=0.8, seq=3)]
    w1, w2 = WorldModel(), WorldModel()
    for o in obs:
        project_observation(w1, o)
    for o in reversed(obs):
        project_observation(w2, o)
    n1 = w1.get_node("domain:api.acme.com")
    n2 = w2.get_node("domain:api.acme.com")
    assert abs(n1.belief_mean - n2.belief_mean) < 1e-9  # Beta update is commutative


def test_projection_round_trips_through_store() -> None:
    w = WorldModel()
    project_observation(w, _dobs("ct", seq=1))
    reloaded = from_json(to_json(w))
    assert reloaded.get_node("domain:api.acme.com").kind is NodeKind.DOMAIN


def test_observation_to_evidence_feeds_the_confidence_engine() -> None:
    from framework.v2.confidence import ScientificHypothesis, assess

    ev = observation_to_evidence(_dobs("ct"))
    assert ev.likelihood_ratio > 1.0  # an affirming reliable observation supports
    r = assess(ScientificHypothesis(id="EXISTS", statement="exists", prior=0.5, evidence=[ev]))
    assert r.focal.posterior > 0.5
