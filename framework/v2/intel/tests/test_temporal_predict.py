"""
Phase C — temporal intelligence and prediction.

The load-bearing property is DISAPPEARANCE HONESTY: an asset is reported gone ONLY
when an enumerative source (CT) was re-run over its scope and omitted it; a
point-query source's silence leaves the asset STALE (unknown), never disappeared.
Predictions are gated hypotheses with capped priors — never facts, never
auto-verified.
"""

from __future__ import annotations

from framework.v2.confidence import assess
from framework.v2.intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from framework.v2.intel.predict import AssetPredictor
from framework.v2.intel.refs import canonicalize
from framework.v2.intel.temporal import SurfaceDelta, TemporalIndex
from framework.v2.worldmodel.models import EdgeKind, NodeKind


def _ct_node(name: str, apex: str, seq: int, *, pol=Polarity.AFFIRMS) -> Observation:
    """A CT node-claim (enumerative source): asset EXISTS, carrying its apex scope."""
    return Observation(
        obs_id=f"ct:{name}:{seq}", source="cert_transparency",
        source_kind=IntelSourceKind.CERT_TRANSPARENCY,
        subject=canonicalize(NodeKind.DOMAIN, name),
        source_reliability=SourceReliability(reliability=Reliability.A, credibility=Credibility.C2),
        confidence=0.9, polarity=pol, seq=seq, attrs={"apex": apex})


def _dns_node(name: str, seq: int) -> Observation:
    """A DNS node-claim (point-query source): not enumerative."""
    return Observation(
        obs_id=f"dns:{name}:{seq}", source="dns", source_kind=IntelSourceKind.DNS,
        subject=canonicalize(NodeKind.DOMAIN, name),
        source_reliability=SourceReliability(reliability=Reliability.B, credibility=Credibility.C2),
        confidence=0.9, seq=seq)


# ---- temporal: appearance ----------------------------------------------------


def test_appeared_between_snapshots() -> None:
    idx = TemporalIndex.from_observations([
        _ct_node("api.company.com", "company.com", 1),
        _ct_node("api.company.com", "company.com", 3),
        _ct_node("staging.company.com", "company.com", 3),
    ])
    d = idx.delta(1, 3)
    assert "domain:staging.company.com" in d.appeared
    assert "domain:api.company.com" in d.persisted


# ---- temporal: disappearance honesty (the crux) ------------------------------


def test_disappearance_only_via_enumerative_recheck() -> None:
    # api + backend seen at seq 1 (CT enumeration of company.com).
    # At seq 3 CT is re-run and lists ONLY api → backend genuinely disappeared.
    idx = TemporalIndex.from_observations([
        _ct_node("api.company.com", "company.com", 1),
        _ct_node("backend.company.com", "company.com", 1),
        _ct_node("api.company.com", "company.com", 3),   # re-enumeration omits backend
    ])
    d = idx.delta(1, 3)
    assert "domain:backend.company.com" in d.disappeared
    assert "domain:backend.company.com" not in d.stale


def test_point_query_silence_is_stale_not_disappeared() -> None:
    # backend seen once via DNS (a point query). Later we only re-query api via DNS.
    # backend is NOT re-enumerated by any complete-list source → STALE, never gone.
    idx = TemporalIndex.from_observations([
        _dns_node("api.company.com", 1),
        _dns_node("backend.company.com", 1),
        _dns_node("api.company.com", 3),
    ])
    d = idx.delta(1, 3)
    assert "domain:backend.company.com" in d.stale
    assert d.disappeared == []


def test_reappearance_is_not_disappearance() -> None:
    idx = TemporalIndex.from_observations([
        _ct_node("api.company.com", "company.com", 1),
        _ct_node("backend.company.com", "company.com", 1),
        _ct_node("api.company.com", "company.com", 5),
        _ct_node("backend.company.com", "company.com", 5),  # still present at re-enum
    ])
    d = idx.delta(1, 5)
    assert d.disappeared == []
    assert "domain:backend.company.com" in d.persisted


def test_timeline_records_first_seen_and_refutation() -> None:
    idx = TemporalIndex.from_observations([
        _ct_node("api.company.com", "company.com", 1),
        _ct_node("api.company.com", "company.com", 2),
        _ct_node("api.company.com", "company.com", 4, pol=Polarity.REFUTES),
    ])
    tl = idx.timeline("domain:api.company.com")
    assert [e.kind for e in tl] == ["first_seen", "reaffirmed", "refuted"]


# ---- prediction: gated hypotheses, never facts -------------------------------


def test_predicts_siblings_as_gated_hypotheses() -> None:
    preds = AssetPredictor().predict(
        observed_domains=["api.company.com", "backend.company.com", "www.company.com"])
    ids = {p.node_id for p in preds}
    assert "domain:staging.company.com" in ids
    assert "domain:dev.company.com" in ids
    # never predicts something already observed
    assert "domain:api.company.com" not in ids
    for p in preds:
        assert p.gated is True and p.status == "predicted"
        assert 0.0 < p.prior <= 0.6              # capped — never high-confidence
        assert p.hypothesis.alternatives          # MECE: carries a "does not exist" alt


def test_prediction_feeds_the_confidence_engine() -> None:
    preds = AssetPredictor().predict(observed_domains=["api.company.com", "backend.company.com"])
    p = preds[0]
    report = assess(p.hypothesis)
    # with no evidence yet the posterior is just the normalised prior — an honest
    # "here is how likely, and what test would decide it"
    assert 0.0 < report.focal.posterior < 1.0


def test_prediction_roster_is_bounded_and_reports_cap() -> None:
    pred = AssetPredictor(max_per_apex=3)
    preds = pred.predict(observed_domains=["api.company.com"])
    per_apex = [p for p in preds if p.apex == "company.com"]
    assert len(per_apex) <= 3
    assert pred.dropped_for_cap > 0              # the trim is reported, not silent


def test_netblock_neighbours_are_low_prior_secondary() -> None:
    preds = AssetPredictor().predict(
        observed_hosts=["10.15.4.2"], netblocks=["10.15.4.0/29"])
    nb = [p for p in preds if p.pattern == "netblock-neighbour"]
    assert nb and all(p.prior <= 0.2 for p in nb)   # weak by design
    assert all(p.gated for p in nb)


def test_prediction_is_deterministic() -> None:
    a = AssetPredictor().predict(observed_domains=["api.company.com", "www.company.com"])
    b = AssetPredictor().predict(observed_domains=["www.company.com", "api.company.com"])
    assert [p.node_id for p in a] == [p.node_id for p in b]
