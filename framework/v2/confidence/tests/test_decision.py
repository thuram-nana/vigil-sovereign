"""
confidence.decision — the SCE at the vulnerability gate.

A confirmed finding becomes a scientific claim: an oracle confirmation is strong
affirming evidence, a passive signal is weak and leaves the benign alternative live,
a replayable certificate strengthens further, and independent corroboration raises the
posterior. The oracle stays authoritative; this only calibrates HOW confident it left us.
"""

from __future__ import annotations

from framework.v2.confidence import assess_finding
from framework.v2.confidence.models import CandidateObservation, Evidence, Provenance


def _finding(bug_class="xss", confidence=0.9, confirmed_by="oracle", cert=True) -> dict:
    return {"bug_class": bug_class, "confidence": confidence, "confirmed_by": confirmed_by,
            "insertion_point": "query.q", "param": "q",
            "oracle_context": {"x": 1} if cert else None}


def test_oracle_confirmation_yields_high_posterior() -> None:
    r = assess_finding(_finding())
    assert r.focal.posterior > 0.95
    assert r.focal.id == "REAL:xss"
    assert r.alternatives and r.alternatives[0].id == "reflected-escaped"   # MECE benign alt


def test_passive_signal_leaves_the_alternative_live() -> None:
    strong = assess_finding(_finding(confirmed_by="oracle")).focal.posterior
    weak = assess_finding(_finding(confirmed_by="passive", confidence=0.5, cert=False)).focal.posterior
    assert weak < strong
    # a merely-passive finding does NOT reach a 0.99 target on its own
    assert not assess_finding(_finding(confirmed_by="passive", confidence=0.5, cert=False)).reaches_target


def test_certificate_strengthens_confirmation() -> None:
    with_cert = assess_finding(_finding(confirmed_by="oracle", cert=True)).focal.posterior
    without = assess_finding(_finding(confirmed_by="oracle", cert=False)).focal.posterior
    assert with_cert > without


def test_corroboration_raises_posterior() -> None:
    base = assess_finding(_finding(confirmed_by="reflected", confidence=0.6, cert=False))
    corrob = assess_finding(
        _finding(confirmed_by="reflected", confidence=0.6, cert=False),
        corroborations=[Evidence(seq=1, observation="second independent confirmation",
                                 likelihood_ratio=8.0, weight=1.0,
                                 provenance=Provenance(source="reverify"))])
    assert corrob.focal.posterior > base.focal.posterior


def test_candidate_gives_most_decisive_next_test() -> None:
    r = assess_finding(
        _finding(confirmed_by="reflected", confidence=0.5, cert=False),
        candidates=[CandidateObservation(id="exec-probe", statement="prove JS execution",
                                         tpr=0.95, fpr=0.02, cost=1.0)])
    assert r.best_next is not None and r.best_next.id == "exec-probe"
    assert "decisive" in r.narrative.lower() or r.reaches_target


def test_unknown_bug_class_uses_generic_alternative() -> None:
    r = assess_finding(_finding(bug_class="exotic-thing", confirmed_by="oracle"))
    assert r.alternatives and r.alternatives[0].id == "benign"


def test_prior_scalar_seeds_but_does_not_pin() -> None:
    # even a scanner 'confidence 1.0' does not become a posterior of exactly 1.0 —
    # competing alternatives + finite evidence keep it honest
    r = assess_finding(_finding(confidence=1.0, confirmed_by="oracle"))
    assert r.focal.posterior < 1.0
