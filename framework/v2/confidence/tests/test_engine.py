"""
The Scientific Confidence Engine — behaves like a scientist, not a scanner.

These pin the properties that make a verdict scientific: a Bayesian posterior that
rises with supporting evidence and FALLS with refuting evidence, redundant evidence
that barely moves it, competing explanations that normalise to 1, a credible interval
that tightens with evidence, and a value-of-information ranking that points at the
single most decisive next test.
"""

from __future__ import annotations

import math

from framework.v2.confidence.engine import assess
from framework.v2.confidence.models import (
    AlternativeHypothesis,
    CandidateObservation,
    Evidence,
    ScientificHypothesis,
)


def _ev(seq, lr, weight=1.0, independence=1.0):
    return Evidence(seq=seq, observation=f"obs{seq}", likelihood_ratio=lr,
                    weight=weight, independence=independence)


def test_supporting_evidence_raises_posterior() -> None:
    h0 = ScientificHypothesis(id="H", statement="x", prior=0.5)
    h1 = ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 8.0), _ev(2, 6.0)])
    assert assess(h1).focal.posterior > assess(h0).focal.posterior


def test_refuting_evidence_lowers_posterior() -> None:
    base = assess(ScientificHypothesis(id="H", statement="x", prior=0.7)).focal.posterior
    refuted = assess(ScientificHypothesis(id="H", statement="x", prior=0.7,
                                          evidence=[_ev(1, 0.1)])).focal.posterior  # LR<1 refutes
    assert refuted < base


def test_redundant_evidence_barely_moves_posterior() -> None:
    novel = assess(ScientificHypothesis(id="H", statement="x", prior=0.5,
                                        evidence=[_ev(1, 6.0), _ev(2, 6.0, independence=1.0)])).focal.posterior
    redundant = assess(ScientificHypothesis(id="H", statement="x", prior=0.5,
                                            evidence=[_ev(1, 6.0), _ev(2, 6.0, independence=0.0)])).focal.posterior
    # the fully-redundant second datum contributes ~nothing
    single = assess(ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 6.0)])).focal.posterior
    assert abs(redundant - single) < 1e-6
    assert novel > redundant


def test_competing_posteriors_sum_to_one() -> None:
    h = ScientificHypothesis(
        id="H", statement="real xss", prior=0.5, evidence=[_ev(1, 4.0)],
        alternatives=[AlternativeHypothesis(id="A1", statement="escaped reflection", prior=0.3,
                                            evidence=[_ev(1, 2.0)])],
        residual_prior=0.2)
    r = assess(h)
    total = r.focal.posterior + sum(a.posterior for a in r.alternatives) + r.residual
    assert abs(total - 1.0) < 5e-5  # softmax sums to exactly 1; slack is 5-decimal display rounding


def test_strong_alternative_steals_mass_from_focal() -> None:
    weak_alt = assess(ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 5.0)],
        alternatives=[AlternativeHypothesis(id="A", statement="y", prior=0.4, evidence=[_ev(1, 1.0)])])).focal.posterior
    strong_alt = assess(ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 5.0)],
        alternatives=[AlternativeHypothesis(id="A", statement="y", prior=0.4, evidence=[_ev(1, 20.0)])])).focal.posterior
    assert strong_alt < weak_alt  # a well-supported alternative lowers the focal posterior


def test_credible_interval_tightens_with_more_evidence() -> None:
    few = assess(ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 5.0)])).focal
    many = assess(ScientificHypothesis(id="H", statement="x", prior=0.5,
                                       evidence=[_ev(i, 5.0) for i in range(1, 9)])).focal
    assert (many.ci_high - many.ci_low) < (few.ci_high - few.ci_low)
    assert many.effective_n > few.effective_n


def test_no_evidence_stays_at_prior_max_uncertainty() -> None:
    r = assess(ScientificHypothesis(id="H", statement="x", prior=0.5))
    assert abs(r.focal.posterior - 0.5) < 0.15  # near the prior; wide interval
    assert (r.focal.ci_high - r.focal.ci_low) > 0.4


def test_value_of_next_evidence_prefers_the_decisive_test() -> None:
    h = ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 3.0)])
    cands = [
        CandidateObservation(id="decisive", statement="d", tpr=0.98, fpr=0.02, cost=1.0),
        CandidateObservation(id="useless", statement="u", tpr=0.5, fpr=0.5, cost=1.0),  # uninformative
    ]
    best = assess(h, candidates=cands).best_next
    assert best is not None and best.id == "decisive" and best.eig_bits > 0.0


def test_eig_is_highest_near_a_coinflip_belief() -> None:
    cand = [CandidateObservation(id="t", statement="t", tpr=0.9, fpr=0.05)]
    coin = assess(ScientificHypothesis(id="H", statement="x", prior=0.5), candidates=cand).best_next.eig_bits
    near_sure = assess(ScientificHypothesis(id="H", statement="x", prior=0.5,
                       evidence=[_ev(i, 20.0) for i in range(1, 6)]), candidates=cand).best_next.eig_bits
    assert coin > near_sure  # a near-certain belief has little left to learn


def test_reaches_target_flag() -> None:
    r = assess(ScientificHypothesis(id="H", statement="x", prior=0.5,
               evidence=[_ev(i, 30.0) for i in range(1, 6)]), target_confidence=0.99)
    assert r.reaches_target and r.focal.posterior >= 0.99


def test_assess_is_deterministic() -> None:
    h = ScientificHypothesis(id="H", statement="x", prior=0.5, evidence=[_ev(1, 4.0), _ev(2, 0.3)],
                             alternatives=[AlternativeHypothesis(id="A", statement="y", prior=0.3)])
    a, b = assess(h), assess(h)
    assert a.model_dump() == b.model_dump()


def test_from_kernel_hypothesis_carries_prior_and_refutation() -> None:
    class _K:
        id = "K1"; surface = "s"; bug_class = "xss"
        then_observation = "payload executes"; refute_on = "output is html-escaped"; confidence = 0.8
    sh = ScientificHypothesis.from_kernel_hypothesis(_K())
    assert sh.id == "K1" and sh.bug_class == "xss" and abs(sh.prior - 0.8) < 1e-9
    assert sh.refute_on == "output is html-escaped" and sh.statement == "payload executes"


def test_narrative_reads_like_a_scientist() -> None:
    r = assess(ScientificHypothesis(id="H1", statement="real xss", prior=0.5, evidence=[_ev(1, 8.0)],
               alternatives=[AlternativeHypothesis(id="H2", statement="escaped", prior=0.3)]))
    assert "posterior" in r.narrative and "H1" in r.narrative and "alternative" in r.narrative
