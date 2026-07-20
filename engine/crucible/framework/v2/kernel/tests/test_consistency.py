"""
Anti-hallucination P5 — self-consistency + semantic entropy for NO-ORACLE bindings.

Where no oracle disposes a claim, disagreement across N samples IS the uncertainty signal:
a stable inference clusters, a fabrication scatters. run_consistent returns the modal answer
and — the load-bearing part — ABSTAINS (routes to needs_evidence) when the samples disagree.
It only ever demotes; it never manufactures confidence, and it stays out of the oracle path.
"""

from __future__ import annotations

from framework.v2.kernel.consistency import (
    ConsistencyResult,
    categorical_entropy,
    consistency_evidence,
    run_consistent,
)
from framework.v2.kernel.hypothesize import hypothesize_consistent


# ---- categorical entropy ----------------------------------------------------


def test_categorical_entropy_bounds() -> None:
    assert categorical_entropy({"a": 5}) == 0.0                    # unanimous → 0
    assert categorical_entropy({"a": 1, "b": 1}, n_samples=2) == 1.0  # even 2-split → 1
    assert categorical_entropy([], n_samples=3) == 0.0             # degenerate → 0
    mixed = categorical_entropy({"a": 3, "b": 1}, n_samples=4)     # skewed → strictly between
    assert 0.0 < mixed < 1.0


# ---- a scripted run_fn drives the clustering --------------------------------


def _script(values):
    """A run_fn that yields the next scripted value (with a dummy trace) on each call."""
    it = iter(values)
    return lambda: (next(it), {"trace": True})


def test_agreeing_samples_do_not_abstain() -> None:
    r = run_consistent(_script([{"d": "sqli"}] * 5), samples=5, agreement_gate=0.6,
                       key_fn=lambda v: v["d"])
    assert not r.abstained and r.agreement == 1.0 and r.entropy == 0.0
    assert r.modal == {"d": "sqli"} and r.n_samples == 5


def test_scattered_samples_abstain() -> None:
    r = run_consistent(_script([{"d": x} for x in ("a", "b", "c", "d", "e")]),
                       samples=5, agreement_gate=0.6, key_fn=lambda v: v["d"])
    assert r.abstained and r.agreement == 0.2 and r.entropy == 1.0
    assert "ABSTAIN" in r.reason and "needs_evidence" in r.reason


def test_majority_below_gate_abstains_above_gate_does_not() -> None:
    # 3/5 modal = 0.6 agreement
    votes = [{"d": "sqli"}, {"d": "sqli"}, {"d": "sqli"}, {"d": "xss"}, {"d": "ssrf"}]
    below = run_consistent(_script(list(votes)), samples=5, agreement_gate=0.7,
                           key_fn=lambda v: v["d"])
    assert below.abstained and below.agreement == 0.6
    at = run_consistent(_script(list(votes)), samples=5, agreement_gate=0.6,
                        key_fn=lambda v: v["d"])
    assert not at.abstained and at.modal == {"d": "sqli"}         # modal wins at the gate


def test_clusters_on_decision_field_not_prose() -> None:
    # same decision, different prose → ONE cluster → unanimous (the semantic-entropy point)
    samples = [{"d": "sqli", "note": f"reasoning variant {i}"} for i in range(5)]
    r = run_consistent(_script(samples), samples=5, key_fn=lambda v: v["d"])
    assert not r.abstained and r.agreement == 1.0 and len(r.clusters) == 1


def test_consistency_evidence_is_a_penalty_never_a_boost() -> None:
    r = run_consistent(_script([{"d": x} for x in ("a", "b", "c", "d", "e")]),
                       samples=5, key_fn=lambda v: v["d"])
    ev = consistency_evidence(r)
    assert ev["kind"] == "self_consistency" and ev["penalty"] == r.entropy
    assert ev["abstained"] is True and 0.0 <= ev["penalty"] <= 1.0


# ---- the wired no-oracle binding --------------------------------------------


def test_hypothesize_consistent_is_stable_on_the_deterministic_backend() -> None:
    # the dry-run backend is deterministic → every sample identical → agrees trivially,
    # never abstains (self-consistency only bites against a varied live backend).
    r = hypothesize_consistent("login form reflects the username unescaped",
                               surface="/login", samples=3)
    assert isinstance(r, ConsistencyResult)
    assert not r.abstained and r.agreement == 1.0 and r.n_samples == 3
    assert r.modal is not None and r.modal.hypotheses            # a real HypothesisSet


# ---- P6: bug_class value-membership on the Hypothesis schema ----------------


def test_hypothesis_flags_oracle_provability_without_mutating_the_label() -> None:
    from framework.v2.kernel.models import Hypothesis

    def _h(bc):
        return Hypothesis.model_validate({
            "id": "H-1", "surface": "/x", "bug_class": bc, "given": "g",
            "if": "a", "then": "o", "because": "m", "refute_on": "r", "cheap_test": "c"})

    # the RAW label is preserved (downstream exploit/planner keys match its exact spelling),
    # but oracle_provable normalises internally to report whether an oracle can confirm it.
    prov = _h("IDOR")
    assert prov.bug_class == "IDOR" and prov.oracle_provable is True
    assert prov.model_dump()["oracle_provable"] is True          # surfaced in the output
    # an exploratory class is KEPT verbatim but flagged NOT provable
    lead = _h("cache-poisoning")
    assert lead.bug_class == "cache-poisoning" and lead.oracle_provable is False
