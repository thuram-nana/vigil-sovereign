"""
Wave 5 — the SPRT boolean-inference oracle, whose per-round signal is a TRUTH-VALUE
ATTRIBUTION test.

A boolean_sqli FACT means the response is a deterministic FUNCTION of the injected
boolean's TRUTH VALUE: every one of K_T distinct always-TRUE clauses lands on the same
response, every one of K_F distinct always-FALSE clauses lands on the same response, and
the two clusters are disjoint. These tests confirm a clean 2-cluster split on a real
channel, refuse a deterministic non-vuln, refuse a page that changes every request, refuse
a COARSE (low-cardinality) input-independent page, refuse a SKEWED one whose determinism
pre-gate is FORCED to pass, and refuse an old single-clause context (fail-closed on shape).
"""

from __future__ import annotations

import random

from framework.v2.verify.oracles import boolean_inference_oracle

_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}


def _round(trues, falses) -> dict:
    """A TRUTH-VALUE ATTRIBUTION round on a DETERMINISTIC page: each clause's byte-identical
    repeat returns the same response, so the repeats are copies of the clause responses."""
    return {"trues": list(trues), "falses": list(falses),
            "true_repeats": [dict(r) for r in trues], "false_repeats": [dict(r) for r in falses]}


def _clean(true=_MANY, false=_NONE, k: int = 4) -> dict:
    """A round from a page that IS a function of the truth value: every true clause -> one
    page, every false clause -> another."""
    return _round([dict(true) for _ in range(k)], [dict(false) for _ in range(k)])


def _baseline(resp, n: int = 16) -> list:
    # the determinism PRE-FILTER: n responses to ONE IDENTICAL false-clause request (all
    # identical on a deterministic page). A confirm additionally requires this to have passed.
    return [dict(resp) for _ in range(n)]


def test_clean_two_cluster_split_confirms_in_few_rounds() -> None:
    # every always-TRUE clause returns the whole table, every always-FALSE clause returns
    # "no results" — the response IS a function of the truth value.
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["rounds_used"] <= 6  # SPRT stops early on a clear signal


def test_confirm_requires_the_baseline_determinism_pregate() -> None:
    # FAIL-CLOSED: even a perfect 2-cluster split does NOT mint a FACT without the up-front
    # identical-request baseline. (A cheap pre-filter on top of the attribution test, not the
    # thing that makes the oracle sound — see the skewed test below, where it is forced to pass.)
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds)  # no false_baseline_samples
    assert not sig.fired
    assert sig.observed["decision"] == "inconclusive"


def test_insufficient_baseline_samples_cannot_confirm() -> None:
    rounds = [_clean() for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE, n=3))
    assert not sig.fired


def test_one_clause_per_truth_value_cannot_confirm_fail_closed() -> None:
    # A SINGLE clause per truth value is ONE DRAW — it cannot attribute a response to a truth
    # VALUE, so the round is never a positive signal no matter how cleanly it separates.
    rounds = [_round([dict(_MANY)], [dict(_NONE)]) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_old_single_clause_context_cannot_confirm_fail_closed() -> None:
    # An OLD retained context ({"true", "false_a", "false_b", "false_a_repeat"}) carries no
    # truth-value arms, so it can only ever REFUTE — old evidence can never mint.
    rounds = [{"true": dict(_MANY), "false_a": dict(_NONE), "false_b": dict(_NONE),
               "false_a_repeat": dict(_NONE)} for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_within_truth_disagreement_refuses() -> None:
    # The true clauses do NOT all land on the same response (one of them returns the false page):
    # there is no single TRUE cluster, so the response is not a function of the truth value.
    rounds = [_round([dict(_MANY), dict(_MANY), dict(_MANY), dict(_NONE)],
                     [dict(_NONE) for _ in range(4)]) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_coarse_input_independent_page_is_refused() -> None:
    # A page whose body is one of only K=2 distinct variants chosen independently of the input:
    # its identical-request baseline is not all-identical -> proven non-deterministic -> REFUSE.
    v0 = {"status": 200, "body": "no results variant A" + "A" * 50}
    v1 = {"status": 200, "body": "no results variant B" + "B" * 50}
    coarse_baseline = [v0, v1, v0, v0, v1, v0, v1, v1, v0, v1, v0, v0, v1, v0, v1, v1]
    sig = boolean_inference_oracle([_clean(v1, v0) for _ in range(24)],
                                   false_baseline_samples=coarse_baseline)
    assert not sig.fired
    assert sig.observed.get("nondeterministic") is True


def test_skewed_input_independent_page_refuses_with_the_pregate_forced_to_pass() -> None:
    # THE red-pen BLOCK regression at the ORACLE level, with the determinism pre-gate DEFEATED
    # by construction: a SKEWED (dominant variant p=0.9) K=2 input-independent page, handed an
    # all-identical 16-sample baseline so the pre-gate PASSES. Every response — clause and
    # repeat — is an independent draw. A clean 2-cluster split by truth value then requires all
    # 8 true-side draws to be one variant and all 8 false-side draws the other (<= 2*2**-16),
    # so the oracle must refuse every seed. This is what a determinism gate alone could not do.
    variants = [{"status": 200, "body": "no results variant A" + "A" * 60},
                {"status": 200, "body": "no results variant B" + "B" * 60}]
    forced_baseline = [dict(variants[0]) for _ in range(16)]
    for seed in range(400):
        rng = random.Random(seed)

        def draw(_rng=rng):
            return dict(_rng.choices(variants, weights=[0.9, 0.1], k=1)[0])

        rounds = [{"trues": [draw() for _ in range(4)], "true_repeats": [draw() for _ in range(4)],
                   "falses": [draw() for _ in range(4)], "false_repeats": [draw() for _ in range(4)]}
                  for _ in range(24)]
        sig = boolean_inference_oracle(rounds, false_baseline_samples=forced_baseline)
        assert not sig.fired, f"skewed input-independent page minted a FALSE FACT at seed {seed}"


def test_deterministic_non_vuln_is_refuted() -> None:
    # the clause is treated as literal data: true and false give the same response
    sig = boolean_inference_oracle([_clean(_NONE, _NONE) for _ in range(24)],
                                   false_baseline_samples=_baseline(_NONE))
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_dynamic_page_hard_refutes_on_a_differing_repeat() -> None:
    # every response differs (a per-request nonce), so a byte-identical clause repeat comes back
    # different -> the page is PROVEN non-deterministic -> hard refute, never a FACT.
    def _nonce(tag: str) -> dict:
        # a long per-request token dominates the body, so ANY two responses diverge lexically
        return {"status": 200, "body": "session " + (tag * 40) + " — no results"}

    rounds = [{"trues": [_nonce(f"a{i}{j}") for j in range(3)],
               "true_repeats": [_nonce(f"b{i}{j}") for j in range(3)],
               "falses": [_nonce(f"c{i}{j}") for j in range(3)],
               "false_repeats": [_nonce(f"d{i}{j}") for j in range(3)]}
              for i in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed.get("nondeterministic") is True


def test_flaky_endpoint_does_not_confirm() -> None:
    # the clusters separate only half the time, by chance; the SPRT must not confirm
    rounds = [_clean() if i % 2 == 0 else _clean(_NONE, _NONE) for i in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert not sig.fired


def test_request_count_is_bounded() -> None:
    sig = boolean_inference_oracle([_clean(_NONE, _NONE) for _ in range(100)])
    # SPRT decides well before consuming all rounds
    assert sig.observed["rounds_used"] <= 24


def test_the_deterministic_arbitrary_map_residual_is_real_and_is_disclosed() -> None:
    """THE HONEST LIMIT, PINNED — not merely asserted in prose.

    A page that is a DETERMINISTIC but ARBITRARY function of the URL (a CDN caching per exact
    URL over an origin that picked a variant at fill time) can hand back a perfect 2-cluster
    split with NO boolean channel: the repeats are cache hits, so determinism holds, and every
    later round returns the same bytes. The oracle DOES confirm here, and that is the residual
    the docstring discloses — no response-only test closes it, because such a page IS a
    deterministic function of the request, which is exactly what boolean-blind inference reads.
    K_T/K_F are the only lever (``<= 2 * 2**-(K_T+K_F)`` that this split happens by chance).

    This test exists so the code and the disclosure cannot drift apart: if someone later claims
    this residual is closed, this test fails and forces the claim to be re-earned or the
    docstring to be corrected."""
    v_a = {"status": 200, "body": "variant A" + "A" * 60}
    v_b = {"status": 200, "body": "variant B" + "B" * 60}
    # the cache froze variant A on every true-clause URL and variant B on every false-clause URL
    sig = boolean_inference_oracle([_clean(v_a, v_b) for _ in range(24)],
                                   false_baseline_samples=_baseline(v_b))
    assert sig.fired, "the disclosed deterministic-arbitrary-map residual is no longer reachable"
    # and the disclosure lives in the oracle's own docstring, not only in a design note
    doc = boolean_inference_oracle.__doc__ or ""
    assert "IRREDUCIBLE RESIDUAL" in doc and "caching per exact URL" in doc
    assert "RAISING ``K_T``/``K_F`` is the only lever" in doc
