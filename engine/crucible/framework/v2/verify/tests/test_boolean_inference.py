"""
Wave 5 — the SPRT boolean-inference oracle.

Confirms a boolean-blind bug by a Wald sequential probability ratio test over
repeated true/false probes, behind a HARD DETERMINISM GATE (an up-front baseline
of identical-request sends + a per-round identical-repeat hard-refute). It confirms
a clean signal on a page proven deterministic, refuses a deterministic non-vuln,
refuses a flaky endpoint that differs by chance, refuses a page that changes every
request, and — crucially — refuses a COARSE (low-cardinality) dynamic page whose
per-round agreement is coincidental, because its baseline is not all-identical.
"""

from __future__ import annotations

from framework.v2.verify.oracles import boolean_inference_oracle

_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}


def _round(true, false_a, false_b, false_a_repeat=None) -> dict:
    # false_a_repeat defaults to a byte-identical repeat of false_a (a STABLE page). A dynamic page
    # passes an explicit, DIFFERING false_a_repeat so the same-request stability control trips.
    return {"true": true, "false_a": false_a, "false_b": false_b,
            "false_a_repeat": false_a if false_a_repeat is None else false_a_repeat}


def _baseline(resp, n: int = 16) -> list:
    # a determinism PRE-GATE: n responses to the IDENTICAL false-clause request (all identical on a
    # deterministic page). A confirm REQUIRES this to have passed (fail-closed).
    return [dict(resp) for _ in range(n)]


def test_clean_signal_confirms_in_few_rounds() -> None:
    # true clause returns the whole table; false clause is stable "no results" (deterministic page)
    rounds = [_round(_MANY, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE))
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["rounds_used"] <= 6  # SPRT stops early on a clear signal


def test_confirm_requires_the_baseline_determinism_pregate() -> None:
    # FAIL-CLOSED: even a PERFECT signal (true!=false, false pair agree, identical repeat stable) does
    # NOT mint a FACT without the up-front baseline determinism pre-gate — boolean inference is unsound
    # unless the page is first PROVEN deterministic to identical input. This is what makes a direct
    # coarse-page Monte-Carlo (no baseline supplied) yield 0 FACTs.
    rounds = [_round(_MANY, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds)  # no false_baseline_samples
    assert not sig.fired
    assert sig.observed["decision"] == "inconclusive"


def test_insufficient_baseline_samples_cannot_confirm() -> None:
    # fewer than the pre-gate floor of identical samples is not enough determinism proof → no FACT.
    rounds = [_round(_MANY, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=_baseline(_NONE, n=3))
    assert not sig.fired


def test_coarse_dynamic_page_baseline_is_refused() -> None:
    # THE red-pen BLOCK regression (coarse class): a page whose body is one of only K=2 distinct
    # variants chosen independently of the input. Its up-front baseline of identical-request sends is
    # NOT all-identical → the determinism pre-gate proves non-determinism → REFUSE, even though the
    # per-round signal could coincidentally look separable. Was a live false FACT before this gate.
    v0 = {"status": 200, "body": "no results variant A" + "A" * 50}
    v1 = {"status": 200, "body": "no results variant B" + "B" * 50}
    coarse_baseline = [v0, v1, v0, v0, v1, v0, v1, v1, v0, v1, v0, v0, v1, v0, v1, v1]
    rounds = [_round(_MANY, v0, v0, false_a_repeat=v0) for _ in range(24)]
    sig = boolean_inference_oracle(rounds, false_baseline_samples=coarse_baseline)
    assert not sig.fired
    assert sig.observed.get("nondeterministic") is True


def test_deterministic_non_vuln_is_refuted() -> None:
    # the clause is treated as literal data: true and false give the same response
    rounds = [_round(_NONE, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_dynamic_page_is_refused_by_the_control() -> None:
    # every response differs (a per-request nonce), INCLUDING the two different-marker false
    # responses AND the identical repeat — so both dynamic-page controls (false_a == false_b) and
    # (false_a == false_a_repeat) fail and the naive "true != false" cannot masquerade as a bug
    rounds = [
        _round(
            {"status": 200, "body": f"page nonce={i}a"},
            {"status": 200, "body": f"page nonce={i}b"},
            {"status": 200, "body": f"page nonce={i}c"},
            false_a_repeat={"status": 200, "body": f"page nonce={i}d"},
        )
        for i in range(24)
    ]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired


def test_stability_control_refuses_a_page_whose_within_pair_coincides() -> None:
    # THE regression for the false-FACT defect: a page where the two DIFFERENT-marker false
    # responses happen to agree (within_same passes) — so the OLD (across AND within_same) signal
    # would fire — but an IDENTICAL false repeat still differs (varies with any input). The
    # same-request STABILITY control catches exactly this coincidence → refute (LEAD, no FACT).
    rounds = [
        _round(
            _MANY,                                      # true clause differs → across fires
            {"status": 200, "body": "no results"},      # false_a
            {"status": 200, "body": "no results"},      # false_b == false_a → within_same passes
            false_a_repeat={"status": 200, "body": f"no results token={i}"},   # identical repeat DIFFERS
        )
        for i in range(24)
    ]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_missing_stability_sample_cannot_confirm_fail_closed() -> None:
    # BACKWARD-TOLERANCE / fail-closed: an OLD-shape round (no false_a_repeat) can never contribute a
    # POSITIVE signal, so an old-shape context can only refute — it can never over-confirm a FACT.
    rounds = [{"true": _MANY, "false_a": _NONE, "false_b": _NONE} for _ in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_flaky_endpoint_does_not_confirm() -> None:
    # true differs from false only half the time, by chance; the SPRT should NOT
    # accumulate enough evidence to confirm within the bound
    rounds = []
    for i in range(24):
        true = _MANY if i % 2 == 0 else _NONE  # signal only on even rounds
        rounds.append(_round(true, _NONE, _NONE))
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired


def test_request_count_is_bounded() -> None:
    rounds = [_round(_NONE, _NONE, _NONE) for _ in range(100)]
    sig = boolean_inference_oracle(rounds)
    # SPRT decides well before consuming all rounds
    assert sig.observed["rounds_used"] <= 24
