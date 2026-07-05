"""
Wave 5 — the SPRT boolean-inference oracle.

Confirms a boolean-blind bug by a Wald sequential probability ratio test over
repeated true/false probes, with a per-round dynamic-page control. It confirms a
clean signal in a few rounds, refuses a deterministic non-vuln, refuses a flaky
endpoint that differs by chance, and — crucially — refuses a page that simply
changes every request (the control the naive repeated-differential lacks).
"""

from __future__ import annotations

from framework.v2.verify.oracles import boolean_inference_oracle

_MANY = {"status": 200, "body": "id=1\nid=2\nid=3\nid=4\nid=5 (all rows)"}
_NONE = {"status": 200, "body": "no results"}


def _round(true, false_a, false_b) -> dict:
    return {"true": true, "false_a": false_a, "false_b": false_b}


def test_clean_signal_confirms_in_few_rounds() -> None:
    # true clause returns the whole table; false clause is stable "no results"
    rounds = [_round(_MANY, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert sig.fired and sig.confidence >= 0.7
    assert sig.observed["rounds_used"] <= 6  # SPRT stops early on a clear signal


def test_deterministic_non_vuln_is_refuted() -> None:
    # the clause is treated as literal data: true and false give the same response
    rounds = [_round(_NONE, _NONE, _NONE) for _ in range(24)]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired
    assert sig.observed["decision"] == "refute"


def test_dynamic_page_is_refused_by_the_control() -> None:
    # every response differs (a per-request nonce), INCLUDING the two false
    # responses — so the dynamic-page control (false_a == false_b) fails and the
    # naive "true != false" cannot masquerade as a bug
    rounds = [
        _round(
            {"status": 200, "body": f"page nonce={i}a"},
            {"status": 200, "body": f"page nonce={i}b"},
            {"status": 200, "body": f"page nonce={i}c"},
        )
        for i in range(24)
    ]
    sig = boolean_inference_oracle(rounds)
    assert not sig.fired


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
