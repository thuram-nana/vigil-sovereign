"""Tests for verify.oracles — fire and no-fire cases for every oracle."""

from __future__ import annotations

from ..models import OracleKind
from ..oracles import (
    achieved_state_oracle,
    differential_response_oracle,
    oob_callback_oracle,
    sanitizer_signal_oracle,
    side_effect_oracle,
)


# ---------------------------------------------------------------------------
# differential_response_oracle
# ---------------------------------------------------------------------------


def test_differential_fires_on_status_and_body_divergence() -> None:
    baseline = {"status": 200, "body": "Welcome back, user. Here is your dashboard."}
    mutated = {"status": 500, "body": "Internal Server Error: SQL syntax near ''"}
    sig = differential_response_oracle(baseline, mutated)
    assert sig.fired
    assert sig.kind is OracleKind.DIFFERENTIAL_RESPONSE
    assert sig.confidence >= 0.7


def test_differential_no_fire_on_identical_responses() -> None:
    resp = {"status": 200, "body": "a" * 500}
    sig = differential_response_oracle(resp, dict(resp))
    assert not sig.fired
    assert sig.confidence == 0.0


def test_differential_boolean_true_vs_false_condition() -> None:
    # Classic boolean-blind: TRUE returns the record, FALSE returns nothing.
    false_resp = {"status": 200, "body": "No results found."}
    true_resp = {"status": 200, "body": "Result: id=1 name=admin role=superuser " * 5}
    sig = differential_response_oracle(false_resp, true_resp)
    assert sig.fired
    assert sig.confidence >= 0.7


def test_differential_time_based_latency() -> None:
    baseline = {"status": 200, "body": "ok", "latency_ms": 40}
    mutated = {"status": 200, "body": "ok", "latency_ms": 5040}
    sig = differential_response_oracle(baseline, mutated)
    assert sig.fired
    assert any(d["dim"] == "latency" and d["differs"] for d in sig.observed["dimensions"])


def test_differential_true_marker_present_only_in_mutated() -> None:
    baseline = {"status": 200, "body": "value = 14"}
    mutated = {"status": 200, "body": "value = 49"}  # 7*7 evaluated
    sig = differential_response_oracle(
        baseline, mutated, discriminator={"dimensions": ["marker"], "true_marker": "49"}
    )
    assert sig.fired
    assert sig.confidence >= 0.7


def test_differential_expect_same_confirms_control() -> None:
    a = {"status": 200, "body": "stable content here"}
    b = {"status": 200, "body": "stable content here"}
    sig = differential_response_oracle(a, b, discriminator={"expect": "same"})
    assert sig.fired  # "they are the same" is the asserted signal
    assert sig.confidence >= 0.7


def test_differential_accepts_plain_strings() -> None:
    sig = differential_response_oracle("hello world", "totally different text here")
    assert sig.fired


# ---------------------------------------------------------------------------
# achieved_state_oracle
# ---------------------------------------------------------------------------


def test_achieved_state_fires_on_full_match() -> None:
    expected = {"owner": "victim", "readable": True}
    observed = {"owner": "victim", "readable": True, "id": 42, "balance": 1000}
    sig = achieved_state_oracle(expected, observed)
    assert sig.fired
    assert sig.kind is OracleKind.ACHIEVED_STATE
    assert sig.confidence >= 0.7


def test_achieved_state_no_fire_on_partial_match() -> None:
    expected = {"owner": "victim", "readable": True}
    observed = {"owner": "victim", "readable": False}
    sig = achieved_state_oracle(expected, observed)
    assert not sig.fired
    assert sig.confidence < 0.7


def test_achieved_state_no_fire_on_empty_expectation() -> None:
    sig = achieved_state_oracle({}, {"anything": 1})
    assert not sig.fired
    assert sig.confidence == 0.0


def test_achieved_state_no_fire_when_key_absent() -> None:
    sig = achieved_state_oracle({"secret": "abc"}, {"other": "abc"})
    assert not sig.fired


# ---------------------------------------------------------------------------
# side_effect_oracle
# ---------------------------------------------------------------------------


def test_side_effect_fires_when_marker_reaches_sink() -> None:
    marker = "OBSIDIAN-CANARY-7f3a9c"
    sink = f"<div>comment: {marker}</div>"
    sig = side_effect_oracle(marker, sink)
    assert sig.fired
    assert sig.kind is OracleKind.SIDE_EFFECT
    assert sig.confidence >= 0.7
    assert marker in sig.evidence


def test_side_effect_no_fire_when_marker_absent() -> None:
    sig = side_effect_oracle("OBSIDIAN-CANARY-7f3a9c", "clean rendered output")
    assert not sig.fired
    assert sig.confidence == 0.0


def test_side_effect_no_fire_on_trivially_short_marker() -> None:
    sig = side_effect_oracle("ab", "xxabxx")
    assert not sig.fired


def test_side_effect_searches_list_and_dict_sinks() -> None:
    marker = "canary-91h2"
    assert side_effect_oracle(marker, ["line1", f"line2 {marker}", "line3"]).fired
    assert side_effect_oracle(marker, {"log": f"entry {marker}"}).fired


# ---------------------------------------------------------------------------
# sanitizer_signal_oracle
# ---------------------------------------------------------------------------


def test_sanitizer_fires_on_asan() -> None:
    out = (
        "=================================================================\n"
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
        "READ of size 4 at 0x60200000eff0 thread T0\n"
    )
    sig = sanitizer_signal_oracle(out)
    assert sig.fired
    assert sig.kind is OracleKind.SANITIZER_SIGNAL
    assert sig.confidence >= 0.9
    assert sig.observed["best"] == "asan"


def test_sanitizer_fires_on_ubsan() -> None:
    out = "foo.c:10:5: runtime error: signed integer overflow: 2147483647 + 1"
    sig = sanitizer_signal_oracle(out)
    assert sig.fired
    assert sig.observed["best"] == "ubsan"


def test_sanitizer_fires_on_rust_panic() -> None:
    out = "thread 'main' panicked at src/main.rs:4:5:\nindex out of bounds"
    sig = sanitizer_signal_oracle(out)
    assert sig.fired
    assert sig.observed["best"] == "rust-panic"


def test_sanitizer_python_traceback_is_lower_confidence() -> None:
    out = "Traceback (most recent call last):\n  File 'x.py', line 1\nValueError: bad"
    sig = sanitizer_signal_oracle(out)
    assert sig.fired
    assert sig.confidence < 0.7  # a handled error must not confirm on its own


def test_sanitizer_no_fire_on_clean_output() -> None:
    sig = sanitizer_signal_oracle("All 42 tests passed. Exit code 0.")
    assert not sig.fired
    assert sig.confidence == 0.0


def test_sanitizer_strongest_match_wins() -> None:
    out = (
        "Traceback (most recent call last):\n"
        "==1==ERROR: AddressSanitizer: heap-use-after-free\n"
    )
    sig = sanitizer_signal_oracle(out)
    assert sig.confidence >= 0.9  # ASAN beats traceback


# ---------------------------------------------------------------------------
# oob_callback_oracle
# ---------------------------------------------------------------------------


def test_oob_callback_fires_on_hit() -> None:
    hits = [{"method": "GET", "path": "/tok/x", "client_ip": "127.0.0.1"}]
    sig = oob_callback_oracle(hits)
    assert sig.fired
    assert sig.kind is OracleKind.OOB_CALLBACK
    assert sig.confidence >= 0.9


def test_oob_callback_no_fire_on_empty() -> None:
    sig = oob_callback_oracle([])
    assert not sig.fired
    assert sig.confidence == 0.0
    assert oob_callback_oracle(None).fired is False
