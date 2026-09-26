"""Tests for verify.verifier — the confirmation authority and its mapping."""

from __future__ import annotations

from ..models import OracleKind
from ..oob import OOBReceiver
from ..verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    differential_protocol_discriminator,
    normalize_bug_class,
)

import urllib.request


def _get(url: str) -> None:
    with urllib.request.urlopen(url, timeout=5) as resp:
        resp.read()


# ---------------------------------------------------------------------------
# bug_class -> oracle mapping / normalisation
# ---------------------------------------------------------------------------


def test_normalize_folds_aliases_and_format() -> None:
    assert normalize_bug_class("SQL-Injection") == "sqli"
    assert normalize_bug_class("insecure direct object reference") == "idor"
    assert normalize_bug_class("Server_Side_Request_Forgery") == "ssrf"
    assert normalize_bug_class("Remote Code Execution") == "rce"


def test_oracles_for_known_class() -> None:
    v = OracleVerifier()
    assert v.oracles_for("idor") == (OracleKind.ACHIEVED_STATE,)
    assert OracleKind.OOB_CALLBACK in v.oracles_for("ssrf")


def test_oracles_for_unknown_class_falls_back_to_all() -> None:
    # G1 (AEGIS): the unknown-class fallback is FROZEN to the pre-AEGIS oracle set
    # (`_ALL_ORACLES`), NOT `tuple(OracleKind)`. Additive AEGIS oracle kinds are opt-in by
    # bug_class and must NEVER run on an arbitrary unknown finding — that is what keeps
    # `make gate` byte-identical when the shared OracleKind enum grows.
    from framework.v2.verify.verifier import _ALL_ORACLES
    v = OracleVerifier()
    fb = set(v.oracles_for("some-novel-bug"))
    assert fb == set(_ALL_ORACLES)
    # every pre-existing oracle is still in the catch-all ...
    assert OracleKind.DIFFERENTIAL_RESPONSE in fb and OracleKind.OOB_CALLBACK in fb
    # ... but the AEGIS oracles are excluded (they only run on explicit AEGIS bug_classes).
    assert OracleKind.PROMPT_INJECTION not in fb
    assert OracleKind.SYSTEM_PROMPT_DISCLOSURE not in fb
    assert OracleKind.AUTOMATED_ACCESS not in fb


def test_every_mapping_value_is_valid() -> None:
    for kinds in BUG_CLASS_ORACLES.values():
        assert kinds
        assert all(isinstance(k, OracleKind) for k in kinds)


# ---------------------------------------------------------------------------
# confirm — positive paths
# ---------------------------------------------------------------------------


def test_confirm_idor_via_achieved_state() -> None:
    result = OracleVerifier().confirm({
        "bug_class": "idor",
        "expected_state": {"owner": "victim", "readable": True},
        "observed_state": {"owner": "victim", "readable": True, "id": 42},
    })
    assert result.confirmed
    assert result.confirming_signals
    assert "CONFIRMED" in result.rationale


def test_confirm_boolean_sqli_via_differential() -> None:
    result = OracleVerifier().confirm({
        "bug_class": "boolean_sqli",
        "baseline": {"status": 200, "body": "No results found."},
        "mutated": {"status": 200, "body": "admin superuser row " * 20},
    })
    assert result.confirmed


def test_confirm_xss_via_reflection_context() -> None:
    # xss now confirms via the context-aware oracle: the marker must reach an
    # EXECUTABLE position (here the payload broke out into a live tag), not merely
    # be reflected as inert text — so this is a real XSS, not a substring match.
    marker = "OBSIDIANXSSa1b2c3"
    result = OracleVerifier().confirm({
        "bug_class": "xss",
        "marker": marker,
        "observed_sink": f"<p>results</p>\"'><x{marker}>",
    })
    assert result.confirmed
    assert result.confirming_signals[0].kind is OracleKind.REFLECTION_CONTEXT


def test_inert_text_reflection_does_not_confirm_xss() -> None:
    # the precision win: a marker reflected only as inert HTML text is NOT XSS
    marker = "OBSIDIANXSSa1b2c3"
    result = OracleVerifier().confirm({
        "bug_class": "xss",
        "marker": marker,
        "observed_sink": f"<p>{marker}</p>",
    })
    assert not result.confirmed


def test_confirm_memory_corruption_via_sanitizer() -> None:
    result = OracleVerifier().confirm({
        "bug_class": "buffer_overflow",
        "process_output": "==1==ERROR: AddressSanitizer: stack-buffer-overflow",
    })
    assert result.confirmed


def test_confirm_ssrf_via_real_oob_callback() -> None:
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(url)  # a real inbound loopback interaction
        result = OracleVerifier().confirm({
            "bug_class": "ssrf",
            "oob_hits": oob.poll(token),
            "oob_token": token,   # VF-2a: the context must carry the REGISTERED token for the oracle to fire
        })
    assert result.confirmed
    assert result.confirming_signals[0].kind is OracleKind.OOB_CALLBACK


def test_confirm_ssrf_refused_without_registered_token() -> None:
    # VF-2a: the SAME real callback WITHOUT the registered token on the context does NOT confirm (fail-closed)
    # — the old "fires on any oob_hits" weakness is closed.
    with OOBReceiver() as oob:
        token, url = oob.register_token()
        _get(url)
        result = OracleVerifier().confirm({"bug_class": "ssrf", "oob_hits": oob.poll(token)})
    assert not result.confirmed


# ---------------------------------------------------------------------------
# confirm — negative / conservative paths
# ---------------------------------------------------------------------------


def test_no_confirm_when_inputs_absent() -> None:
    result = OracleVerifier().confirm({"bug_class": "idor"})
    assert not result.confirmed
    assert result.signals == []
    assert "no oracle" in result.rationale.lower()


def test_no_confirm_when_oracle_does_not_fire() -> None:
    result = OracleVerifier().confirm({
        "bug_class": "ssrf",
        "oob_hits": [],  # no callback ever landed
    })
    assert not result.confirmed
    assert result.signals and not result.confirming_signals


def test_no_confirm_on_low_confidence_signal() -> None:
    # A bare python traceback fires the sanitizer oracle below threshold.
    result = OracleVerifier().confirm({
        "bug_class": "crash",
        "process_output": "Traceback (most recent call last):\nValueError: x",
    })
    assert not result.confirmed
    assert any(s.fired for s in result.signals)
    assert "below the" in result.rationale


def test_unknown_bug_class_fails_closed_even_when_a_fallback_oracle_fires() -> None:
    # audit A1 (unknown-class fail-closed): an INVENTED / out-of-vocabulary class must NEVER be oracle-
    # confirmed, even though the frozen _ALL_ORACLES fallback still RUNS its input-matching oracles for
    # diagnostic completeness (G1). Here side_effect fires on the echoed marker, but the class is unknown ->
    # NOT confirmed. Before the fix this returned confirmed=True (a proof-soundness hole).
    marker = "canary-zz99xx"
    result = OracleVerifier().confirm({
        "bug_class": "brand-new-thing",
        "marker": marker,
        "observed_sink": f"leaked {marker} here",
    })
    assert not result.confirmed                                   # fail-closed on unknown vocabulary
    kinds = {s.kind for s in result.signals}
    assert kinds == {OracleKind.SIDE_EFFECT, OracleKind.REFLECTION_CONTEXT}   # fallback still RAN (diagnostic)
    assert {s.kind for s in result.confirming_signals} == {OracleKind.SIDE_EFFECT}  # side_effect DID fire...
    assert "vocabulary" in result.rationale.lower()              # ...and the rationale says why it didn't confirm
    # MUTATION-VERIFIED: the SAME evidence with a KNOWN side_effect class (rce) DOES confirm — the vocabulary
    # gate is the ONLY thing suppressing the unknown one, so the negative is not vacuous.
    known = OracleVerifier().confirm({
        "bug_class": "rce", "marker": marker, "observed_sink": f"leaked {marker} here"})
    assert known.confirmed


def test_custom_threshold_is_respected() -> None:
    ctx = {
        "bug_class": "crash",
        "process_output": "Traceback (most recent call last):\nValueError: x",
    }
    # A traceback fires ~0.65; a lenient verifier accepts it, the default won't.
    assert OracleVerifier(high_confidence=0.6).confirm(ctx).confirmed
    assert not OracleVerifier().confirm(ctx).confirmed


# ---------------------------------------------------------------------------
# AUDIT F8 — the differential discriminator is a PROTOCOL CONSTANT, never the
# producer's. A hand-edited report used to mint a FACT out of two BYTE-IDENTICAL
# responses by shipping its own discriminator.
# ---------------------------------------------------------------------------

_IDENTICAL = {"status": 200, "body": "<html><body>identical</body></html>", "latency_ms": 10.0}


def _hostile(bug_class: str, discriminator: dict) -> dict:
    """The exact audited shape: two BYTE-IDENTICAL retained responses (same status,
    same body, same latency) plus an attacker-chosen discriminator."""
    return {"bug_class": bug_class, "baseline": dict(_IDENTICAL), "mutated": dict(_IDENTICAL),
            "discriminator": discriminator}


def test_byte_identical_responses_never_confirm_whatever_the_discriminator() -> None:
    # Each of these re-verified as a CONFIRMED differential_response FACT on 838e0b42.
    hostile_discriminators = [
        {"dimensions": ["latency"], "latency_threshold_ms": 0},          # the measured F8 repro
        {"dimensions": ["latency"], "latency_threshold_ms": -1},
        {"dimensions": ["status", "length", "lexical"], "expect": "same"},  # sign-flipped
        {"dimensions": ["marker"], "true_marker": "l"},                  # 1-char marker
        {"dimensions": ["length", "lexical"], "length_threshold": -1.0,
         "lexical_threshold": -1.0},                                     # negative thresholds
    ]
    for disc in hostile_discriminators:
        for bug_class in ("boolean_sqli", "nosqli", "sqli", "auth_bypass", "request_smuggling"):
            result = OracleVerifier().confirm(_hostile(bug_class, disc))
            assert not result.confirmed, f"{bug_class} minted a FACT from identical bytes via {disc}"
            for sig in result.signals:
                if sig.kind is OracleKind.DIFFERENTIAL_RESPONSE:
                    assert not sig.fired, f"{bug_class}/{disc}: differential fired on identical bytes"


def test_genuine_differential_still_confirms() -> None:
    # the mutation control: real divergence in the retained bytes still re-confirms,
    # so the F8 negative above is not vacuous.
    result = OracleVerifier().confirm({
        "bug_class": "nosqli",
        "baseline": {"status": 200, "body": "<html><body>no results</body></html>", "latency_ms": 10.0},
        "mutated": {"status": 200,
                    "body": "<html><body><ul><li>alice</li><li>bob</li><li>carol</li></ul></body></html>",
                    "latency_ms": 11.0},
    })
    assert result.confirmed
    assert result.confirming_signals[0].kind is OracleKind.DIFFERENTIAL_RESPONSE


def test_producer_discriminator_cannot_widen_or_narrow_the_comparison() -> None:
    # a REAL divergence judged under a producer discriminator that tries to hide it
    # (e.g. an impossible length threshold) must STILL confirm: the producer does not
    # get to choose the rule in either direction.
    real = {
        "bug_class": "nosqli",
        "baseline": {"status": 200, "body": "no results", "latency_ms": 10.0},
        "mutated": {"status": 500, "body": "SQL syntax error near '", "latency_ms": 10.0},
    }
    assert OracleVerifier().confirm(real).confirmed
    muted = dict(real, discriminator={"dimensions": ["latency"], "latency_threshold_ms": 10_000_000})
    assert OracleVerifier().confirm(muted).confirmed


def test_protocol_discriminator_table_is_closed_and_latency_free_by_default() -> None:
    generic = differential_protocol_discriminator("nosqli")
    assert generic["dimensions"] == ["status", "length", "lexical"]
    assert "latency" not in generic["dimensions"]
    assert generic["expect"] == "differ"
    assert "true_marker" not in generic
    # the one legitimate latency consumer keeps its dimension but NOT a tunable threshold
    smuggling = differential_protocol_discriminator("request_smuggling")
    assert smuggling["dimensions"] == ["latency"]
    assert smuggling["latency_threshold_ms"] == 1500.0
    # and the accessor hands out a COPY — a caller cannot mutate the protocol
    generic["dimensions"].append("latency")
    assert "latency" not in differential_protocol_discriminator("nosqli")["dimensions"]


def test_differential_oracle_default_dimensions_exclude_latency() -> None:
    # AUDIT R6: latency's weight is exactly HIGH_CONFIDENCE, so a default-dimension
    # caller inherited a latency-only confirm path over otherwise identical responses.
    from .. import oracles

    sig = oracles.differential_response_oracle(
        {"status": 200, "body": "same", "latency_ms": 10.0},
        {"status": 200, "body": "same", "latency_ms": 5_000.0},
    )
    assert not sig.fired, sig.evidence
    # explicit opt-in still works, for the A12 smuggling timing LEAD probe
    explicit = oracles.differential_response_oracle(
        {"status": 200, "body": "same", "latency_ms": 10.0},
        {"status": 200, "body": "same", "latency_ms": 5_000.0},
        {"dimensions": ["latency"], "latency_threshold_ms": 1500.0},
    )
    assert explicit.fired
