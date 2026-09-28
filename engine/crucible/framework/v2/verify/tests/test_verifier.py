"""Tests for verify.verifier — the confirmation authority and its mapping."""

from __future__ import annotations

from ..models import OracleKind
from ..oob import OOBReceiver
from ..verifier import (
    BUG_CLASS_ORACLES,
    _DIFFERENTIAL_PROTOCOL_DISCRIMINATORS,
    OracleVerifier,
    differential_baseline_admissible,
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


def test_bare_differential_cannot_confirm_boolean_sqli() -> None:
    # This used to assert the opposite. A benign-vs-payload differential has NO ATTRIBUTION STEP: it
    # cannot separate "the injected boolean changed the query" from "the app treated two strings
    # differently", so it minted High boolean_sqli FACTs (0.87-0.95, offline-re-verifiable) against a
    # STATIC page behind a CRS-942130 WAF rule and against an app doing strict input validation —
    # both with no database at all. DIFFERENTIAL_RESPONSE is no longer an acceptable confirmer for
    # any truth-value-attribution class; BOOLEAN_INFERENCE (the SPRT truth-value partition) is.
    result = OracleVerifier().confirm({
        "bug_class": "boolean_sqli",
        "baseline": {"status": 200, "body": "No results found."},
        "mutated": {"status": 200, "body": "admin superuser row " * 20},
    })
    assert not result.confirmed
    assert "boolean_inference" in result.rationale


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
    # RED-PEN B3: the original version varied ONLY the discriminator, which is why it
    # passed while `latency_ms` was still a free field. The LATENCY NUMBERS are now
    # varied too — that, not the discriminator, was the live lever on 1ccd18a5
    # (identical bodies + a fabricated `latency_ms: 9999.0` minted a confirmed
    # `request_smuggling` FACT at 0.700 with no canary and no second connection).
    latency_pairs = [
        (10.0, 10.0),          # the original: identical
        (10.0, 9_999.0),       # the measured B3 repro
        (10.0, 1_500.0),       # exactly the retired protocol threshold
        (10.0, 1_500_000.0),   # absurd
        (9_999.0, 10.0),       # sign-flipped
        (0.0, 0.0),
    ]
    for disc in hostile_discriminators:
        for base_ms, mut_ms in latency_pairs:
            for bug_class in ("boolean_sqli", "nosqli", "sqli", "auth_bypass",
                              # every spelling that folds onto `request_smuggling`
                              "request_smuggling", "http_request_smuggling", "http_desync",
                              "request_desync", "response_smuggling"):
                ctx = _hostile(bug_class, disc)
                ctx["baseline"]["latency_ms"] = base_ms
                ctx["mutated"]["latency_ms"] = mut_ms
                result = OracleVerifier().confirm(ctx)
                assert not result.confirmed, (
                    f"{bug_class} minted a FACT from identical bytes via {disc} "
                    f"with latency {base_ms}->{mut_ms}")
                for sig in result.signals:
                    if sig.kind is OracleKind.DIFFERENTIAL_RESPONSE:
                        assert not sig.fired, (
                            f"{bug_class}/{disc}: differential fired on identical bytes "
                            f"with latency {base_ms}->{mut_ms}")


def test_request_smuggling_refuses_a_baseline_mutated_pair_outright() -> None:
    """RED-PEN B3 — the F8 pin keyed the discriminator on `normalize_bug_class(
    ctx["bug_class"])`, a field the producer of the untrusted report also writes, so
    it was bypassable through the very field it keyed on. The row is GONE and the
    differential arm now REFUSES the class: not "compares it under a stricter rule",
    refuses. A refusal is a SKIPPED oracle, so the finding is inconclusive."""
    for spelling in ("request_smuggling", "http_request_smuggling", "http_desync",
                     "request_desync", "response_smuggling"):
        assert not differential_baseline_admissible(spelling)
        # even a GENUINELY divergent pair is refused: content divergence between two
        # producer-supplied bodies proves nothing about HTTP framing.
        result = OracleVerifier().confirm({
            "bug_class": spelling,
            "baseline": {"status": 200, "body": "a" * 100, "latency_ms": 10.0},
            "mutated": {"status": 500, "body": "totally different", "latency_ms": 9_999.0},
        })
        assert not result.confirmed, f"{spelling} confirmed from a baseline/mutated pair"
        assert result.signals == [], f"{spelling} ran an oracle at all: {result.signals}"
    # the classes that legitimately use a content differential are untouched
    assert differential_baseline_admissible("nosqli")
    assert differential_baseline_admissible("boolean_sqli")


def test_smuggling_desync_canary_path_still_confirms() -> None:
    """The mutation control for the refusal above: the SOUND desync proof — the
    unique-canary differential over VIGIL's own second requests — must still mint.
    Without this the B3 refusal could be hiding a total loss of the class."""
    canary = "vigilDesyncCanary8f21a7c3"
    result = OracleVerifier().confirm({
        "bug_class": "request_smuggling",
        "smuggling_desync": {
            "canary": canary,
            "technique": "CL.TE",
            "conflict": {"channel": True, "status": 200, "body": f"reflected c={canary}"},
            "control": {"channel": True, "status": 200, "body": "vigil-follow ok"},
        },
    })
    assert result.confirmed, result.rationale
    assert result.confirming_signals[0].kind is OracleKind.DIFFERENTIAL_RESPONSE


def test_protocol_discriminator_table_is_closed_and_latency_free_by_default() -> None:
    generic = differential_protocol_discriminator("nosqli")
    assert generic["dimensions"] == ["status", "length", "lexical"]
    assert "latency" not in generic["dimensions"]
    assert generic["expect"] == "differ"
    assert "true_marker" not in generic
    # RED-PEN B3: the table is EMPTY. No class gets a latency discriminator from the
    # authority, so there is no row for a producer-written bug_class to select.
    assert _DIFFERENTIAL_PROTOCOL_DISCRIMINATORS == {}
    for spelling in ("request_smuggling", "http_request_smuggling", "http_desync",
                     "request_desync", "response_smuggling"):
        assert "latency" not in differential_protocol_discriminator(spelling)["dimensions"]
    # and the accessor hands out a COPY — a caller cannot mutate the protocol
    generic["dimensions"].append("latency")
    assert "latency" not in differential_protocol_discriminator("nosqli")["dimensions"]


# ---------------------------------------------------------------------------
# RED-PEN B3b — the TIMING arm was entirely unpinned: `timing_alpha`,
# `timing_injected_ms` and `timing_dose` came straight out of the untrusted ctx.
# ---------------------------------------------------------------------------

_JITTER_BASE = [100.0, 101.0, 102.0, 103.0, 104.0]
_JITTER_TREAT = [105.0, 106.0, 107.0, 108.0, 109.0]
_TIMING_CLASSES = ("time_based_sqli", "time_based", "time_based_command_injection")


def test_ordinary_jitter_never_confirms_a_timing_fact_however_the_ctx_is_tuned() -> None:
    # MEASURED on 1ccd18a5: `defaults` refused (median shift 5ms < floor 250ms), but
    # `timing_injected_ms: 1.0` (floor -> 0ms) and `timing_alpha: 0.5` both CONFIRMED.
    hostile = [
        {},
        {"timing_injected_ms": 1.0},              # the measured repro
        {"timing_injected_ms": 0.001},
        {"timing_injected_ms": -5_000.0},         # negative: floor would go negative
        {"timing_alpha": 0.5},                    # the measured repro
        {"timing_alpha": 0.99},
        {"timing_alpha": 1.0, "timing_injected_ms": 1.0},
        {"timing_alpha": 0.5, "timing_injected_ms": 1.0,
         "timing_dose": {"low_ms": 1.0, "low_samples": _JITTER_TREAT,
                         "high_ms": 2.0, "high_samples": _JITTER_TREAT}},
    ]
    for extra in hostile:
        for bug_class in _TIMING_CLASSES:
            result = OracleVerifier().confirm({
                "bug_class": bug_class,
                "baseline_latencies": list(_JITTER_BASE),
                "treatment_latencies": list(_JITTER_TREAT),
                **extra,
            })
            assert not result.confirmed, (
                f"{bug_class} minted a timing FACT out of a 5ms jitter shift via {extra}")


def test_a_permissive_ctx_alpha_cannot_widen_the_significance_level() -> None:
    # bimodal samples: the effect floor is cleared (400ms median shift) but the ranks
    # overlap, so p = 0.028 — refused at the protocol alpha of 0.01 and ACCEPTED at the
    # ctx-supplied 0.5 on 1ccd18a5.
    base = [100.0] * 5 + [1_000.0] * 5
    treat = [500.0] * 5 + [1_400.0] * 5
    for alpha in (0.05, 0.5, 0.99, 1.0):
        result = OracleVerifier().confirm({
            "bug_class": "time_based_sqli",
            "baseline_latencies": base, "treatment_latencies": treat,
            "timing_alpha": alpha,
        })
        assert not result.confirmed, f"ctx alpha={alpha} widened the significance level"
    # a ctx alpha may still TIGHTEN — the ratchet is one-way, not a hard override
    from .. import oracles

    assert oracles.timing_oracle(base, treat, alpha=1e-9).fired is False


def test_ctx_injected_ms_can_only_raise_the_effect_floor() -> None:
    from .. import oracles

    base = [100.0] * 8
    treat = [400.0] * 8            # a real 300ms shift: above the 250ms absolute floor
    assert oracles.timing_oracle(base, treat).fired
    # a tiny declared delay used to drive the floor to ~0; it may no longer lower it
    assert oracles.timing_oracle(base, treat, injected_ms=1.0).fired
    assert oracles.timing_oracle(base, treat, injected_ms=1.0).observed["floor_ms"] == 250.0
    # a big declared delay still TIGHTENS, exactly as the honest producer intends
    big = oracles.timing_oracle(base, treat, injected_ms=5_000.0)
    assert big.observed["floor_ms"] == 2_500.0
    assert not big.fired


def test_timing_dose_is_demote_only() -> None:
    """Why `timing_dose` is still read from the ctx while `timing_alpha` is not: a
    hostile dose can only REFUSE a fire, never cause one. Dropping it would strictly
    WEAKEN the verifier, so it stays — this test is the proof obligation."""
    from .. import oracles

    base = [100.0] * 8
    treat = [400.0] * 8
    assert oracles.timing_oracle(base, treat).fired
    # a fabricated dose that does not scale REFUSES the fire (demote)
    flat = oracles.timing_oracle(base, treat, dose={
        "low_ms": 300.0, "low_samples": treat, "high_ms": 3_000.0, "high_samples": treat})
    assert not flat.fired
    # and no dose can make a NON-firing comparison fire (promote is impossible)
    quiet_base, quiet_treat = list(_JITTER_BASE), list(_JITTER_TREAT)
    assert not oracles.timing_oracle(quiet_base, quiet_treat).fired
    for dose in (None,
                 {"low_ms": 1.0, "low_samples": quiet_treat, "high_ms": 2.0,
                  "high_samples": quiet_treat},
                 {"low_ms": 1e-9, "low_samples": quiet_treat, "high_ms": 1e9,
                  "high_samples": quiet_treat},
                 {"garbage": True}):
        assert not oracles.timing_oracle(quiet_base, quiet_treat, dose=dose).fired


def test_a_real_time_based_delay_still_confirms() -> None:
    """The mutation control for the B3b pins: a genuine multi-second sleep, with the
    honest producer's declared `injected_ms`, must still mint."""
    base = [120.0, 118.0, 125.0, 119.0, 121.0, 117.0, 123.0, 120.0]
    treat = [3_130.0, 3_118.0, 3_140.0, 3_122.0, 3_127.0, 3_119.0, 3_135.0, 3_124.0]
    result = OracleVerifier().confirm({
        "bug_class": "time_based_sqli",
        "baseline_latencies": base, "treatment_latencies": treat,
        "timing_injected_ms": 3_000.0,
    })
    assert result.confirmed, result.rationale


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
