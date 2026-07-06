"""Tests for verify.verifier — the confirmation authority and its mapping."""

from __future__ import annotations

from ..models import OracleKind
from ..oob import OOBReceiver
from ..verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
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
    v = OracleVerifier()
    assert set(v.oracles_for("some-novel-bug")) == set(OracleKind)


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
        })
    assert result.confirmed
    assert result.confirming_signals[0].kind is OracleKind.OOB_CALLBACK


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


def test_unknown_bug_class_runs_only_available_inputs() -> None:
    marker = "canary-zz99xx"
    result = OracleVerifier().confirm({
        "bug_class": "brand-new-thing",
        "marker": marker,
        "observed_sink": f"leaked {marker} here",
    })
    # Falls back to all oracles; both marker-based oracles (side_effect and the
    # context-aware reflection oracle) have inputs and run. side_effect fires on
    # the substring; reflection_context correctly does NOT (inert text). The
    # finding still confirms via side_effect.
    assert result.confirmed
    kinds = {s.kind for s in result.signals}
    assert kinds == {OracleKind.SIDE_EFFECT, OracleKind.REFLECTION_CONTEXT}
    assert {s.kind for s in result.confirming_signals} == {OracleKind.SIDE_EFFECT}


def test_custom_threshold_is_respected() -> None:
    ctx = {
        "bug_class": "crash",
        "process_output": "Traceback (most recent call last):\nValueError: x",
    }
    # A traceback fires ~0.65; a lenient verifier accepts it, the default won't.
    assert OracleVerifier(high_confidence=0.6).confirm(ctx).confirmed
    assert not OracleVerifier().confirm(ctx).confirmed
