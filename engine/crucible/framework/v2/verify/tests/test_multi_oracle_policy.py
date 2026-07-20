"""
Multi-oracle disagreement policy (Wave 4, item 5).

When more than one oracle applies to a finding, the combine rule is explicit and
safety-monotone: **any_high_confidence_fired**. One deterministic oracle firing
at/above the threshold is sufficient proof; a non-firing oracle CANNOT veto a
fired one (absence of a signal is not evidence of absence). The disagreement is
RECORDED as `dissent`, never treated as a refutation.

These tests pin the documented outcome + the dissent record.
"""

from __future__ import annotations

from framework.v2.verify.verifier import OracleVerifier

# error_based_sqli maps to (SIDE_EFFECT, DIFFERENTIAL_RESPONSE): two applicable
# oracles, so we can make one fire and the other stay silent.
_MARKER = "VIGIL-CANARY-7c1d"


def _side_effect_fires() -> dict:
    return {
        "marker": _MARKER,
        "observed_sink": f"SQL error: near '{_MARKER}': syntax error",
    }


def _differential_silent() -> dict:
    same = {"status": 200, "body": "identical body"}
    return {"baseline": same, "mutated": dict(same)}


def test_one_fires_one_silent_confirms_and_records_dissent() -> None:
    ctx = {"bug_class": "error_based_sqli", **_side_effect_fires(), **_differential_silent()}
    r = OracleVerifier().confirm(ctx)

    assert r.confirmed is True, "a high-confidence oracle fired -> confirmed"
    assert r.combine_policy == "any_high_confidence_fired"
    # The silent oracle ran but did not confirm — recorded as dissent, not a veto.
    assert r.dissent == ["differential_response"]
    # Both oracles are retained for audit.
    kinds = {(s.kind.value, s.fired) for s in r.signals}
    assert ("side_effect", True) in kinds
    assert ("differential_response", False) in kinds
    assert "Dissent" in r.rationale


def test_silent_oracle_cannot_veto_a_fired_one() -> None:
    # Safety-monotone: adding a disagreeing (silent) oracle must NOT flip a
    # confirmed finding to unconfirmed.
    fired_only = OracleVerifier().confirm({"bug_class": "error_based_sqli", **_side_effect_fires()})
    with_dissent = OracleVerifier().confirm(
        {"bug_class": "error_based_sqli", **_side_effect_fires(), **_differential_silent()}
    )
    assert fired_only.confirmed is True
    assert with_dissent.confirmed is True, "a non-firing oracle cannot veto a fired one"


def test_lone_confirming_oracle_has_no_dissent() -> None:
    r = OracleVerifier().confirm({"bug_class": "error_based_sqli", **_side_effect_fires()})
    assert r.confirmed is True
    assert r.dissent == [], "a single confirming oracle has nothing to dissent from"


def test_no_confirmation_leaves_dissent_empty() -> None:
    # Nothing fires: not confirmed, and dissent is empty (the 'not confirmed'
    # rationale already accounts for every oracle; dissent is a confirmed-only
    # disagreement record).
    r = OracleVerifier().confirm({"bug_class": "error_based_sqli", **_differential_silent()})
    assert r.confirmed is False
    assert r.dissent == []
