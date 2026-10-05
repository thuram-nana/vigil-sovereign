"""
End-to-end proof that a REAL (local) target drives a REAL confirmed finding.

This test is the artifact that discharges the audit's most important finding —
"no real target has ever driven a real confirmed finding." Each positive test
stands up a deliberately-vulnerable stdlib HTTP app on loopback, sends real
baseline and probe requests, and asserts the finding is confirmed by a *fired*
oracle signal, not an assertion. The negative-control app (non-injectable)
must NOT confirm — proving the authority does not rubber-stamp.

Hermetic by construction: ephemeral 127.0.0.1 port, clean server shutdown,
no clock in the verdict, no network beyond loopback.
"""

from __future__ import annotations

from ..adapter import FindingContext
from ..confirmation import (
    _BENIGN_QUERY,
    _TAUTOLOGY_QUERY,
    ConfirmedFinding,
    DifferentialDemoHandler,
    SafeDemoHandler,
    _http_get,
    _local_server,
    confirm_against_local_target,
    confirm_finding,
)
from ..models import OracleKind
from ..verifier import HIGH_CONFIDENCE, OracleVerifier


# ---------------------------------------------------------------------------
# The load-bearing assertion: a real local target -> a real confirmed finding
# ---------------------------------------------------------------------------


def test_local_target_drives_real_confirmed_finding() -> None:
    confirmed = confirm_against_local_target()  # DifferentialDemoHandler

    assert isinstance(confirmed, ConfirmedFinding)
    assert confirmed.confirmed is True
    assert confirmed.bug_class == "boolean_sqli"

    # The confirmation was carried by an oracle that actually fired — and it is the SOUND one.
    # A bare benign-vs-payload DIFFERENTIAL_RESPONSE is no longer an acceptable confirmer for any
    # truth-value-attribution class (verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES): it has no attribution
    # step and confirmed against a WAF block page and against strict input validation on targets
    # with no database. This proof now rests on the SPRT truth-value partition.
    assert confirmed.confirmed_by is OracleKind.BOOLEAN_INFERENCE
    assert confirmed.confidence >= HIGH_CONFIDENCE

    # A fired signal is retained as machine evidence.
    fired = [s for s in confirmed.signals if s.fired]
    assert fired, "a confirmed finding must retain at least one fired signal"
    carrier = next(s for s in fired if s.kind is confirmed.confirmed_by)
    assert carrier.confidence >= HIGH_CONFIDENCE
    assert carrier.evidence  # concrete artifact justifying the verdict

    assert "CONFIRMED" in confirmed.rationale


def test_confirmation_confidence_matches_strongest_signal() -> None:
    confirmed = confirm_against_local_target()
    assert confirmed is not None
    strongest = max(
        (s.confidence for s in confirmed.signals if s.fired),
        default=0.0,
    )
    assert confirmed.confidence == strongest


# ---------------------------------------------------------------------------
# The negative control: a non-injectable target must NOT confirm
# ---------------------------------------------------------------------------


def test_negative_control_local_target_does_not_confirm() -> None:
    # SafeDemoHandler is parameterised: benign and probe queries both miss,
    # so the two responses are indistinguishable and no oracle fires.
    result = confirm_against_local_target(app=SafeDemoHandler)
    assert result is None


def test_a_bare_benign_vs_tautology_differential_cannot_confirm_the_vulnerable_app() -> None:
    # The SAME genuinely-injectable target, judged the OLD way: one benign string, one tautology,
    # "did the responses differ?". That inference is refused now whatever it observes — it cannot
    # attribute the difference to the injected boolean, which is exactly how it minted FACTs on
    # targets with no database. Recall is preserved by the SPRT path above, not by this one.
    with _local_server(DifferentialDemoHandler) as base_url:
        baseline = _http_get(base_url, _BENIGN_QUERY)
        mutated = _http_get(base_url, _TAUTOLOGY_QUERY)
    assert baseline["body"] != mutated["body"], "the differential really does diverge here"
    ctx = FindingContext.from_http_responses(
        baseline, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})
    assert confirm_finding({"bug_class": "boolean_sqli"}, ctx) is None


# ---------------------------------------------------------------------------
# confirm_finding contract, exercised directly
# ---------------------------------------------------------------------------


def test_confirm_finding_returns_none_when_no_oracle_fires() -> None:
    # A context whose oracle cannot fire (empty OOB hit list) yields no finding.
    ctx = FindingContext.from_oob([], bug_class="ssrf")
    assert confirm_finding({"bug_class": "ssrf", "title": "blind ssrf"}, ctx) is None


def test_confirm_finding_promotes_on_real_state_signal() -> None:
    # A genuine captured record (attacker reached victim's readable order) adjudicated by a value-dependent
    # predicate over the captured evidence — the SOUND achieved-state FACT path (predicate_oracle). The
    # old expected/observed echo form is retired (Lane S / S1).
    ctx = FindingContext.from_predicate(
        {"owner": "victim", "readable": True, "id": 42},
        {"all": [{"eq": [{"var": "owner"}, "victim"]}, {"eq": [{"var": "readable"}, True]}]},
        bug_class="idor",
    )
    confirmed = confirm_finding(
        {"title": "IDOR on /account", "bug_class": "idor", "severity": "High"},
        ctx,
    )
    assert isinstance(confirmed, ConfirmedFinding)
    assert confirmed.confirmed_by is OracleKind.ACHIEVED_STATE
    assert confirmed.title == "IDOR on /account"
    assert confirmed.severity == "High"


def test_confirm_finding_fills_bug_class_from_finding() -> None:
    # Context carries no bug_class; the finding supplies it. (The carrier class is `idor` because a
    # bare differential can no longer confirm a boolean class at all — see
    # verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES; what is under test here is the bug_class fill-in.)
    ctx = FindingContext.from_predicate(
        {"owner": "victim", "readable": True, "id": 42},
        {"all": [{"eq": [{"var": "owner"}, "victim"]}, {"eq": [{"var": "readable"}, True]}]},
    )
    ctx.bug_class = ""
    confirmed = confirm_finding({"bug_class": "idor"}, ctx)
    assert confirmed is not None
    assert confirmed.bug_class == "idor"


def test_confirm_finding_accepts_raw_context_mapping() -> None:
    # a genuine reflected XSS: the canary broke out into a live element (not inert
    # text), so the context-aware oracle confirms it from a raw context mapping.
    marker = "OBSIDIANXSScanary7f3a"
    confirmed = confirm_finding(
        {"bug_class": "xss", "title": "reflected xss"},
        {
            "bug_class": "xss",
            "marker": marker,
            "observed_sink": f"<div>results</div>\"'><x{marker}>",
        },
    )
    assert confirmed is not None
    assert confirmed.confirmed_by is OracleKind.REFLECTION_CONTEXT


def test_custom_verifier_threshold_is_honoured() -> None:
    # A bare traceback fires the sanitizer oracle ~0.65 — below the default
    # threshold (None) but above a lenient one (a ConfirmedFinding).
    ctx = FindingContext.from_process_output(
        "Traceback (most recent call last):\nValueError: boom", bug_class="crash"
    )
    finding = {"bug_class": "crash", "title": "unhandled crash"}
    assert confirm_finding(finding, ctx) is None
    lenient = confirm_finding(finding, ctx, verifier=OracleVerifier(high_confidence=0.6))
    assert isinstance(lenient, ConfirmedFinding)


# ---------------------------------------------------------------------------
# The differential twin handlers behave as claimed (sanity on the demo target)
# ---------------------------------------------------------------------------


def test_vulnerable_and_safe_handlers_are_distinct() -> None:
    assert DifferentialDemoHandler.matcher is not SafeDemoHandler.matcher
