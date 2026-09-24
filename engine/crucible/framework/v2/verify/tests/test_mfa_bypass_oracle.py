"""
verify.oracles.mfa_bypass_oracle (Wave 4.5) — the pure MFA-bypass oracle + its verifier wiring.

The oracle proves the ACHIEVED post-MFA state (CWE-287/CWE-308) under TWO independent locks:
  LOCK 1 — a FAIL-CLOSED three-part operator attestation (mfa_enrolled_account + factor1_only_presented +
           post_mfa_resource_certified, each strict True), re-derived from the retained record at every
           verification. WITHOUT it NO fire is emitted for ANY input — the killer FP of an intentionally
           factor-1 page can never round to a FACT.
  LOCK 2 — the PRIVATE-READ REDUCTION (the same machinery SESSION_FIXATION / Wave-3.1 use), re-derived from the
           RETAINED RAW bytes: a victim-PRIVATE D PRESENT in the factor-1-only read AND the post-MFA owner's
           read yet PROVABLY ABSENT from a SUBSTANTIVE SAME-SHAPE read by an OTHER not-post-MFA identity — the
           DECISIVE clause — and a valid no-session baseline, with D a valid non-reflected discriminator.

It uses its OWN dedicated ``OracleKind.MFA_BYPASS`` (so ``oracle_version(ACHIEVED_STATE)`` is UNTOUCHED), held
OUT of the frozen ``_ALL_ORACLES`` (which stays EXACTLY 15), reachable ONLY through the explicit ``mfa_bypass``
row keyed on a fresh ``mfa_bypass`` ctx key (``make gate`` byte-identical).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import mfa_bypass_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_D = "PRIVATE-MFA-TOKEN-victim-9207-5531"    # the victim-PRIVATE, post-MFA-gated discriminator
_MARK = "MFA-CONSOLE-DASHBOARD"              # chrome marker rendered to EVERY authenticated identity (NOT private)
# the factor-1-only session's read: chrome + the VICTIM's private datum (the bypass reached post-MFA content).
_F1_READ = {"status": 200, "body": f"<h1>{_MARK}</h1><p>console overview.</p><p>{_D}</p>"}
# the fully post-MFA owner's read: the same private datum is present (the POSITIVE reference).
_OWNER = {"status": 200, "body": f"<h1>{_MARK}</h1><p>console overview.</p><p>{_D}</p>"}
# an OTHER not-post-MFA identity's SUBSTANTIVE SAME-SHAPE read: chrome present, the victim datum ABSENT.
_OTHER = {"status": 200, "body": f"<h1>{_MARK}</h1><p>console overview.</p><p>PRIVATE-MFA-TOKEN-mallory-0-0</p>"}
# a no-session read: a substantive logged-out page (the victim datum absent).
_NOSESS = {"status": 200, "body": "<h1>Please log in</h1><p>You are logged out.</p>"}

_ATTEST = {"mfa_enrolled_account": True, "factor1_only_presented": True, "post_mfa_resource_certified": True}


def _obs(**over):
    base = {"operator_attestation": dict(_ATTEST), "private_discriminator": _D,
            "factor1_view": dict(_F1_READ), "owner_view": dict(_OWNER), "pre_mfa_ref": dict(_OTHER),
            "logged_out_ref": dict(_NOSESS), "logged_out_markers": [], "logged_out_statuses": []}
    base.update(over)
    return base


def test_fires_when_attested_and_factor1_reached_private_view() -> None:
    sig = mfa_bypass_oracle(_obs())
    assert sig.fired and sig.kind is OracleKind.MFA_BYPASS
    assert sig.conclusive and sig.confidence >= 0.9
    assert "mfa bypass" in sig.evidence.lower()


def test_no_attestation_is_a_lead_never_a_fact_or_clean() -> None:
    # THE KILLER FP: an intentionally factor-1 page is indistinguishable from a bypass. Absent the attestation
    # NO fire for ANY input — even the SAME firing capture — and NOT a channel-confirmed clean.
    for att in (None, {}, {"mfa_enrolled_account": True, "factor1_only_presented": True},
                {"mfa_enrolled_account": True, "factor1_only_presented": True,
                 "post_mfa_resource_certified": False},
                # a truthy non-bool must not pass the strict `is True` gate
                {"mfa_enrolled_account": 1, "factor1_only_presented": "yes", "post_mfa_resource_certified": 1}):
        sig = mfa_bypass_oracle(_obs(operator_attestation=att))
        assert not sig.fired and sig.conclusive is False, f"attestation {att!r} minted/cleared"
        assert "attestation" in sig.evidence.lower()


def test_benign_factor2_enforcing_app_is_a_conclusive_clean() -> None:
    # The BENIGN TWIN: attested, the full differential validated (owner has D, the other-identity same-shape
    # read lacks it, the no-session baseline is valid), but D is ABSENT from the factor-1-only read (the app
    # enforces the second factor before releasing the private datum) ⇒ the factor-1-only session did NOT reach
    # the post-MFA view ⇒ conclusive CLEAN, never a FACT — even WITH the attestation.
    f1_no_d = {"status": 200, "body": f"<h1>{_MARK}</h1><p>console overview.</p><p>Complete your second factor.</p>"}
    sig = mfa_bypass_oracle(_obs(factor1_view=dict(f1_no_d)))
    assert not sig.fired and sig.conclusive is True


def test_no_private_discriminator_is_a_lead() -> None:
    for bad in (None, "", "  ", "ab"):
        sig = mfa_bypass_oracle(_obs(private_discriminator=bad))
        assert not sig.fired and sig.conclusive is False, f"discriminator {bad!r} minted a FACT"


def test_missing_positive_owner_reference_is_a_lead() -> None:
    # Without a SUBSTANTIVE owner (positive) reference containing D, D is not proven to be REAL post-MFA-gated
    # content (vs chrome shown for any credential) ⇒ undecidable ⇒ LEAD.
    for owner in (None, {"status": 200, "body": ""}, {"status": 401, "body": "Unauthorized"},
                  {"status": 200, "body": "<h1>Console</h1><p>a substantive page WITHOUT the datum</p>"}):
        sig = mfa_bypass_oracle(_obs(owner_view=owner))
        assert not sig.fired and sig.conclusive is False, f"owner_view={owner!r} minted a FACT"


def test_missing_or_non_substantive_same_shape_negative_reference_is_a_lead() -> None:
    # The DECISIVE clause needs an OTHER-identity read that is a SUBSTANTIVE SAME-SHAPE 2xx. A missing
    # reference, a denial (401/403), an empty/short 2xx, or an error page is REFUSED (its absent D is vacuous)
    # ⇒ LEAD. A no-session-ONLY differential can NEVER mint.
    for other in (None, {"status": 401, "body": "Access denied. Please authenticate."},
                  {"status": 403, "body": "Forbidden"}, {"status": 200, "body": ""},
                  {"status": 200, "body": "Internal Server Error"}, {"status": 500, "body": "<h1>crash</h1>"}):
        sig = mfa_bypass_oracle(_obs(pre_mfa_ref=other))
        assert not sig.fired and sig.conclusive is False, f"pre_mfa_ref={other!r} minted a FACT"


def test_discriminator_present_in_the_same_shape_other_identity_reference_is_a_lead() -> None:
    # If D appears in the OTHER identity's substantive same-shape read, it is chrome / shared / not
    # victim-private ⇒ the private-read differential is unsatisfied ⇒ LEAD (the anti-chrome proof).
    shared = {"status": 200, "body": f"<h1>{_MARK}</h1><p>console overview.</p><p>{_D}</p>"}
    sig = mfa_bypass_oracle(_obs(pre_mfa_ref=dict(shared)))
    assert not sig.fired and sig.conclusive is False


def test_discriminator_present_in_a_substantive_no_session_baseline_is_a_lead() -> None:
    # D present in a SUBSTANTIVE no-session read ⇒ D is public, not authorization-gated ⇒ LEAD.
    public = {"status": 200, "body": f"<h1>Public</h1><p>{_D}</p><p>everyone can see this.</p>"}
    sig = mfa_bypass_oracle(_obs(logged_out_ref=dict(public)))
    assert not sig.fired and sig.conclusive is False


def test_missing_or_invalid_no_session_baseline_is_a_lead() -> None:
    for lo in (None, {"status": 200, "body": ""}, {"status": 500, "body": "<h1>err</h1>"},
               {"status": 401, "body": ""}):
        sig = mfa_bypass_oracle(_obs(logged_out_ref=lo))
        assert not sig.fired and sig.conclusive is False, f"logged_out_ref={lo!r} minted a FACT"


def test_factor1_view_not_substantive_is_a_lead() -> None:
    # A non-substantive factor-1-only read (empty / too-short / error-or-deny 2xx) cannot PROVE the private
    # read ⇒ LEAD.
    for av in ({"status": 200, "body": ""},
               {"status": 200, "body": f"Internal Server Error rendering {_D}"},
               {"status": 500, "body": f"<h1>{_D}</h1> crashed"}):
        sig = mfa_bypass_oracle(_obs(factor1_view=av))
        assert not sig.fired and sig.conclusive is False


def test_logged_out_marker_in_factor1_read_disproves_auth_conclusive_clean() -> None:
    # An operator logged-out marker in the factor-1-only read decisively DISPROVES the achieved read ⇒ clean.
    sig = mfa_bypass_oracle(_obs(
        factor1_view={"status": 200, "body": f"<h1>{_MARK}</h1><p>Please sign in to continue.</p>"},
        logged_out_markers=["Please sign in"]))
    assert not sig.fired and sig.conclusive is True


def test_genuine_denial_no_session_baseline_still_permits_a_fact() -> None:
    # A 401/403 that CARRIES a real deny body is a valid gating baseline; the differential is still established
    # by the same-shape other-identity reference ⇒ FACT.
    sig = mfa_bypass_oracle(_obs(logged_out_ref={"status": 401, "body": "Unauthorized: please log in."}))
    assert sig.fired and sig.conclusive


def test_ignores_a_bare_bool_with_no_raw_bytes() -> None:
    # DURABLE soundness: a legacy-shaped record carrying only a bool (no attestation, no D, no references) is
    # IGNORED — the oracle re-derives from raw bytes + the attestation and fails closed to a LEAD.
    sig = mfa_bypass_oracle({"mfa_bypassed": True})
    assert not sig.fired and sig.conclusive is False


# ---- verifier wiring (byte-identity discipline) ------------------------------


def test_mfa_bypass_routes_to_its_own_kind_held_out_of_the_frozen_fallback() -> None:
    assert BUG_CLASS_ORACLES["mfa_bypass"] == (OracleKind.MFA_BYPASS,)
    assert OracleKind.MFA_BYPASS not in _ALL_ORACLES        # held OUT of the frozen unknown-class fallback
    assert len(_ALL_ORACLES) == 15
    for alias in ("second_factor_bypass", "2fa_bypass", "mfa_not_enforced", "otp_bypass"):
        assert normalize_bug_class(alias) == "mfa_bypass"


def test_verifier_confirms_a_wired_mfa_bypass_context() -> None:
    ctx = {"bug_class": "mfa_bypass", "mfa_bypass": _obs()}
    outcome = OracleVerifier().confirm(ctx)
    assert outcome.confirmed
    assert any(s.kind is OracleKind.MFA_BYPASS and s.fired for s in outcome.signals)


def test_verifier_without_the_mfa_bypass_key_does_not_fire() -> None:
    # The dispatch arm fires ONLY when the ctx carries the fresh `mfa_bypass` key — so no benchmark/scan/engage
    # finding (none of which carry it) can route to this kind, keeping `make gate` byte-identical.
    outcome = OracleVerifier().confirm({"bug_class": "mfa_bypass"})
    assert not outcome.confirmed
