"""
verify.oracles.session_fixation_oracle (Wave 3.2) — the pure session-fixation oracle + its verifier wiring.

The oracle proves the ACHIEVED fixation state (CWE-384) by the PRIVATE-READ REDUCTION re-derived from the
RETAINED RAW bytes — it never trusts a bool and never mints on a bare success-marker / credential-presence
differential (six rounds proved that proves only that the cookie changed the response, not that S0
authenticated). It fires ONLY when a VIGIL-fixed pre-auth sentinel id SURVIVED login UNROTATED (post-auth id
== the fixed id) AND a genuine victim-PRIVATE discriminator D is PRESENT in S0's read of the protected
resource AND PRESENT in the owner's authoritative read yet PROVABLY ABSENT from (a) a SUBSTANTIVE SAME-SHAPE
2xx read by an OTHER unauthorized identity — the DECISIVE clause that defeats a benign credential-presence-
varying app — and (b) a valid no-session baseline. It fails closed to a LEAD on: no/invalid/reflected D; a
non-substantive S0 read; a missing/failing owner (positive) reference; a missing / denial / empty / error /
different-shape other-identity reference; a missing/invalid no-session baseline; or D present in a negative
reference. It uses its OWN dedicated ``OracleKind.SESSION_FIXATION`` (so ``oracle_version(ACHIEVED_STATE)`` is
UNTOUCHED), held OUT of the frozen ``_ALL_ORACLES`` (which stays EXACTLY 15), reachable ONLY through the
explicit ``session_fixation`` row keyed on a fresh ``session_fixation`` ctx key (``make gate`` byte-identical).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import session_fixation_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_S0 = "sfx_" + "ab12cd34" * 4   # 32 hex chars → matches the sfx_<hex> sentinel shape
_D = "PRIVATE-SSN-victim-4021-7788"       # the victim-PRIVATE discriminator (the achieved-state proof)
_MARK = "SESSFIX-AUTHENTICATED"           # chrome marker rendered to EVERY authenticated identity (NOT private)
# S0's read: the chrome marker + the VICTIM's private datum (S0 is the victim's fixed session).
_S0_READ = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>{_D}</p>"}
# the owner's authoritative read: the same private datum is present (the POSITIVE reference).
_OWNER = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>{_D}</p>"}
# an OTHER unauthorized identity's SUBSTANTIVE SAME-SHAPE read: chrome present, the victim datum ABSENT.
_UNAUTH = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>PRIVATE-SSN-mallory-9999-0000</p>"}
# a no-session read: a substantive logged-out page (the victim datum absent).
_NOSESS = {"status": 200, "body": "<h1>Please log in</h1><p>You are logged out.</p>"}


def _obs(**over):
    base = {"sentinel_id": _S0, "post_auth_id": _S0, "cookie_name": "SESSION", "private_discriminator": _D,
            "authorized_view": dict(_S0_READ), "owner_view": dict(_OWNER), "unauth_ref": dict(_UNAUTH),
            "logged_out_ref": dict(_NOSESS), "logged_out_markers": [], "logged_out_statuses": []}
    base.update(over)
    return base


def test_fires_when_fixed_id_survives_and_private_read_achieved() -> None:
    sig = session_fixation_oracle(_obs())
    assert sig.fired and sig.kind is OracleKind.SESSION_FIXATION
    assert sig.conclusive and sig.confidence >= 0.9
    assert "fixation" in sig.evidence.lower() and _S0 in sig.evidence


def test_benign_cookie_varying_app_marker_present_with_cookie_absent_without_is_a_lead() -> None:
    # THE ROUND-5 SIXTH-VARIANT (CRITICAL): a benign app renders the operator marker whenever ANY session
    # cookie is present (marker not derived from the sentinel) and omits it without a cookie — 'present-with-
    # cookie / absent-without'. That proves only the COOKIE changed the response, NOT that S0 authenticated.
    # Under the private-read reduction the operator's D is the chrome marker (not private): it is present in
    # S0's read, the owner's read AND the OTHER-identity's same-shape read (any credential shows the chrome),
    # so the DECISIVE clause (D absent from the same-shape other-identity reference) FAILS ⇒ LEAD, never a FACT.
    chrome = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome, valued user.</p>"}
    nocookie = {"status": 200, "body": "<h1>Portal</h1><p>Please sign in.</p>"}
    sig = session_fixation_oracle(_obs(private_discriminator=_MARK, authorized_view=dict(chrome),
                                       owner_view=dict(chrome), unauth_ref=dict(chrome),
                                       logged_out_ref=dict(nocookie)))
    assert not sig.fired and sig.conclusive is False


def test_private_looking_but_reflected_discriminator_is_a_lead() -> None:
    # A D that LOOKS private but is a SUBSTRING of / STRADDLES the VIGIL-fixed sentinel is a reflected
    # cookie-echo artifact (S0's read is the ONLY leg carrying Cookie: SESSION=S0), not access-gated content.
    # (d) disqualifies it ⇒ LEAD. Both the whole-substring and the straddle forms.
    substr = _S0[4:24]                       # a 20-hex chunk of the sentinel — looks like a private token
    echo_read = {"status": 200, "body": f"<h1>{_MARK}</h1><p>token {_S0} home</p>"}
    echo_owner = {"status": 200, "body": f"<h1>{_MARK}</h1><p>token {_S0} home</p>"}
    sig = session_fixation_oracle(_obs(private_discriminator=substr, authorized_view=dict(echo_read),
                                       owner_view=dict(echo_owner)))
    assert not sig.fired and sig.conclusive is False
    straddle = _S0[-6:] + " home"            # a hex tail of S0 + adjacent static text — straddles the sentinel
    sig2 = session_fixation_oracle(_obs(private_discriminator=straddle, authorized_view=dict(echo_read),
                                        owner_view=dict(echo_owner)))
    assert not sig2.fired and sig2.conclusive is False


def test_no_private_discriminator_is_a_lead() -> None:
    for bad in (None, "", "  ", "ab"):
        sig = session_fixation_oracle(_obs(private_discriminator=bad))
        assert not sig.fired and sig.conclusive is False, f"discriminator {bad!r} minted a FACT"


def test_missing_positive_owner_reference_is_a_lead() -> None:
    # Without a SUBSTANTIVE owner (positive) reference containing D, D is not proven to be REAL private
    # content (as opposed to chrome that appears whenever a credential is present) ⇒ undecidable ⇒ LEAD.
    for owner in (None, {"status": 200, "body": ""}, {"status": 401, "body": "Unauthorized"},
                  {"status": 200, "body": "<h1>Account</h1><p>a substantive page WITHOUT the datum</p>"}):
        sig = session_fixation_oracle(_obs(owner_view=owner))
        assert not sig.fired and sig.conclusive is False, f"owner_view={owner!r} minted a FACT"


def test_missing_or_non_substantive_same_shape_negative_reference_is_a_lead() -> None:
    # The DECISIVE clause needs an OTHER-identity read that is a SUBSTANTIVE SAME-SHAPE 2xx (a real render of
    # the resource). A missing reference, a denial (401/403), an empty/short 2xx, or an error page is REFUSED
    # (its absent D is vacuous) ⇒ LEAD. A no-session-ONLY differential can NEVER mint.
    for unauth in (None, {"status": 401, "body": "Access denied. Please authenticate."},
                   {"status": 403, "body": "Forbidden"}, {"status": 200, "body": ""},
                   {"status": 200, "body": "Internal Server Error"}, {"status": 500, "body": "<h1>crash</h1>"}):
        sig = session_fixation_oracle(_obs(unauth_ref=unauth))
        assert not sig.fired and sig.conclusive is False, f"unauth_ref={unauth!r} minted a FACT"


def test_discriminator_present_in_the_same_shape_other_identity_reference_is_a_lead() -> None:
    # If D appears in the OTHER identity's substantive same-shape read, it is chrome / shared / not
    # victim-private ⇒ the private-read differential is unsatisfied ⇒ LEAD (this is the anti-chrome proof).
    shared = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>{_D}</p>"}
    sig = session_fixation_oracle(_obs(unauth_ref=dict(shared)))
    assert not sig.fired and sig.conclusive is False


def test_discriminator_present_in_a_substantive_no_session_baseline_is_a_lead() -> None:
    # D present in a SUBSTANTIVE no-session read ⇒ D is public, not authorization-gated ⇒ LEAD.
    public = {"status": 200, "body": f"<h1>Public</h1><p>{_D}</p><p>everyone can see this.</p>"}
    sig = session_fixation_oracle(_obs(logged_out_ref=dict(public)))
    assert not sig.fired and sig.conclusive is False


def test_missing_or_invalid_no_session_baseline_is_a_lead() -> None:
    # No valid no-session gating baseline (a bare 5xx / empty / body-less denial) ⇒ the datum's gating is
    # unproven ⇒ LEAD. (A genuine 401/403 WITH a real deny body, or a substantive 2xx, is a valid baseline.)
    for lo in (None, {"status": 200, "body": ""}, {"status": 500, "body": "<h1>err</h1>"},
               {"status": 401, "body": ""}):
        sig = session_fixation_oracle(_obs(logged_out_ref=lo))
        assert not sig.fired and sig.conclusive is False, f"logged_out_ref={lo!r} minted a FACT"


def test_genuine_denial_no_session_baseline_still_permits_a_fact() -> None:
    # A 401/403 that CARRIES a real deny body is a valid gating baseline (access requires credentials): the
    # differential is still established by the same-shape other-identity reference ⇒ FACT.
    sig = session_fixation_oracle(_obs(logged_out_ref={"status": 401, "body": "Unauthorized: please log in."}))
    assert sig.fired and sig.conclusive


def test_authorized_view_not_substantive_is_a_lead() -> None:
    # A non-substantive S0 read (empty / too-short / error-or-deny 2xx) cannot PROVE the private read ⇒ LEAD.
    for av in ({"status": 200, "body": ""},
               {"status": 200, "body": f"Internal Server Error rendering {_D}"},
               {"status": 500, "body": f"<h1>{_D}</h1> crashed"}):
        sig = session_fixation_oracle(_obs(authorized_view=av))
        assert not sig.fired and sig.conclusive is False


def test_survived_unrotated_but_private_datum_absent_from_s0_read_is_a_conclusive_clean() -> None:
    # S1 == S0 and the full differential is validated (owner has D, the other-identity same-shape read lacks
    # it, the no-session baseline is valid) but D is ABSENT from S0's otherwise-substantive read ⇒ S0 rendered
    # the resource but did NOT reach the victim's private datum (like the unauthorized peer) ⇒ conclusive CLEAN.
    s0_no_d = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>PRIVATE-SSN-mallory-1-2</p>"}
    sig = session_fixation_oracle(_obs(authorized_view=dict(s0_no_d)))
    assert not sig.fired and sig.conclusive is True


def test_logged_out_marker_in_s0_read_disproves_auth_conclusive_clean() -> None:
    # An operator logged-out marker present in S0's read decisively DISPROVES auth (no D needed) ⇒ clean.
    sig = session_fixation_oracle(_obs(
        authorized_view={"status": 200, "body": f"<h1>{_MARK}</h1><p>Please sign in to continue.</p>"},
        logged_out_markers=["Please sign in"]))
    assert not sig.fired and sig.conclusive is True


def test_rotation_with_dead_fixed_id_is_a_conclusive_clean() -> None:
    # S1 != S0 AND the VIGIL-fixed id S0 no longer authenticates (its read is a logged-out page: a decisive
    # logged-out status) ⇒ the app rotated AND invalidated the pre-auth id (the correct defense) ⇒ clean.
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16,
                                       authorized_view={"status": 401, "body": "Unauthorized"}))
    assert not sig.fired and sig.conclusive is True
    assert "rotat" in sig.evidence.lower()


def test_rotation_but_fixed_id_still_reaches_private_view_is_inconclusive() -> None:
    # A value rotation ALONE is not proof of defense: an app can rotate the cookie VALUE yet leave the
    # VIGIL-fixed pre-auth id S0 still valid (a REAL fixation). With the private-read differential proving S0
    # still reaches the victim's datum, the oracle must NOT round that to a clean — and, indistinguishable
    # from a hand-forged rotation, does not mint either: INCONCLUSIVE.
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16))
    assert not sig.fired and sig.conclusive is False
    assert "rotat" in sig.evidence.lower()


def test_server_set_non_sentinel_id_refuses_and_is_a_lead() -> None:
    server_id = "JSESSIONID_9f8e7d6c5b4a"
    sig = session_fixation_oracle(_obs(sentinel_id=server_id, post_auth_id=server_id))
    assert not sig.fired and sig.conclusive is False
    assert "sentinel" in sig.evidence.lower()


def test_missing_post_auth_id_is_inconclusive() -> None:
    assert not session_fixation_oracle(_obs(post_auth_id=None)).fired
    assert session_fixation_oracle(_obs(post_auth_id=None)).conclusive is False
    assert not session_fixation_oracle(_obs(post_auth_id="")).fired


def test_ignores_a_bare_authenticated_bool_with_no_raw_bytes() -> None:
    # DURABLE soundness: a legacy-shaped record carrying only authenticated_after_login=True (no D, no
    # references) must be IGNORED — the oracle re-derives from raw bytes and fails closed to a LEAD.
    sig = session_fixation_oracle({"sentinel_id": _S0, "post_auth_id": _S0, "cookie_name": "SESSION",
                                   "authenticated_after_login": True})
    assert not sig.fired and sig.conclusive is False


def test_bare_success_marker_differential_is_no_longer_a_minting_path() -> None:
    # The OLD design: a success_marker PRESENT in the fixed-session view, ABSENT from a no-cookie reference,
    # WITHOUT a private discriminator D. That is exactly the credential-presence differential six rounds
    # proved unsound ⇒ it must NOT mint (no D ⇒ LEAD), even shaped like a fixation.
    legacy = {"sentinel_id": _S0, "post_auth_id": _S0, "cookie_name": "SESSION",
              "success_marker": _MARK,
              "authorized_view": {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back, admin.</p>"},
              "logged_out_ref": {"status": 200, "body": "<h1>Please log in</h1><p>Logged out.</p>"}}
    sig = session_fixation_oracle(legacy)
    assert not sig.fired and sig.conclusive is False


def test_empty_or_malformed_observed_does_not_fire() -> None:
    assert not session_fixation_oracle({}).fired
    assert not session_fixation_oracle(None).fired


def test_is_deterministic() -> None:
    a = session_fixation_oracle(_obs())
    b = session_fixation_oracle(_obs())
    assert (a.fired, a.confidence, a.evidence, a.conclusive) == (b.fired, b.confidence, b.evidence, b.conclusive)


def test_verifier_routes_only_via_the_explicit_row_on_a_fresh_key() -> None:
    v = OracleVerifier()
    assert normalize_bug_class("session_fixation") == "session_fixation"
    assert normalize_bug_class("session_id_fixation") == "session_fixation"
    assert BUG_CLASS_ORACLES["session_fixation"] == (OracleKind.SESSION_FIXATION,)
    assert v.oracles_for("session_fixation") == (OracleKind.SESSION_FIXATION,)
    out = v.confirm({"bug_class": "session_fixation", "session_fixation": _obs()})
    assert out.confirmed
    # a chrome-in-every-view record (D present in the same-shape other-identity read) does NOT confirm.
    shared = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back.</p><p>{_D}</p>"}
    assert not v.confirm({"bug_class": "session_fixation",
                          "session_fixation": _obs(unauth_ref=dict(shared))}).confirmed


def test_dedicated_kind_out_of_frozen_fallback_gate_byte_identical() -> None:
    # SESSION_FIXATION is its OWN kind, held OUT of the frozen fallback (which stays EXACTLY 15).
    assert BUG_CLASS_ORACLES["session_fixation"] == (OracleKind.SESSION_FIXATION,)
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.SESSION_FIXATION not in _ALL_ORACLES
    # the fresh `session_fixation` ctx key is NOT carried by an unknown class, so the kind cannot fire for one
    v = OracleVerifier()
    assert v.confirm({"bug_class": "some_unknown_class", "session_fixation": _obs()}).confirmed is False
