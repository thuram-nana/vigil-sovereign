"""
verify.oracles.session_fixation_oracle (Wave 3.2) — the pure session-fixation oracle + its verifier wiring.

The oracle proves the ACHIEVED fixation state (CWE-384) by a DIFFERENTIAL re-derived from the RETAINED RAW
bytes — it never trusts a pre-computed authenticated bool. It fires ONLY when a VIGIL-fixed pre-auth sentinel
id SURVIVED login UNROTATED (post-auth id == the fixed id) AND the operator ``success_marker`` is PRESENT in
the fixed-session view of the protected URL yet PROVABLY ABSENT from a SUBSTANTIVE same-URL LOGGED-OUT
reference. It refuses on a marker present in BOTH views (a common token / chrome / a benign soft-200 body both
share — the ROUND-4 defeating class), on no substantive logged-out reference (a LEAD), on rotation (the
correct defense), on a survived-but-unauthenticated id, on a non-sentinel (server-set) id, and on a missing
post-auth id. It uses its OWN dedicated ``OracleKind.SESSION_FIXATION`` (so ``oracle_version(ACHIEVED_STATE)``
is UNTOUCHED), held OUT of the frozen ``_ALL_ORACLES`` (which stays EXACTLY 15), reachable ONLY through the
explicit ``session_fixation`` row keyed on a fresh ``session_fixation`` ctx key (``make gate`` byte-identical).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import session_fixation_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_S0 = "sfx_" + "ab12cd34" * 4   # 32 hex chars → matches the sfx_<hex> sentinel shape
_MARK = "SESSFIX-AUTHENTICATED"
_AUTHED = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Welcome back, admin.</p>"}
_LOGGED_OUT = {"status": 200, "body": "<h1>Please log in</h1><p>You are logged out.</p>"}


def _obs(**over):
    base = {"sentinel_id": _S0, "post_auth_id": _S0, "cookie_name": "SESSION", "success_marker": _MARK,
            "authorized_view": dict(_AUTHED), "logged_out_ref": dict(_LOGGED_OUT),
            "logged_out_markers": [], "logged_out_statuses": []}
    base.update(over)
    return base


def test_fires_when_fixed_id_survives_and_differential_proves_auth() -> None:
    sig = session_fixation_oracle(_obs())
    assert sig.fired and sig.kind is OracleKind.SESSION_FIXATION
    assert sig.conclusive and sig.confidence >= 0.9
    assert "fixation" in sig.evidence.lower() and _S0 in sig.evidence


def test_marker_present_in_both_views_is_disqualified_no_fact() -> None:
    # ROUND-4 core: the marker appears in BOTH the fixed-session view AND the logged-out reference — a common
    # token / chrome / a benign soft-200 body both share. It is NOT access-gated ⇒ proves no auth ⇒ LEAD.
    both = {"status": 200, "body": f"<h1>{_MARK}</h1><p>Public landing page.</p>"}
    sig = session_fixation_oracle(_obs(authorized_view=dict(both), logged_out_ref=dict(both)))
    assert not sig.fired and sig.conclusive is False


def test_common_html_token_marker_in_both_views_no_fact() -> None:
    # The round-3 4th-variant: a 3-char common HTML token present in any HTML body, including the logged-out
    # reference ⇒ disqualified by the differential ⇒ no durable FACT.
    for token in ("<p>", "div"):
        body = {"status": 200, "body": "<html><body><div><p>page body content</p></div></body></html>"}
        sig = session_fixation_oracle(_obs(success_marker=token, authorized_view=dict(body),
                                           logged_out_ref=dict(body)))
        assert not sig.fired and sig.conclusive is False, f"token {token!r} minted a FACT"


def test_no_substantive_logged_out_reference_is_a_lead() -> None:
    # A fixation-shaped record (marker present in the fixed-session view, S1 == S0) but the logged-out
    # reference is empty / non-substantive ⇒ the differential cannot be established ⇒ LEAD, never a FACT.
    for lo in ({"status": 200, "body": ""}, {"status": 200, "body": "short"},
               {"status": 401, "body": "Unauthorized"}, None):
        sig = session_fixation_oracle(_obs(logged_out_ref=lo))
        assert not sig.fired and sig.conclusive is False, f"logged_out_ref={lo!r} minted a FACT"


def test_authorized_view_not_substantive_is_a_lead() -> None:
    # Even with a valid marker and a good negative reference, a non-substantive authorized view (empty /
    # too-short / error-or-deny 200) cannot PROVE auth ⇒ undecidable ⇒ LEAD.
    for av in ({"status": 200, "body": ""},
               {"status": 200, "body": f"Internal Server Error rendering {_MARK}"},
               {"status": 500, "body": f"<h1>{_MARK}</h1> crashed"}):
        sig = session_fixation_oracle(_obs(authorized_view=av))
        assert not sig.fired and sig.conclusive is False


def test_no_valid_success_marker_is_a_lead() -> None:
    for bad in (None, "", "  ", "ab"):
        sig = session_fixation_oracle(_obs(success_marker=bad))
        assert not sig.fired and sig.conclusive is False


def test_logged_out_marker_in_authorized_view_disproves_auth() -> None:
    # An operator logged-out marker present in the fixed-session view decisively DISPROVES auth ⇒ clean.
    sig = session_fixation_oracle(_obs(
        authorized_view={"status": 200, "body": f"<h1>{_MARK}</h1><p>Please sign in to continue.</p>"},
        logged_out_markers=["Please sign in"]))
    assert not sig.fired and sig.conclusive is True


def test_rotation_with_dead_fixed_id_is_a_conclusive_clean() -> None:
    # S1 != S0 AND the VIGIL-fixed id S0 no longer authenticates (its view is the logged-out body, no marker)
    # ⇒ the app rotated AND invalidated the pre-auth id (the correct defense) — a channel-confirmed clean.
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16,
                                       authorized_view=dict(_LOGGED_OUT)))
    assert not sig.fired and sig.conclusive is True
    assert "rotat" in sig.evidence.lower()


def test_rotation_but_fixed_id_still_live_is_inconclusive_never_a_false_clean() -> None:
    # A value rotation ALONE is not proof of defense: an app can rotate the cookie VALUE yet leave the
    # VIGIL-fixed pre-auth id S0 still valid (a REAL fixation). With the differential proving S0 still live,
    # the oracle must NOT round that to a clean — and, being indistinguishable from a hand-forged rotation,
    # it does not mint either: INCONCLUSIVE (never a false CLEAN, never a false FACT).
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16))
    assert not sig.fired and sig.conclusive is False
    assert "rotat" in sig.evidence.lower()


def test_survived_but_not_authenticated_is_a_conclusive_clean() -> None:
    # S1 == S0 but the fixed-session view is a substantive success WITHOUT the marker (S0 is dead) ⇒ clean.
    sig = session_fixation_oracle(_obs(authorized_view=dict(_LOGGED_OUT)))
    assert not sig.fired and sig.conclusive is True


def test_server_set_non_sentinel_id_refuses_and_is_a_lead() -> None:
    # A server-issued id (no sfx_ sentinel shape) can NEVER mint this FACT — it degrades to a weaker LEAD.
    server_id = "JSESSIONID_9f8e7d6c5b4a"
    sig = session_fixation_oracle(_obs(sentinel_id=server_id, post_auth_id=server_id))
    assert not sig.fired and sig.conclusive is False
    assert "sentinel" in sig.evidence.lower()


def test_missing_post_auth_id_is_inconclusive() -> None:
    assert not session_fixation_oracle(_obs(post_auth_id=None)).fired
    assert session_fixation_oracle(_obs(post_auth_id=None)).conclusive is False
    assert not session_fixation_oracle(_obs(post_auth_id="")).fired


def test_ignores_a_bare_authenticated_bool_with_no_raw_bytes() -> None:
    # DURABLE soundness: a legacy-shaped record carrying only authenticated_after_login=True (no
    # authorized_view / no logged_out_ref) must be IGNORED — the oracle re-derives from raw bytes and fails
    # closed to a LEAD, so no durable false FACT can be constructed off a pre-computed bool.
    sig = session_fixation_oracle({"sentinel_id": _S0, "post_auth_id": _S0, "cookie_name": "SESSION",
                                   "authenticated_after_login": True})
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
    # a marker-in-both record does NOT confirm through the verifier
    both = {"status": 200, "body": f"<h1>{_MARK}</h1>"}
    assert not v.confirm({"bug_class": "session_fixation",
                          "session_fixation": _obs(authorized_view=dict(both),
                                                   logged_out_ref=dict(both))}).confirmed


def test_dedicated_kind_out_of_frozen_fallback_gate_byte_identical() -> None:
    # SESSION_FIXATION is its OWN kind, held OUT of the frozen fallback (which stays EXACTLY 15).
    assert BUG_CLASS_ORACLES["session_fixation"] == (OracleKind.SESSION_FIXATION,)
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.SESSION_FIXATION not in _ALL_ORACLES
    # the fresh `session_fixation` ctx key is NOT carried by an unknown class, so the kind cannot fire for one
    v = OracleVerifier()
    assert v.confirm({"bug_class": "some_unknown_class", "session_fixation": _obs()}).confirmed is False
