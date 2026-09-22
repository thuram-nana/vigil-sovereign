"""
verify.oracles.session_fixation_oracle (Wave 3.2) — the pure session-fixation oracle + its verifier wiring.

Proves the oracle fires ONLY on the ACHIEVED fixation state (a VIGIL-fixed pre-auth sentinel id that SURVIVED
login — post-auth id == the fixed id — AND authenticates a protected request), refuses on rotation (the
correct defense), on a survived-but-unauthenticated id, on a non-sentinel (server-set) id, and on a missing
post-auth id; that it is deterministic; and that it reuses ``OracleKind.ACHIEVED_STATE`` via a FRESH
``session_fixation`` ctx key — so it adds NO new OracleKind, ``_ALL_ORACLES`` stays EXACTLY 15, and the kind
fires only through the explicit ``session_fixation`` row (``make gate`` byte-identical).
"""

from __future__ import annotations

from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import session_fixation_oracle
from framework.v2.verify.verifier import _ALL_ORACLES, BUG_CLASS_ORACLES, OracleVerifier, normalize_bug_class

_S0 = "sfx_" + "ab12cd34" * 4   # 32 hex chars → matches the sfx_<hex> sentinel shape


def _obs(**over):
    base = {"sentinel_id": _S0, "post_auth_id": _S0, "authenticated_after_login": True,
            "cookie_name": "SESSION"}
    base.update(over)
    return base


def test_fires_when_fixed_id_survives_login_and_authenticates() -> None:
    sig = session_fixation_oracle(_obs())
    assert sig.fired and sig.kind is OracleKind.ACHIEVED_STATE
    assert sig.conclusive and sig.confidence >= 0.9
    assert "fixation" in sig.evidence.lower() and _S0 in sig.evidence


def test_rotation_with_dead_fixed_id_is_a_conclusive_clean() -> None:
    # S1 != S0 AND the VIGIL-fixed id S0 no longer authenticates ⇒ the app rotated AND invalidated the
    # pre-auth id (the correct defense) — a channel-confirmed clean.
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16, authenticated_after_login=False))
    assert not sig.fired
    assert sig.conclusive is True
    assert "rotat" in sig.evidence.lower()


def test_rotation_but_fixed_id_still_live_is_inconclusive_never_a_false_clean() -> None:
    # A value rotation ALONE is not proof of defense: an app can rotate the cookie VALUE yet leave the
    # VIGIL-fixed pre-auth id S0 still valid (a REAL fixation). The oracle must NOT round that to a clean —
    # and, because a live-S0 rotated record is indistinguishable from a hand-forged rotation, it does not
    # mint either: it is INCONCLUSIVE (never a false CLEAN, never a false FACT).
    sig = session_fixation_oracle(_obs(post_auth_id="rot_" + "00" * 16, authenticated_after_login=True))
    assert not sig.fired
    assert sig.conclusive is False
    assert "rotat" in sig.evidence.lower()


def test_survived_but_not_authenticated_does_not_fire() -> None:
    sig = session_fixation_oracle(_obs(authenticated_after_login=False))
    assert not sig.fired and sig.conclusive is True
    # None = no positive authenticated-state discriminator was available ⇒ undecidable ⇒ INCONCLUSIVE
    # (never rounded to a clean, never to a FACT).
    sig2 = session_fixation_oracle(_obs(authenticated_after_login=None))
    assert not sig2.fired and sig2.conclusive is False


def test_server_set_non_sentinel_id_refuses_and_is_inconclusive() -> None:
    # A server-issued id (no sfx_ sentinel shape) can NEVER mint this FACT — it degrades to a weaker LEAD.
    # Non-conclusive: the oracle refuses to mint AND refuses to clear.
    server_id = "JSESSIONID_9f8e7d6c5b4a"
    sig = session_fixation_oracle(_obs(sentinel_id=server_id, post_auth_id=server_id))
    assert not sig.fired and sig.conclusive is False
    assert "sentinel" in sig.evidence.lower()


def test_missing_post_auth_id_is_inconclusive() -> None:
    sig = session_fixation_oracle(_obs(post_auth_id=None))
    assert not sig.fired and sig.conclusive is False
    sig2 = session_fixation_oracle(_obs(post_auth_id=""))
    assert not sig2.fired and sig2.conclusive is False


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
    assert BUG_CLASS_ORACLES["session_fixation"] == (OracleKind.ACHIEVED_STATE,)
    assert v.oracles_for("session_fixation") == (OracleKind.ACHIEVED_STATE,)
    out = v.confirm({"bug_class": "session_fixation", "session_fixation": _obs()})
    assert out.confirmed
    # a rotation-shaped record does NOT confirm through the verifier
    assert not v.confirm({"bug_class": "session_fixation",
                          "session_fixation": _obs(post_auth_id="rot_" + "00" * 16)}).confirmed


def test_reuses_achieved_state_no_new_kind_gate_byte_identical() -> None:
    # No new OracleKind: session_fixation reuses ACHIEVED_STATE, which is already in the frozen fallback.
    assert BUG_CLASS_ORACLES["session_fixation"] == (OracleKind.ACHIEVED_STATE,)
    assert len(_ALL_ORACLES) == 15
    assert OracleKind.ACHIEVED_STATE in _ALL_ORACLES
    # the fresh `session_fixation` ctx key is NOT carried by an unknown class, so the kind cannot fire for one
    v = OracleVerifier()
    assert v.confirm({"bug_class": "some_unknown_class", "session_fixation": _obs()}).confirmed is False
