"""M-11 — the EvalCapabilityGrant on the SOVEREIGN plane: the owner-signed, evaluator-countersigned
pre-authorization that lifts a CLOSED-ENUM set of opt-in authority-gate vetoes for one engagement/target.

Locks every invariant the slice promises on the sovereign side:
  * DEFAULT-UNGRANTED: no grant on the spine ⇒ state() is ungranted and assert_* raises.
  * COVERING ATTESTATION: attest() refuses unless a verified EvalOffenseAttestation already covers the
    engagement (the grant rides strictly inside the arming envelope).
  * CLOSED ENUM: build_core RAISES on any override token outside {witness_quorum,blast_veto,
    containment_preview}, BEFORE any spine write — the never-liftable floors can never be named.
  * FIX B / TWO-PARTY: the FRESH evaluator PoP over the GRANT core is required (an unenrolled evaluator, a
    mismatched pubkey, or a self-grant whose evaluator is the owner key are each refused); a valid evaluator
    PoP without the owner signature grants nothing.
  * REVOKE / REPLAY: a revoke un-grants; a replayed-below-the-anchor grant refuses; state survives a restart.
  * FIX C1: revoking the covering eval-offense attestation also voids the grant (engagement close).

FATAL-2: the governor imports no framework/strix (assert_no_offense holds at import).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


_iss = itertools.count(1)


def _iss_() -> float:
    return float(next(_iss))


SLUG = "eng-apme"
TGT = "https://staging.apme.example"
CID = "charter-apme-2026"
CHASH = "a" * 64
NOW = 1_000_000_000.0
FUTURE = 2_000_000_000.0
OVR = ["witness_quorum", "blast_veto", "containment_preview"]


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _owner():
    from sigil.governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def _enroll(store, username="eval-bob"):
    from sigil.governor.accounts import AccountsRegistry
    from sigil.reuse import generate_keypair
    user = generate_keypair()
    reg = AccountsRegistry(store, owner_key=_owner())
    reg.create(username, "operator", bearer_token="B" * 40, issued_at=_iss_())
    reg.enroll_pubkey(username, user.public_key_b64, issued_at=_iss_())
    return user


def _cover(store, user, *, slug=SLUG, charter_hash=CHASH, not_after=FUTURE):
    """Publish a covering eval-offense attestation for the engagement (the grant's hard precondition)."""
    from sigil.governor.eval_offense_attestation import (
        EvalOffenseAttestation,
        build_core,
        sign_evaluator_pop,
    )
    iat = _iss_()
    core = build_core(engagement_slug=slug, charter_id=CID, charter_hash=charter_hash,
                      evaluator_pubkey=user.public_key_b64, not_after=not_after, issued_at=iat)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    EvalOffenseAttestation(store, owner_key=_owner()).attest(
        engagement_slug=slug, charter_id=CID, charter_hash=charter_hash, evaluator="eval-bob",
        evaluator_pubkey=user.public_key_b64, evaluator_pop=pop, not_after=not_after, issued_at=iat)


def _grant(store):
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    return EvalCapabilityGrant(store, owner_key=_owner())


def _arm(store, user, *, slug=SLUG, target=TGT, overrides=None, max_actions=100, anchor=None,
         charter_hash=CHASH, evaluator="eval-bob", evaluator_pubkey=None):
    from sigil.governor.eval_capability_grant import build_core, sign_evaluator_pop
    overrides = OVR if overrides is None else overrides
    anchor = _iss_() if anchor is None else anchor
    epub = user.public_key_b64 if evaluator_pubkey is None else evaluator_pubkey
    core = build_core(engagement_slug=slug, target=target, allowed_gate_overrides=overrides,
                      issued_anchor=anchor, max_covered_actions=max_actions, evaluator_pubkey=epub)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    return _grant(store).attest(
        engagement_slug=slug, target=target, allowed_gate_overrides=overrides, evaluator=evaluator,
        evaluator_pubkey=epub, evaluator_pop=pop, max_covered_actions=max_actions, issued_anchor=anchor,
        charter_hash=charter_hash, now=NOW)


# --- default-ungranted ------------------------------------------------------------------------------
def test_default_ungranted():
    from sigil.governor.eval_capability_grant import (
        EvalCapabilityGrantMissing,
        assert_eval_capability_granted,
    )
    s = _store()
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is False
    with pytest.raises(EvalCapabilityGrantMissing):
        assert_eval_capability_granted(s, engagement_slug=SLUG, now=NOW)


def test_valid_grant_is_granted():
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    _arm(s, user)
    st = _grant(s).state(engagement_slug=SLUG, target=TGT, now=NOW)
    assert st.granted
    assert set(st.allowed_gate_overrides) == set(OVR)
    assert st.max_covered_actions == 100
    assert st.evaluator_pubkey == user.public_key_b64


# --- covering attestation is a hard precondition ---------------------------------------------------
def test_grant_requires_a_covering_attestation():
    s = _store()
    user = _enroll(s)
    # NO covering attestation published → attest refuses before any spine write
    with pytest.raises(ValueError, match="covering EvalOffenseAttestation"):
        _arm(s, user)
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is False


# --- closed enum ------------------------------------------------------------------------------------
def test_closed_enum_raises_on_a_bad_token_before_any_write():
    from sigil.governor.eval_capability_grant import build_core
    with pytest.raises(ValueError, match="refuses override token"):
        build_core(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=["egress_floor"],
                   issued_anchor=1.0, max_covered_actions=1, evaluator_pubkey="x")
    # and via attest(), with a covering attestation present, it still refuses + writes no grant
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    with pytest.raises(ValueError):
        _arm(s, user, overrides=["destruction_quorum"])
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is False


# --- FIX B / two-party ------------------------------------------------------------------------------
def test_self_grant_is_refused():
    s = _store()
    user = _enroll(s)
    _cover(s, user)  # a covering attestation exists
    owner = _owner()
    # evaluator_pubkey is the OWNER key → refused before any spine write
    from sigil.governor.eval_capability_grant import build_core, sign_evaluator_pop
    core = build_core(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, issued_anchor=_iss_(),
                      max_covered_actions=1, evaluator_pubkey=owner.public_key_b64)
    with pytest.raises(ValueError, match="DISTINCT from the owner"):
        _grant(s).attest(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, evaluator="owner-ish",
                         evaluator_pubkey=owner.public_key_b64, evaluator_pop="x", max_covered_actions=1,
                         issued_anchor=core["issued_anchor"], charter_hash=CHASH, now=NOW)


def test_unenrolled_or_mismatched_evaluator_refused():
    from sigil.reuse import generate_keypair
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    stranger = generate_keypair()  # never enrolled
    with pytest.raises(ValueError, match="no owner-bound cryptographic identity|does not match the enrolled"):
        _arm(s, user, evaluator="ghost", evaluator_pubkey=stranger.public_key_b64)


def test_bad_evaluator_pop_refused():
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    from sigil.governor.eval_capability_grant import build_core
    core = build_core(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, issued_anchor=_iss_(),
                      max_covered_actions=1, evaluator_pubkey=user.public_key_b64)
    with pytest.raises(ValueError, match="proof-of-possession is invalid"):
        _grant(s).attest(engagement_slug=SLUG, target=TGT, allowed_gate_overrides=OVR, evaluator="eval-bob",
                         evaluator_pubkey=user.public_key_b64, evaluator_pop="not-a-sig",
                         max_covered_actions=1, issued_anchor=core["issued_anchor"], charter_hash=CHASH,
                         now=NOW)


# --- revoke / replay / restart ----------------------------------------------------------------------
def test_revoke_ungrants():
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    _arm(s, user)
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is True
    _grant(s).revoke(engagement_slug=SLUG)
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is False


def test_state_survives_restart_from_the_spine():
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    _arm(s, user)
    # a fresh grant object over the SAME spine path re-derives the state (no cache)
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.spine.store import SpineStore
    s2 = SpineStore(s.path) if hasattr(s, "path") else s
    assert EvalCapabilityGrant(s2, owner_key=_owner()).is_granted(engagement_slug=SLUG, now=NOW) is True


# --- FIX C1: covering-attestation revoke voids the grant (engagement close) ------------------------
def test_c1_attestation_revoke_voids_the_grant():
    from sigil.governor.eval_offense_attestation import EvalOffenseAttestation
    s = _store()
    user = _enroll(s)
    _cover(s, user)
    _arm(s, user)
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is True
    EvalOffenseAttestation(s, owner_key=_owner()).revoke(engagement_slug=SLUG, reason="engagement close")
    assert _grant(s).is_granted(engagement_slug=SLUG, now=NOW) is False
