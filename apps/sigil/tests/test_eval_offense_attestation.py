"""M-11.1 — the EvalOffenseAttestation: the owner-signed, evaluator-countersigned HARD PRECONDITION that
must verify before weaponized offense may ARM on a LIVE eval target (sovereign plane).

These tests lock every invariant the slice promises:
  * HARD PRECONDITION: with NO verified attestation, state() is UNATTESTED, assert_* raises, and add_target
    REFUSES environment="live" (even with a valid WS2 evaluator proof present).
  * FRESH DOMAIN TAG: the evaluator PoP signs under the distinct ``eval-offense-attestation`` tag — a PoP
    computed without it (or an owner sig for another purpose / signal) does NOT verify here.
  * EVALUATOR PoP binds a DISTINCT identity: attest() refuses an unenrolled evaluator or a mismatched
    pubkey; a valid evaluator PoP without the owner signature arms nothing (the owner sig is still required);
    the evaluator cannot forge the owner.
  * REVOKE / EXPIRY / REPLAY: a revoked, an expired, or a replayed-below-the-high-water attestation all
    refuse; state() is never cached and survives a process restart (re-derived from the spine).
  * allow_destructive STAYS false: the minted core hard-wires it False; tampering it True breaks the owner
    signature so it is never honoured.

FATAL-2: the governor imports no framework/strix (assert_no_offense holds at import).
"""
from __future__ import annotations

import itertools
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared seam (eval-offense records)
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


_iss = itertools.count(1)


def _iss_() -> float:
    return float(next(_iss))


SLUG = "eng-apme"
CID = "charter-apme-2026"
CHASH = "a" * 64
DIFF_HASH = "b" * 64
NOW = 1_000_000_000.0
FUTURE = 2_000_000_000.0


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _owner():
    from sigil.governor.identity import ensure_owner_keypair
    return ensure_owner_keypair()


def _enroll(store, username="eval-bob"):
    """Owner-create + owner-enroll a distinct evaluator keypair (the additive identity)."""
    from sigil.governor.accounts import AccountsRegistry
    from sigil.reuse import generate_keypair
    user = generate_keypair()
    reg = AccountsRegistry(store, owner_key=_owner())
    reg.create(username, "operator", bearer_token="B" * 40, issued_at=_iss_())
    reg.enroll_pubkey(username, user.public_key_b64, issued_at=_iss_())
    return user


def _gate(store):
    from sigil.governor.eval_offense_attestation import EvalOffenseAttestation
    return EvalOffenseAttestation(store, owner_key=_owner())


def _attest(store, user, *, slug=SLUG, evaluator="eval-bob", charter_id=CID, charter_hash=CHASH,
            not_after=FUTURE, issued_at=None):
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    iat = _iss_() if issued_at is None else issued_at
    core = build_core(engagement_slug=slug, charter_id=charter_id, charter_hash=charter_hash,
                      evaluator_pubkey=user.public_key_b64, not_after=not_after, issued_at=iat)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    return _gate(store).attest(engagement_slug=slug, charter_id=charter_id, charter_hash=charter_hash,
                               evaluator=evaluator, evaluator_pubkey=user.public_key_b64,
                               evaluator_pop=pop, not_after=not_after, issued_at=iat)


# --- HARD PRECONDITION: default-unattested ---------------------------------------------------------
def test_default_unattested():
    from sigil.governor.eval_offense_attestation import (
        EvalOffenseAttestationMissing, assert_eval_offense_attested,
    )
    s = _store()
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False
    with pytest.raises(EvalOffenseAttestationMissing):
        assert_eval_offense_attested(s, engagement_slug=SLUG, now=NOW)


def test_valid_attestation_is_attested_and_asserts():
    from sigil.governor.eval_offense_attestation import assert_eval_offense_attested
    s = _store()
    user = _enroll(s)
    _attest(s, user)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is True
    st = assert_eval_offense_attested(s, engagement_slug=SLUG, charter_hash=CHASH, now=NOW)  # no raise
    assert st.attested and st.evaluator_pubkey == user.public_key_b64


def test_attestation_for_a_different_charter_or_engagement_does_not_cover_this_one():
    s = _store()
    user = _enroll(s)
    _attest(s, user, charter_hash=DIFF_HASH)
    # queried for CHASH specifically → not covered; queried for the slug with no charter filter → covered
    assert _gate(s).is_attested(engagement_slug=SLUG, charter_hash=CHASH, now=NOW) is False
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is True
    # an attestation for a DIFFERENT engagement never covers this slug
    s2 = _store()
    u2 = _enroll(s2)
    _attest(s2, u2, slug="other-eng")
    assert _gate(s2).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_wrong_environment_does_not_attest_live():
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    s = _store()
    user = _enroll(s)
    iat = _iss_()
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=iat,
                      environment="staging")
    pop = sign_evaluator_pop(core, user.private_key_b64)
    _gate(s).attest(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH, evaluator="eval-bob",
                    evaluator_pubkey=user.public_key_b64, evaluator_pop=pop, not_after=FUTURE,
                    issued_at=iat, environment="staging")
    # a staging-bound attestation does NOT arm the live gate
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW, environment="live") is False


def test_expired_attestation_auto_unarms():
    s = _store()
    user = _enroll(s)
    _attest(s, user, not_after=NOW + 10)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is True
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW + 20) is False


def test_revoke_unarms_even_after_a_valid_attestation():
    s = _store()
    user = _enroll(s)
    _attest(s, user)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is True
    _gate(s).revoke(engagement_slug=SLUG)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_replay_of_attestation_after_revoke_does_not_rearm():
    s = _store()
    g = _gate(s)
    user = _enroll(s)
    seq = _attest(s, user, issued_at=100.0)
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is True
    captured = dict(s.get(seq).payload)       # the exact signed attestation bytes
    g.revoke(engagement_slug=SLUG)
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is False
    # replay the byte-identical attestation (same issued_at) → anti-replay high-water refuses it
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(captured))
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is False


def test_stale_lower_issued_attestation_cannot_override_a_newer_one():
    s = _store()
    g = _gate(s)
    user = _enroll(s)
    old = dict(s.get(_attest(s, user, issued_at=10.0)).payload)
    _attest(s, user, issued_at=20.0)
    g.revoke(engagement_slug=SLUG)
    s.append(kind="event", source="governor", actor="WARDEN", payload=dict(old))  # replay the OLD attestation
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is False


def test_forged_owner_signature_does_not_attest():
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    from sigil.governor.authn import signed_payload
    from sigil.reuse import generate_keypair
    s = _store()
    user = _enroll(s)
    attacker = generate_keypair()
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=100.0)
    # a REAL evaluator PoP, but the OWNER core is signed by an attacker (pinned trusted key is the owner)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    payload = {**signed_payload(core, attacker), "evaluator_sig": pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_evaluator_pop_alone_cannot_arm_without_the_owner_signature():
    """The evaluator cannot forge the owner: a record carrying a valid evaluator PoP but NO owner signature
    arms nothing (the owner is the sole governance signer; the PoP is purely additive)."""
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    s = _store()
    user = _enroll(s)
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=100.0)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    # no owner sig/pubkey at all — only the evaluator PoP
    payload = {**core, "sig": None, "pubkey": None, "evaluator_sig": pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_missing_or_wrong_evaluator_pop_does_not_attest():
    """The owner signature is necessary but NOT sufficient: without a valid evaluator PoP the attestation
    does not arm (both signatures are required)."""
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    from sigil.governor.authn import signed_payload
    from sigil.reuse import generate_keypair
    s = _store()
    user = _enroll(s)
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=100.0)
    # owner-signed correctly, but the evaluator PoP is by a DIFFERENT (wrong) key
    wrong = generate_keypair()
    bad_pop = sign_evaluator_pop(core, wrong.private_key_b64)
    payload = {**signed_payload(core, _owner()), "evaluator_sig": bad_pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False
    # and a MISSING evaluator PoP likewise does not attest
    payload2 = {**signed_payload(core, _owner()), "evaluator": "eval-bob", "tier": "A0", "decision": "auto"}
    s2 = _store()
    _enroll(s2)
    s2.append(kind="event", source="governor", actor="WARDEN", payload=payload2)
    assert _gate(s2).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_attest_refuses_an_unenrolled_or_mismatched_evaluator():
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    from sigil.reuse import generate_keypair
    s = _store()
    stranger = generate_keypair()
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=stranger.public_key_b64, not_after=FUTURE, issued_at=5.0)
    pop = sign_evaluator_pop(core, stranger.private_key_b64)
    # no account enrolled for "ghost" → attest refuses
    with pytest.raises(ValueError):
        _gate(s).attest(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH, evaluator="ghost",
                        evaluator_pubkey=stranger.public_key_b64, evaluator_pop=pop, not_after=FUTURE,
                        issued_at=5.0)
    # enroll eval-bob, but pass a pubkey that is NOT bob's enrolled key → attest refuses the mismatch
    user = _enroll(s)
    core2 = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                       evaluator_pubkey=stranger.public_key_b64, not_after=FUTURE, issued_at=6.0)
    pop2 = sign_evaluator_pop(core2, stranger.private_key_b64)
    with pytest.raises(ValueError):
        _gate(s).attest(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH, evaluator="eval-bob",
                        evaluator_pubkey=stranger.public_key_b64, evaluator_pop=pop2, not_after=FUTURE,
                        issued_at=6.0)
    assert user is not None


def test_attest_refuses_a_self_attestation_evaluator_equals_owner():
    """M-11.1 red-pen §11.4 BLOCK 1 (SOVEREIGN MINT): even if the OWNER key is also enrolled as an account
    (so the enrollment + PoP checks would pass with the owner signing BOTH slots — the exact precondition the
    red-pen used), attest() refuses to mint a SELF-attestation whose evaluator_pubkey is the owner's own key,
    BEFORE any spine write. This is the two-party control enforced at the mint (the offense verifier enforces
    the identical shape at the arm)."""
    from sigil.governor.accounts import AccountsRegistry
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    s = _store()
    owner = _owner()
    # Enroll the OWNER key itself as an account (enroll_pubkey places no owner-key guard) — the reachable
    # precondition. WITHOUT the fix this mint would succeed and produce a self-attestation.
    reg = AccountsRegistry(s, owner_key=owner)
    reg.create("owner-as-eval", "operator", bearer_token="B" * 40, issued_at=_iss_())
    reg.enroll_pubkey("owner-as-eval", owner.public_key_b64, issued_at=_iss_())
    iat = _iss_()
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=owner.public_key_b64, not_after=FUTURE, issued_at=iat)
    pop = sign_evaluator_pop(core, owner.private_key_b64)      # the owner signs its own "evaluator" PoP
    before = len(list(s.iter_records()))
    with pytest.raises(ValueError) as ei:
        _gate(s).attest(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH, evaluator="owner-as-eval",
                        evaluator_pubkey=owner.public_key_b64, evaluator_pop=pop, not_after=FUTURE,
                        issued_at=iat)
    assert "DISTINCT" in str(ei.value) and "self-attestation" in str(ei.value)
    # nothing was written to the spine (refused BEFORE the append) and the gate does not arm
    assert len(list(s.iter_records())) == before
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_state_fold_refuses_a_self_attestation_appended_outside_attest():
    """DEFENSE-IN-DEPTH (red-pen variant): a self-attestation appended DIRECTLY to the spine (bypassing the
    attest() mint guard — e.g. a compromised owner writing the spine) is NOT honoured by the read fold, so
    assert_eval_offense_attested / add_target cannot be fooled by it either. The owner signature + evaluator
    PoP are BOTH genuine here (the owner signs both slots); only the evaluator==owner distinctness refuses it."""
    from sigil.governor.authn import signed_payload
    from sigil.governor.eval_offense_attestation import (
        EvalOffenseAttestationMissing,
        assert_eval_offense_attested,
        build_core,
        sign_evaluator_pop,
    )
    s = _store()
    owner = _owner()
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=owner.public_key_b64, not_after=FUTURE, issued_at=100.0)
    pop = sign_evaluator_pop(core, owner.private_key_b64)      # owner signs its own "evaluator" PoP
    payload = {**signed_payload(core, owner), "evaluator_sig": pop, "evaluator": "owner-as-eval",
               "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)   # directly, not via attest()
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False
    with pytest.raises(EvalOffenseAttestationMissing):
        assert_eval_offense_attested(s, engagement_slug=SLUG, now=NOW)


def test_attest_still_mints_with_a_distinct_evaluator_positive_control():
    """POSITIVE CONTROL: the SAME ceremony with a genuine DISTINCT enrolled evaluator still mints and arms —
    the distinctness guard refuses only the owner-as-evaluator collapse, nothing legitimate."""
    from sigil.governor.eval_offense_attestation import assert_eval_offense_attested
    s = _store()
    user = _enroll(s)                 # a DISTINCT evaluator keypair, owner-enrolled
    _attest(s, user)
    st = assert_eval_offense_attested(s, engagement_slug=SLUG, charter_hash=CHASH, now=NOW)
    assert st.attested and st.evaluator_pubkey == user.public_key_b64


def test_fresh_domain_tag_pop_without_the_tag_is_refused():
    """The evaluator PoP MUST sign under the fresh eval-offense-attestation domain tag. A PoP computed over
    the bare canonical core (no tag) does not verify — so a signature minted for any other purpose cannot be
    replayed as an eval-offense PoP."""
    from sigil.governor.eval_offense_attestation import _CORE, build_core
    from sigil.governor.authn import signed_payload
    from sigil.reuse import canonical_json, sign
    s = _store()
    user = _enroll(s)
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=100.0)
    # PoP WITHOUT the domain tag (bare canonical JSON of the core) — cross-purpose-replay shape
    bare = canonical_json({k: core.get(k) for k in _CORE})
    bare = bare if isinstance(bare, (bytes, bytearray)) else str(bare).encode("utf-8")
    untagged_pop = sign(user.private_key_b64, bare)
    payload = {**signed_payload(core, _owner()), "evaluator_sig": untagged_pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_cross_signal_isolation_from_the_offense_gate():
    """An owner-signed offense_gate OPEN for the same charter does not attest the eval-offense gate, and a
    valid eval-offense attestation does not open the offense_gate (distinct signals AND distinct cores)."""
    from sigil.governor.offense_gate import OffenseGate
    s = _store()
    user = _enroll(s)
    _attest(s, user)
    og = OffenseGate(s, owner_key=_owner())
    assert og.is_open(charter_id=CID, charter_hash=CHASH, now=NOW) is False  # eval att != offense open
    og.open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE, issued_at=_iss_())
    # the offense_gate open must not, in turn, attest the eval-offense gate
    s2 = _store()
    OffenseGate(s2, owner_key=_owner()).open_gate(charter_id=CID, charter_hash=CHASH, not_after=FUTURE,
                                                  issued_at=1.0)
    assert _gate(s2).is_attested(engagement_slug=SLUG, now=NOW) is False


def test_allow_destructive_stays_false():
    from sigil.governor.eval_offense_attestation import SIGNAL, _CORE, build_core, sign_evaluator_pop
    from sigil.governor.authn import signed_payload
    s = _store()
    user = _enroll(s)
    seq = _attest(s, user)
    # the minted record hard-wires allow_destructive=False
    assert s.get(seq).payload.get("allow_destructive") is False
    # a record TAMPERED to claim allow_destructive=True breaks the owner signature → never honoured
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=500.0)
    pop = sign_evaluator_pop(core, user.private_key_b64)
    payload = {**signed_payload(core, _owner()), "evaluator_sig": pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    payload["allow_destructive"] = True        # flip the floor echo WITHOUT re-signing
    s2 = _store()
    _enroll(s2)
    s2.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert _gate(s2).is_attested(engagement_slug=SLUG, now=NOW) is False
    assert SIGNAL in payload["signal"] and "allow_destructive" in _CORE


def test_state_survives_a_fresh_instance_restart():
    from sigil.governor.eval_offense_attestation import EvalOffenseAttestation
    from sigil.spine.store import SpineStore
    s = _store()
    user = _enroll(s)
    _attest(s, user)
    g2 = EvalOffenseAttestation(SpineStore(s.path), owner_key=_owner())   # re-derives from the spine
    assert g2.is_attested(engagement_slug=SLUG, now=NOW) is True


def test_nan_issued_at_cannot_poison_the_replay_high_water():
    from sigil.governor.eval_offense_attestation import build_core, sign_evaluator_pop
    from sigil.governor.authn import signed_payload
    s = _store()
    g = _gate(s)
    user = _enroll(s)
    core = build_core(engagement_slug=SLUG, charter_id=CID, charter_hash=CHASH,
                      evaluator_pubkey=user.public_key_b64, not_after=FUTURE, issued_at=float("nan"))
    pop = sign_evaluator_pop(core, user.private_key_b64)
    payload = {**signed_payload(core, _owner()), "evaluator_sig": pop, "evaluator": "eval-bob",
               "tier": "A0", "decision": "auto"}
    seq = s.append(kind="event", source="governor", actor="WARDEN", payload=payload)
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is True        # honoured once
    captured = dict(s.get(seq).payload)
    g.revoke(engagement_slug=SLUG)
    s.append(kind="event", source="governor", actor="WARDEN", payload=captured)  # replay verbatim
    assert g.is_attested(engagement_slug=SLUG, now=NOW) is False, \
        "a NaN issued_at must not poison the high-water into accepting replays"


# --- the SOVEREIGN add_target gate (move 4a) -------------------------------------------------------
def _ws2_enrolled(store, username="eval-alice"):
    from sigil.governor.accounts import AccountsRegistry
    from sigil.reuse import generate_keypair
    user = generate_keypair()
    reg = AccountsRegistry(store, owner_key=_owner())
    reg.create(username, "operator", bearer_token="B" * 40, issued_at=_iss_())
    reg.enroll_pubkey(username, user.public_key_b64, issued_at=_iss_())
    return user


def _ws2_attestation(store, user, *, host="apme.cm", evaluator="eval-alice"):
    import secrets

    from sigil.reuse import sign
    from sigil.ui.target_authorization import _attestation_challenge_ledger, _attestation_message
    chal = secrets.token_urlsafe(32)
    _attestation_challenge_ledger(store).issue(chal)
    msg = _attestation_message(host=host, environment="live", challenge=chal, evaluator=evaluator)
    return {"evaluator": evaluator, "challenge": chal, "signature": sign(user.private_key_b64, msg)}


def test_add_target_live_refused_without_an_eval_offense_attestation():
    """HARD PRECONDITION at add_target: even with a VALID WS2 evaluator proof, environment="live" is REFUSED
    when no eval-offense attestation covers the engagement — and nothing is written to the seam."""
    from sigil.ui import target_authorization as ta
    from vigil_integration.live.authorization_broker import read_authorization
    import os
    s = _store()
    user = _ws2_enrolled(s)
    att = _ws2_attestation(s, user)
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "eval-offense attestation" in r["error"], r
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], "apme-cm") is None


def test_add_target_live_permitted_with_an_eval_offense_attestation():
    from sigil.ui import target_authorization as ta
    s = _store()
    user = _ws2_enrolled(s)
    # mint the eval-offense attestation for the console-canonical slug of apme.cm
    _attest(s, user, slug="apme-cm", evaluator="eval-alice")
    att = _ws2_attestation(s, user)
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is True and r["environment"] == "live", r
    assert r["allow_destructive"] is False


def test_add_target_twin_and_staging_never_consult_the_eval_gate():
    """SAFE NEGATIVE CONTROL: twin/staging need no attestation and the live/eval gate never fires on them
    (byte-identical to before this slice)."""
    from sigil.ui import target_authorization as ta
    s = _store()
    assert ta.add_target("apme.cm", environment="staging", store=s)["ok"] is True
    assert ta.add_target("twin.example", environment="twin", store=s)["ok"] is True
