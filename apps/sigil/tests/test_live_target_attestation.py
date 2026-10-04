"""WS2 — Mode-2 live-target self-serve EVALUATOR ATTESTATION (sovereign plane only).

``environment="live"`` was refused outright; WS2 unblocks it ONLY when a distinct evaluator proves, with
THEIR OWN owner-bound key, that the specific target is theirs — an ADDITIVE proof-of-possession, never a
governance key. These tests lock the invariants:

  * POSITIVE (benchmark): a valid attestation unblocks live — the owner still signs a verifiable, GET-only
    (allow_destructive=False) authority AND records the attestation as an owner-signed governance signal on
    the sovereign spine (witnessed / anti-rollback head).
  * SAFE NEGATIVE CONTROL: a legitimate twin/staging authorization needs NO attestation and the live gate
    never fires on it (no attestation record, allow_destructive stays False).
  * missing / forged / wrong-key / replayed / unknown-evaluator attestation ⇒ refused, nothing written.
  * destructive stays refused even on live (allow_destructive=False — writes need the separate per-action
    approval; unblocking live does not unblock writes).
  * a .gov/.mil/.edu/.int host is refused even WITH a valid attestation (the categorical floor is checked
    FIRST, before the attestation, so the evaluator's single-use challenge is not even consumed).
  * the signature BINDS the target: an attestation signed for host A cannot authorize host B.
  * a mutation neutering verify_one flips the forged case into a leak (the signature IS the admission gate).

FATAL-2: the ceremony imports no framework/strix (covered in test_target_authorization.py too).
"""
from __future__ import annotations

import itertools
import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())      # the shared seam (authority bundles)
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())     # isolate the owner vault/spine
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


_iss = itertools.count(1)


def _store():
    from sigil.spine.store import SpineStore
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _enrolled_evaluator(store, username="eval-alice"):
    """Owner-create an account and owner-bind a fresh evaluator keypair (the distinct identity). Returns the
    user KeyPair whose PRIVATE half the evaluator signs attestations with."""
    from sigil.governor.accounts import AccountsRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.reuse import generate_keypair
    owner = ensure_owner_keypair()
    reg = AccountsRegistry(store, owner_key=owner)
    user = generate_keypair()
    reg.create(username, "operator", bearer_token="B" * 40, issued_at=float(next(_iss)))
    reg.enroll_pubkey(username, user.public_key_b64, issued_at=float(next(_iss)))
    return user


def _mint_challenge(store, value=None):
    """Mint a single-use challenge in the SAME login-challenge ledger add_target consumes from."""
    import secrets

    from sigil.ui.target_authorization import _attestation_challenge_ledger
    c = value or secrets.token_urlsafe(32)
    _attestation_challenge_ledger(store).issue(c)
    return c


def _attestation(store, user, *, host, evaluator, challenge, environment="live"):
    from sigil.reuse import sign
    from sigil.ui.target_authorization import _attestation_message
    msg = _attestation_message(host=host, environment=environment, challenge=challenge, evaluator=evaluator)
    return {"evaluator": evaluator, "challenge": challenge, "signature": sign(user.private_key_b64, msg)}


def _mint_eval_attestation(store, user, *, slug="apme-cm", evaluator="eval-alice",
                           charter_id="eval-2026", charter_hash="a" * 64, not_after=None):
    """M-11.1: owner-mint the EvalOffenseAttestation hard precondition so a LIVE add_target is permitted. The
    evaluator (`user`) counter-signs the exact core; the OWNER signs it. Mirrors the sovereign attest()
    ceremony so these WS2 live tests exercise the real (raised) live bar."""
    import time as _t

    from sigil.governor.eval_offense_attestation import (
        EvalOffenseAttestation, build_core, sign_evaluator_pop,
    )
    from sigil.governor.identity import ensure_owner_keypair
    na = not_after if not_after is not None else _t.time() + 3600.0
    iat = float(next(_iss))
    core = build_core(engagement_slug=slug, charter_id=charter_id, charter_hash=charter_hash,
                      evaluator_pubkey=user.public_key_b64, not_after=na, issued_at=iat, environment="live")
    pop = sign_evaluator_pop(core, user.private_key_b64)
    att = EvalOffenseAttestation(store, owner_key=ensure_owner_keypair())
    return att.attest(engagement_slug=slug, charter_id=charter_id, charter_hash=charter_hash,
                      evaluator=evaluator, evaluator_pubkey=user.public_key_b64, evaluator_pop=pop,
                      not_after=na, issued_at=iat)


# --- POSITIVE benchmark ---------------------------------------------------------------------------
def test_live_unblocked_with_a_valid_attestation():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.ui import target_authorization as ta
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization

    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user)                               # M-11.1 hard precondition
    chal = _mint_challenge(s)
    att = _attestation(s, user, host="apme.cm", evaluator="eval-alice", challenge=chal)

    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is True and r["environment"] == "live", r
    assert r["evaluator"] == "eval-alice" and r["allow_destructive"] is False
    assert isinstance(r.get("attestation_recorded_seq"), int)

    # the owner STILL signs a verifiable authority; GET-only / non-destructive even on live.
    got = read_authorization(os.environ["VIGIL_BASE_DIR"], r["slug"])
    assert got is not None
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    kp = ensure_owner_keypair()
    assert {a.public_key_b64 for a in got.trust_root.authorizers} == {kp.public_key_b64}
    assert got.signed_authority.document.environment.value == "live"
    assert got.signed_authority.document.allow_destructive is False
    assert got.signed_authority.document.live_destructive_acknowledged is False


def test_live_attestation_is_recorded_as_an_owner_signed_governance_signal():
    from sigil.governor.authn import verify_signed
    from sigil.governor.identity import owner_pubkey
    from sigil.ui import target_authorization as ta

    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user)                               # M-11.1 hard precondition
    chal = _mint_challenge(s)
    att = _attestation(s, user, host="apme.cm", evaluator="eval-alice", challenge=chal)
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"], r

    pay = s.get(r["attestation_recorded_seq"]).payload
    assert pay["signal"] == ta.LIVE_ATTESTATION_SIGNAL
    assert pay["host"] == "apme.cm" and pay["evaluator"] == "eval-alice"
    assert pay["evaluator_pubkey"] == user.public_key_b64 and pay["allow_destructive"] is False
    # the governance row is OWNER-signed (the evaluator PoP gated admission; the owner is the sole signer).
    core_fields = ["signal", "slug", "host", "environment", "evaluator", "evaluator_pubkey",
                   "challenge", "allow_destructive", "not_before", "not_after", "issued_at"]
    assert verify_signed(pay, core_fields, owner_pubkey()) is True
    # tamper the recorded evaluator → the owner signature no longer verifies (fail-closed provenance).
    tampered = {**pay, "evaluator": "someone-else"}
    assert verify_signed(tampered, core_fields, owner_pubkey()) is False


# --- SAFE NEGATIVE CONTROL: the gate never fires on a legitimate non-live request -----------------
def test_staging_needs_no_attestation_and_the_live_gate_does_not_fire():
    from sigil.ui import target_authorization as ta
    s = _store()
    r = ta.add_target("apme.cm", environment="staging", store=s)
    assert r["ok"] is True and r["environment"] == "staging", r
    assert "attestation_recorded_seq" not in r and "evaluator" not in r
    # twin likewise
    r2 = ta.add_target("twin.example", environment="twin", store=s)
    assert r2["ok"] is True and r2["environment"] == "twin", r2


# --- deliberate refusals --------------------------------------------------------------------------
def test_live_refused_without_an_attestation():
    from sigil.ui import target_authorization as ta
    s = _store()
    _mint_eval_attestation(s, _enrolled_evaluator(s))   # M-11.1 satisfied; the missing piece is the WS2 proof
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=None)
    assert r["ok"] is False and "LIVE" in r["error"] and "attestation" in r["error"], r
    # nothing was written to the seam
    from vigil_integration.live.authorization_broker import read_authorization
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], "apme-cm") is None


def test_live_refused_with_a_forged_wrong_key_signature():
    from sigil.reuse import generate_keypair, sign
    from sigil.ui import target_authorization as ta
    from sigil.ui.target_authorization import _attestation_message
    s = _store()
    user = _enrolled_evaluator(s)                            # eval-alice has a bound key
    _mint_eval_attestation(s, user)                         # M-11.1 satisfied, so the WS2 signature check runs
    chal = _mint_challenge(s)
    wrong = generate_keypair()                               # NOT the evaluator's key
    msg = _attestation_message(host="apme.cm", environment="live", challenge=chal, evaluator="eval-alice")
    att = {"evaluator": "eval-alice", "challenge": chal, "signature": sign(wrong.private_key_b64, msg)}
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "signature is invalid" in r["error"], r
    from vigil_integration.live.authorization_broker import read_authorization
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], "apme-cm") is None


def test_live_refused_for_an_evaluator_with_no_bound_key():
    from sigil.governor.accounts import AccountsRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.reuse import generate_keypair
    from sigil.ui import target_authorization as ta
    s = _store()
    _mint_eval_attestation(s, _enrolled_evaluator(s))       # M-11.1 satisfied (a DISTINCT enrolled evaluator)
    # create the account but DO NOT enroll a pubkey
    AccountsRegistry(s, owner_key=ensure_owner_keypair()).create(
        "nokey", "operator", bearer_token="B" * 40, issued_at=float(next(_iss)))
    chal = _mint_challenge(s)
    att = _attestation(s, generate_keypair(), host="apme.cm", evaluator="nokey", challenge=chal)
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "no owner-bound cryptographic identity" in r["error"], r


def test_live_refused_on_a_replayed_attestation():
    from sigil.ui import target_authorization as ta
    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user)                               # M-11.1 hard precondition
    chal = _mint_challenge(s)
    att = _attestation(s, user, host="apme.cm", evaluator="eval-alice", challenge=chal)
    assert ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)["ok"] is True
    # exact replay of the same {evaluator, challenge, signature} → the single-use challenge is spent → refused
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "already used" in r["error"], r


def test_attestation_is_bound_to_the_target_host():
    """An attestation signed for host A cannot authorize host B (the host is in the signed message)."""
    from sigil.ui import target_authorization as ta
    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user, slug="other-example")   # M-11.1 for the TARGET slug, so the WS2 check runs
    chal = _mint_challenge(s)
    att_for_a = _attestation(s, user, host="apme.cm", evaluator="eval-alice", challenge=chal)
    # submit the apme.cm-signed attestation against a DIFFERENT host → the recomputed message differs → refused
    r = ta.add_target("other.example", environment="live", store=s, evaluator_attestation=att_for_a)
    assert r["ok"] is False and "signature is invalid" in r["error"], r


# --- destructive stays refused even on live -------------------------------------------------------
def test_destructive_is_not_unblocked_by_a_live_attestation():
    """Unblocking live does NOT unblock writes: the minted authority is allow_destructive=False, so a write
    still needs the SEPARATE owner-signed, single-use, action-bound per-action approval."""
    from sigil.ui import target_authorization as ta
    from vigil_integration.live.authorization_broker import read_authorization
    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user)                               # M-11.1 hard precondition
    chal = _mint_challenge(s)
    att = _attestation(s, user, host="apme.cm", evaluator="eval-alice", challenge=chal)
    r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] and r["allow_destructive"] is False
    got = read_authorization(os.environ["VIGIL_BASE_DIR"], r["slug"])
    assert got.signed_authority.document.allow_destructive is False
    assert got.signed_authority.document.live_destructive_acknowledged is False


# --- the categorical floor is checked FIRST -------------------------------------------------------
@pytest.mark.parametrize("host", ["example.gov", "foo.mil", "test.edu", "who.int", "x.gov.cm"])
def test_protected_host_refused_even_with_a_valid_attestation(host):
    from sigil.ui import target_authorization as ta
    from sigil.ui.target_authorization import _attestation_challenge_ledger
    s = _store()
    user = _enrolled_evaluator(s)
    chal = _mint_challenge(s)
    att = _attestation(s, user, host=host, evaluator="eval-alice", challenge=chal)
    r = ta.add_target(host, environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "safety floor" in r["error"], r
    # the floor was checked BEFORE the attestation, so the single-use challenge was NOT consumed.
    assert _attestation_challenge_ledger(s).consume(chal) is True, "the protected-host refusal must precede " \
        "the challenge consume (the evaluator's nonce must not be burned on a floor refusal)"


# --- the signature IS the admission gate (mutation) -----------------------------------------------
def test_mutation_neutering_verify_one_flips_the_forged_case_to_a_leak():
    import sigil.reuse as reuse_mod
    from sigil.reuse import generate_keypair, sign
    from sigil.ui import target_authorization as ta
    from sigil.ui.target_authorization import _attestation_message
    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user)                               # M-11.1 hard precondition (real crypto)
    wrong = generate_keypair()

    chal = _mint_challenge(s)
    msg = _attestation_message(host="apme.cm", environment="live", challenge=chal, evaluator="eval-alice")
    bad = {"evaluator": "eval-alice", "challenge": chal, "signature": sign(wrong.private_key_b64, msg)}
    # baseline: the real verify_one refuses the wrong key
    assert ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=bad)["ok"] is False

    orig = reuse_mod.verify_one
    try:
        reuse_mod.verify_one = lambda *a, **k: True          # neuter the signature gate
        chal2 = _mint_challenge(s)                            # fresh challenge (the first was consumed)
        msg2 = _attestation_message(host="apme.cm", environment="live", challenge=chal2, evaluator="eval-alice")
        bad2 = {"evaluator": "eval-alice", "challenge": chal2, "signature": sign(wrong.private_key_b64, msg2)}
        r = ta.add_target("apme.cm", environment="live", store=s, evaluator_attestation=bad2)
        assert r["ok"] is True, "mutation must flip the forged refusal into a leak (proving the sig is the gate)"
    finally:
        reuse_mod.verify_one = orig


# --- WS2 floor: a LIVE authority must never be minted for internal space --------------------------
# The egress floor (denylist Tier 2) LIFTS its conditional private deny for any IP written as a charter-scope
# literal (egress_floor.charter_allowed_ips). So a LIVE authority scoped to a private literal would AIM egress
# at internal space. The ceremony must refuse private literals AT MINT, for the LIVE environment only
# (twin/staging legitimately engage internal space). Metadata/link-local stay refused for EVERY environment.
@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1"])
def test_live_refuses_private_internal_literal_even_with_a_valid_attestation(ip):
    """A LIVE add_target for an RFC1918 (10/8, 172.16/12, 192.168/16) or CGNAT (100.64/10) literal is REFUSED
    even WITH a fully valid WS2 + M-11.1 attestation — the refusal is at _validate_host, BEFORE the attestation,
    so nothing is minted and the evaluator's single-use challenge is NOT consumed. (CGNAT is covered explicitly:
    ipaddress.is_private is False for 100.64/10 on this runtime.)"""
    from sigil.ui import target_authorization as ta
    from sigil.ui.target_authorization import _attestation_challenge_ledger, _slug_for
    from vigil_integration.live.authorization_broker import read_authorization
    s = _store()
    user = _enrolled_evaluator(s)
    _mint_eval_attestation(s, user, slug=_slug_for(ip, None))     # a VALID M-11.1 for this engagement
    chal = _mint_challenge(s)
    att = _attestation(s, user, host=ip, evaluator="eval-alice", challenge=chal)   # a VALID WS2 proof
    r = ta.add_target(ip, environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is False and "private / internal" in r["error"], r
    # nothing minted, and the floor refusal PRECEDED the challenge consume (the nonce is still live to spend).
    assert read_authorization(os.environ["VIGIL_BASE_DIR"], _slug_for(ip, None)) is None
    assert _attestation_challenge_ledger(s).consume(chal) is True, \
        "the private-literal refusal must precede the WS2 challenge consume (do not burn the nonce)"


@pytest.mark.parametrize("ula", ["fc00::1", "fd00::1"])
def test_live_refuses_ipv6_ula_literal(ula):
    """An IPv6 ULA literal is refused for a LIVE target (a DISTINCT refusal: the bare-hostname ':' guard rejects
    every IPv6 literal before the Tier-2 check, which is why the ULA term in _validate_host is defense-in-depth)."""
    from sigil.ui import target_authorization as ta
    r = ta.add_target(ula, environment="live")
    assert r["ok"] is False, r


def test_live_still_refuses_cloud_metadata_literal():
    """The never-liftable Tier-1 floor still refuses the cloud metadata address on live (distinct from the new
    Tier-2 private refusal: metadata/link-local are denied for EVERY environment, never lifted by a scope)."""
    from sigil.ui import target_authorization as ta
    r = ta.add_target("169.254.169.254", environment="live")
    assert r["ok"] is False and ("link-local" in r["error"] or "reserved" in r["error"]
                                 or "loopback" in r["error"]), r


@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.1", "172.16.0.1", "100.64.0.1"])
@pytest.mark.parametrize("env", ["twin", "staging"])
def test_twin_staging_still_allow_internal_literals(env, ip):
    """twin/staging legitimately engage internal space, so the Tier-2 private refusal is scoped to live: an
    internal literal is still authorized for twin/staging, needing no attestation (byte-identical to before)."""
    from sigil.ui import target_authorization as ta
    s = _store()
    r = ta.add_target(ip, environment=env, store=s)
    assert r["ok"] is True and r["environment"] == env and r["scope"] == [ip], r
    assert "attestation_recorded_seq" not in r and "evaluator" not in r


def test_live_allows_a_public_ip_literal_with_a_valid_attestation():
    """A PUBLIC IP literal is a legitimate live target: the Tier-2 refusal must not over-block it (is_private /
    CGNAT / ULA all False, is_global True). With a valid WS2 + M-11.1 attestation it is authorized end-to-end."""
    from sigil.ui import target_authorization as ta
    from sigil.ui.target_authorization import _slug_for
    from vigil_core import verify_engagement_authority
    from vigil_integration.live.authorization_broker import read_authorization
    s = _store()
    user = _enrolled_evaluator(s)
    ip = "93.184.216.34"                                          # a globally-routable literal
    _mint_eval_attestation(s, user, slug=_slug_for(ip, None))
    chal = _mint_challenge(s)
    att = _attestation(s, user, host=ip, evaluator="eval-alice", challenge=chal)
    r = ta.add_target(ip, environment="live", store=s, evaluator_attestation=att)
    assert r["ok"] is True and r["environment"] == "live" and r["scope"] == [ip], r
    got = read_authorization(os.environ["VIGIL_BASE_DIR"], r["slug"])
    ok, reason = verify_engagement_authority(got.signed_authority, got.trust_root)
    assert ok, reason
    assert got.signed_authority.document.allow_destructive is False
