"""M-11.1 — the OFFENSE-side enforcement of the EvalOffenseAttestation hard precondition.

A LIVE EngagementAuthority may ARM weaponized offense ONLY when a verified, owner-signed,
evaluator-countersigned EvalOffenseAttestation covers the engagement on the shared seam. This test runs in
the OFFENSE leg (framework present) and must NOT import ``sigil`` — it simulates exactly what the sovereign
governor publishes, using ONLY the import-clean shared primitives (``vigil_core`` sign/canonical + the
``eval_attestation`` broker). It locks all three enforced arm sites plus the fail-closed verifier:

  * ``console.actions._has_verified_authority`` (the console launch gate),
  * ``engage._engage_authority_trust_root`` (the production engage trust-root pin),
  * ``conjunctive_gate.build_offense_gate`` (every target-touching offense action).

For EACH: a LIVE authority with NO verified attestation REFUSES to arm; a valid attestation permits; a
TWIN/STAGING authority is byte-identical (no attestation needed). Plus: revoked / expired / forged-owner /
missing-evaluator-PoP / wrong-domain-tag attestations all refuse, and the verifier honours the anti-replay
high-water and the charter-hash filter.

FATAL-2: the offense plane only VERIFIES public signed material against the pinned owner key; it never
imports the sovereign governor nor holds the owner key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from framework.v2.console import actions
from framework.v2.engage import EngagementRefused, _engage_authority_trust_root
from vigil_core import (
    AuthorizerKey,
    EngagementAuthority,
    TargetEnvironment,
    TrustRoot,
    canonical_json,
    generate_keypair,
    sign,
    sign_engagement_authority,
)
from vigil_core.spine_domains import DOMAIN_TAGS

# The offense console/gate import vigil_integration LAZILY; this test needs the broker directly to SEED the
# published records, so skip cleanly in the framework-only CI job where vigil_integration is not installed.
_eva = pytest.importorskip("vigil_integration.live.eval_attestation")
write_eval_attestations = _eva.write_eval_attestations
verify_live_offense_attested = _eva.verify_live_offense_attested
owner_pubkeys_of = _eva.owner_pubkeys_of
build_offense_gate = pytest.importorskip("vigil_integration.conjunctive_gate").build_offense_gate

_SLUG = "apme-cm"
_HOST = "apme.cm"
_CHASH = "a" * 64
_CORE = (
    "signal", "state", "engagement_slug", "charter_id", "charter_hash", "evaluator_pubkey",
    "environment", "not_after", "issued_at", "allow_destructive",
)
_FUTURE = 2_000_000_000.0
_PAST = 1.0
_NOW = 1_000_000_000.0


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """A tmp crucible root (with the CLAUDE.md sentinel so crucible_root() resolves to it) + a tmp seam."""
    root = tmp_path / "cruc"
    (root / "framework" / "v2").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# crucible\n", encoding="utf-8")
    base = tmp_path / ".vigil-live"
    base.mkdir()
    monkeypatch.setenv("CRUCIBLE_ROOT", str(root))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(base))
    return {"root": root, "base": str(base)}


def _canon(core: dict) -> bytes:
    cb = canonical_json({k: core.get(k) for k in _CORE})
    return cb if isinstance(cb, (bytes, bytearray)) else str(cb).encode("utf-8")


def _att_record(owner, evaluator, *, slug=_SLUG, charter_id="c-2026", charter_hash=_CHASH,
                not_after=_FUTURE, issued_at=5.0, environment="live", owner_signer=None,
                ev_signer=None, tag=None, state="attested"):
    """One public signed attestation record, byte-shaped exactly like the sovereign governor's payload."""
    core = {
        "signal": "governor.eval_offense_attestation", "state": state, "engagement_slug": slug,
        "charter_id": charter_id, "charter_hash": charter_hash,
        "evaluator_pubkey": evaluator.public_key_b64, "environment": environment,
        "not_after": float(not_after), "issued_at": float(issued_at), "allow_destructive": False,
    }
    cb = _canon(core)
    osig = sign((owner_signer or owner).private_key_b64, cb)
    tagb = DOMAIN_TAGS["eval-offense-attestation"] if tag is None else tag
    esig = sign((ev_signer or evaluator).private_key_b64, tagb + cb)
    return {**core, "sig": osig, "pubkey": owner.public_key_b64, "evaluator_sig": esig, "evaluator": "eval"}


def _revoke_record(owner, *, slug=_SLUG):
    core = {
        "signal": "governor.eval_offense_attestation", "state": "revoked", "engagement_slug": slug,
        "charter_id": "", "charter_hash": "", "evaluator_pubkey": "", "environment": "",
        "not_after": 0.0, "issued_at": 0.0, "allow_destructive": False,
    }
    return {**core, "sig": sign(owner.private_key_b64, _canon(core)), "pubkey": owner.public_key_b64}


def _provision(owner, *, slug=_SLUG, host=_HOST, env_kind=TargetEnvironment.LIVE):
    from framework.v2.authority.store import save_signed_authority, write_authority_root
    ts = datetime.now(timezone.utc)
    doc = EngagementAuthority(
        engagement_slug=slug, environment=env_kind, scope=[host],
        not_before=ts - timedelta(minutes=1), not_after=ts + timedelta(hours=8), issued_by="owner",
    )
    signed = sign_engagement_authority(doc, {"owner": owner.private_key_b64})
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="owner", name="owner", public_key_b64=owner.public_key_b64)])
    write_authority_root(tr)
    save_signed_authority(signed)
    return tr


def _seal_for(seal_owner, records, *, seq=1):
    """An owner-signed publish seal over the ordered ``records`` + monotonic ``seq`` — exactly what the
    SIGIL governor's ``_publish`` mints (reuses the production seal helpers so test + prod never drift)."""
    return _eva.build_seal(
        _SLUG, seq, records,
        sign_fn=lambda b: sign(seal_owner.private_key_b64, b), pubkey=seal_owner.public_key_b64)


def _write(base, records, *, seal_owner, seq=1, seal=None):
    """Publish ``records`` sealed by ``seal_owner`` (the pinned owner in the happy path). Pass an explicit
    ``seal`` to simulate a tampered publish (a seal that does NOT match the written ``records``)."""
    write_eval_attestations(
        base, _SLUG, records, seal=seal if seal is not None else _seal_for(seal_owner, records, seq=seq))


def _publish(base, owner, evaluator, *, seq=1, **kw):
    _write(base, [_att_record(owner, evaluator, **kw)], seal_owner=owner, seq=seq)


# === arm site 1/3: console.actions._has_verified_authority =========================================
def test_live_authority_without_attestation_refuses_arm(env):
    owner = generate_keypair()
    _provision(owner)                                     # LIVE authority, no eval-offense record published
    assert actions._has_verified_authority(_SLUG) is False
    assert actions._has_verified_authority(_SLUG, _HOST) is False


def test_live_authority_with_valid_attestation_arms(env):
    owner, ev = generate_keypair(), generate_keypair()
    _provision(owner)
    _publish(env["base"], owner, ev)
    assert actions._has_verified_authority(_SLUG) is True
    assert actions._has_verified_authority(_SLUG, _HOST) is True


def test_staging_authority_arms_without_an_attestation_but_live_does_not(env):
    # CONTROL: a TWIN/STAGING authority never consults the eval gate (byte-identical to before this slice).
    owner = generate_keypair()
    _provision(owner, env_kind=TargetEnvironment.STAGING)
    assert actions._has_verified_authority(_SLUG) is True
    # re-provision the SAME slug as LIVE (no attestation) → now refused
    _provision(owner, env_kind=TargetEnvironment.LIVE)
    assert actions._has_verified_authority(_SLUG) is False


def test_revoked_attestation_refuses_arm(env):
    owner, ev = generate_keypair(), generate_keypair()
    _provision(owner)
    _write(env["base"], [_att_record(owner, ev), _revoke_record(owner)], seal_owner=owner, seq=2)
    assert actions._has_verified_authority(_SLUG) is False


def test_expired_attestation_refuses_arm(env):
    owner, ev = generate_keypair(), generate_keypair()
    _provision(owner)
    _publish(env["base"], owner, ev, not_after=_PAST)     # already expired
    assert actions._has_verified_authority(_SLUG) is False


def test_forged_owner_attestation_refuses_arm(env):
    owner, ev, attacker = generate_keypair(), generate_keypair(), generate_keypair()
    _provision(owner)                                     # trust root pins `owner`
    # Defense-in-depth: even inside a list validly SEALED by the pinned owner, a record signed by `attacker`
    # (carrying attacker's pubkey → not the pinned owner) is refused by the per-record owner-sig check.
    _write(env["base"], [_att_record(attacker, ev)], seal_owner=owner)  # record owner=attacker ⇒ not pinned
    assert actions._has_verified_authority(_SLUG) is False


def test_missing_evaluator_pop_refuses_arm(env):
    owner, ev, stranger = generate_keypair(), generate_keypair(), generate_keypair()
    _provision(owner)
    _publish(env["base"], owner, ev, ev_signer=stranger)  # evaluator PoP by the WRONG key
    assert actions._has_verified_authority(_SLUG) is False


def test_fresh_domain_tag_pop_without_the_tag_refuses_arm(env):
    owner, ev = generate_keypair(), generate_keypair()
    _provision(owner)
    _publish(env["base"], owner, ev, tag=b"")             # evaluator PoP computed WITHOUT the domain tag
    assert actions._has_verified_authority(_SLUG) is False


# === arm site 2/3: engage._engage_authority_trust_root ============================================
def test_engage_live_without_attestation_refuses(env):
    owner = generate_keypair()
    _provision(owner)
    with pytest.raises(EngagementRefused) as ei:
        _engage_authority_trust_root(_SLUG)
    assert "eval-offense attestation" in str(ei.value)


def test_engage_live_with_attestation_pins_the_trust_root(env):
    owner, ev = generate_keypair(), generate_keypair()
    _provision(owner)
    _publish(env["base"], owner, ev)
    assert _engage_authority_trust_root(_SLUG) is not None


def test_engage_staging_pins_without_an_attestation(env):
    owner = generate_keypair()
    _provision(owner, env_kind=TargetEnvironment.STAGING)
    assert _engage_authority_trust_root(_SLUG) is not None   # CONTROL: staging never consults the eval gate


# === arm site 3/3: conjunctive_gate.build_offense_gate ============================================
def _gate(tr, base):
    return build_offense_gate(slug=_SLUG, trust_root=tr, classify=lambda t: "A1", base_dir=base)


def test_gate_live_without_attestation_denies(env):
    owner = generate_keypair()
    tr = _provision(owner)
    v = _gate(tr, env["base"])("http_get", f"http://{_HOST}/")
    assert v.outcome == "deny" and v.allowed is False
    assert v.crucible_allowed is False and "M-11.1" in v.reason


def test_gate_live_with_attestation_passes_the_crucible_leg(env):
    owner, ev = generate_keypair(), generate_keypair()
    tr = _provision(owner)
    _publish(env["base"], owner, ev)
    v = _gate(tr, env["base"])("http_get", f"http://{_HOST}/")
    assert "M-11.1" not in v.reason   # the eval-offense gate no longer denies (it flipped from deny→pass)


def test_gate_staging_is_byte_identical(env):
    owner = generate_keypair()
    tr = _provision(owner, env_kind=TargetEnvironment.STAGING)
    v = _gate(tr, env["base"])("http_get", f"http://{_HOST}/")   # no attestation published
    assert "M-11.1" not in v.reason   # CONTROL: the eval gate never fires on staging


# === the fail-closed verifier directly ============================================================
def test_verify_no_pinned_owner_key_refuses(env):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(env["base"], owner, ev)
    ok, reason = verify_live_offense_attested(
        env["base"], engagement_slug=_SLUG, trusted_owner_pubkeys=[], now=_NOW)
    assert ok is False and "no pinned owner key" in reason


def test_verify_charter_hash_filter(env):
    owner, ev = generate_keypair(), generate_keypair()
    _publish(env["base"], owner, ev, charter_hash=_CHASH)
    pinned = [owner.public_key_b64]
    ok_match, _ = verify_live_offense_attested(
        env["base"], engagement_slug=_SLUG, trusted_owner_pubkeys=pinned, now=_NOW, charter_hash=_CHASH)
    ok_diff, _ = verify_live_offense_attested(
        env["base"], engagement_slug=_SLUG, trusted_owner_pubkeys=pinned, now=_NOW, charter_hash="b" * 64)
    assert ok_match is True and ok_diff is False


def test_verify_replay_below_highwater_refused(env):
    owner, ev = generate_keypair(), generate_keypair()
    pinned = [owner.public_key_b64]
    # attest (issued=10) → revoke → replay the SAME issued=10 attestation: below the high-water → ignored,
    # so the state stays revoked (un-armed). Mirrors the sovereign anti-replay fold.
    replay = _att_record(owner, ev, issued_at=10.0)
    _write(env["base"], [
        _att_record(owner, ev, issued_at=10.0), _revoke_record(owner), replay,
    ], seal_owner=owner, seq=3)
    ok, _ = verify_live_offense_attested(
        env["base"], engagement_slug=_SLUG, trusted_owner_pubkeys=pinned, now=_NOW)
    assert ok is False


def test_verify_owner_pubkeys_of_extracts_pinned_keys(env):
    owner = generate_keypair()
    tr = _provision(owner)
    assert owner_pubkeys_of(tr) == frozenset({owner.public_key_b64})
    assert owner_pubkeys_of(None) == frozenset()


# === tamper-evidence of the LIST ITSELF (red-pen 12/13 + rollback residual) =======================
# The loose seam's record-list order/membership is not authenticated by the per-record signatures, and the
# fold honours a revoke POSITIONALLY. An attacker WITHOUT the owner key must not be able to re-arm a revoked
# attestation by DROPPING / REORDERING / ROLLING BACK the published list. The owner-signed publish seal +
# the durable monotonic high-water close all three; each probe asserts the offense verifier REFUSES.
def _verify(base, owner, now=_NOW):
    return verify_live_offense_attested(
        base, engagement_slug=_SLUG, trusted_owner_pubkeys=[owner.public_key_b64], now=now)


def test_unsealed_list_refuses_to_arm(env):
    # CONTROL: a validly SEALED single attestation arms; the SAME list with NO seal refuses (fail-closed —
    # an unauthenticated list is exactly what an off-seam drop/reorder would leave).
    owner, ev = generate_keypair(), generate_keypair()
    att = _att_record(owner, ev)
    write_eval_attestations(env["base"], _SLUG, [att])                 # no seal at all
    ok, reason = _verify(env["base"], owner)
    assert ok is False and "seal" in reason.lower()
    write_eval_attestations(env["base"], _SLUG, [att], seal=_seal_for(owner, [att]))   # now sealed
    ok2, _ = _verify(env["base"], owner)
    assert ok2 is True


def test_forged_seal_by_non_owner_refuses(env):
    # A seal signed by an attacker key (not the pinned owner) does not authenticate the list.
    owner, ev, attacker = generate_keypair(), generate_keypair(), generate_keypair()
    att = _att_record(owner, ev)
    write_eval_attestations(env["base"], _SLUG, [att], seal=_seal_for(attacker, [att]))
    ok, reason = _verify(env["base"], owner)
    assert ok is False and "owner" in reason.lower()


def test_dropped_revoke_record_is_detected_and_refused(env):
    # PROBE 12: owner published [att, revoke] (revoked ⇒ un-armed). Attacker DROPS the revoke but keeps the
    # genuine seal (minted over [att, revoke]). The verifier recomputes the seal over the dropped list [att] —
    # it no longer verifies ⇒ REFUSED. Without the seal the bare fold would see only [att] and ARM.
    owner, ev = generate_keypair(), generate_keypair()
    att, revoke = _att_record(owner, ev), _revoke_record(owner)
    good_seal = _seal_for(owner, [att, revoke], seq=2)
    write_eval_attestations(env["base"], _SLUG, [att], seal=good_seal)   # revoke dropped, seal unchanged
    ok, reason = _verify(env["base"], owner)
    assert ok is False and "seal" in reason.lower()


def test_reordered_revoke_before_attest_is_detected_and_refused(env):
    # PROBE 13: owner published [att, revoke] (revoke LAST ⇒ un-armed). Attacker REORDERS to [revoke, att]
    # hoping the positional fold lets the now-last attest win, keeping the genuine seal over [att, revoke].
    # The verifier recomputes the seal over [revoke, att] — it no longer verifies ⇒ REFUSED.
    owner, ev = generate_keypair(), generate_keypair()
    att, revoke = _att_record(owner, ev), _revoke_record(owner)
    good_seal = _seal_for(owner, [att, revoke], seq=2)
    write_eval_attestations(env["base"], _SLUG, [revoke, att], seal=good_seal)  # reordered, seal unchanged
    ok, reason = _verify(env["base"], owner)
    assert ok is False and "seal" in reason.lower()


def test_rolledback_pre_revoke_publication_is_detected_and_refused(env):
    # ROLLBACK: owner publishes [att] (seq=1, armed), then [att, revoke] (seq=2, revoked). The offense plane
    # verifies each in turn, advancing its durable high-water to 2. The attacker then REPLAYS the genuine,
    # still-owner-signed seq=1 file — the seal verifies, but seq=1 is below the high-water ⇒ REFUSED.
    owner, ev = generate_keypair(), generate_keypair()
    att, revoke = _att_record(owner, ev, issued_at=10.0), _revoke_record(owner)
    write_eval_attestations(env["base"], _SLUG, [att], seal=_seal_for(owner, [att], seq=1))
    ok1, _ = _verify(env["base"], owner)
    assert ok1 is True                                                   # armed; high-water now 1
    write_eval_attestations(env["base"], _SLUG, [att, revoke], seal=_seal_for(owner, [att, revoke], seq=2))
    ok2, _ = _verify(env["base"], owner)
    assert ok2 is False                                                  # revoked; high-water now 2
    # ROLLBACK: byte-for-byte replay of the genuine seq=1 publication
    write_eval_attestations(env["base"], _SLUG, [att], seal=_seal_for(owner, [att], seq=1))
    ok3, reason = _verify(env["base"], owner)
    assert ok3 is False and "ROLLBACK" in reason
