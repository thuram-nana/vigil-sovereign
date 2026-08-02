"""VF-1c — a WITNESSED, TIME-BOUNDED checkpoint over the Continuous Attestation Log head.

Framework-FREE (routes into the P5 no-framework integration job): it builds a minimal but REAL
``vigil_core.SignedChainHead`` (the same type the attestation log persists at ``<log_dir>/head.json``)
and summarises it with the merged ``transparency.checkpoint_of`` — it never touches ``prove_driver`` /
the offense engine, so ``PYTHONPATH=integration:gateway`` is sufficient.

Covers: happy-path strict-majority quorum + head binding + median time bound; ``witness_attestation_head``
loading the persisted head.json (and the take-a-head-directly path); and the adversarial matrix —
sub-majority / duplicate-key set (not split-view resistant), a forged witness sig (not counted → quorum
fails), a low-order witness key (refused), a TIMELESS transparency co-signature replayed as a timed one
(distinct domain → does not verify), a single dishonest witness reporting an extreme time (median
unmoved), and a checkpoint tampered after signing (sigs no longer verify).
"""
from __future__ import annotations

import base64

import pytest

from vigil_core import AuthorizerKey, SignedChainHead, TrustRoot, generate_keypair
from vigil_integration.transparency import Checkpoint, Witness, checkpoint_of
from vigil_integration.remediation.attestation_witness import (
    _ATTESTATION_WITNESS_TIME_DOMAIN,
    _timed_signing_bytes,
    TimedWitnessSignature,
    TimedWitnessedCheckpoint,
    timed_cosign,
    verify_timed_witnessed,
    verify_timed_witnessed_checkpoint,
    witness_attestation_head,
)

# Three independently-keyed witnesses + an attacker (for forgeries).
W0 = generate_keypair()
W1 = generate_keypair()
W2 = generate_keypair()
ATTACKER = generate_keypair()

# base64 of 32 zero bytes = the Ed25519 identity/low-order point that load_public_key must reject.
LOW_ORDER_B64 = base64.b64encode(bytes(32)).decode("ascii")


def _auth(kp, key_id):
    return AuthorizerKey(key_id=key_id, name=key_id, public_key_b64=kp.public_key_b64)


def _trust_root(threshold, *auths):
    return TrustRoot(threshold=threshold, authorizers=list(auths))


def _head(last_seq=2, entry_count=3, head_hash="head-hash-abc", merkle="merkle-root-xyz"):
    return SignedChainHead(
        last_seq=last_seq, entry_count=entry_count, head_hash=head_hash,
        cumulative_merkle_root=merkle, engagement_slug="acme",
    )


def _cp(head=None) -> Checkpoint:
    return checkpoint_of(head or _head())


# strict-majority 2-of-3 over the three distinct witnesses — the canonical split-view-resistant quorum.
QUORUM = _trust_root(2, _auth(W0, "w0"), _auth(W1, "w1"), _auth(W2, "w2"))


# ============================ happy path: quorum + head binding + median T ============================
def test_happy_path_quorum_binds_head_and_bounds_time():
    head = _head(last_seq=7, entry_count=8, head_hash="deadbeef", merkle="mroot")
    cp = checkpoint_of(head)

    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200),
        timed_cosign(cp, witness_keypair=W2, key_id="w2", observed_time=300),
    ]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=QUORUM)
    assert ok, reason
    assert T == 200, reason                              # (n//2)-th of [100,200,300] = exact median
    assert "no-later-than T=200" in reason and "median" in reason

    # the checkpoint binds the attestation head it summarised.
    assert cp.head_hash == head.head_hash == "deadbeef"
    assert cp.last_seq == head.last_seq == 7
    assert cp.entry_count == head.entry_count == 8


def test_even_count_uses_upper_median():
    cp = _cp()
    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=10),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=20),
    ]
    # 2-of-2 is a strict majority (2*2 > 2). n=2 → index 2//2=1 → the UPPER of the two central values.
    tr = _trust_root(2, _auth(W0, "w0"), _auth(W1, "w1"))
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=tr)
    assert ok and T == 20, reason


# ============================ witness_attestation_head: load head.json + head-direct ============================
def test_witness_attestation_head_loads_persisted_head_json(tmp_path):
    log = tmp_path / "attlog"
    log.mkdir()
    head = _head(last_seq=4, entry_count=5, head_hash="persisted-head")
    # persist exactly as attestation_log._write_head does (model_dump_json → head.json).
    (log / "head.json").write_text(head.model_dump_json(), encoding="utf-8")

    twc = witness_attestation_head(
        log, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")], observed_times=[500, 600, 700]
    )
    assert isinstance(twc, TimedWitnessedCheckpoint)
    assert twc.checkpoint["head_hash"] == "persisted-head"
    ok, T, reason = verify_timed_witnessed_checkpoint(twc, witness_trust_root=QUORUM)
    assert ok and T == 600, reason


def test_witness_attestation_head_take_head_directly():
    head = _head(head_hash="direct-head")
    twc = witness_attestation_head(
        head=head, witnesses=[(W0, "w0"), (W1, "w1"), (W2, "w2")], observed_times=[1, 2, 3]
    )
    assert twc.checkpoint["head_hash"] == "direct-head"
    ok, T, _ = verify_timed_witnessed_checkpoint(twc, witness_trust_root=QUORUM)
    assert ok and T == 2


def test_witness_attestation_head_parallel_length_enforced():
    with pytest.raises(ValueError):
        witness_attestation_head(head=_head(), witnesses=[(W0, "w0")], observed_times=[1, 2])


def test_witness_attestation_head_needs_a_source():
    with pytest.raises(ValueError):
        witness_attestation_head(witnesses=[(W0, "w0")], observed_times=[1])


# ============================ ADVERSARIAL ============================
def test_sub_majority_is_not_split_view_resistant():
    cp = _cp()
    # threshold=1, n=3 → 2*1 !> 3 → sub-majority: two disjoint quorums could sign two forks → refuse.
    tr = _trust_root(1, _auth(W0, "w0"), _auth(W1, "w1"), _auth(W2, "w2"))
    sigs = [timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100)]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=tr)
    assert not ok and T is None and "not split-view resistant" in reason


def test_duplicate_public_key_witness_set_rejected():
    cp = _cp()
    # two DISTINCT key_ids share ONE public key (W0's) — a single keyholder would forge a 'strict majority'.
    tr = _trust_root(2, _auth(W0, "w0"), _auth(W0, "w0-alias"), _auth(W1, "w1"))
    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200),
    ]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=tr)
    assert not ok and T is None and "not split-view resistant" in reason


def test_low_order_witness_key_is_refused():
    cp = _cp()
    tr = _trust_root(2, _auth(W0, "w0"), _auth(W1, "w1"),
                     AuthorizerKey(key_id="w2", name="w2", public_key_b64=LOW_ORDER_B64))
    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200),
    ]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=tr)
    assert not ok and T is None and "not split-view resistant" in reason


def test_forged_witness_sig_is_not_counted_and_quorum_fails():
    cp = _cp()
    # one honest sig + one FORGED sig (signed by ATTACKER but labelled 'w2'): the forged sig does not
    # verify under w2's real pubkey → dropped → 1 distinct witness < threshold 2 → quorum fails.
    honest = timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100)
    forged = timed_cosign(cp, witness_keypair=ATTACKER, key_id="w2", observed_time=200)
    ok, T, reason = verify_timed_witnessed(cp, [honest, forged], witness_trust_root=QUORUM)
    assert not ok and T is None and "quorum not met" in reason


def test_forged_extra_sig_is_ignored_but_a_full_quorum_still_holds():
    cp = _cp()
    # two honest + one forged: the forged is ignored, the two honest still meet the 2-of-3 quorum.
    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200),
        timed_cosign(cp, witness_keypair=ATTACKER, key_id="w2", observed_time=999999),  # forged
    ]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=QUORUM)
    assert ok, reason
    # T is the median of the TWO verifying (honest) clocks only — the forged 999999 never enters the set.
    assert T == 200, reason


def test_unknown_key_id_sig_is_ignored():
    cp = _cp()
    stranger = timed_cosign(cp, witness_keypair=ATTACKER, key_id="not-in-trust-root", observed_time=5)
    honest = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200),
    ]
    ok, T, reason = verify_timed_witnessed(cp, honest + [stranger], witness_trust_root=QUORUM)
    assert ok and T == 200, reason


def test_timeless_transparency_cosign_does_not_verify_as_timed():
    cp = _cp()
    # transparency.Witness.cosign signs under the TIMELESS _WITNESS_DOMAIN (no observed_time). Present those
    # co-signatures as TIMED sigs (same key_id, an arbitrary observed_time): the timed verify recomputes the
    # message under the DISTINCT timed domain + the embedded time, so none verify → quorum not met.
    timeless = [
        Witness("w0", W0.private_key_b64).cosign(cp),
        Witness("w1", W1.private_key_b64).cosign(cp),
        Witness("w2", W2.private_key_b64).cosign(cp),
    ]
    replayed = [
        TimedWitnessSignature(key_id=s.key_id, observed_time=100, signature_b64=s.signature_b64)
        for s in timeless
    ]
    ok, T, reason = verify_timed_witnessed(cp, replayed, witness_trust_root=QUORUM)
    assert not ok and T is None and "quorum not met" in reason

    # sanity: the SAME witnesses signing under the TIMED domain DO verify — proving it is the domain, not
    # the keys, that rejected the replay.
    timed = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=100),
        timed_cosign(cp, witness_keypair=W2, key_id="w2", observed_time=100),
    ]
    ok2, T2, _ = verify_timed_witnessed(cp, timed, witness_trust_root=QUORUM)
    assert ok2 and T2 == 100
    # and the domain tags are genuinely distinct byte strings.
    assert _ATTESTATION_WITNESS_TIME_DOMAIN == b"vigil-attestation-witness-time-v1\x00"
    from vigil_integration.transparency import _WITNESS_DOMAIN
    assert _ATTESTATION_WITNESS_TIME_DOMAIN != _WITNESS_DOMAIN


@pytest.mark.parametrize("extreme,expected_T", [(10_000_000, 1001), (0, 1000)])
def test_single_dishonest_extreme_time_does_not_move_the_median(extreme, expected_T):
    cp = _cp()
    # two honest clocks {1000, 1001} + one dishonest witness reporting an extreme τ. All three verify, so
    # n=3 and T = the (3//2)=1-st sorted value = a HONEST clock — the extreme is sandwiched out.
    sigs = [
        timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=1000),
        timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=1001),
        timed_cosign(cp, witness_keypair=W2, key_id="w2", observed_time=extreme),  # dishonest
    ]
    ok, T, reason = verify_timed_witnessed(cp, sigs, witness_trust_root=QUORUM)
    assert ok, reason
    assert T == expected_T
    assert 1000 <= T <= 1001                              # bounded by the two honest clocks


def test_checkpoint_tampered_after_signing_no_longer_verifies():
    signed_head = _head(head_hash="original-head")
    cp_signed = checkpoint_of(signed_head)
    sigs = [
        timed_cosign(cp_signed, witness_keypair=W0, key_id="w0", observed_time=100),
        timed_cosign(cp_signed, witness_keypair=W1, key_id="w1", observed_time=200),
        timed_cosign(cp_signed, witness_keypair=W2, key_id="w2", observed_time=300),
    ]
    # a verifier is shown a DIFFERENT checkpoint (head_hash swapped) with the same signatures.
    tampered = checkpoint_of(_head(head_hash="attacker-swapped-head"))
    ok, T, reason = verify_timed_witnessed(tampered, sigs, witness_trust_root=QUORUM)
    assert not ok and T is None and "quorum not met" in reason

    # control: the untampered checkpoint still verifies with those same sigs.
    ok2, T2, _ = verify_timed_witnessed(cp_signed, sigs, witness_trust_root=QUORUM)
    assert ok2 and T2 == 200


def test_observed_time_tamper_invalidates_that_witness():
    cp = _cp()
    good = timed_cosign(cp, witness_keypair=W0, key_id="w0", observed_time=100)
    # forge a new record with the SAME signature bytes but a changed observed_time → the sig binds the
    # original time, so the recomputed message differs → this witness no longer verifies.
    mutated = TimedWitnessSignature(key_id="w0", observed_time=999, signature_b64=good.signature_b64)
    others = [timed_cosign(cp, witness_keypair=W1, key_id="w1", observed_time=200)]
    ok, T, reason = verify_timed_witnessed(cp, [mutated] + others, witness_trust_root=QUORUM)
    assert not ok and "quorum not met" in reason      # only w1 verified → 1 < 2
