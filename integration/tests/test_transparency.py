"""I2 — witnessed transparency log: witness-quorum co-signing + consistency proof + split-view
detection over the signed spine head. Reuses vigil_core signatures; import-clean."""

from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_integration.transparency import (
    GENESIS_LINK,
    Checkpoint,
    ConsistencyError,
    Witness,
    WitnessedCheckpoint,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split,
    verify_log,
    verify_witnessed,
)


def _cp(last_seq, entry_count, head_hash, prev=GENESIS_LINK, merkle=None):
    return Checkpoint(last_seq=last_seq, entry_count=entry_count, head_hash=head_hash,
                      merkle_root=merkle or f"m{entry_count}", prev_checkpoint_hash=prev)


def _linked_chain(n):
    cps, prev = [], GENESIS_LINK
    for i in range(n):
        cp = _cp(i * 10, i * 10, f"h{i}", prev=prev)
        cps.append(cp)
        prev = checkpoint_hash(cp)
    return cps


def test_checkpoint_of_summarises_a_head():
    class _Head:
        last_seq, entry_count, head_hash, cumulative_merkle_root = 42, 100, "abc", "root"
    cp = checkpoint_of(_Head(), prev_checkpoint_hash="prev")
    assert (cp.last_seq, cp.entry_count, cp.head_hash, cp.merkle_root, cp.prev_checkpoint_hash) == \
        (42, 100, "abc", "root", "prev")


def test_hash_is_stable_and_content_sensitive():
    cp = _cp(1, 1, "h")
    assert checkpoint_hash(cp) == checkpoint_hash(cp)
    assert checkpoint_hash(cp) != checkpoint_hash(_cp(1, 1, "h2"))


def test_consistent_extension_ok():
    a = _cp(10, 10, "h0")
    b = _cp(20, 20, "h1", prev=checkpoint_hash(a))
    assert consistent(a, b)[0]


def test_rollback_shrink_rejected():
    a = _cp(20, 20, "h1")
    ok, reason = consistent(a, _cp(10, 10, "h0", prev=checkpoint_hash(a)))
    assert not ok and "shrank" in reason


def test_last_seq_backwards_rejected():
    a = _cp(20, 20, "h1")
    ok, reason = consistent(a, _cp(10, 30, "h2", prev=checkpoint_hash(a)))  # count grows, seq back
    assert not ok and "backwards" in reason


def test_broken_link_rejected():
    a = _cp(10, 10, "h0")
    ok, reason = consistent(a, _cp(20, 20, "h1", prev="wrong-link"))
    assert not ok and "chain broken" in reason


def test_fork_at_same_height_rejected():
    a = _cp(10, 10, "h0")
    ok, reason = consistent(a, _cp(10, 10, "h0-fork", prev=checkpoint_hash(a)))
    assert not ok and "split view" in reason


def test_witness_cosigns_a_consistent_extension_and_refuses_a_fork():
    W = generate_keypair()
    w = Witness("w0", W.private_key_b64)
    a = _cp(10, 10, "h0")
    b = _cp(20, 20, "h1", prev=checkpoint_hash(a))
    w.cosign(a)
    assert w.cosign(b).key_id == "w0"  # consistent extension → signs
    fork = _cp(20, 20, "h1-fork", prev=checkpoint_hash(a))  # a different tip at b's height
    with pytest.raises(ConsistencyError):
        w.cosign(fork)  # inconsistent with the witness's tracked tip → refuses


def test_quorum_verify_needs_m_of_n_witnesses():
    W0, W1 = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64)])
    cp = _cp(10, 10, "h0")
    sigs = (Witness("w0", W0.private_key_b64).cosign(cp), Witness("w1", W1.private_key_b64).cosign(cp))
    assert verify_witnessed(WitnessedCheckpoint(cp, sigs), witness_trust_root=tr) is True
    assert verify_witnessed(WitnessedCheckpoint(cp, (sigs[0],)), witness_trust_root=tr) is False  # 1<2


def test_tampering_a_witnessed_checkpoint_breaks_the_quorum():
    W0, W1 = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64)])
    cp = _cp(10, 10, "h0")
    sigs = (Witness("w0", W0.private_key_b64).cosign(cp), Witness("w1", W1.private_key_b64).cosign(cp))
    forged = _cp(10, 10, "h0-tampered")  # same height, different head
    assert verify_witnessed(WitnessedCheckpoint(forged, sigs), witness_trust_root=tr) is False


def test_verify_log_walks_the_chain():
    chain = _linked_chain(5)
    assert verify_log(chain)[0] is True
    broken = chain[:2] + [_cp(30, 30, "hX", prev="wrong")] + chain[3:]
    assert verify_log(broken)[0] is False


def test_split_view_is_detectable_across_two_witnessed_forks():
    # each fork can be individually witnessed, but same-height + different-content IS the split proof
    x = _cp(100, 100, "head-X")
    y = _cp(100, 100, "head-Y")  # a fork at the same height
    assert is_split(x, y) is True
    # a genuine extension is not a split
    z = _cp(200, 200, "head-Z", prev=checkpoint_hash(x))
    assert is_split(x, z) is False
