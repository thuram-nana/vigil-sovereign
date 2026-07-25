"""S7c — multi-segment transparency: witness the WHOLE S5 spine-domain view at once.

A MultiSegmentCheckpoint composes every S5 segment's tip into one witnessable object, so a witness quorum
co-signs the entire control plane in one signature and split-view resistance covers ALL segments: a fork in
any segment, or a segment silently added/dropped, breaks consistency. Reuses the single-segment primitives.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_transparency_multi.py -q
"""
from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_integration.transparency import (
    GENESIS_LINK,
    Checkpoint,
    ConsistencyError,
    MultiSegmentCheckpoint,
    MultiWitnessedCheckpoint,
    Witness,
    WitnessedCheckpoint,
    _multi_signing_bytes,
    is_multi_split,
    multi_checkpoint_hash,
    multi_consistent,
    verify_split_view_resistant_multi,
    verify_witnessed,
    verify_witnessed_multi,
)

W0, W1, W2 = generate_keypair(), generate_keypair(), generate_keypair()
# a STRICT-majority witness set (2-of-3 distinct keys → 2*2 > 3 → split-view resistant)
STRICT = TrustRoot(threshold=2, authorizers=[
    AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64),
    AuthorizerKey(key_id="w1", name="w1", public_key_b64=W1.public_key_b64),
    AuthorizerKey(key_id="w2", name="w2", public_key_b64=W2.public_key_b64)])


def _cp(entry_count, head_hash, prev=GENESIS_LINK):
    return Checkpoint(last_seq=entry_count, entry_count=entry_count, head_hash=head_hash,
                      merkle_root=f"m{entry_count}", prev_checkpoint_hash=prev)


def _mc(*, sov="hs0", off="ho0", prev=GENESIS_LINK, ecount=10):
    return MultiSegmentCheckpoint(
        segments={"sovereign-spine": _cp(ecount, sov), "offense-spine": _cp(ecount, off)},
        prev_checkpoint_hash=prev)


def test_a_witness_quorum_cosigns_the_whole_view():
    mc = _mc()
    sigs = (Witness("w0", W0.private_key_b64).cosign_multi(mc),
            Witness("w1", W1.private_key_b64).cosign_multi(mc))
    mwc = MultiWitnessedCheckpoint(mc, sigs)
    assert verify_witnessed_multi(mwc, witness_trust_root=STRICT) is True
    assert verify_split_view_resistant_multi(mwc, witness_trust_root=STRICT) is True
    # sub-quorum (1 of 2 needed) fails
    assert verify_witnessed_multi(MultiWitnessedCheckpoint(mc, (sigs[0],)),
                                  witness_trust_root=STRICT) is False


def test_multi_consistent_requires_every_segment_to_extend():
    a = _mc(ecount=10)
    b = _mc(sov="hs1", off="ho1", ecount=20, prev=multi_checkpoint_hash(a))
    ok, _ = multi_consistent(a, b)
    assert ok
    # a segment that ROLLS BACK breaks the whole composite
    regressed = MultiSegmentCheckpoint(
        segments={"sovereign-spine": _cp(5, "hs-old"), "offense-spine": _cp(20, "ho1")},
        prev_checkpoint_hash=multi_checkpoint_hash(a))
    ok2, reason = multi_consistent(a, regressed)
    assert not ok2 and "sovereign-spine" in reason


def test_a_changed_segment_set_is_a_split_view():
    a = _mc()
    dropped = MultiSegmentCheckpoint(segments={"sovereign-spine": _cp(20, "hs1")},
                                     prev_checkpoint_hash=multi_checkpoint_hash(a))
    ok, reason = multi_consistent(a, dropped)
    assert not ok and "segment" in reason.lower()


def test_is_multi_split_detects_a_fork_in_any_segment():
    a = _mc(sov="hsA", off="ho0", ecount=10)
    b = _mc(sov="hsB", off="ho0", ecount=10)   # same height, DIFFERENT sovereign head → fork
    assert is_multi_split(a, b) is True
    assert is_multi_split(a, _mc(sov="hsA", off="ho0", ecount=10)) is False   # identical, no fork


def test_an_honest_witness_refuses_to_cosign_a_fork():
    w = Witness("w0", W0.private_key_b64)
    a = _mc(ecount=10)
    w.cosign_multi(a)
    fork = _mc(sov="hs-FORK", off="ho0", ecount=10, prev=multi_checkpoint_hash(a))  # same height, new head
    with pytest.raises(ConsistencyError):
        w.cosign_multi(fork)


def test_added_segment_and_broken_chain_link_are_refused():
    a = _mc(ecount=10)
    added = MultiSegmentCheckpoint(
        segments={"sovereign-spine": _cp(20, "hs1"), "offense-spine": _cp(20, "ho1"),
                  "extra-spine": _cp(20, "hx1")},
        prev_checkpoint_hash=multi_checkpoint_hash(a))
    ok, reason = multi_consistent(a, added)
    assert not ok and "segment" in reason.lower()          # a segment ADDED is a control-plane split view
    # a valid segment set but a WRONG composite prev-link (fork) is refused
    forged_link = _mc(sov="hs1", off="ho1", ecount=20, prev="not-the-real-prev-hash")
    ok2, reason2 = multi_consistent(a, forged_link)
    assert not ok2 and "chain broken" in reason2


def test_last_seq_only_rollback_is_refused():
    a = MultiSegmentCheckpoint(segments={"s": Checkpoint(last_seq=100, entry_count=10, head_hash="h",
                                                         merkle_root="m")})
    # same entry_count + head but last_seq rolled back → refused (anti-rollback)
    b = MultiSegmentCheckpoint(segments={"s": Checkpoint(last_seq=50, entry_count=10, head_hash="h",
                                                         merkle_root="m")},
                               prev_checkpoint_hash=multi_checkpoint_hash(a))
    ok, reason = multi_consistent(a, b)
    assert not ok and "last_seq" in reason


def test_refused_cosign_multi_does_not_advance_the_tip_and_tips_are_isolated():
    w = Witness("w0", W0.private_key_b64)
    a = _mc(ecount=10)
    w.cosign_multi(a)
    fork = _mc(sov="hs-FORK", off="ho0", ecount=10, prev=multi_checkpoint_hash(a))
    with pytest.raises(ConsistencyError):
        w.cosign_multi(fork)
    # tip NOT advanced by the refused fork → a genuine extension of `a` is still accepted
    ext = _mc(sov="hs1", off="ho1", ecount=20, prev=multi_checkpoint_hash(a))
    w.cosign_multi(ext)   # would raise if the tip had wrongly advanced to `fork`
    # single-segment and multi tips are INDEPENDENT: co-signing a single cp doesn't disturb the multi tip
    w.cosign(_cp(30, "single-h"))
    ext2 = _mc(sov="hs2", off="ho2", ecount=30, prev=multi_checkpoint_hash(ext))
    w.cosign_multi(ext2)   # multi tip still tracks `ext`, so this consistent extension is accepted


def test_hash_is_insertion_order_independent():
    m1 = MultiSegmentCheckpoint(segments={"a-seg": _cp(10, "ha"), "b-seg": _cp(10, "hb")})
    m2 = MultiSegmentCheckpoint(segments={"b-seg": _cp(10, "hb"), "a-seg": _cp(10, "ha")})
    assert multi_checkpoint_hash(m1) == multi_checkpoint_hash(m2)   # deterministic (sorted keys)


def test_segments_mapping_is_immutable():
    mc = _mc()
    with pytest.raises(TypeError):
        mc.segments["offense-spine"] = _cp(999, "tampered")   # frozen mapping — can't silently change the hash


def test_multi_signature_does_not_replay_as_single_segment():
    # a multi checkpoint's signed bytes are structurally distinct from a single Checkpoint's (different
    # top-level key set + a type marker) → a multi witness sig can't verify a single cp, or vice-versa
    mc = _mc()
    sig = Witness("w0", W0.private_key_b64).cosign_multi(mc)
    single = mc.segments["sovereign-spine"]
    solo = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W0.public_key_b64)])
    assert verify_witnessed(WitnessedCheckpoint(single, (sig,)), witness_trust_root=solo) is False
    # but it DOES verify as the multi checkpoint it actually signed
    assert verify_witnessed_multi(MultiWitnessedCheckpoint(mc, (sig,)), witness_trust_root=solo) is True
    assert _multi_signing_bytes(mc).startswith(b"vigil-transparency-checkpoint-v1\x00")
