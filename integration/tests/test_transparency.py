"""I2 — witnessed transparency log: witness-quorum co-signing + consistency proof + split-view
detection over the signed spine head. Reuses vigil_core signatures; import-clean."""

from __future__ import annotations

import pytest

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
from vigil_integration.transparency import (
    GENESIS_LINK,
    Checkpoint,
    CheckpointEmitter,
    ConsistencyError,
    Witness,
    WitnessedCheckpoint,
    checkpoint_hash,
    checkpoint_of,
    consistent,
    is_split,
    is_split_view_resistant,
    verify_log,
    verify_split_view_resistant,
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


def _witnesses(n):
    """n independent witnesses + a strict m-of-n trust root over their public keys."""
    kps = [generate_keypair() for _ in range(n)]
    ws = [Witness(f"w{i}", kp.private_key_b64) for i, kp in enumerate(kps)]
    def root(m):
        return TrustRoot(threshold=m, authorizers=[
            AuthorizerKey(key_id=f"w{i}", name=f"w{i}", public_key_b64=kp.public_key_b64)
            for i, kp in enumerate(kps)])
    return ws, root


class _Head:
    """A duck-typed SignedChainHead: checkpoint_of reads these attrs via getattr."""
    def __init__(self, last_seq, entry_count, head_hash, merkle):
        self.last_seq, self.entry_count = last_seq, entry_count
        self.head_hash, self.cumulative_merkle_root = head_hash, merkle


def test_checkpoint_emitter_produces_a_verifiable_witnessed_chain():
    ws, root = _witnesses(3)  # 2-of-3 strict majority
    tr = root(2)
    em = CheckpointEmitter()
    assert em.head is None
    chain = []
    for i in range(1, 5):
        wc = em.emit(_Head(i * 10, i * 10, f"h{i}", f"m{i}"), ws)
        assert verify_witnessed(wc, witness_trust_root=tr) is True
        assert verify_split_view_resistant(wc, witness_trust_root=tr) is True
        chain.append(wc.checkpoint)
    assert verify_log(chain)[0] is True            # the checkpoints form a valid append-only log
    assert chain[0].prev_checkpoint_hash == GENESIS_LINK  # first links to genesis
    assert em.head == chain[-1]


def test_checkpoint_emitter_refuses_a_regressed_head():
    ws, _ = _witnesses(3)
    em = CheckpointEmitter()
    em.emit(_Head(20, 20, "h2", "m2"), ws)
    with pytest.raises(ConsistencyError):
        em.emit(_Head(10, 10, "h1", "m1"), ws)  # entry_count shrank → refused before witnessing


def test_split_view_is_detectable_across_two_actually_witnessed_forks():
    # DRIVE real witnesses: a shared history, then two forks at the same height, each countersigned
    # by a (sub-majority) disjoint quorum — then prove is_split flags them and each quorum verifies.
    ws, root = _witnesses(4)
    tr = root(2)  # 2-of-4 — sub-majority
    old = _cp(10, 10, "h-old")
    for w in ws:
        w.cosign(old)  # shared honest history
    fa = _cp(20, 20, "head-A", prev=checkpoint_hash(old))
    fb = _cp(20, 20, "head-B", prev=checkpoint_hash(old))
    qa = WitnessedCheckpoint(fa, (ws[0].cosign(fa), ws[1].cosign(fa)))   # {w0,w1} see only fork A
    qb = WitnessedCheckpoint(fb, (ws[2].cosign(fb), ws[3].cosign(fb)))   # {w2,w3} see only fork B
    assert verify_witnessed(qa, witness_trust_root=tr) is True           # each quorum is valid...
    assert verify_witnessed(qb, witness_trust_root=tr) is True
    assert is_split(fa, fb) is True                                      # ...and the fork is detectable
    # no witness equivocated: each stateful witness tracked exactly one side
    assert (ws[0]._last.head_hash, ws[2]._last.head_hash) == ("head-A", "head-B")


def test_sub_majority_quorum_is_not_split_view_resistant():
    # the honest contract: at 2m<=n, verify_witnessed passes for two forks but the FULL guarantee
    # (verify_split_view_resistant) is False — the module does not overclaim prevention here.
    ws, root = _witnesses(4)
    tr = root(2)  # 2*2 == 4, NOT > 4 → not strict majority
    old = _cp(10, 10, "h-old")
    for w in ws:
        w.cosign(old)
    fa = _cp(20, 20, "head-A", prev=checkpoint_hash(old))
    qa = WitnessedCheckpoint(fa, (ws[0].cosign(fa), ws[1].cosign(fa)))
    assert is_split_view_resistant(tr) is False
    assert verify_witnessed(qa, witness_trust_root=tr) is True
    assert verify_split_view_resistant(qa, witness_trust_root=tr) is False  # fail-closed on config


def test_strict_majority_forces_an_honest_witness_to_refuse_the_second_fork():
    # the ENFORCED guarantee: at strict majority any second quorum must reuse a witness, and that
    # witness (stateful, honest) REFUSES the conflicting fork — so the operator cannot form it.
    ws, root = _witnesses(3)
    tr = root(2)  # 2*2 == 4 > 3 → strict majority
    assert is_split_view_resistant(tr) is True
    old = _cp(10, 10, "h-old")
    for w in ws:
        w.cosign(old)
    fa = _cp(20, 20, "head-A", prev=checkpoint_hash(old))
    qa = WitnessedCheckpoint(fa, (ws[0].cosign(fa), ws[1].cosign(fa)))
    assert verify_split_view_resistant(qa, witness_trust_root=tr) is True
    fb = _cp(20, 20, "head-B", prev=checkpoint_hash(old))  # a competing fork at the same height
    # any 2-of-3 quorum for fb must include w0, w1, or w2; w0 and w1 already tracked fork A, and w2
    # after tracking fb still needs a second signer — every candidate refuses to equivocate.
    for w in (ws[0], ws[1]):
        with pytest.raises(ConsistencyError):
            w.cosign(fb)  # can't get a second quorum without an equivocation the witness refuses
    # sufficiency: the BEST fb quorum the operator can assemble is w2 alone — below threshold 2, so
    # no valid competing same-height quorum can form (not merely "some witnesses refused").
    best_fb = WitnessedCheckpoint(fb, (ws[2].cosign(fb),))
    assert verify_witnessed(best_fb, witness_trust_root=tr) is False


def test_duplicate_authorizer_key_is_not_split_view_resistant():
    # a shared/duplicate witness PUBLIC KEY defeats quorum intersection: TrustRoot dedups key_ids
    # only, so one operator key registered under two key_ids would forge a 'strict majority' alone.
    # is_split_view_resistant must count DISTINCT KEYS and fail closed on a duplicate.
    shared, other = generate_keypair(), generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=shared.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=shared.public_key_b64),  # SAME key as w0
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=other.public_key_b64)])
    assert is_split_view_resistant(tr) is False  # 2*2 > 3 arithmetically, but a dup key → fail closed
    # the operator's single key signs as BOTH w0 and w1 (distinct key_ids) to "meet" threshold 2...
    old = _cp(10, 10, "h-old")
    fa = _cp(20, 20, "head-A", prev=checkpoint_hash(old))
    wa, wb = Witness("w0", shared.private_key_b64), Witness("w1", shared.private_key_b64)
    q = WitnessedCheckpoint(fa, (wa.cosign(fa), wb.cosign(fa)))
    assert verify_witnessed(q, witness_trust_root=tr) is True            # ...verify_witnessed is fooled
    assert verify_split_view_resistant(q, witness_trust_root=tr) is False  # but the full guarantee is not


def _noncanonical_b64(pubkey_b64):
    """A different base64 STRING that decodes to the SAME Ed25519 key (trailing bits are malleable)."""
    import base64
    raw = base64.b64decode(pubkey_b64, validate=True)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
        cand = pubkey_b64[:-2] + c + "="
        if cand != pubkey_b64 and base64.b64decode(cand, validate=True) == raw:
            return cand
    raise AssertionError("no non-canonical variant found")


def test_encoding_variant_of_one_key_is_not_split_view_resistant():
    # the SAME operator key encoded two DIFFERENT ways (non-canonical base64) must not forge a strict
    # majority — dedup is over the decoded key, not the string. (Byte-identical dup is the easy case;
    # this is the malleable-encoding case a deliberate adversary would use.)
    op, other = generate_keypair(), generate_keypair()
    alt = _noncanonical_b64(op.public_key_b64)
    assert alt != op.public_key_b64  # a genuinely different string...
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=op.public_key_b64),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=alt),          # ...for the SAME key
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=other.public_key_b64)])
    assert is_split_view_resistant(tr) is False  # decoded-key dedup catches the encoding variant
    old = _cp(10, 10, "h-old")
    fa = _cp(20, 20, "head-A", prev=checkpoint_hash(old))
    q = WitnessedCheckpoint(fa, (Witness("w0", op.private_key_b64).cosign(fa),
                                 Witness("w1", op.private_key_b64).cosign(fa)))
    assert verify_witnessed(q, witness_trust_root=tr) is True                # one key signs as w0 & w1
    assert verify_split_view_resistant(q, witness_trust_root=tr) is False     # guarantee fails closed


def test_malformed_authorizer_key_fails_closed():
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64="!!!not-base64!!!")])
    assert is_split_view_resistant(tr) is False  # unparseable key material → cannot reason → fail closed


def test_low_order_witness_key_is_not_split_view_resistant():
    # a low-order Ed25519 point admits a KEYLESS signature forgery — one such key under two key_ids
    # would forge a strict majority. The core rejects low-order keys, so a witness set containing one
    # is not split-view-resistant (fail-closed via IntegrityError from load_public_key).
    import base64
    identity = base64.b64encode((1).to_bytes(32, "little")).decode()
    identity_alt = base64.b64encode((1 | (1 << 255)).to_bytes(32, "little")).decode()  # same point
    real = generate_keypair()
    tr = TrustRoot(threshold=2, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=identity),
        AuthorizerKey(key_id="w1", name="w1", public_key_b64=identity_alt),
        AuthorizerKey(key_id="w2", name="w2", public_key_b64=real.public_key_b64)])
    assert is_split_view_resistant(tr) is False


def test_split_view_resistance_predicate_is_strict_majority():
    _, root = _witnesses(4)
    assert is_split_view_resistant(root(3)) is True     # 6 > 4 — strict majority
    assert is_split_view_resistant(root(2)) is False    # 4 == 4, not strict
    assert is_split_view_resistant(root(1)) is False    # 2 < 4 — the blessed threshold=1 is NOT resistant
    _, solo_root = _witnesses(1)
    assert is_split_view_resistant(solo_root(1)) is True  # 2 > 1 — a lone witness can't be bypassed
