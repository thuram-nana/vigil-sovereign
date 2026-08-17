"""C-S1 — fold ``merkle_root`` into fork detection (make the state-root residual DECIDABLE).

The v1 checkpoint carried a 5-field summary, so a differing ``merkle_root`` at the same ``head_hash`` +
``entry_count`` was un-decidable: an honest re-prune boundary looked identical to a fabricated root, and
``is_split`` had to ignore it. C-S1 commits the prune boundary (``base_seq``/``base_count``) into the
checkpoint's signed identity: at ONE absolute count AND one boundary the leaf set is fixed, so a differing
cumulative root is a FABRICATED root (a fork), while a benign re-prune MOVES the boundary and is still
excluded (no false accusation). The signing bytes changed, so the witness domain is bumped v1->v2.

Covers the spec's negative controls:
  * #7  no-op fidelity: base_*=0 everywhere reproduces the pre-C-S1 head-fork verdicts byte-for-byte.
  * #8  benign re-prune (moved boundary) is NOT a fork; same-boundary different-root IS.
  * #9  v1<->v2 signature non-confusion: a v1 witness signature never verifies under v2, and vice-versa.

Run: PYTHONPATH=integration:gateway pytest integration/tests/test_transparency_rootfork.py -q
"""
from __future__ import annotations

from vigil_core import (
    AuthorizerKey,
    Signature,
    TrustRoot,
    canonical_json,
    generate_keypair,
    sign,
    verify_one,
)
from vigil_integration.transparency import (
    GENESIS_LINK,
    Checkpoint,
    MultiSegmentCheckpoint,
    MultiWitnessedCheckpoint,
    Witness,
    WitnessedCheckpoint,
    _MULTI_MARK,
    _WITNESS_DOMAIN,
    _multi_signing_bytes,
    _signing_bytes,
    checkpoint_hash,
    consistent,
    is_multi_split,
    is_split,
    multi_checkpoint_hash,
    multi_consistent,
    verify_witnessed,
    verify_witnessed_multi,
)


def _cp(last_seq, entry_count, head_hash, *, merkle=None, base_seq=0, base_count=0, prev=GENESIS_LINK):
    return Checkpoint(last_seq=last_seq, entry_count=entry_count, head_hash=head_hash,
                      merkle_root=merkle if merkle is not None else f"m{entry_count}",
                      base_seq=base_seq, base_count=base_count, prev_checkpoint_hash=prev)


# ----------------------------------------------------------------------------- risk #7: no-op fidelity ----
def test_noop_fidelity_matches_the_pre_cs1_head_only_verdict():
    """With base_*=0 everywhere (the pre-C-S1 world), ``is_split`` reproduces the OLD head-only rule for
    every case it could decide: head-forks still caught, identical checkpoints still not a fork, different
    heights never a fork. Verdicts are checked against a hand-computed baseline."""
    def old_is_split(a: Checkpoint, b: Checkpoint) -> bool:   # the verbatim pre-C-S1 rule
        return a.entry_count == b.entry_count and a.head_hash != b.head_hash

    cases = [
        (_cp(10, 10, "h0"), _cp(10, 10, "h0")),      # identical → no fork
        (_cp(10, 10, "h0"), _cp(10, 10, "h1")),      # same height, different head → fork
        (_cp(20, 20, "h1"), _cp(10, 10, "h0")),      # different height → no fork
        (_cp(10, 10, "h0"), _cp(20, 20, "h0")),      # different height, same head → no fork
    ]
    for a, b in cases:
        assert is_split(a, b) == old_is_split(a, b)


def test_noop_fidelity_base0_append_only_chain_still_consistent():
    """A base_*=0 append-only chain's ``consistent`` verdicts are unchanged: a genuine extension passes,
    a shrink and a same-height head-fork still fail with their original reasons."""
    a = _cp(10, 10, "h0")
    b = _cp(20, 20, "h1", prev=checkpoint_hash(a))
    assert consistent(a, b)[0] is True
    ok, why = consistent(a, _cp(5, 5, "h-old", prev=checkpoint_hash(a)))
    assert not ok and "shrank" in why
    ok, why = consistent(a, _cp(10, 10, "h0-fork", prev=checkpoint_hash(a)))
    assert not ok and "split view" in why


# --------------------------------------------------------------- risk #8: re-prune vs fabricated root -----
def test_benign_reprune_moved_boundary_is_not_a_fork():
    """Same live tip (head_hash, entry_count) but a MOVED prune boundary (base_* grow) as merkle advances —
    a legitimate re-prune. It is EXCLUDED (no false accusation), exactly like the old head-only key."""
    a = _cp(100, 100, "head-X", merkle="m-before", base_seq=0, base_count=0)
    b = _cp(100, 100, "head-X", merkle="m-after", base_seq=40, base_count=40)
    assert is_split(a, b) is False


def test_same_boundary_different_root_is_a_fork():
    """Same absolute count AND same prune boundary ⇒ the leaf set is fixed ⇒ a differing cumulative root is
    a FABRICATED root (a genuine fork), now caught."""
    a = _cp(100, 100, "head-X", merkle="m-real", base_seq=10, base_count=10)
    forged = _cp(100, 100, "head-X", merkle="m-FABRICATED", base_seq=10, base_count=10)
    assert is_split(a, forged) is True


def test_head_fork_still_dominates_regardless_of_boundary():
    """A different head at the same height is a fork whether or not the boundary matches (head_hash is the
    authoritative fork commitment)."""
    a = _cp(50, 50, "head-A", base_seq=5, base_count=5)
    b = _cp(50, 50, "head-B", base_seq=7, base_count=7)   # different boundary AND different head
    assert is_split(a, b) is True


def test_consistent_flags_same_boundary_root_fork():
    a = _cp(10, 10, "H", merkle="m-real", base_seq=2, base_count=2)
    b = _cp(10, 10, "H", merkle="m-fake", base_seq=2, base_count=2, prev=checkpoint_hash(a))
    ok, why = consistent(a, b)
    assert not ok and "fabricated root" in why


def test_consistent_accepts_a_reprune_at_the_same_tip():
    """A re-prune advances base_*+merkle at an unchanged live tip; monotonic, not a rollback, not a fork —
    a valid append-only extension (the boundary MOVED, so the root-fork clause does not fire)."""
    a = _cp(10, 10, "H", merkle="m1", base_seq=0, base_count=0)
    b = _cp(10, 10, "H", merkle="m2", base_seq=3, base_count=3, prev=checkpoint_hash(a))
    assert consistent(a, b)[0] is True


def test_consistent_rejects_base_seq_shrink_as_unprune():
    a = _cp(20, 20, "H", base_seq=10, base_count=10)
    b = _cp(25, 25, "H2", base_seq=5, base_count=10, prev=checkpoint_hash(a))   # base_seq rolled back
    ok, why = consistent(a, b)
    assert not ok and "base_seq" in why


def test_consistent_rejects_base_count_shrink_as_unprune():
    a = _cp(20, 20, "H", base_seq=10, base_count=10)
    b = _cp(25, 25, "H2", base_seq=10, base_count=5, prev=checkpoint_hash(a))   # base_count rolled back
    ok, why = consistent(a, b)
    assert not ok and "base_count" in why


# ------------------------------------------------------- risk #9: v1<->v2 signature non-confusion ---------
_V1_DOMAIN = b"vigil-transparency-checkpoint-v1\x00"


def _v1_signing_bytes(cp: Checkpoint) -> bytes:
    """The EXACT bytes a v1 witness signed: the OLD 5-field summary (no base_*) under the OLD domain."""
    d = {"last_seq": cp.last_seq, "entry_count": cp.entry_count, "head_hash": cp.head_hash,
         "merkle_root": cp.merkle_root, "prev_checkpoint_hash": cp.prev_checkpoint_hash}
    return _V1_DOMAIN + canonical_json(d)


def test_wire_format_is_v2():
    assert _WITNESS_DOMAIN == b"vigil-transparency-checkpoint-v2\x00"
    assert _MULTI_MARK.endswith(".v2")
    cp = _cp(1, 1, "h")
    assert _signing_bytes(cp).startswith(b"vigil-transparency-checkpoint-v2\x00")
    mc = MultiSegmentCheckpoint(segments={"s": cp})
    assert _multi_signing_bytes(mc).startswith(b"vigil-transparency-checkpoint-v2\x00")


def test_v1_witness_signature_does_not_verify_under_v2():
    W = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W.public_key_b64)])
    cp = _cp(10, 10, "h0")

    # a genuine v2 co-signature (what the running witness now produces) verifies under v2...
    v2_sig = Witness("w0", W.private_key_b64).cosign(cp)
    assert verify_witnessed(WitnessedCheckpoint(cp, (v2_sig,)), witness_trust_root=tr) is True

    # ...but a v1 signature over the same logical checkpoint is REFUSED under v2 (anti-replay rotation).
    v1_sig = Signature(key_id="w0", signature_b64=sign(W.private_key_b64, _v1_signing_bytes(cp)))
    assert verify_witnessed(WitnessedCheckpoint(cp, (v1_sig,)), witness_trust_root=tr) is False

    # ...and the v2 signature does NOT verify as a v1 signature (the reverse direction).
    assert verify_one(W.public_key_b64, _v1_signing_bytes(cp), v2_sig.signature_b64) is False
    # sanity: the v1 signature IS a valid signature over its own v1 bytes (so the refusal is domain, not key)
    assert verify_one(W.public_key_b64, _v1_signing_bytes(cp), v1_sig.signature_b64) is True


# ------------------------------------------------------------------- multi-segment mirror (spec: mirror) --
def test_is_multi_split_detects_same_boundary_root_fork():
    seg_a = _cp(10, 10, "H", merkle="m-real", base_seq=2, base_count=2)
    seg_b = _cp(10, 10, "H", merkle="m-fake", base_seq=2, base_count=2)   # same tip+boundary, forged root
    a = MultiSegmentCheckpoint(segments={"sovereign-spine": seg_a})
    b = MultiSegmentCheckpoint(segments={"sovereign-spine": seg_b})
    assert is_multi_split(a, b) is True


def test_multi_consistent_excludes_a_reprune_but_flags_a_forged_root():
    base = MultiSegmentCheckpoint(segments={"s": _cp(10, 10, "H", merkle="m1", base_seq=0, base_count=0)})
    # a re-prune in the segment (boundary moved) is a valid composite extension
    reprune = MultiSegmentCheckpoint(
        segments={"s": _cp(10, 10, "H", merkle="m2", base_seq=4, base_count=4)},
        prev_checkpoint_hash=multi_checkpoint_hash(base))
    assert multi_consistent(base, reprune)[0] is True
    # a forged root at the SAME boundary breaks the composite
    forged = MultiSegmentCheckpoint(
        segments={"s": _cp(10, 10, "H", merkle="m-fake", base_seq=0, base_count=0)},
        prev_checkpoint_hash=multi_checkpoint_hash(base))
    ok, why = multi_consistent(base, forged)
    assert not ok and "fabricated root" in why


def test_v1_multi_signature_does_not_verify_under_v2():
    W = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="w0", name="w0", public_key_b64=W.public_key_b64)])
    mc = MultiSegmentCheckpoint(segments={"s": _cp(10, 10, "h0")})
    v2_sig = Witness("w0", W.private_key_b64).cosign_multi(mc)
    assert verify_witnessed_multi(MultiWitnessedCheckpoint(mc, (v2_sig,)), witness_trust_root=tr) is True
    # a signature made under the OLD .v1 marker cannot verify under the .v2 composite bytes
    v1_marker_bytes = _V1_DOMAIN + canonical_json({
        "type": "vigil.multi-segment-checkpoint.v1",
        "segments": {"s": mc.segments["s"].to_dict()},
        "prev_checkpoint_hash": mc.prev_checkpoint_hash,
    })
    v1_sig = Signature(key_id="w0", signature_b64=sign(W.private_key_b64, v1_marker_bytes))
    assert verify_witnessed_multi(MultiWitnessedCheckpoint(mc, (v1_sig,)), witness_trust_root=tr) is False
