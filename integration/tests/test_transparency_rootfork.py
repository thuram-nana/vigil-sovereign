"""C-S1 — commit the prune boundary into the witnessed checkpoint identity (state-root residual).

C-S1 adds ``base_seq``/``base_count`` (the head's PRUNE BOUNDARY) to the witnessed ``Checkpoint``. This is
sound and useful for TWO reasons: (1) a witness quorum now attests the prune boundary, not just the head; and
(2) a checkpoint CHAIN can reject an UN-prune — a boundary that moves BACKWARDS = an older-snapshot replay —
via a monotonic guard in ``consistent``/``_segment_extends``. The signing bytes changed, so the witness domain
is rotated v1->v2 (a v1 signature can never verify under v2, anti-replay).

It does NOT make the cumulative ``merkle_root`` a fork signal. The root is a left-FOLD over the operator-chosen
prune SCHEDULE (``chain_cumulative = H("C:" ‖ prior ‖ "|" ‖ delta)``, folded once per prune batch), NOT a
canonical function of the leaf set — so two HONEST heads that pruned the SAME records to the SAME boundary on
different cadences legitimately carry DIFFERENT cumulative roots. ``head_hash`` hash-links the entire ordered
entry chain and is schedule-INVARIANT, so it remains the sole SOUND fork commitment (exactly as in v1). Keying
fork detection on the root would FALSE-ACCUSE an honest re-prune; ``is_split`` deliberately does not (ADR 0006).

Covers the spec's negative controls, corrected for that soundness fact:
  * #7  no-op fidelity: base_*=0 everywhere reproduces the pre-C-S1 head-fork verdicts byte-for-byte.
  * #8  SOUNDNESS: an honest re-prune — whether the boundary MOVED or the SAME boundary was reached by a
        different SCHEDULE (different cumulative root) — is NEVER a fork. Only a differing ``head_hash`` is.
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
    sha256_hex,
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

# A FAITHFUL copy of apps/sigil/sigil/spine/merkle.chain_cumulative — the running prune accumulator step. Kept
# local (not imported) because that module is sovereign-plane and this suite runs in the offense CI leg; the
# formula is what makes the cumulative root SCHEDULE-DEPENDENT, which is the whole point of the soundness test.
_ACC = "C:"


def _chain_cumulative(prior_cumulative: str, delta_root: str) -> str:
    return sha256_hex((_ACC + prior_cumulative + "|" + delta_root).encode("utf-8"))


def _cp(last_seq, entry_count, head_hash, *, merkle=None, base_seq=0, base_count=0, prev=GENESIS_LINK):
    return Checkpoint(last_seq=last_seq, entry_count=entry_count, head_hash=head_hash,
                      merkle_root=merkle if merkle is not None else f"m{entry_count}",
                      base_seq=base_seq, base_count=base_count, prev_checkpoint_hash=prev)


# ----------------------------------------------------------------------------- risk #7: no-op fidelity ----
def test_noop_fidelity_matches_the_pre_cs1_head_only_verdict():
    """With base_*=0 everywhere (the pre-C-S1 world), ``is_split`` reproduces the OLD head-only rule for
    every case: head-forks still caught, identical checkpoints still not a fork, different heights never a
    fork. Verdicts are checked against a hand-computed baseline."""
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


# ---------------------------------------------- risk #8 (SOUNDNESS): an honest re-prune is never a fork ----
def test_benign_reprune_moved_boundary_is_not_a_fork():
    """Same live tip (head_hash, entry_count) but a MOVED prune boundary (base_* grow) as merkle advances —
    a legitimate re-prune. It is NOT a fork (head_hash is unchanged)."""
    a = _cp(100, 100, "head-X", merkle="m-before", base_seq=0, base_count=0)
    b = _cp(100, 100, "head-X", merkle="m-after", base_seq=40, base_count=40)
    assert is_split(a, b) is False


def test_same_boundary_different_prune_schedule_is_not_a_fork():
    """SOUNDNESS regression (the C-S1 red-pen finding). The cumulative ``merkle_root`` is a left-FOLD over the
    operator-chosen prune SCHEDULE, NOT a canonical function of the leaf set. Two HONEST heads that pruned the
    SAME records [0..40) to the SAME boundary (base_count=40) on DIFFERENT cadences carry DIFFERENT cumulative
    roots. ``is_split`` MUST NOT brand that an equivocation — else it false-accuses an honest re-prune."""
    # schedule A: prune [0..40) in ONE batch. schedule B: prune [0..20) then [20..40). Same leaf set, same
    # final boundary; the accumulator FOLD structure differs, so the cumulative roots genuinely differ.
    root_A = _chain_cumulative("", "delta[0..40)")
    root_B = _chain_cumulative(_chain_cumulative("", "delta[0..20)"), "delta[20..40)")
    assert root_A != root_B, "sanity: two honest schedules genuinely differ (else this proves nothing)"

    a = _cp(100, 100, "head-X", merkle=root_A, base_seq=40, base_count=40)
    b = _cp(100, 100, "head-X", merkle=root_B, base_seq=40, base_count=40)
    assert is_split(a, b) is False                          # same tip + same boundary + honest root variance
    # and a chain-linked consecutive pair with identical content is a VALID extension, not a "fabricated root"
    b_linked = _cp(100, 100, "head-X", merkle=root_B, base_seq=40, base_count=40, prev=checkpoint_hash(a))
    assert consistent(a, b_linked)[0] is True


def test_head_fork_still_dominates_regardless_of_boundary():
    """A different head at the same height IS a fork whether or not the boundary matches — ``head_hash`` is the
    authoritative, schedule-invariant fork commitment."""
    a = _cp(50, 50, "head-A", base_seq=5, base_count=5)
    b = _cp(50, 50, "head-B", base_seq=7, base_count=7)   # different head (and boundary)
    assert is_split(a, b) is True


def test_consistent_accepts_a_reprune_at_the_same_tip():
    """A re-prune advances base_*+merkle at an unchanged live tip; monotonic, not a rollback, not a fork —
    a valid append-only extension. The schedule-dependent root difference is NOT adjudicated."""
    a = _cp(10, 10, "H", merkle="m1", base_seq=0, base_count=0)
    b = _cp(10, 10, "H", merkle="m2", base_seq=3, base_count=3, prev=checkpoint_hash(a))
    assert consistent(a, b)[0] is True


# ------------------------------------- the UN-prune monotonic guard (the SOUND anti-rollback C-S1 adds) ----
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
def test_is_multi_split_does_not_flag_same_boundary_schedule_variance():
    """The composite mirror inherits the SOUND rule: same tip + same boundary + honest root variance in a
    segment is NOT a fork (only a differing segment ``head_hash`` is)."""
    seg_a = _cp(10, 10, "H", merkle=_chain_cumulative("", "dA"), base_seq=2, base_count=2)
    seg_b = _cp(10, 10, "H", merkle=_chain_cumulative(_chain_cumulative("", "dA1"), "dA2"),
                base_seq=2, base_count=2)                     # same tip+boundary, honest schedule variance
    a = MultiSegmentCheckpoint(segments={"sovereign-spine": seg_a})
    b = MultiSegmentCheckpoint(segments={"sovereign-spine": seg_b})
    assert is_multi_split(a, b) is False
    # but a genuine per-segment HEAD fork IS caught
    seg_c = _cp(10, 10, "H-FORK", base_seq=2, base_count=2)
    c = MultiSegmentCheckpoint(segments={"sovereign-spine": seg_c})
    assert is_multi_split(a, c) is True


def test_multi_consistent_accepts_a_reprune_and_schedule_variance():
    base = MultiSegmentCheckpoint(segments={"s": _cp(10, 10, "H", merkle="m1", base_seq=0, base_count=0)})
    # a re-prune in the segment (boundary moved) is a valid composite extension
    reprune = MultiSegmentCheckpoint(
        segments={"s": _cp(10, 10, "H", merkle="m2", base_seq=4, base_count=4)},
        prev_checkpoint_hash=multi_checkpoint_hash(base))
    assert multi_consistent(base, reprune)[0] is True
    # same boundary + different (honest-schedule) root is ALSO a valid extension, not a fork
    variance = MultiSegmentCheckpoint(
        segments={"s": _cp(10, 10, "H", merkle="m-other-schedule", base_seq=0, base_count=0)},
        prev_checkpoint_hash=multi_checkpoint_hash(base))
    assert multi_consistent(base, variance)[0] is True
    # but a per-segment HEAD fork DOES break the composite
    headfork = MultiSegmentCheckpoint(
        segments={"s": _cp(10, 10, "H-FORK", merkle="m1", base_seq=0, base_count=0)},
        prev_checkpoint_hash=multi_checkpoint_hash(base))
    ok, why = multi_consistent(base, headfork)
    assert not ok and "split view" in why


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
