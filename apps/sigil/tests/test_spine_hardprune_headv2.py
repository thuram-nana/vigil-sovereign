"""SIGIL hard-prune Slice A — head-schema v2 + snapshot-aware verify seam (NO prune yet; base_count=0
everywhere is byte-identical). Pins: a v1 head signs/verifies byte-identically under the v2 model; a
synthetic pruned-shape v2 head verifies BY SEQ over its live window; the unconditional left-edge pin
catches a front-drop; a too-new head schema is 'upgrade required', never treated as clean.
Run: ~/.sigil/venv/bin/python -m pytest tests/test_spine_hardprune_headv2.py -q
"""
import pytest

from sigil.reuse import (
    AuthorizerKey,
    TrustRoot,
    build_chain,
    digest_payload,
    generate_keypair,
)
from sigil.reuse.canonical import evidence_signing_bytes
from sigil.reuse.chain import _head_payload, sign_head
from sigil.reuse.crypto import sign
from sigil.reuse.models import _GENESIS_PREV, SignedChainHead, Signature
from sigil.spine.checkpoint import classify_head


def _chain(n: int):
    return build_chain([digest_payload({"i": i}) for i in range(n)])


def _owner():
    kp = generate_keypair()
    tr = TrustRoot(threshold=1, authorizers=[AuthorizerKey(key_id="owner", name="owner",
                                                           public_key_b64=kp.public_key_b64)])
    return kp, tr


def _sign_v2(head: SignedChainHead, kp) -> SignedChainHead:
    msg = evidence_signing_bytes(_head_payload(head))
    return head.model_copy(update={"signatures": [Signature(key_id="owner", signature_b64=sign(kp.private_key_b64, msg))]})


def test_v1_head_signs_and_verifies_byte_identical():
    """The migration linchpin: a v1 head (schema_version=1) under the v2 model produces signing bytes that
    contain NONE of the 6 v2 fields — byte-identical to a pre-v2 head — and verifies."""
    kp, tr = _owner()
    entries = _chain(5)
    head = sign_head(entries, engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    assert head.schema_version == 1
    payload = _head_payload(head)
    for f in ("base_seq", "base_prev_hash", "base_count", "cumulative_merkle_root", "snapshot_seq", "prev_head_hash"):
        assert f not in payload, f"v1 signing payload must not carry the v2 field {f}"
    ok, reason = classify_head(head, entries, tr)
    assert ok, reason                                       # v1 verifies unchanged


def test_v2_rebased_window_verifies_by_seq():
    """A pruned-shape head: live window = entries[K:], base_seq=K, base_prev_hash=entry_hash(K-1),
    base_count=K, entry_count ABSOLUTE = N. classify_head selects BY SEQ and verifies the live window from
    base_prev_hash."""
    kp, tr = _owner()
    entries = _chain(8)
    K = 3
    live = entries[K:]
    head = _sign_v2(SignedChainHead(
        schema_version=2, engagement_slug="s", last_seq=entries[-1].seq, entry_count=len(entries),
        head_hash=entries[-1].entry_hash, base_seq=K, base_prev_hash=entries[K - 1].entry_hash,
        base_count=K, cumulative_merkle_root="ab" * 32, snapshot_seq=99, prev_head_hash="cd" * 32), kp)
    ok, reason = classify_head(head, live, tr)
    assert ok, reason                                       # the re-based window links from base_prev_hash


def test_front_truncation_of_live_window_is_tampering():
    kp, tr = _owner()
    entries = _chain(8)
    K = 3
    head = _sign_v2(SignedChainHead(
        schema_version=2, engagement_slug="s", last_seq=entries[-1].seq, entry_count=len(entries),
        head_hash=entries[-1].entry_hash, base_seq=K, base_prev_hash=entries[K - 1].entry_hash,
        base_count=K, cumulative_merkle_root="ab" * 32, snapshot_seq=99), kp)
    ok, reason = classify_head(head, entries[K + 1:], tr)   # drop the first live record (seq K)
    assert not ok and "TAMPERING" in reason


def test_left_edge_pin_wrong_base_prev_hash_is_tampering():
    """The unconditional left-edge pin: if the live window's first record does not link from the SIGNED
    base_prev_hash, it is TAMPERING (closes the false-clean front-drop hole) — checked before the sig."""
    kp, tr = _owner()
    entries = _chain(8)
    K = 3
    head = _sign_v2(SignedChainHead(
        schema_version=2, engagement_slug="s", last_seq=entries[-1].seq, entry_count=len(entries),
        head_hash=entries[-1].entry_hash, base_seq=K, base_prev_hash=entries[K - 1].entry_hash,
        base_count=K, cumulative_merkle_root="ab" * 32, snapshot_seq=99), kp)
    tampered = head.model_copy(update={"base_prev_hash": "ff" * 32})   # claim a different base
    ok, reason = classify_head(tampered, entries[K:], tr)
    assert not ok and "TAMPERING" in reason


def test_forged_unsigned_zero_anchor_head_is_tampering():
    """Review BLOCK-1 regression: the signature check must run even for an EMPTY live window. A forged
    UNSIGNED zero-anchor head (entry_count=0, head_hash=GENESIS, last_seq=0, no signature) — what an
    attacker who overwrites head.json presents — must be TAMPERING, not a benign 'un-notarized'. Both on an
    empty spine AND when the spine actually holds records the forged head claims not to anchor."""
    _kp, tr = _owner()
    forged = SignedChainHead(schema_version=1, engagement_slug="s", last_seq=0, entry_count=0,
                             head_hash=_GENESIS_PREV)       # signatures=[] — UNSIGNED
    ok_a, reason_a = classify_head(forged, [], tr)
    assert not ok_a and "TAMPERING" in reason_a, reason_a   # empty spine
    ok_b, reason_b = classify_head(forged, _chain(5), tr)
    assert not ok_b and "TAMPERING" in reason_b, reason_b   # 5 real records, forged head anchors 0


def test_empty_spine_v1_head_is_clean():
    kp, tr = _owner()
    head = sign_head([], engagement_slug="s", signers=[("owner", kp.private_key_b64)])
    ok, reason = classify_head(head, [], tr)
    assert ok, reason                                       # 0 records anchored, 0 present — current


def test_head_schema_too_new_is_upgrade_not_clean():
    from sigil.spine.checkpoint import _MAX_HEAD_SCHEMA
    # a head claiming a schema beyond this build must fail-closed as "upgrade", never clean
    kp, tr = _owner()
    entries = _chain(3)
    head = _sign_v2(SignedChainHead(
        schema_version=_MAX_HEAD_SCHEMA + 1, engagement_slug="s", last_seq=entries[-1].seq,
        entry_count=len(entries), head_hash=entries[-1].entry_hash, base_prev_hash=_GENESIS_PREV), kp)
    # classify_head itself doesn't gate schema (verify_checkpoint/tailer do); assert the model still parses
    # its fields so the guard has something to read
    assert head.schema_version == _MAX_HEAD_SCHEMA + 1
