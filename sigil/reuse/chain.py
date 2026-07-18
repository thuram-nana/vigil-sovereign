"""Tamper-evident, hash-linked spine chain.

VENDORED VERBATIM from CRUCIBLE `framework/v2/evidence/chain.py` (owner's own work).
Each `ChainEntry` hashes (seq, prev_hash, cert_digest); a `SignedChainHead` anchors the
whole log with a monotonic `last_seq` anti-rollback. Deterministic + append-only; signing
the head is provisioning, the runtime verifies. Only the imports are localised.
"""
from __future__ import annotations

from .canonical import canonical_json, evidence_signing_bytes, sha256_hex
from .crypto import sign, verify_threshold
from .models import _GENESIS_PREV, ChainEntry, Signature, SignedChainHead, TrustRoot


def _entry_hash(seq: int, prev_hash: str, cert_digest: str) -> str:
    return sha256_hex(canonical_json({"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))


def build_chain(cert_digests: list[str], *, start_seq: int = 0) -> list[ChainEntry]:
    entries: list[ChainEntry] = []
    prev = _GENESIS_PREV
    for i, cd in enumerate(cert_digests):
        seq = start_seq + i
        eh = _entry_hash(seq, prev, cd)
        entries.append(ChainEntry(seq=seq, prev_hash=prev, cert_digest=cd, entry_hash=eh))
        prev = eh
    return entries


def append_entry(entries: list[ChainEntry], cert_digest: str) -> ChainEntry:
    prev = entries[-1].entry_hash if entries else _GENESIS_PREV
    seq = (entries[-1].seq + 1) if entries else 0
    return ChainEntry(seq=seq, prev_hash=prev, cert_digest=cert_digest,
                      entry_hash=_entry_hash(seq, prev, cert_digest))


def verify_chain(entries: list[ChainEntry]) -> tuple[bool, str]:
    prev = _GENESIS_PREV
    for i, e in enumerate(entries):
        if e.prev_hash != prev:
            return False, f"chain break at seq {e.seq}: prev_hash mismatch (entry deleted/reordered)"
        if e.entry_hash != _entry_hash(e.seq, e.prev_hash, e.cert_digest):
            return False, f"chain break at seq {e.seq}: entry_hash mismatch (entry tampered)"
        if i > 0 and e.seq != entries[i - 1].seq + 1:
            return False, f"chain break: seq gap at {e.seq}"
        prev = e.entry_hash
    return True, f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} link cleanly"


def _head_payload(head: SignedChainHead) -> dict:
    d = head.model_dump(mode="json")
    d.pop("signatures", None)
    return d


def sign_head(entries: list[ChainEntry], *, engagement_slug: str, signers: list[tuple[str, str]]) -> SignedChainHead:
    head_hash = entries[-1].entry_hash if entries else _GENESIS_PREV
    last_seq = entries[-1].seq if entries else 0
    head = SignedChainHead(engagement_slug=engagement_slug, last_seq=last_seq,
                           entry_count=len(entries), head_hash=head_hash)
    msg = evidence_signing_bytes(_head_payload(head))
    sigs = [Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers]
    return head.model_copy(update={"signatures": sigs})


def verify_head(head: SignedChainHead, entries: list[ChainEntry], trust_root: TrustRoot,
                *, prev_highwater: int | None = None) -> tuple[bool, str]:
    ok_chain, reason = verify_chain(entries)
    if not ok_chain:
        return False, reason
    exp_hash = entries[-1].entry_hash if entries else _GENESIS_PREV
    exp_seq = entries[-1].seq if entries else 0
    if head.head_hash != exp_hash or head.last_seq != exp_seq or head.entry_count != len(entries):
        return False, "head does not match the chain (log truncated or head rewritten)"
    thr = verify_threshold(evidence_signing_bytes(_head_payload(head)), head.signatures, trust_root)
    if not thr.satisfied:
        return False, f"head signature invalid: {thr.reason}"
    if prev_highwater is not None and head.last_seq < prev_highwater:
        return False, f"rollback rejected: head last_seq {head.last_seq} < accepted high-water {prev_highwater}"
    return True, f"chain of {len(entries)} entr{'y' if len(entries)==1 else 'ies'} anchored by a valid signed head"
