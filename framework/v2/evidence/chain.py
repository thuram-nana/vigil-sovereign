"""
evidence.chain — a tamper-evident, hash-linked evidence log.

Signed certificates prove each finding is authentic; a hash chain proves the SET of
findings was not silently pruned, reordered, or back-dated. Each `ChainEntry` hashes
`(seq, prev_hash, cert_digest)`, linking to its predecessor, so removing or reordering
any certificate breaks the chain at recomputation. A `SignedChainHead` — the last
entry's hash, its `last_seq`, and the entry count, signed by the governance trust root —
anchors the whole log; rewriting history requires forging a governance signature, and a
shrunk/back-dated head is caught by the monotonic `last_seq` anti-rollback check (the
same defence the revocation high-water mark uses).

Deterministic and append-only. Signing the head is provisioning; the runtime verifies.
"""

from __future__ import annotations

from ..entitlement.crypto import sign, verify_threshold
from ..entitlement.models import Signature, TrustRoot
from .canonical import canonical_json, evidence_signing_bytes, sha256_hex
from .models import _GENESIS_PREV, ChainEntry, SignedChainHead


def _entry_hash(seq: int, prev_hash: str, cert_digest: str) -> str:
    return sha256_hex(canonical_json(
        {"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))


def build_chain(cert_digests: list[str], *, start_seq: int = 0) -> list[ChainEntry]:
    """Build the hash chain over an ordered list of certificate digests."""
    entries: list[ChainEntry] = []
    prev = _GENESIS_PREV
    for i, cd in enumerate(cert_digests):
        seq = start_seq + i
        eh = _entry_hash(seq, prev, cd)
        entries.append(ChainEntry(seq=seq, prev_hash=prev, cert_digest=cd, entry_hash=eh))
        prev = eh
    return entries


def append_entry(entries: list[ChainEntry], cert_digest: str) -> ChainEntry:
    """The next link after ``entries`` for ``cert_digest`` (append-only)."""
    prev = entries[-1].entry_hash if entries else _GENESIS_PREV
    seq = (entries[-1].seq + 1) if entries else 0
    return ChainEntry(seq=seq, prev_hash=prev, cert_digest=cert_digest,
                      entry_hash=_entry_hash(seq, prev, cert_digest))


def verify_chain(entries: list[ChainEntry]) -> tuple[bool, str]:
    """Recompute every link and the seq continuity. False (with the break location) if
    any entry was altered, deleted, or reordered."""
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
    # everything the head asserts EXCEPT its own signatures
    d = head.model_dump(mode="json")
    d.pop("signatures", None)
    return d


def sign_head(entries: list[ChainEntry], *, engagement_slug: str,
              signers: list[tuple[str, str]]) -> SignedChainHead:
    """Anchor the chain with a governance-signed head (PROVISIONING ONLY)."""
    head_hash = entries[-1].entry_hash if entries else _GENESIS_PREV
    last_seq = entries[-1].seq if entries else 0
    head = SignedChainHead(engagement_slug=engagement_slug, last_seq=last_seq,
                           entry_count=len(entries), head_hash=head_hash)
    msg = evidence_signing_bytes(_head_payload(head))
    sigs = [Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers]
    return head.model_copy(update={"signatures": sigs})


def verify_head(
    head: SignedChainHead,
    entries: list[ChainEntry],
    trust_root: TrustRoot,
    *,
    prev_highwater: int | None = None,
) -> tuple[bool, str]:
    """Verify the chain links, that the head matches the chain, that its signature meets
    the governance threshold, and that it does not roll back below ``prev_highwater``."""
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
        return False, (f"rollback rejected: head last_seq {head.last_seq} < "
                       f"accepted high-water {prev_highwater}")

    return True, f"chain of {len(entries)} entr{'y' if len(entries)==1 else 'ies'} anchored by a valid signed head"
