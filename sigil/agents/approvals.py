"""Approval queue (SIGIL §5, §9.3 mobile bridge) — the human gate for A2/A3 proposals. An agent
QUEUES a proposal (governor → QUEUE); the owner APPROVES or DENIES it here. Authentication is an
Ed25519 signature over the canonical (target, decision, approver) by the OWNER key — the same
"signed confirmation" §5 requires for A3, which is HARD-required for A3 targets (an id-only tap
cannot approve a destructive action). The decision is an append-only event that SUPERSEDES the
queued record, so `pending()` stops listing it and the audit log shows who decided and how.

This records the DECISION; it does not itself execute an external effect — SIGIL still has no
send/deploy path (the structural doctrine). Approving marks the item actioned for a human/execution
layer. The transport (Telegram/WhatsApp over WireGuard, §9.3) is a seam: any channel that carries the
seq + a signed approve/deny reaches this same authenticated core. Offense-free (assert_no_offense)."""
from __future__ import annotations

from typing import List, Optional

from ..reuse import KeyPair, canonical_json, sha256_hex, sign, verify_one
from ..spine.store import SpineStore

SIGNAL = "governor.approval"
_QUEUED_STATUS = "awaiting-approval"


def _approval_message(target_seq: int, decision: str, approver: str) -> bytes:
    m = canonical_json({"target": target_seq, "decision": decision, "approver": approver})
    return m if isinstance(m, bytes) else m.encode()


def pending(store: SpineStore) -> List:
    """Queued proposals not yet approved/denied, oldest first. A later approval event that supersedes
    a queued seq removes it from the queue."""
    resolved = set()
    queued = {}
    for r in store.iter_records():
        p = r.payload
        if p.get("signal") == SIGNAL and r.supersedes_id is not None:
            resolved.add(r.supersedes_id)
        if p.get("decision") == "queued" and p.get("status") == _QUEUED_STATUS:
            queued[r.seq] = r
    return [r for seq, r in sorted(queued.items()) if seq not in resolved]


class ApprovalError(Exception):
    pass


class ApprovalQueue:
    def __init__(self, store: Optional[SpineStore] = None, *, owner_key: Optional[KeyPair] = None,
                 trusted_pubkey_b64: Optional[str] = None):
        self.store = store or SpineStore()
        self.owner_key = owner_key
        # the pubkey approvals are verified against; defaults to the owner key's own pubkey
        self.trusted_pubkey_b64 = trusted_pubkey_b64 or (owner_key.public_key_b64 if owner_key else None)

    def _target(self, seq: int):
        for r in pending(self.store):
            if r.seq == seq:
                return r
        raise ApprovalError(f"seq {seq} is not a pending approval (already decided, or not queued)")

    def _decide(self, seq: int, decision: str, *, approver: str, reason: str = "") -> int:
        target = self._target(seq)
        tier = target.payload.get("tier")
        # A3 (destructive/financial/security) requires a real signed confirmation — no id-only taps.
        if tier == "A3" and self.owner_key is None:
            raise ApprovalError("A3 approval requires a signed confirmation (owner key), not an id-only tap")
        msg = _approval_message(seq, decision, approver)
        sig = sign(self.owner_key.private_key_b64, msg) if self.owner_key else None
        payload = {"signal": SIGNAL, "approval": decision, "target_seq": seq, "target_kind": target.kind,
                   "target_tier": tier, "approver": approver, "reason": reason,
                   "pubkey": self.trusted_pubkey_b64, "sig": sig,
                   "msg_digest": sha256_hex(msg), "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="OWNER",
                                 payload=payload, supersedes_id=seq)

    def approve(self, seq: int, *, approver: str = "owner", reason: str = "") -> int:
        return self._decide(seq, "approved", approver=approver, reason=reason)

    def deny(self, seq: int, *, approver: str = "owner", reason: str = "") -> int:
        return self._decide(seq, "denied", approver=approver, reason=reason)


def verify_approval(record, trusted_pubkey_b64: str) -> bool:
    """True iff an approval record carries a valid owner signature over its (target, decision, approver).
    An unsigned approval never verifies against a trusted key (fail-closed)."""
    p = record.payload if hasattr(record, "payload") else record
    sig = p.get("sig")
    if not sig or not trusted_pubkey_b64:
        return False
    if p.get("pubkey") != trusted_pubkey_b64:
        return False       # signed by a key that is not the trusted owner key
    msg = _approval_message(p.get("target_seq"), p.get("approval"), p.get("approver"))
    return verify_one(trusted_pubkey_b64, msg, sig)
