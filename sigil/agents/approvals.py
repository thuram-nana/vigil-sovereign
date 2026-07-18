"""Approval queue (SIGIL §5, §9.3 mobile bridge) — the human gate for A2/A3 proposals. An agent
QUEUES a proposal (governor → QUEUE); the owner APPROVES or DENIES it here. Authentication is an
Ed25519 signature over the canonical (target, decision, approver) by the OWNER key.

RED-PEN HARDENING (Phase 6):
 • The trusted pubkey is the PERSISTED owner identity — NOT the key supplied to the queue, so an
   attacker cannot self-certify by bringing their own key (RP-APPROVAL-2). approve/deny require the
   supplied signing key to BE the trusted owner key.
 • `pending()` treats a queued item as resolved ONLY when a superseding approval VERIFIES against the
   trusted owner key, and keys resolution off the SIGNED target_seq (not the raw supersedes_id) — so
   an unsigned/forged approval can't silently drop an item (RP-1/RP-APPROVAL-1), and a genuine
   approval of one item can't be replayed onto another (RP-APPROVAL-4). `verify_approval` is thereby
   on the enforcement path (RP-APPROVAL-3).

This records the DECISION; it executes no external effect (SIGIL has no send/deploy path). The
transport (Telegram/WhatsApp over WireGuard, §9.3) is a seam over this authenticated core."""
from __future__ import annotations

from typing import List, Optional

from ..reuse import canonical_json, sha256_hex, sign, verify_one
from ..spine.store import SpineStore

SIGNAL = "governor.approval"
_QUEUED_STATUS = "awaiting-approval"


def _approval_message(target_seq, decision: str, approver: str) -> bytes:
    m = canonical_json({"target": target_seq, "decision": decision, "approver": approver})
    return m if isinstance(m, bytes) else m.encode()


def verify_approval(record, trusted_pubkey_b64: Optional[str]) -> bool:
    """True iff the approval carries a valid OWNER signature over its (target, decision, approver).
    Unsigned, wrong-key, or no-trusted-key → False (fail-closed)."""
    p = record.payload if hasattr(record, "payload") else record
    sig = p.get("sig")
    if not sig or not trusted_pubkey_b64 or p.get("pubkey") != trusted_pubkey_b64:
        return False
    msg = _approval_message(p.get("target_seq"), p.get("approval"), p.get("approver"))
    return verify_one(trusted_pubkey_b64, msg, sig)


def pending(store: SpineStore, trusted_pubkey_b64: Optional[str] = None) -> List:
    """Queued proposals with NO valid owner approval yet, oldest first. Resolution requires a
    VERIFIED approval; an unsigned/forged/wrong-key approval leaves the item pending (fail-closed)."""
    if trusted_pubkey_b64 is None:
        from ..governor.identity import owner_pubkey
        trusted_pubkey_b64 = owner_pubkey()
    resolved = set()
    queued = {}
    for r in store.iter_records():
        p = r.payload
        if p.get("signal") == SIGNAL and verify_approval(r, trusted_pubkey_b64):
            resolved.add(p.get("target_seq"))       # honor the SIGNED target, not raw supersedes_id
        if p.get("decision") == "queued" and p.get("status") == _QUEUED_STATUS:
            queued[r.seq] = r
    return [r for seq, r in sorted(queued.items()) if seq not in resolved]


class ApprovalError(Exception):
    pass


class ApprovalQueue:
    def __init__(self, store: Optional[SpineStore] = None, *, owner_key=None,
                 trusted_pubkey_b64: Optional[str] = None):
        from ..governor.identity import owner_keypair, owner_pubkey
        self.store = store or SpineStore()
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        # PINNED to the persisted owner identity — never defaulted to the supplied key (RP-APPROVAL-2)
        self.trusted_pubkey_b64 = trusted_pubkey_b64 if trusted_pubkey_b64 is not None else owner_pubkey()

    def _target(self, seq: int):
        for r in pending(self.store, self.trusted_pubkey_b64):
            if r.seq == seq:
                return r
        raise ApprovalError(f"seq {seq} is not a pending approval (already decided, or not queued)")

    def _decide(self, seq: int, decision: str, *, approver: str, reason: str = "") -> int:
        target = self._target(seq)
        # the signing key MUST be the trusted owner key — not merely "some key present" (RP-APPROVAL-2).
        if (self.owner_key is None or self.trusted_pubkey_b64 is None
                or self.owner_key.public_key_b64 != self.trusted_pubkey_b64):
            raise ApprovalError("approval requires the OWNER's signing key (missing or not the trusted key)")
        msg = _approval_message(seq, decision, approver)
        sig = sign(self.owner_key.private_key_b64, msg)
        payload = {"signal": SIGNAL, "approval": decision, "target_seq": seq, "target_kind": target.kind,
                   "target_tier": target.payload.get("tier"), "approver": approver, "reason": reason,
                   "pubkey": self.trusted_pubkey_b64, "sig": sig, "msg_digest": sha256_hex(msg),
                   "tier": "A0", "decision": "auto"}
        return self.store.append(kind="event", source="governor", actor="OWNER",
                                 payload=payload, supersedes_id=seq)

    def approve(self, seq: int, *, approver: str = "owner", reason: str = "") -> int:
        return self._decide(seq, "approved", approver=approver, reason=reason)

    def deny(self, seq: int, *, approver: str = "owner", reason: str = "") -> int:
        return self._decide(seq, "denied", approver=approver, reason=reason)
