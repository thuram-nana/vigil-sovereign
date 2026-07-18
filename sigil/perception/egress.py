"""Frontier-vision EGRESS gate (Phase 7, WS-A V-ii). Sending a screen/camera frame to the frontier
Anthropic VLM uploads private bytes off the owned machine — that is A2 data-egress, not a free
"try local then frontier" quality bump. This gate makes the cascade doctrine-honest:

  • The tier is DERIVED from the WARDEN oracle (`KernelClassifier` on `vision.frontier.upload` → A2),
    never self-declared.
  • Nothing uploads until a VERIFIED owner approval exists that is BOUND to this exact egress — an
    `egress_token = sha256(frame.sha256 | question)`. An approval of a different egress (a replay)
    does not match `target_seq` and does not authorize the upload.
  • Absent approval, the egress is QUEUED (an A2 proposal recorded on the spine) and the frontier
    reading is WITHHELD; the local (on-box) reading still stands.

Reuses the hardened signed `ApprovalQueue` verification (`verify_approval`) — the same fail-closed
owner-key check the mesh already trusts."""
from __future__ import annotations

from ..agents.approvals import SIGNAL as _APPROVAL_SIGNAL
from ..agents.approvals import verify_approval
from ..reuse import sha256_hex

EGRESS_SIGNAL = "vision.egress"
FRONTIER_TOOL = "vision.frontier.upload"   # classified A2 by the WARDEN oracle (contains "upload")


def egress_token(frame_sha256: str, question: str) -> str:
    """A stable id binding an approval to exactly this (frame, question) upload."""
    return sha256_hex(f"{frame_sha256}|{question or ''}".encode("utf-8"))


def egress_approved(store, seq: int, token: str, trusted_pubkey) -> bool:
    """True iff `seq` is an egress request bound to `token` AND carries a VERIFIED owner approval.
    Fail-closed: wrong token, no approval, denied, or an approval of a different seq → False."""
    rec = store.get(seq)
    if rec is None or rec.payload.get("signal") != EGRESS_SIGNAL or rec.payload.get("egress_token") != token:
        return False
    for r in store.iter_records(since_seq=seq):
        p = r.payload
        if (p.get("signal") == _APPROVAL_SIGNAL and p.get("target_seq") == seq
                and p.get("approval") == "approved" and verify_approval(r, trusted_pubkey)):
            return True
    return False
