"""
sigil.knowledge.proposals — enqueue a learn-proposal onto the owner-approval queue (K2b).

An offense-drafted proposal to deep-learn a vulnerability is enqueued as an ordinary
``decision:"queued", status:"awaiting-approval"`` spine record — the SAME shape agents use for A2/A3
proposals — so the existing owner-signed ``ApprovalQueue.approve``/``deny`` (in ``sigil.agents.approvals``)
resolves it unchanged. Nothing here is owner-signed: ENQUEUING is a request that grants nothing; the
owner-signed APPROVE is the sole trust operation. Accepting authorises LEARNING (K3), never a fact.

Idempotent: a vuln already awaiting approval is not re-queued (its existing seq is returned), so repeated
propose ticks never pile up duplicate pending items for the same CVE.
"""

from __future__ import annotations

from typing import Optional

from ..spine.store import SpineStore

LEARN_SIGNAL = "knowledge.learn_proposal"
# A2 = needs owner approval before any downstream effect (K3 learning). Enqueuing itself does nothing.
_LEARN_TIER = "A2"
# Bound the append-only pending queue at the enqueue choke point, so neither a repeated owner action nor a
# future automatic propose tick (K5) can pile up unbounded awaiting-approval records. A distinct-vuln flood
# is refused once this many are already awaiting the owner's decision (accept/deny some first).
_MAX_PENDING = 200


def pending_learn_proposals(store: SpineStore, trusted_pubkey_b64: Optional[str] = None) -> list[dict]:
    """The learn-proposals still awaiting the owner's signed decision, oldest first — each with its spine
    ``seq`` (the id the owner approves/denies) and the proposal fields. Read-only; delegates resolution to
    the owner-signed ``pending`` (an unsigned/forged approval never drops an item)."""
    from ..agents.approvals import pending
    out: list[dict] = []
    for r in pending(store, trusted_pubkey_b64):
        p = r.payload
        if p.get("signal") != LEARN_SIGNAL:
            continue
        out.append({"seq": r.seq, "vuln_id": p.get("vuln_id"), "rank": p.get("rank"),
                    "exploit_known": bool(p.get("exploit_known")), "severity": p.get("severity"),
                    "rationale": p.get("rationale")})
    return out


def _pending_vuln_ids(store: SpineStore, trusted_pubkey_b64: Optional[str]) -> dict:
    return {str(lp["vuln_id"]): lp["seq"] for lp in pending_learn_proposals(store, trusted_pubkey_b64)
            if lp.get("vuln_id")}


def enqueue_learn_proposal(store: SpineStore, proposal: dict, *,
                           trusted_pubkey_b64: Optional[str] = None) -> int:
    """Enqueue one learn-proposal as an awaiting-approval item; return its spine ``seq``.

    IDEMPOTENT: if a proposal for the same ``vuln_id`` is already awaiting approval, no new record is
    written and the existing seq is returned. The record is a plain queued proposal — it grants nothing
    and takes no effect until the owner signs an approval over its seq (``ApprovalQueue.approve``). This
    function does NOT check the autolearn latch / kill-switch: its sole caller (the ``queue_learn`` action)
    gates on both first (fail-closed), so enqueuing is never reached when autolearn is off or STOP is engaged.
    """
    vuln_id = str(proposal.get("vuln_id") or "").strip()
    if not vuln_id:
        raise ValueError("learn-proposal requires a vuln_id")
    pending_ids = _pending_vuln_ids(store, trusted_pubkey_b64)
    existing = pending_ids.get(vuln_id)
    if existing is not None:
        return int(existing)                          # already awaiting approval — idempotent no-op
    if len(pending_ids) >= _MAX_PENDING:              # bound the append-only queue (no unbounded pile-up)
        raise ValueError(
            f"learn-proposal queue is full ({_MAX_PENDING} awaiting approval); accept or deny some first")
    payload = {
        "signal": LEARN_SIGNAL, "decision": "queued", "status": "awaiting-approval", "tier": _LEARN_TIER,
        "vuln_id": vuln_id, "rank": proposal.get("rank"),
        "exploit_known": bool(proposal.get("exploit_known")),
        "severity": proposal.get("severity"), "rationale": str(proposal.get("rationale") or "")[:500],
        "subject": f"learn vuln {vuln_id} (find/detect/prevent) — awaiting approval",
    }
    return store.append(kind="event", source="knowledge", actor="knowledge", payload=payload)
