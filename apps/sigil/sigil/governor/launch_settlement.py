"""Owner-signed launch SETTLEMENT records on the spine — the backed-up, file-loss-proof half of settle idempotency.

``LaunchGate.settle_launch`` must be exactly-once per lease ``(slug, nonce)`` regardless of the amount: a
COMPLETED run's settle (refund 0) writes NO refund grant, so without a durable "this lease was settled" fact a
LATER full-refund settle (``launch_cancel`` / ``ops-sweep reservations --apply``, consumed 0) would be the first
writer of the refund grant and fully refund a charged run. The seam settlement marker
(``credit_lease_broker.record_lease_settlement``) records that fact, but it lives in the cross-plane seam
directory, which is not on the spine and is not captured by the sovereign backup — a lost or out-of-step seam
silently re-opened the refund.

So every fresh settle FIRST appends one owner-signed ``governor.launch_settled`` record here, before the seam
marker and before any money moves, and ``settle_launch`` treats a lease as settled when EITHER the seam marker
OR this record exists. The record is the DECISION: when several settles for one lease race (separate
processes), each appends its own record and the FIRST owner-verified record by spine seq is the settlement; a
settle that finds an earlier record than its own moves no money. Cross-process seq allocation is serialized by
the spine's own flock, so "first by seq" is total and agreed by every reader.

The record carries ``consumed`` (from the verified lease clamp) for audit; it never drives a refund amount on
its own. Verified under the owner key valid AT ITS SEQ (succession-aware), fail-closed: an unsigned or
foreign-signed record is ignored. A live scan is used (as ``PlanCreditLedger.debited_entry`` does); settlements
are rare (one per launch).

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, ``assert_no_offense()`` at import.
"""
from __future__ import annotations

from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402

LAUNCH_SETTLED_SIGNAL = "governor.launch_settled"
_SETTLED_CORE = ("signal", "org_id", "slug", "nonce", "consumed", "issued_at")


def record_launch_settled(store, owner_key, *, org_id: str, slug: str, nonce: str, consumed: int,
                          issued_at: float) -> int:
    """Owner-sign + append the settlement record for lease ``(slug, nonce)``. Returns its spine seq. Raises on a
    missing owner key / invalid org (the caller fails the settle CLOSED before any money moves)."""
    if owner_key is None:
        raise ValueError("a launch settlement record requires the owner signing key")
    oid = org_tenant_id(org_id)
    s, n = str(slug or ""), str(nonce or "")
    if not s or not n:
        raise ValueError("a launch settlement record needs a slug and a nonce")
    core = {"signal": LAUNCH_SETTLED_SIGNAL, "org_id": oid, "slug": s, "nonce": n,
            "consumed": int(consumed), "issued_at": float(issued_at)}
    payload = {**signed_payload(core, owner_key), "by": "owner", "requested_by": "owner", "tier": "A0",
               "decision": "auto", "reason": f"launch settled {s}:{n} (consumed {int(consumed)}) -> {oid}"}
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def first_launch_settlement(store, trusted_pubkey: Optional[str], *, org_id: str, slug: str,
                            nonce: str) -> Optional[int]:
    """The spine seq of the FIRST owner-verified settlement record for ``(org_id, slug, nonce)``, or None.
    Total: never raises on a hostile payload (it is skipped)."""
    if not (trusted_pubkey and org_id and slug and nonce):
        return None
    s, n = str(slug), str(nonce)
    resolver = _kh.key_resolver(store, current=trusted_pubkey)
    for r in store.iter_records():
        p = r.payload
        if not isinstance(p, dict) or p.get("signal") != LAUNCH_SETTLED_SIGNAL:
            continue
        if p.get("org_id") != org_id or p.get("slug") != s or p.get("nonce") != n:
            continue
        if verify_signed(p, _SETTLED_CORE, resolver.at(r.seq)):
            return int(r.seq)
    return None
