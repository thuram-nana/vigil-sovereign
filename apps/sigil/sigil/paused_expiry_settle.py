"""paused_expiry_settle — SETTLE a paused customer launch whose lease window has closed (E8), sovereign plane.

A paused launch is held, never settled, and once its window closes nothing can run it again (see
``vigil_integration.live.credit_lease_expiry``, the predicate this settles on). Without this the reservation
stayed debited until an operator ran the default-OFF ``sigil ops-sweep reservations --apply``. The settle-drain
(the shipped ``vigil-settle-drain`` unit, every ~60 s) now settles each such launch itself, after the completions
it drained in the same pass, while ``config.paused_expiry_settle_enabled()`` is on (default OFF).

EXACTLY ONCE, and never ahead of a completion: each settle goes through ``LaunchGate.settle_launch`` — owner-pinned
lease verify, then the cross-process settle lock and the spine + seam "already settled?" check (E3bc) — so it can
never race the settle-drain's charge of a completion or a cancel into a second settle. Its precondition
(``refuse_if``) runs INSIDE that critical section: no completion for the lease may be waiting in (or quarantined
by) the drain's completion spool, the spool must be fully readable, and the lease must STILL be due — a customer
resume serialized just before it restarts the grace (``LaunchGate.resume_launch`` records the expiry hold under the
same lock).

CONSUMPTION: :func:`expired_pause_consumption` — a FULL refund until the metered settle lands (never a charge on a
guess). SOVEREIGN PLANE ONLY (FATAL-2): ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Optional

from .reuse import assert_no_offense

assert_no_offense()


def expired_pause_consumption(lease_doc: Any) -> int:
    """The consumption an expired paused launch settles at: 0, a FULL refund. A run that a pause cut short did
    consume something, but nothing on the sovereign plane measures it until the metered settle (the model-gateway
    meter, ``VIGIL_METERED_BILLING``) lands, and a launch is never charged on a guess. The switch to "charge the
    metered consumption so far, release the rest" is this one return (``settle_launch`` clamps it to the
    owner-signed reservation)."""
    return 0


def _still_due(base: str, spool: Path, slug: str, nonce: str, not_after: float, now: float,
               grace: Optional[float]) -> "Callable[[], Optional[str]]":
    """The settle precondition, evaluated inside the settle critical section: a reason to refuse, or None."""
    from vigil_integration.live.credit_lease_expiry import settle_due_at

    from .ops_sweeps import _completion_block
    completion = _completion_block(spool, (slug, nonce))

    def _check() -> Optional[str]:
        why = completion()
        if why:
            return why
        at = settle_due_at(base, slug, nonce, not_after, grace=grace)
        return None if at is not None and now >= at else "not_due"
    return _check


def settle_expired_paused_launches(gate: Any, *, now: float, completion_spool: "str | os.PathLike",
                                   scope: str = "*", grace: Optional[float] = None) -> "list[dict]":
    """Settle every expired paused launch due at ``now`` on ``gate``'s seam (only ``scope``'s, unless ``*``).
    Returns one row per due launch: ``status`` ``settled`` (with ``refunded``), ``already_settled``, a refusal
    reason (``completion_pending`` / ``completion_unknown`` / ``not_due``), or ``settle_failed`` (with ``error``).
    Never raises for one lease."""
    from vigil_integration.live.credit_lease_expiry import due_expired_pauses

    base = gate._seam_base()
    spool = Path(completion_spool)
    rows: "list[dict]" = []
    for d in due_expired_pauses(base, now=now, grace=grace):
        if scope != "*" and d.slug != scope:
            continue
        row: dict = {"slug": d.slug, "nonce": d.nonce}
        try:
            signed = d.bundle.signed_lease
            r = gate.settle_launch(signed_lease=signed.model_dump(mode="json"),
                                   consumed_units=expired_pause_consumption(signed.document), now=now,
                                   refuse_if=_still_due(base, spool, d.slug, d.nonce, d.not_after, now, grace))
        except Exception as e:  # noqa: BLE001 — one bad lease never sinks the pass (nothing moved: settle is atomic)
            r = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if r.get("refused"):
            row["status"] = str(r["refused"])
        elif not r.get("ok"):
            row.update(status="settle_failed", error=str(r.get("error", "")))
        elif r.get("action") == "launch_already_settled":
            row["status"] = "already_settled"
        else:
            row.update(status="settled", refunded=int(r.get("refunded", 0)))
        rows.append(row)
    return rows
