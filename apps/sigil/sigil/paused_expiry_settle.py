"""paused_expiry_settle — the settle-drain SETTLES a paused customer launch whose lease window has closed (E8).

A paused launch is held, and once its window closes nothing can run it again (``vigil_integration.live.
credit_lease_expiry`` is the due predicate this settles on). ``sigil ops-sweep reservations --apply`` settles it
by the owner's paused-launch rule; with ``config.paused_expiry_settle_enabled()`` on (default OFF) the settle-drain
(the shipped ``vigil-settle-drain`` unit) settles each such launch itself, after the completions it drained in the
same pass, once the settle grace has passed.

HOW MUCH — the sweep's rule for a launch the customer paused and never resumed (owner decision 2026-11-13), the same
code (``ops_sweeps._paused_metered_charge``): a launch published METERED is charged its confirmed metered use (its
meter is closed first; ``min(reservation, max(floor, ceil(cost x markup)))``, and nothing when it made no request
and has no confirmed spend); a FLAT launch has no meter, so it is refunded in full. The decision record (settle
record on) carries the sweep's bases (``sweep:paused`` / ``sweep:refund``).

EXACTLY ONCE, and never ahead of a completion: each settle goes through ``LaunchGate.settle_launch`` — owner-pinned
lease verify, then the cross-process settle lock and the spine + seam "already settled?" check — so it can never
race the drain's charge of a completion, a cancel or the sweep into a second settle. Its precondition
(``refuse_if``) runs INSIDE that critical section: no completion for the lease may be waiting in (or quarantined
by) the drain's completion spool and the spool must be fully readable; a metered launch's pause state must still
read as it was priced; and the lease must STILL be due — a pause or a late resume recorded since restarts the
grace (``not_due``).

SOVEREIGN PLANE ONLY (FATAL-2): ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Optional

from .reuse import assert_no_offense

assert_no_offense()

#: the row statuses that mean the launch is settled by this pass (money moved, or a recorded settle was finished)
SETTLED_STATUSES = frozenset({"settled", "charged_paused", "settle_completed"})


def _still_due(precondition: "Callable[[], Optional[str]]", base: str, slug: str, nonce: str, not_after: float,
               now: float, grace: Optional[float]) -> "Callable[[], Optional[str]]":
    """The settle's in-lock precondition: the sweep's (completion / pause state), then "still due"."""
    from vigil_integration.live.credit_lease_expiry import settle_due_at

    def _check() -> Optional[str]:
        why = precondition()
        if why:
            return why
        at = settle_due_at(base, slug, nonce, not_after, grace=grace)
        return None if at is not None and now >= at else "not_due"
    return _check


def _settle_one(gate: Any, d: Any, *, now: float, spool: Path, base: str, grace: Optional[float]) -> dict:
    from .ops_sweeps import (
        _moved, _paused_metered_charge, _pending_completions, _settle_precondition, _SweepDefer,
    )
    slug, nonce = d.slug, d.nonce
    signed = d.bundle.signed_lease
    pending, unreadable = _pending_completions(spool)        # a fast refusal; re-checked inside the settle
    if (slug, nonce) in pending:
        return {"status": "completion_pending"}
    if unreadable:
        return {"status": "completion_unknown"}
    try:
        metered = bool(gate._launch_was_metered(slug, nonce))
    except OSError as e:
        return {"status": "deferred", "error": f"billing mode unreadable: {type(e).__name__}"}
    consumed = 0
    if metered:
        try:
            consumed = _paused_metered_charge(gate, slug, nonce, int(signed.document.units_reserved), now)
        except _SweepDefer as e:
            return {"status": e.status, "error": str(e)}
        except ValueError as e:
            return {"status": "settle_failed", "error": f"the run's model meter is broken: {e}"}
    refuse_if = _still_due(_settle_precondition(spool, (slug, nonce), base, metered=metered, paused=True),
                           base, slug, nonce, d.not_after, now, grace)
    r = gate.settle_launch(signed_lease=signed.model_dump(mode="json"), consumed_units=consumed, now=now,
                           basis=("sweep:paused" if consumed > 0 else "sweep:refund"), refuse_if=refuse_if)
    if r.get("refused"):
        return {"status": str(r["refused"])}
    if not r.get("ok") and r.get("retry"):
        return {"status": "deferred", "error": str(r.get("error", ""))}
    if not r.get("ok"):
        return {"status": "settle_failed", "error": str(r.get("error", ""))}
    if r.get("action") == "launch_already_settled":
        return {"status": "settle_completed", **_moved(r)} if r.get("rolled_forward") else {"status": "already_settled"}
    if consumed > 0:
        return {"status": "charged_paused", "charged": consumed, "refunded": int(r.get("refunded", 0))}
    return {"status": "settled", "refunded": int(r.get("refunded", 0))}


def settle_expired_paused_launches(gate: Any, *, now: float, completion_spool: "str | os.PathLike",
                                   scope: str = "*", grace: Optional[float] = None) -> "list[dict]":
    """Settle every expired paused launch due at ``now`` on ``gate``'s seam (only ``scope``'s, unless ``*``).
    Returns one row per due launch: ``status`` ``settled`` (with ``refunded``), ``charged_paused`` (with ``charged``
    and ``refunded``), ``settle_completed`` (a recorded settle finished), ``already_settled``, a refusal reason
    (``completion_pending`` / ``completion_unknown`` / ``pause_changed`` / ``pause_unknown`` / ``not_due``),
    ``deferred`` / ``deferred_config`` (retried next pass) or ``settle_failed`` (with ``error``). Never raises for
    one lease."""
    from vigil_integration.live.credit_lease_expiry import due_expired_pauses

    base = gate._seam_base()
    spool = Path(completion_spool)
    rows: "list[dict]" = []
    for d in due_expired_pauses(base, now=now, grace=grace):
        if scope != "*" and d.slug != scope:
            continue
        row: dict = {"slug": d.slug, "nonce": d.nonce}
        try:
            row.update(_settle_one(gate, d, now=now, spool=spool, base=base, grace=grace))
        except Exception as e:  # noqa: BLE001 — one bad lease never sinks the pass (a settle is atomic)
            row.update(status="settle_failed", error=f"{type(e).__name__}: {e}")
        rows.append(row)
    return rows
