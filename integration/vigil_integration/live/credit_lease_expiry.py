"""credit_lease_expiry — when a PAUSED customer launch whose lease window has closed is DUE to settle (E8).

A pause holds a launch: the seam poller, the pickup gate and the engine arm refuse a paused lease, a run in flight
halts at its next action, and the held delivery re-admits on resume. Once ``not_after`` has passed they refuse the
window as well, so such a launch can never run again and no completion is coming for it. It settles by the owner's
paused-launch rule (charged for what it used; a flat launch, which has no meter, refunded) — through
``sigil ops-sweep reservations --apply``, and, with ``VIGIL_PAUSED_EXPIRY_SETTLE`` on, by the settle-drain itself
(``sigil.paused_expiry_settle``).

This module is the ONE predicate both planes use for that state:

  * the sovereign settle-drain settles every launch it lists, through the exactly-once ``LaunchGate.settle_launch``;
  * ``vigil doctor`` reports every launch it lists as a HARD issue (an expired paused reservation nothing settled).

DUE — the lease on the seam for ``(slug, nonce)`` is not recorded settled, and either or both of:

  (a) ``(slug, nonce)`` is POSITIVELY paused — a cleanly-read pause marker lists the nonce (an unreadable marker is
      never evidence for a settle) — evidence time ``paused_at`` = the marker's mtime, an upper bound on when this
      nonce was paused (the per-slug marker is rewritten only by a later pause or resume of that slug);
  (b) the customer lifted its pause after the window closed — the paused-past-expiry record
      (``credit_lease_pause.record_paused_past_expiry``, written by ``LaunchGate.resume_launch`` BEFORE it clears
      the pause) lists the nonce — evidence time = that record's mtime, an upper bound on the resume (the add-only
      per-slug record is rewritten only to add a later launch of that slug);

and ``now >= max(not_after, every evidence time) + grace``. So a pause that lands after ``not_after`` (the halt of a
run still in flight past its window) and a resume after it each get the whole grace from their own time. The two
records are read in the settle-side order (the pause marker BEFORE the paused-past-expiry record), so a resume
racing this read is seen as one or the other, never as "never paused".

``grace`` (``VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS``, default 86400 s — the ``ops-sweep reservations --ttl``
default) covers clock skew between the planes and a run that a late pause or a late resume let finish: its
completion lands first and is charged, and the settle re-checks the completion spool inside its critical section.
Nothing here carries an amount: a settle is bound to the owner-signed lease (``settle_launch`` verifies it).

FATAL-2 / import-clean: stdlib + the import-clean seam modules only, so it is safe on both planes. Read-only.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vigil_integration.live.credit_lease_broker import is_lease_settled, list_credit_leases
from vigil_integration.live.credit_lease_pause import (
    _past_expiry_path,
    lease_pause_state,
    pause_path,
    paused_past_expiry,
)

__all__ = [
    "DEFAULT_GRACE_SECONDS",
    "DueExpiredPause",
    "due_expired_pauses",
    "settle_due_at",
    "settle_grace_seconds",
]

_GRACE_ENV = "VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS"
DEFAULT_GRACE_SECONDS = 86400.0


def settle_grace_seconds() -> float:
    """The settle grace in seconds: ``VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS`` when it is a finite number >= 0,
    else :data:`DEFAULT_GRACE_SECONDS` (an unreadable value never shortens the grace)."""
    raw = (os.environ.get(_GRACE_ENV) or "").strip()
    try:
        v = float(raw) if raw else DEFAULT_GRACE_SECONDS
    except ValueError:
        return DEFAULT_GRACE_SECONDS
    return v if math.isfinite(v) and v >= 0 else DEFAULT_GRACE_SECONDS


def _mtime(path: Optional[Path]) -> Optional[float]:
    """``path``'s mtime, or None (no path, gone, unreadable). Never raises."""
    try:
        if path is None:
            return None
        t = path.stat().st_mtime
    except (OSError, ValueError):
        return None
    return t if math.isfinite(t) else None


def settle_due_at(base_dir: Any, slug: Any, nonce: Any, not_after: float, *,
                  grace: Optional[float] = None) -> Optional[float]:
    """When ``(slug, nonce)``, whose lease window ends at ``not_after``, is due to settle as an expired paused
    launch — or None when there is no positive, readable evidence that it was held paused (see the module
    docstring). Settlement is the caller's check. Never raises."""
    try:
        g = settle_grace_seconds() if grace is None else float(grace)
        s, n = str(slug), str(nonce)
        times: "list[float]" = []
        if lease_pause_state(base_dir, s, n) is True:            # READ ORDER: the pause marker first ...
            t = _mtime(pause_path(base_dir, s))
            if t is not None:
                times.append(t)
        if paused_past_expiry(base_dir, s, n) is True:           # ... then the paused-past-expiry record
            t = _mtime(_past_expiry_path(base_dir, s))
            if t is not None:
                times.append(t)
        if not times:
            return None
        return max(float(not_after), *times) + g
    except Exception:  # noqa: BLE001 — an odd or racing store is "no evidence", never an exception for the caller
        return None


@dataclass(frozen=True)
class DueExpiredPause:
    """One expired paused launch that is due to settle: its lease bundle as found on the seam (NOT verified here —
    ``settle_launch`` verifies it under the owner key before anything moves)."""
    slug: str
    nonce: str
    not_after: float
    due_at: float
    bundle: Any


def due_expired_pauses(base_dir: Any, *, now: float, grace: Optional[float] = None) -> "list[DueExpiredPause]":
    """Every lease on the seam that is an expired paused launch due to settle at ``now`` and not recorded settled.
    The slug is the one the lease is signed for. Read-only, total: an unreadable lease (``list_credit_leases`` skips
    it) or marker contributes nothing."""
    out: "list[DueExpiredPause]" = []
    for b in list_credit_leases(base_dir):
        try:
            doc = b.signed_lease.document
            s, n, na = str(doc.engagement_slug), str(doc.nonce), float(doc.not_after.timestamp())
            if is_lease_settled(base_dir, s, n):
                continue
        except Exception:  # noqa: BLE001 — a malformed bundle is no evidence
            continue
        at = settle_due_at(base_dir, s, n, na, grace=grace)
        if at is not None and now >= at:
            out.append(DueExpiredPause(slug=s, nonce=n, not_after=na, due_at=at, bundle=b))
    return out
