"""credit_lease_expiry — when a PAUSED customer launch whose lease window has closed is DUE to settle (E8).

A pause HOLDS a launch: the seam poller, the pickup gate and the engine arm refuse a paused lease, a run in flight
halts at its next action and raises ``EngagementPaused`` (the worker then emits NO completion), and the held
delivery re-admits on resume. That is reversible only while the lease WINDOW is open. Once ``not_after`` has
passed, the poller, the gate and the arm refuse the window as well, so the held launch can never run again — and
nothing settled it: the settle-drain settles completions, and no completion is coming. Its reserved credits were
stranded until an operator ran the default-OFF ``sigil ops-sweep reservations --apply``.

This module is the ONE predicate both planes use for that state:

  * the sovereign settle-drain settles every launch it lists (``sigil.paused_expiry_settle``, default-OFF behind
    ``VIGIL_PAUSED_EXPIRY_SETTLE``) through the exactly-once ``LaunchGate.settle_launch``; and
  * ``vigil doctor`` reports every launch it lists as a HARD issue (an expired reservation nothing settled).

DUE — the lease on the seam for ``(slug, nonce)`` is not recorded settled, and

  (a) ``(slug, nonce)`` is POSITIVELY paused — a cleanly-read pause marker lists the nonce; an unreadable marker
      is never evidence for a settle — and ``now >= max(not_after, paused_at) + grace``. ``paused_at`` is the pause
      marker's mtime, an upper bound on when this nonce was paused (the per-slug marker is rewritten only by a later
      pause or resume of that slug), so a pause that lands after ``not_after`` — the halt of a run still in flight
      past its window — gets the whole grace too; or

  (b) it carries an EXPIRY HOLD and ``now >= max(not_after, resumed_at) + grace``. A customer may lift the pause of
      an expired lease (``LaunchGate.resume_launch``, so a run still in flight past ``not_after`` is not left halted
      for good). That erases the pause marker, so the resume first records the hold: the durable note that this
      launch was paused when its window closed, stamped with the resume time.

``grace`` (``VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS``, default 86400 s — the ``ops-sweep reservations --ttl``
default) covers clock skew between the planes and a run that a late pause or an expired resume let finish: its
completion lands first and is charged, and the settle re-checks the completion spool inside its critical section.

Store: ``<base>/credit-lease-expiry-holds/<slug>.json`` — ``{schema_version, kind, slug, holds: {nonce: resumed_at}}``,
a sibling of the lease, settlement and pause dirs, written with the broker's atomic write under its per-file
cross-process lock. The reader fails SAFE to "no hold": a hold is evidence FOR a refund, so one that cannot be read
is never used (the launch stays held, as before, and ``ops-sweep reservations`` still lists it). It carries no
amount: a settle is bound to the owner-signed lease (``settle_launch`` verifies it under the owner key).

FATAL-2 / import-clean: stdlib + the import-clean seam modules only, so it is safe on both planes. Read-only except
:func:`record_expiry_hold`, whose only caller is the sovereign ``LaunchGate.resume_launch``.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from vigil_integration.live.credit_lease_broker import (
    _atomic_write_json,
    _contained_child,
    _marker_lock,
    _safe_component,
    is_lease_settled,
    list_credit_leases,
)
from vigil_integration.live.credit_lease_pause import pause_path, paused_launches

__all__ = [
    "DEFAULT_GRACE_SECONDS",
    "DueExpiredPause",
    "due_expired_pauses",
    "expiry_hold_at",
    "holds_root",
    "record_expiry_hold",
    "settle_due_at",
    "settle_grace_seconds",
]

_HOLD_DIRNAME = "credit-lease-expiry-holds"
_HOLD_SCHEMA = "vigil-credit-lease-expiry-hold-v1"
_SCHEMA_VERSION = 1
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


# ---------------------------------------------------------------------------------------------------
# the expiry-hold store
# ---------------------------------------------------------------------------------------------------


def holds_root(base_dir: Any) -> Path:
    """The expiry-hold root ``<base>/credit-lease-expiry-holds``."""
    return Path(base_dir) / _HOLD_DIRNAME


def _hold_path(base_dir: Any, slug: Any) -> Optional[Path]:
    safe = _safe_component(slug)
    return _contained_child(holds_root(base_dir), f"{safe}.json") if safe else None


def _read_holds(path: Path) -> "dict[str, float]":
    """``{nonce: resumed_at}`` from one hold file; {} on any read / parse / kind error (fail-SAFE: no hold)."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    holds = obj.get("holds") if isinstance(obj, dict) and obj.get("kind") == _HOLD_SCHEMA else None
    if not isinstance(holds, dict):
        return {}
    return {str(n): float(t) for n, t in holds.items()
            if isinstance(t, (int, float)) and not isinstance(t, bool) and math.isfinite(t)}


def record_expiry_hold(base_dir: Any, slug: Any, nonce: Any, *, resumed_at: float) -> Path:
    """Durably note that ``(slug, nonce)`` was paused when its lease window closed and was resumed at
    ``resumed_at``. Re-recording keeps the LATER time (a later resume only postpones the settle). Raises on an
    unsafe slug or a write failure, so the caller lifts no pause it could not record (fail-closed)."""
    path = _hold_path(base_dir, slug)
    if path is None:
        raise ValueError(f"unsafe lease slug: {slug!r}")
    t = float(resumed_at)
    with _marker_lock(path):
        holds = _read_holds(path) if path.is_file() else {}
        holds[str(nonce)] = max(t, holds.get(str(nonce), t))
        _atomic_write_json(path, {"schema_version": _SCHEMA_VERSION, "kind": _HOLD_SCHEMA,
                                  "slug": _safe_component(slug), "holds": holds})
    return path


def expiry_hold_at(base_dir: Any, slug: Any, nonce: Any) -> Optional[float]:
    """The recorded resume time of ``(slug, nonce)``'s expiry hold, or None (no hold / unreadable). Never raises."""
    path = _hold_path(base_dir, slug)
    try:
        if path is None or not path.is_file():
            return None
    except OSError:
        return None
    return _read_holds(path).get(str(nonce))


# ---------------------------------------------------------------------------------------------------
# the due predicate
# ---------------------------------------------------------------------------------------------------


def settle_due_at(base_dir: Any, slug: Any, nonce: Any, not_after: float, *,
                  grace: Optional[float] = None) -> Optional[float]:
    """When ``(slug, nonce)``, whose lease window ends at ``not_after``, is due to settle as an expired paused
    launch — or None when it is neither positively paused nor expiry-held (see the module docstring). Settlement is
    the caller's check. Never raises."""
    g = settle_grace_seconds() if grace is None else float(grace)
    s, n = str(slug), str(nonce)
    start: Optional[float] = None
    if n in dict(paused_launches(base_dir)).get(s, []):
        try:
            p = pause_path(base_dir, s)
            if p is not None:
                start = max(float(not_after), p.stat().st_mtime)
        except OSError:
            pass                                     # no readable pause time: this branch is no evidence
    held = expiry_hold_at(base_dir, s, n)
    if held is not None:
        h = max(float(not_after), held)
        start = h if start is None else max(start, h)
    return None if start is None else start + g


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
    The slug is the one the lease is signed for. Read-only, total: an unreadable lease (``list_credit_leases``
    skips it) or marker contributes nothing."""
    out: "list[DueExpiredPause]" = []
    for b in list_credit_leases(base_dir):
        doc = b.signed_lease.document
        s, n, na = str(doc.engagement_slug), str(doc.nonce), float(doc.not_after.timestamp())
        if is_lease_settled(base_dir, s, n):
            continue
        at = settle_due_at(base_dir, s, n, na, grace=grace)
        if at is not None and now >= at:
            out.append(DueExpiredPause(slug=s, nonce=n, not_after=na, due_at=at, bundle=b))
    return out
