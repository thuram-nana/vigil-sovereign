"""Launch RESERVATIONS as the spine records them — the basis of "one outstanding launch per (org, host)" (E7).

``LaunchGate.reserve_launch`` owner-signs the credit draw of a launch under ``reserve-wallet:`` / ``reserve-plan:``
(prepaid) or ``reserve-postpaid:`` (a postpaid line) ``{slug}:{nonce}``, and ``LaunchGate._settle_once`` settles it
exactly once per lease ``(slug, nonce)``. The slug is the same for every launch of one ``(org, host)`` and the
cross-plane seam holds ONE lease per slug, so a launch whose lease a later launch of the same target replaced is
no longer on the seam (its job is refused at the arm and its completion is quarantined by the settle-drain), while
the spine still holds its reservation. So the one-launch checks (``LaunchGate._one_launch_refusal``) and the
release of a superseded reservation (``ops_sweeps.sweep_superseded_reservations``) read the reservations from
HERE, not from the seam.

``scan_reservations(...)`` returns a ``ReservationIndex``: every owner-signed reservation keyed
``(org_id, slug, nonce)`` (the seq + ``issued_at`` of its first reserve record and its credits per bucket), the
leases the spine shows SETTLED — the same evidence ``launch_settlement.scan_settlement`` reads: a
``governor.launch_settled`` decision record, or a settle grant / credit under the lease's settle entry id — and
the leases a settle-drain ``assessment_outcome`` record names (that record is written after a drained settle; it
is unsigned, so it is only ever used to REFUSE a release, never to allow anything). Each signed record is verified
under the owner key valid AT ITS SEQ (succession-aware), fail-closed: an unsigned / forged / wrong-epoch record is
ignored. It is a LIVE scan (no snapshot seed, like ``scan_settlement``): a caller scans in full BEFORE taking the
settle lock and continues the scan (``since``) inside it. ``org_id`` / ``slug`` narrow the scan to one target.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import verify_signed  # noqa: E402
from .launch_settlement import (  # noqa: E402
    _SETTLED_CORE_V1, _SETTLED_CORE_V2, LAUNCH_SETTLED_SIGNAL, SETTLE_PLAN_PREFIX, SETTLE_WALLET_PREFIX,
)
from .metering import _PLAN_DEBIT_CORE, _PLAN_GRANT_CORE, PLAN_DEBIT_SIGNAL, PLAN_GRANT_SIGNAL  # noqa: E402
from .postpaid import (  # noqa: E402
    _PP_CREDIT_CORE, _PP_DEBIT_CORE, POSTPAID_CREDIT_SIGNAL, POSTPAID_DEBIT_SIGNAL, RESERVE_ENTRY_PREFIX,
    SETTLE_ENTRY_PREFIX,
)
from .wallet import _DEBIT_CORE, _GRANT_CORE, CREDIT_DEBIT_SIGNAL, CREDIT_GRANT_SIGNAL  # noqa: E402

RESERVE_WALLET_PREFIX = "reserve-wallet:"
RESERVE_PLAN_PREFIX = "reserve-plan:"
#: the settle-drain's (unsigned) projection of a drained settle — see ``inbound.completion_spool``
ASSESSMENT_OUTCOME_KIND = "assessment_outcome"

#: signal -> (entry-id prefix, signed core, bucket) of a launch RESERVE record
_RESERVE: "dict[str, tuple[str, tuple[str, ...], str]]" = {
    CREDIT_DEBIT_SIGNAL: (RESERVE_WALLET_PREFIX, _DEBIT_CORE, "wallet"),
    PLAN_DEBIT_SIGNAL: (RESERVE_PLAN_PREFIX, _PLAN_DEBIT_CORE, "plan"),
    POSTPAID_DEBIT_SIGNAL: (RESERVE_ENTRY_PREFIX, _PP_DEBIT_CORE, "postpaid"),
}
#: signal -> (entry-id prefix, signed core) of a launch SETTLE entry (the ones ``scan_settlement`` counts)
_SETTLE: "dict[str, tuple[str, tuple[str, ...]]]" = {
    CREDIT_GRANT_SIGNAL: (SETTLE_WALLET_PREFIX, _GRANT_CORE),
    PLAN_GRANT_SIGNAL: (SETTLE_PLAN_PREFIX, _PLAN_GRANT_CORE),
    POSTPAID_CREDIT_SIGNAL: (SETTLE_ENTRY_PREFIX, _PP_CREDIT_CORE),
}


def _lease_of(entry_id: object, prefix: str) -> "Optional[tuple[str, str]]":
    """``(slug, nonce)`` from ``<prefix><slug>:<nonce>``, or None (neither part may be empty or hold a ':')."""
    if not isinstance(entry_id, str) or not entry_id.startswith(prefix):
        return None
    parts = entry_id[len(prefix):].split(":")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    return parts[0], parts[1]


def _credits(v: object) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v > 0 else 0


def _issued_at(v: Any) -> float:
    """A reserve record's ``issued_at``; an unreadable / non-finite one reads as +inf (the reservation then never
    looks old enough to release, and stays outstanding while unsettled — fail-closed)."""
    try:
        t = float(v)                                 # a hostile payload: anything non-numeric raises
    except (TypeError, ValueError):
        return math.inf
    return t if math.isfinite(t) else math.inf


@dataclass
class Reservation:
    """One launch's reservation as the spine records it."""
    org_id: str
    slug: str
    nonce: str
    seq: int                    # the seq of its FIRST verified reserve record
    issued_at: float            # ...and that record's issued_at (the reserve time)
    units: "dict[str, int]" = field(default_factory=dict)   # bucket (wallet|plan|postpaid) -> credits (first wins)

    @property
    def key(self) -> "tuple[str, str, str]":
        return self.org_id, self.slug, self.nonce

    @property
    def reserved(self) -> int:
        return sum(self.units.values())


@dataclass
class ReservationIndex:
    """What the spine (up to seq ``through``) says about launch reservations and their settlement."""
    through: int = -1
    reservations: "dict[tuple[str, str, str], Reservation]" = field(default_factory=dict)
    settled: "set[tuple[str, str, str]]" = field(default_factory=set)    # owner-signed settlement evidence
    outcomes: "set[tuple[str, str, str]]" = field(default_factory=set)   # a drained settle's outcome record

    def of(self, org_id: str, slug: str) -> "list[Reservation]":
        """The reservations of one ``(org, slug)``, oldest first."""
        return sorted((r for r in self.reservations.values() if r.org_id == org_id and r.slug == slug),
                      key=lambda r: r.seq)


def scan_reservations(store, trusted_pubkey: Optional[str], *, org_id: Optional[str] = None,
                      slug: Optional[str] = None, since: Optional[ReservationIndex] = None) -> ReservationIndex:
    """Scan the spine for launch reservations + their settlement evidence (see the module docstring); with
    ``since``, continue that earlier scan over only the records appended after it. Total on hostile payloads."""
    ix = since if since is not None else ReservationIndex()
    if not trusted_pubkey:
        return ix
    resolver = None
    for r in store.iter_records(since_seq=ix.through):
        if r.seq > ix.through:
            ix.through = r.seq
        p = r.payload
        if not isinstance(p, dict):
            continue
        oid = p.get("org_id")
        if not isinstance(oid, str) or not oid or (org_id is not None and oid != org_id):
            continue
        if r.kind == ASSESSMENT_OUTCOME_KIND:
            s, n = p.get("engagement_slug"), p.get("nonce")
            if isinstance(s, str) and isinstance(n, str) and s and n and (slug is None or s == slug):
                ix.outcomes.add((oid, s, n))
            continue
        sig = p.get("signal")
        lease: "Optional[tuple[str, str]]"
        cores: "tuple[tuple[str, ...], ...]"
        bucket: Optional[str] = None
        if sig == LAUNCH_SETTLED_SIGNAL:
            s, n = p.get("slug"), p.get("nonce")
            if not (isinstance(s, str) and isinstance(n, str) and s and n):
                continue
            # any owner-signed decision record SETTLES the lease, a malformed or legacy one included (exactly as
            # scan_settlement reads it)
            lease, cores = (s, n), (_SETTLED_CORE_V2, _SETTLED_CORE_V1)
        elif sig in _RESERVE:
            prefix, core, bucket = _RESERVE[sig]
            lease, cores = _lease_of(p.get("entry_id"), prefix), (core,)
        elif sig in _SETTLE:
            prefix, core = _SETTLE[sig]
            lease, cores = _lease_of(p.get("entry_id"), prefix), (core,)
        else:
            continue
        if lease is None or (slug is not None and lease[0] != slug):
            continue
        key = (oid, lease[0], lease[1])
        if bucket is None and key in ix.settled:
            continue                                  # already settled: nothing more to learn from this record
        if resolver is None:
            resolver = _kh.key_resolver(store, current=trusted_pubkey)
        key_at = resolver.at(r.seq)
        if not any(verify_signed(p, c, key_at) for c in cores):
            continue                                  # fail-closed: unsigned / forged / wrong-epoch record
        if bucket is None:
            ix.settled.add(key)
            continue
        res = ix.reservations.get(key)
        if res is None:
            res = ix.reservations[key] = Reservation(oid, lease[0], lease[1], seq=int(r.seq),
                                                     issued_at=_issued_at(p.get("issued_at")))
        res.units.setdefault(bucket, _credits(p.get("credits")))   # first record per bucket wins (idempotent)
    return ix
