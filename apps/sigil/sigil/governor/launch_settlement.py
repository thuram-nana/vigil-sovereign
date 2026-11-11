"""Launch SETTLEMENT exactly-once: the cross-process settle lock + the spine evidence of a settlement.

``LaunchGate.settle_launch`` must take effect at most once per lease ``(slug, nonce)``, whichever caller drives it
and in whichever process: the settle-drain (a completed run, refund 0), ``ops-sweep reservations --apply`` and
the cockpit's ``launch_cancel`` (both a full refund) run in THREE processes. Two pieces live here.

``settle_lock(store)`` — the CROSS-PROCESS critical section around "is this lease already settled? -> record ->
move money". It flocks a lockfile beside the spine (``<stem>.settle.lock``), so every process settling against
the same money ledger (the spine) is serialized, whatever seam directory each one resolves. It is a separate
file from the spine's own append lock on purpose: a settle appends to the spine INSIDE this section, and a second
flock on the spine's lockfile from a new fd would self-deadlock. Re-entrant per thread (the flock is taken once,
at the outermost entry). FAIL-CLOSED: a lockfile that cannot be opened or locked raises, so the settle moves
nothing. Lock order: callers hold the per-process ``spine_lock`` FIRST, then this; nothing takes them reversed.

``scan_settlement(...)`` — what the SPINE says about one lease's settlement. A lease is settled on the spine when
it carries an owner-signed ``governor.launch_settled`` record for it (the DECISION, written first by every
settle while ``config.settle_spine_record_enabled()`` is on; it carries the decided ``consumed`` so a later
settle can complete a decision a crash interrupted), or an owner-signed settle grant/credit under the lease's
settle entry id (``settle-wallet:`` / ``settle-plan:`` / ``settle-postpaid:`` — a refund that moved money, or a
postpaid settle, which is always written). The seam settlement marker stays the cross-plane projection the
keyless arm reads; it can be lost with the seam directory, these records cannot be lost with it.

Every record is verified under the owner key valid AT ITS SEQ (succession-aware), fail-closed: an unsigned or
foreign-signed record is ignored. The scan is a LIVE scan of the spine (no snapshot seed — like
``PlanCreditLedger.debited_entry``), so a caller does the full scan BEFORE taking the lock and re-scans only the
records appended since (``since``) inside it. The owner-key resolver is built only when a candidate record
matches.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .metering import _PLAN_GRANT_CORE, PLAN_GRANT_SIGNAL  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402
from .postpaid import _PP_CREDIT_CORE, POSTPAID_CREDIT_SIGNAL, SETTLE_ENTRY_PREFIX  # noqa: E402
from .wallet import _GRANT_CORE, CREDIT_GRANT_SIGNAL  # noqa: E402

try:
    import fcntl  # POSIX advisory lock — the cross-process settle critical section
except ImportError:  # pragma: no cover — non-POSIX: in-process serialization only (as the spine's own lock)
    fcntl = None  # type: ignore[assignment]

LAUNCH_SETTLED_SIGNAL = "governor.launch_settled"
_SETTLED_CORE = ("signal", "org_id", "slug", "nonce", "consumed", "issued_at")
SETTLE_WALLET_PREFIX = "settle-wallet:"
SETTLE_PLAN_PREFIX = "settle-plan:"


# ---------------------------------------------------------------------------------------------------------------
# the cross-process settle lock
# ---------------------------------------------------------------------------------------------------------------

class _SettleLock:
    __slots__ = ("rlock", "depth", "fd")

    def __init__(self) -> None:
        self.rlock = threading.RLock()
        self.depth = 0
        self.fd: Optional[int] = None


_LOCKS_GUARD = threading.Lock()
_LOCKS: "dict[str, _SettleLock]" = {}


def settle_lock_path(store) -> Path:
    """``<spine dir>/<stem>.settle.lock`` for ``store`` (namespaced by the spine data file's stem, like the
    spine's own ``<stem>.lock``; a ``*.lock`` is a transient both backup legs skip)."""
    raw = getattr(store, "path", None)
    if not raw:
        raise ValueError("the settle lock needs a spine store with a path")
    p = Path(raw)
    return p.parent / f"{p.stem or p.name}.settle.lock"


@contextmanager
def settle_lock(store) -> Iterator[None]:
    """Hold the cross-process settle critical section for ``store``'s spine (see the module docstring)."""
    lockp = settle_lock_path(store)
    key = str(lockp.resolve())
    with _LOCKS_GUARD:
        lk = _LOCKS.get(key)
        if lk is None:
            lk = _LOCKS[key] = _SettleLock()
    with lk.rlock:
        if lk.depth == 0:
            fd = os.open(str(lockp), os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)
            except BaseException:
                os.close(fd)
                raise
            lk.fd = fd
        lk.depth += 1
        try:
            yield
        finally:
            lk.depth -= 1
            if lk.depth == 0:
                held, lk.fd = lk.fd, None
                if held is not None:
                    os.close(held)                   # closing the only fd releases the flock


# ---------------------------------------------------------------------------------------------------------------
# the settlement record + the spine evidence of a settlement
# ---------------------------------------------------------------------------------------------------------------

def record_launch_settled(store, owner_key, *, org_id: str, slug: str, nonce: str, consumed: int,
                          issued_at: float) -> int:
    """Owner-sign + append the settlement DECISION for lease ``(slug, nonce)`` (``consumed``, already clamped to
    the signed reservation by the caller). Returns its seq. Raises on a missing owner key / invalid org / empty
    id, so the caller fails the settle CLOSED before any money moves."""
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


@dataclass
class SettlementEvidence:
    """What the spine (up to seq ``through``) says about one lease's settlement."""
    through: int = -1                     # the highest seq scanned so far (-1: nothing yet)
    record_seq: Optional[int] = None      # the FIRST verified governor.launch_settled record for the lease
    consumed: Optional[int] = None        # ...and the consumption it decided
    landed: "set[str]" = field(default_factory=set)   # verified settle entries on the spine: wallet/plan/postpaid

    @property
    def settled(self) -> bool:
        return self.record_seq is not None or bool(self.landed)


def scan_settlement(store, trusted_pubkey: Optional[str], *, org_id: str, slug: str, nonce: str,
                    since: Optional[SettlementEvidence] = None) -> SettlementEvidence:
    """Scan the spine for the settlement evidence of lease ``(org_id, slug, nonce)``; with ``since``, continue
    that earlier scan over only the records appended after it. Total on hostile payloads (they are skipped)."""
    ev = since if since is not None else SettlementEvidence()
    if not (trusted_pubkey and org_id and slug and nonce):
        return ev
    s, n = str(slug), str(nonce)
    tail = f"{s}:{n}"
    wanted: "dict[str, tuple[str, tuple[str, ...], str]]" = {CREDIT_GRANT_SIGNAL: (f"{SETTLE_WALLET_PREFIX}{tail}", _GRANT_CORE, "wallet"),
              PLAN_GRANT_SIGNAL: (f"{SETTLE_PLAN_PREFIX}{tail}", _PLAN_GRANT_CORE, "plan"),
              POSTPAID_CREDIT_SIGNAL: (f"{SETTLE_ENTRY_PREFIX}{tail}", _PP_CREDIT_CORE, "postpaid")}
    resolver = None
    for r in store.iter_records(since_seq=ev.through):
        if r.seq > ev.through:
            ev.through = r.seq
        p = r.payload
        if not isinstance(p, dict) or p.get("org_id") != org_id:
            continue
        sig = p.get("signal")
        core: "tuple[str, ...]"
        tag: Optional[str]
        if sig == LAUNCH_SETTLED_SIGNAL:
            if ev.record_seq is not None or p.get("slug") != s or p.get("nonce") != n:
                continue
            core, tag = _SETTLED_CORE, None
        elif sig in wanted:
            eid, core, tag = wanted[sig]
            if p.get("entry_id") != eid or tag in ev.landed:
                continue
        else:
            continue
        if resolver is None:
            resolver = _kh.key_resolver(store, current=trusted_pubkey)
        if not verify_signed(p, core, resolver.at(r.seq)):
            continue                                  # fail-closed: unsigned / forged / wrong-epoch record
        if tag is None:
            c = p.get("consumed")
            if isinstance(c, bool) or not isinstance(c, int):
                continue                              # a signed record always carries an int; anything else: skip
            ev.consumed, ev.record_seq = max(0, c), int(r.seq)
        else:
            ev.landed.add(tag)
    return ev
