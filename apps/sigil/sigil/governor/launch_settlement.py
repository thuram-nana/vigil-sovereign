"""Launch SETTLEMENT exactly-once: the cross-process settle lock + the owner-signed record of a settle DECISION.

``LaunchGate.settle_launch`` must take effect at most once per lease ``(slug, nonce)``, whichever caller drives it
and in whichever process: the settle-drain (a run's completion), ``ops-sweep reservations --apply`` (an abandoned
launch) and the cockpit's / customer server's ``launch_cancel`` run in separate processes. Three pieces live here.

``settle_lock(store)`` — the CROSS-PROCESS critical section around "is this lease already settled? -> record ->
move money". A hardened flock (``vigil_integration.live.seam_lock.locked_file``: no symlink, regular file only,
a BOUNDED wait that raises :data:`SettleLockBusy`, fail-closed without ``fcntl``) on ``<stem>.settle.lock`` beside
the spine, so every process settling against one money ledger is serialized, whatever seam directory it resolves.
It is a separate file from the spine's own append lock on purpose (a settle appends INSIDE this section). Each
entry flocks a fresh fd, so it is NOT re-entrant: never nest it.

LOCK ORDER (one global order, outermost first; a lock is only ever requested strictly inside the ones held):
``LaunchGate._publish_lock`` (publish, metering only) -> ``spine_lock`` (the per-process RLock) -> ``settle_lock``
-> leaves (the GrantMeter flock, the settlement / pause / past-expiry marker locks, the completion spool lock, the
spine's append flock). Leaves are never nested in each other, and no leaf holder requests ``spine_lock`` or
``settle_lock``. Every cross-process wait at ``settle_lock`` and at the leaves is bounded and ends in a retry or
a refusal.

``record_launch_settled(...)`` — the owner-signed DECISION of a fresh settle (``governor.launch_settled`` v2),
appended BEFORE any money moves while ``config.settle_spine_record_enabled()`` is on. It records everything the
settle will move, so a later settle that finds it (a crash interrupted the first) finishes it from the RECORD alone
— never re-deriving the split from a live, prune-sensitive debit scan, never from its own caller's consumption:

  * ``mode`` (``prepaid`` / ``postpaid``), ``reserved`` (the owner-signed lease's units), ``consumed``;
  * the exact split: ``refund_plan`` (into the ``plan_period_end`` tranche), ``refund_wallet``, ``refund_postpaid``;
  * ``basis`` — which caller decided it (``completion:<outcome>``, ``cancel``, ``sweep:refund``, ``sweep:paused``,
    ``settle``).

Invariants, checked when written (``ValueError`` before signing) and again when scanned: every amount a
non-negative, non-bool int; ``consumed <= reserved``; prepaid: ``refund_plan + refund_wallet == reserved -
consumed`` and ``refund_postpaid == 0``; postpaid: ``refund_postpaid == reserved - consumed`` and no plan / wallet
refund; ``plan_period_end`` finite, ``>= 0`` and ``> 0`` whenever ``refund_plan > 0``; ``basis`` a short str.

``scan_settlement(...)`` — what the SPINE says about one lease's settlement: the FIRST verified decision record
(``decision``; an owner-signed record that fails the invariants, or a legacy v1 record, is ``malformed`` — still
SETTLED, so it blocks a fresh settle, but never rolled forward), and the owner-signed settle entries that landed
(``landed``: ``wallet`` / ``plan`` / ``postpaid`` under ``settle-wallet:`` / ``settle-plan:`` /
``settle-postpaid:``). Every record is verified under the owner key valid AT ITS SEQ (succession-aware),
fail-closed: an unsigned or foreign-signed record is ignored. Total on hostile payloads.

The scan is LIVE (no snapshot seed), so it is NOT prune-durable (OWNER DECISION OD-3): a caller does the full scan
BEFORE taking the lock and re-scans only the records appended since (``since``) inside it. A roll-forward never
trusts a live miss alone: before it writes a recorded entry the live scan did not find, it confirms the entry is
absent from the snapshot-seeded seen-sets (``WalletRegistry.has_grant_entry``,
``PlanCreditLedger.has_grant_entry``, ``PostpaidArrearsLedger.has_credit_entry``), so a pruned refund is never
re-issued.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, ``assert_no_offense()`` at import.
"""
from __future__ import annotations

import math
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_integration.live.seam_lock import LockBusy, locked_file  # noqa: E402  (stdlib-only, both planes)

from . import key_history as _kh  # noqa: E402
from .authn import signed_payload, verify_signed  # noqa: E402
from .metering import _PLAN_GRANT_CORE, PLAN_GRANT_SIGNAL  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402
from .postpaid import _PP_CREDIT_CORE, POSTPAID_CREDIT_SIGNAL, SETTLE_ENTRY_PREFIX  # noqa: E402
from .wallet import _GRANT_CORE, CREDIT_GRANT_SIGNAL  # noqa: E402

LAUNCH_SETTLED_SIGNAL = "governor.launch_settled"
SETTLED_RECORD_VERSION = 2
_SETTLED_CORE_V2 = ("signal", "v", "org_id", "slug", "nonce", "mode", "reserved", "consumed", "refund_plan",
                    "refund_wallet", "refund_postpaid", "plan_period_end", "basis", "issued_at")
#: The E3bc-draft record (``consumed`` only). Read-only: a verified v1 record is SETTLED but malformed (it carries no
#: split, so it is never rolled forward), and nothing writes it any more.
_SETTLED_CORE_V1 = ("signal", "org_id", "slug", "nonce", "consumed", "issued_at")
SETTLE_WALLET_PREFIX = "settle-wallet:"
SETTLE_PLAN_PREFIX = "settle-plan:"
MODE_PREPAID, MODE_POSTPAID = "prepaid", "postpaid"
#: Which caller decided a settlement (the record's ``basis``).
BASES = frozenset({"completion:completed", "completion:canceled", "completion:failed", "cancel", "sweep:refund",
                   "sweep:paused", "settle"})
_MAX_BASIS = 64

#: The bounded wait of :func:`settle_lock` timed out: another settle / publish holds it. Retry; nothing was done.
SettleLockBusy = LockBusy


# ---------------------------------------------------------------------------------------------------------------
# the cross-process settle lock
# ---------------------------------------------------------------------------------------------------------------

def settle_lock_path(store) -> Path:
    """``<spine dir>/<stem>.settle.lock`` for ``store`` (namespaced by the spine data file's stem, like the
    spine's own ``<stem>.lock``; a ``*.lock`` is a transient both backup legs skip)."""
    raw = getattr(store, "path", None)
    if not raw:
        raise ValueError("the settle lock needs a spine store with a path")
    p = Path(raw)
    return p.parent / f"{p.stem or p.name}.settle.lock"


@contextmanager
def settle_lock(store, *, wait_s: Optional[float] = None) -> Iterator[None]:
    """Hold the cross-process settle critical section for ``store``'s spine (see the module docstring). Waits at
    most ``wait_s`` (default ``config.settle_lock_wait_s()``), then raises :data:`SettleLockBusy`; an unusable lock
    file (or no ``fcntl``) raises ``OSError``; a store without a path raises ``ValueError``. Nothing is held when
    it raises."""
    from .. import config
    path = settle_lock_path(store)
    with locked_file(path, wait_s=config.settle_lock_wait_s() if wait_s is None else float(wait_s)):
        yield


# ---------------------------------------------------------------------------------------------------------------
# the settlement decision
# ---------------------------------------------------------------------------------------------------------------

def _amount(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


@dataclass(frozen=True)
class SettlementDecision:
    """What ONE settle of a lease decided: its mode, the owner-signed reservation, the consumption it charged and
    the exact refund split (see the module docstring for the invariants :meth:`validate` enforces)."""
    mode: str
    reserved: int
    consumed: int
    refund_plan: int
    refund_wallet: int
    refund_postpaid: int
    plan_period_end: float
    basis: str

    @classmethod
    def prepaid(cls, reserved: int, consumed: int, refund_plan: int, refund_wallet: int, plan_period_end: float,
                basis: str) -> "SettlementDecision":
        return cls(MODE_PREPAID, reserved, consumed, refund_plan, refund_wallet, 0, plan_period_end, basis)

    @classmethod
    def postpaid(cls, reserved: int, consumed: int, basis: str) -> "SettlementDecision":
        return cls(MODE_POSTPAID, reserved, consumed, 0, 0, reserved - consumed if _amount(reserved) and
                   _amount(consumed) else -1, 0.0, basis)

    def validate(self) -> Optional[str]:
        """None when every invariant holds, else the first one that does not (a short reason)."""
        if self.mode not in (MODE_PREPAID, MODE_POSTPAID):
            return "unknown mode"
        for name in ("reserved", "consumed", "refund_plan", "refund_wallet", "refund_postpaid"):
            if not _amount(getattr(self, name)):
                return f"{name} is not a non-negative int"
        if self.consumed > self.reserved:
            return "consumed exceeds the reservation"
        unused = self.reserved - self.consumed
        if self.mode == MODE_PREPAID:
            if self.refund_plan + self.refund_wallet != unused or self.refund_postpaid != 0:
                return "prepaid split does not sum to the unused reservation"
        elif self.refund_postpaid != unused or self.refund_plan != 0 or self.refund_wallet != 0:
            return "postpaid refund is not the unused reservation"
        pe = self.plan_period_end
        if isinstance(pe, bool) or not isinstance(pe, (int, float)) or not math.isfinite(pe) or pe < 0:
            return "plan_period_end is not a finite non-negative number"
        if self.refund_plan > 0 and not pe > 0:
            return "a plan refund needs its tranche's period_end"
        if not isinstance(self.basis, str) or not self.basis or len(self.basis) > _MAX_BASIS:
            return "basis is not a short string"
        return None


def record_launch_settled(store, owner_key, *, org_id: str, slug: str, nonce: str, decision: SettlementDecision,
                          issued_at: float) -> int:
    """Owner-sign + append the settlement DECISION for lease ``(slug, nonce)``. Returns its seq. Raises
    ``ValueError`` on a missing owner key, an invalid org, an empty id, a decision that fails an invariant or a
    basis outside :data:`BASES` — so the caller fails the settle CLOSED before any money moves."""
    if owner_key is None:
        raise ValueError("a launch settlement record requires the owner signing key")
    oid = org_tenant_id(org_id)
    s, n = str(slug or ""), str(nonce or "")
    if not s or not n:
        raise ValueError("a launch settlement record needs a slug and a nonce")
    if not isinstance(decision, SettlementDecision):
        raise ValueError("a launch settlement record needs a SettlementDecision")
    why = decision.validate()
    if why is not None:
        raise ValueError(f"invalid launch settlement decision: {why}")
    if decision.basis not in BASES:
        raise ValueError("invalid launch settlement decision: unknown basis")
    d = decision
    core = {"signal": LAUNCH_SETTLED_SIGNAL, "v": SETTLED_RECORD_VERSION, "org_id": oid, "slug": s, "nonce": n,
            "mode": d.mode, "reserved": int(d.reserved), "consumed": int(d.consumed),
            "refund_plan": int(d.refund_plan), "refund_wallet": int(d.refund_wallet),
            "refund_postpaid": int(d.refund_postpaid), "plan_period_end": float(d.plan_period_end),
            "basis": d.basis, "issued_at": float(issued_at)}
    payload = {**signed_payload(core, owner_key), "by": "owner", "requested_by": "owner", "tier": "A0",
               "decision": "auto",
               "reason": f"launch settled {s}:{n} ({d.mode}, consumed {int(d.consumed)} of {int(d.reserved)}, "
                         f"{d.basis}) -> {oid}"}
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def _decision_from(p: Any) -> "Optional[SettlementDecision]":
    """The decision a VERIFIED v2 payload carries, or None when it fails an invariant (malformed)."""
    if p.get("v") != SETTLED_RECORD_VERSION:
        return None
    try:
        d = SettlementDecision(mode=p.get("mode"), reserved=p.get("reserved"), consumed=p.get("consumed"),
                               refund_plan=p.get("refund_plan"), refund_wallet=p.get("refund_wallet"),
                               refund_postpaid=p.get("refund_postpaid"), plan_period_end=p.get("plan_period_end"),
                               basis=p.get("basis"))
        if d.validate() is not None:
            return None
        return SettlementDecision(d.mode, d.reserved, d.consumed, d.refund_plan, d.refund_wallet, d.refund_postpaid,
                                  float(d.plan_period_end), d.basis)
    except (TypeError, ValueError, OverflowError):
        return None


# ---------------------------------------------------------------------------------------------------------------
# the spine evidence of a settlement
# ---------------------------------------------------------------------------------------------------------------

@dataclass
class SettlementEvidence:
    """What the spine (up to seq ``through``) says about one lease's settlement."""
    through: int = -1                     # the highest seq scanned so far (-1: nothing yet)
    record_seq: Optional[int] = None      # the FIRST verified governor.launch_settled record for the lease
    decision: Optional[SettlementDecision] = None   # ...its decision, when it is a well-formed v2 record
    malformed: bool = False               # ...True when that first record is owner-signed but unusable (or v1)
    landed: "set[str]" = field(default_factory=set)   # verified settle entries on the spine: wallet/plan/postpaid

    @property
    def settled(self) -> bool:
        return self.record_seq is not None or bool(self.landed)

    @property
    def consumed(self) -> Optional[int]:
        return self.decision.consumed if self.decision is not None else None


def scan_settlement(store, trusted_pubkey: Optional[str], *, org_id: str, slug: str, nonce: str,
                    since: Optional[SettlementEvidence] = None) -> SettlementEvidence:
    """Scan the spine for the settlement evidence of lease ``(org_id, slug, nonce)``; with ``since``, continue
    that earlier scan over only the records appended after it (``since`` is updated in place and returned). The
    FIRST verified decision record wins. Total on hostile payloads (they are skipped)."""
    ev = since if since is not None else SettlementEvidence()
    if not (trusted_pubkey and org_id and slug and nonce):
        return ev
    s, n = str(slug), str(nonce)
    tail = f"{s}:{n}"
    wanted: "dict[str, tuple[str, tuple[str, ...], str]]" = {
        CREDIT_GRANT_SIGNAL: (f"{SETTLE_WALLET_PREFIX}{tail}", _GRANT_CORE, "wallet"),
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
        if sig == LAUNCH_SETTLED_SIGNAL:
            if ev.record_seq is not None or p.get("slug") != s or p.get("nonce") != n:
                continue
            if resolver is None:
                resolver = _kh.key_resolver(store, current=trusted_pubkey)
            key = resolver.at(r.seq)
            if verify_signed(p, _SETTLED_CORE_V2, key):
                ev.record_seq = int(r.seq)
                ev.decision = _decision_from(p)
                ev.malformed = ev.decision is None
            elif verify_signed(p, _SETTLED_CORE_V1, key):
                ev.record_seq, ev.decision, ev.malformed = int(r.seq), None, True   # legacy: settled, never rolled
            continue                                  # unsigned / forged / wrong-epoch: ignored (fail-closed)
        if sig not in wanted:
            continue
        eid, core, tag = wanted[sig]
        if p.get("entry_id") != eid:
            continue
        if resolver is None:
            resolver = _kh.key_resolver(store, current=trusted_pubkey)
        if verify_signed(p, core, resolver.at(r.seq)):
            ev.landed.add(tag)
    return ev
