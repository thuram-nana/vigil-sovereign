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
fail-closed: an unsigned or foreign-signed record is ignored. Total on hostile payloads. ``scan_settlements(...)``
reads the same evidence for MANY leases in one pass over the spine (a sweep or a drain pass that checks every lease
it lists never scans the spine once per lease).

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
from vigil_core.rate_card import MC_PER_CREDIT  # noqa: E402  (W2c-1: one credit = 1,000 milli-credits)

LAUNCH_SETTLED_SIGNAL = "governor.launch_settled"
#: A customer cancel that was HELD for the owner (``launch_gate.PLAN_DEBIT_PRUNED``: nothing moved) leaves this marker
#: for its lease ``(org_id, slug, nonce)``, so the reservation the customer was told stays reserved can never be
#: started afterwards (``SettlementEvidence.cancel_held``; ``LaunchGate.publish_lease`` refuses it). It only ever
#: REFUSES a start — the safe direction — so it is accepted unsigned, as the kill switch's engage is.
LAUNCH_CANCEL_HELD_SIGNAL = "launch.cancel_held"
SETTLED_RECORD_VERSION = 2
_SETTLED_CORE_V2 = ("signal", "v", "org_id", "slug", "nonce", "mode", "reserved", "consumed", "refund_plan",
                    "refund_wallet", "refund_postpaid", "plan_period_end", "basis", "issued_at")
#: W2c-1 — the EXACT (milli-credit) decision of a metered settle: the v2 core plus the run's exact consumption and the
#: org's sub-credit usage remainder before and after it. ``consumed`` keeps its v2 meaning (the WHOLE credits the
#: settle keeps of the reservation): ``remainder_before + consumed_mc == 1000 * consumed + remainder_after``. The
#: record is the ONLY place the remainder moves (the wallet fold sums ``consumed_mc``), so a settle and its remainder
#: are one signed commit.
EXACT_RECORD_VERSION = 3
_SETTLED_CORE_V3 = _SETTLED_CORE_V2 + ("consumed_mc", "remainder_before", "remainder_after")
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
    it raises.

    An absent lock file is created ``O_EXCL`` and, when this process is root (a ``sudo ops-sweep``), handed to the
    owner of the spine directory (``locked_file(create=False, chown_like=...)``, as the completion spool lock is),
    so the services that settle as that user can always open it."""
    from .. import config
    path = settle_lock_path(store)
    with locked_file(path, wait_s=config.settle_lock_wait_s() if wait_s is None else float(wait_s), create=False,
                     chown_like=path.parent):
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
    # W2c-1 — present together on an EXACT (v3) decision, absent (None) on a v2 one.
    consumed_mc: Optional[int] = None
    remainder_before: Optional[int] = None
    remainder_after: Optional[int] = None

    @property
    def exact(self) -> bool:
        """True for an exact (v3, milli-credit) decision."""
        return self.consumed_mc is not None

    def with_exact(self, consumed_mc: int, remainder_before: int) -> "SettlementDecision":
        """This decision with its exact consumption and the org's remainder before it; ``remainder_after`` follows
        (``(remainder_before + consumed_mc) % 1000``). The caller has already set ``consumed`` to the floor of the
        whole credits — :meth:`validate` refuses a decision whose parts do not reconcile."""
        from dataclasses import replace
        return replace(self, consumed_mc=consumed_mc, remainder_before=remainder_before,
                       remainder_after=(remainder_before + consumed_mc) % MC_PER_CREDIT
                       if _amount(consumed_mc) and _amount(remainder_before) else -1)

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
        cmc, rb, ra = self.consumed_mc, self.remainder_before, self.remainder_after
        if cmc is not None or rb is not None or ra is not None:
            if not (isinstance(cmc, int) and isinstance(rb, int) and isinstance(ra, int)
                    and _amount(cmc) and _amount(rb) and _amount(ra)):
                return "an exact decision needs consumed_mc, remainder_before and remainder_after as non-negative ints"
            if rb >= MC_PER_CREDIT or ra >= MC_PER_CREDIT:
                return "a remainder is not below one credit"
            if cmc > MC_PER_CREDIT * self.reserved:
                return "consumed_mc exceeds the reservation"
            # the floor, exactly: never a charge rounded up, never a remainder dropped
            if rb + cmc != MC_PER_CREDIT * self.consumed + ra:
                return "the exact consumption does not reconcile with the whole-credit debit and the remainder"
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
    core = {"signal": LAUNCH_SETTLED_SIGNAL, "v": EXACT_RECORD_VERSION if d.exact else SETTLED_RECORD_VERSION,
            "org_id": oid, "slug": s, "nonce": n,
            "mode": d.mode, "reserved": int(d.reserved), "consumed": int(d.consumed),
            "refund_plan": int(d.refund_plan), "refund_wallet": int(d.refund_wallet),
            "refund_postpaid": int(d.refund_postpaid), "plan_period_end": float(d.plan_period_end),
            "basis": d.basis, "issued_at": float(issued_at)}
    reason = (f"launch settled {s}:{n} ({d.mode}, consumed {int(d.consumed)} of {int(d.reserved)}, "
              f"{d.basis}) -> {oid}")
    if d.exact:            # W2c-1: the exact consumption and the org's remainder, inside the signed core
        # (validate() above has proved all three are non-negative ints)
        core.update(consumed_mc=d.consumed_mc, remainder_before=d.remainder_before, remainder_after=d.remainder_after)
        reason = (f"launch settled {s}:{n} ({d.mode}, {d.consumed_mc} mc -> {int(d.consumed)} of "
                  f"{int(d.reserved)} credits, remainder {d.remainder_before} -> {d.remainder_after} mc, "
                  f"{d.basis}) -> {oid}")
    payload = {**signed_payload(core, owner_key), "by": "owner", "requested_by": "owner", "tier": "A0",
               "decision": "auto", "reason": reason}
    return store.append(kind="event", source="governor", actor="WARDEN", payload=payload)


def _decision_from(p: Any) -> "Optional[SettlementDecision]":
    """The decision a VERIFIED v2 or v3 (exact) payload carries, or None when it fails an invariant (malformed) — a
    v3 payload without its three exact fields included."""
    v = p.get("v")
    if v not in (SETTLED_RECORD_VERSION, EXACT_RECORD_VERSION):
        return None
    try:
        exact = ({"consumed_mc": p.get("consumed_mc"), "remainder_before": p.get("remainder_before"),
                  "remainder_after": p.get("remainder_after")} if v == EXACT_RECORD_VERSION else {})
        if exact and any(x is None for x in exact.values()):
            return None
        d = SettlementDecision(mode=p.get("mode"), reserved=p.get("reserved"), consumed=p.get("consumed"),
                               refund_plan=p.get("refund_plan"), refund_wallet=p.get("refund_wallet"),
                               refund_postpaid=p.get("refund_postpaid"), plan_period_end=p.get("plan_period_end"),
                               basis=p.get("basis"), **exact)
        if d.validate() is not None:
            return None
        return SettlementDecision(d.mode, d.reserved, d.consumed, d.refund_plan, d.refund_wallet, d.refund_postpaid,
                                  float(d.plan_period_end), d.basis, d.consumed_mc, d.remainder_before,
                                  d.remainder_after)
    except (TypeError, ValueError, OverflowError):
        return None


def verified_settle_core(p: Any, key: Any) -> "Optional[tuple[str, ...]]":
    """The core an owner-signed ``governor.launch_settled`` payload verifies under — v3, v2 or the legacy v1 — or None
    (unsigned / forged / wrong epoch). Tries the core its ``v`` claims first, then every other: ANY owner-signed record
    is a settlement (fail-closed), whatever version it claims; :func:`_decision_from` then decides if it is usable."""
    claimed = _SETTLED_CORE_V3 if p.get("v") == EXACT_RECORD_VERSION else _SETTLED_CORE_V2
    for core in (claimed, _SETTLED_CORE_V2 if claimed is _SETTLED_CORE_V3 else _SETTLED_CORE_V3, _SETTLED_CORE_V1):
        if verify_signed(p, core, key):
            return core
    return None


def decision_of(p: Any, core: "Optional[tuple[str, ...]]") -> "Optional[SettlementDecision]":
    """The decision of a payload :func:`verified_settle_core` matched under ``core`` — usable only when that core is
    the one its ``v`` claims (so every field the decision reads is signed), else None: the record still SETTLES the
    lease but is malformed (never rolled forward, moves no remainder)."""
    want = {SETTLED_RECORD_VERSION: _SETTLED_CORE_V2, EXACT_RECORD_VERSION: _SETTLED_CORE_V3}.get(p.get("v"))
    return _decision_from(p) if want is not None and core is want else None


def fold_exact_settle(p: Any, key_at_seq: Any, seen: set, usage: dict) -> None:
    """W2c-1 — THE fold step of the org's lifetime exact usage (``usage[org] = Σ consumed_mc``), shared by the wallet
    fold, its verified fold cache, ``SnapshotState.build`` and the prune tripwire so none can diverge. A
    ``governor.launch_settled`` v3 record verified under the owner key valid at its seq counts ONCE per lease —
    ``(signal, org, "slug:nonce")`` in the wallet's own (prune-durable) seen-set — and only when its decision is well
    formed (a malformed one is still consumed, so a later copy can never count). v1 / v2 records carry no exact
    usage and are skipped before any signature work. The org's remainder is ``usage[org] % 1000``."""
    if not isinstance(p, dict) or p.get("signal") != LAUNCH_SETTLED_SIGNAL or p.get("v") != EXACT_RECORD_VERSION:
        return
    oid, s, n = p.get("org_id"), p.get("slug"), p.get("nonce")
    if not (isinstance(oid, str) and oid and isinstance(s, str) and s and isinstance(n, str) and n):
        return
    key = (LAUNCH_SETTLED_SIGNAL, oid, f"{s}:{n}")
    if key in seen or not verify_signed(p, _SETTLED_CORE_V3, key_at_seq):
        return
    seen.add(key)
    d = _decision_from(p)
    if d is not None and d.consumed_mc is not None:      # a well-formed exact decision
        usage[oid] = usage.get(oid, 0) + d.consumed_mc


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
    cancel_held: bool = False             # a customer cancel of this lease was held for the owner: never start it

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
        if sig == LAUNCH_CANCEL_HELD_SIGNAL:
            if p.get("slug") == s and p.get("nonce") == n:
                ev.cancel_held = True
            continue
        if sig == LAUNCH_SETTLED_SIGNAL:
            if ev.record_seq is not None or p.get("slug") != s or p.get("nonce") != n:
                continue
            if resolver is None:
                resolver = _kh.key_resolver(store, current=trusted_pubkey)
            core = verified_settle_core(p, resolver.at(r.seq))
            if core is _SETTLED_CORE_V1:
                ev.record_seq, ev.decision, ev.malformed = int(r.seq), None, True   # legacy: settled, never rolled
            elif core is not None:
                ev.record_seq = int(r.seq)
                ev.decision = decision_of(p, core)
                ev.malformed = ev.decision is None
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


def scan_settlements(store, trusted_pubkey: Optional[str], *,
                     keys: "Any") -> "dict[tuple[str, str, str], SettlementEvidence]":
    """:func:`scan_settlement` for MANY leases in ONE pass over the spine: ``{(org_id, slug, nonce): evidence}`` for
    every lease in ``keys`` (an iterable of ``(org_id, slug, nonce)``), each exactly what ``scan_settlement`` of
    that lease returns — the same matching (the record's ``org_id``; the decision's ``slug`` / ``nonce``; the settle
    entry's exact entry id), the same first-verified-decision rule, the same succession-aware verification. Only the
    records of the listed leases are verified. A lease with an empty part gets an empty evidence (as
    ``scan_settlement`` returns for it). Total on hostile payloads."""
    return scan_settlements_since(store, trusted_pubkey, keys=keys)[0]


def scan_settlements_since(store, trusted_pubkey: Optional[str], *, keys: "Any",
                           since: "Optional[dict[tuple[str, str, str], SettlementEvidence]]" = None,
                           since_seq: int = -1) -> "tuple[dict[tuple[str, str, str], SettlementEvidence], int, Optional[str]]":
    """:func:`scan_settlements`, CONTINUED: each lease in ``keys`` starts from its evidence in ``since`` (copied, never
    changed in place) or from an empty one, and only the records after ``since_seq`` are read. Returns ``(evidence,
    through, through_hash)``: the evidence of every lease, the highest seq read (``since_seq`` when nothing was) and
    the ``entry_hash`` of that last record (None when nothing was read). Re-reading a record a lease's evidence
    already covers changes nothing (the first verified decision wins; ``landed`` is a set), so a caller may start
    below what a carried evidence covers. With ``since=None`` and ``since_seq=-1`` this is exactly
    :func:`scan_settlements`. Raises what the spine read raises."""
    want: "dict[tuple[str, str, str], SettlementEvidence]" = {}
    for k in keys:
        o, s, n = (str(x or "") for x in k)
        prior = since.get((o, s, n)) if since else None
        want[(o, s, n)] = (SettlementEvidence(through=prior.through, record_seq=prior.record_seq,
                                              decision=prior.decision, malformed=prior.malformed,
                                              landed=set(prior.landed))
                           if prior is not None else SettlementEvidence())
    if not trusted_pubkey:
        return want, since_seq, None
    live = {k for k in want if all(k)}
    # (org_id, signal, entry_id) -> (lease, signed core, tag), for every settle entry a listed lease can have
    entries: "dict[tuple[str, str, str], tuple[tuple[str, str, str], tuple[str, ...], str]]" = {}
    for k in live:
        o, s, n = k
        tail = f"{s}:{n}"
        entries[(o, CREDIT_GRANT_SIGNAL, f"{SETTLE_WALLET_PREFIX}{tail}")] = (k, _GRANT_CORE, "wallet")
        entries[(o, PLAN_GRANT_SIGNAL, f"{SETTLE_PLAN_PREFIX}{tail}")] = (k, _PLAN_GRANT_CORE, "plan")
        entries[(o, POSTPAID_CREDIT_SIGNAL, f"{SETTLE_ENTRY_PREFIX}{tail}")] = (k, _PP_CREDIT_CORE, "postpaid")
    through, through_hash = since_seq, None
    resolver = None
    if live:
        for r in store.iter_records(since_seq=since_seq):
            if r.seq > through:
                through, through_hash = r.seq, r.entry_hash
            p = r.payload
            if not isinstance(p, dict):
                continue
            po, sig = p.get("org_id"), p.get("signal")
            if not isinstance(po, str) or not isinstance(sig, str):
                continue
            if sig == LAUNCH_SETTLED_SIGNAL:
                ps, pn = p.get("slug"), p.get("nonce")
                if not (isinstance(ps, str) and isinstance(pn, str)):
                    continue
                key = (po, ps, pn)
                ev = want.get(key) if key in live else None
                if ev is None or ev.record_seq is not None:
                    continue
                if resolver is None:
                    resolver = _kh.key_resolver(store, current=trusted_pubkey)
                core = verified_settle_core(p, resolver.at(r.seq))
                if core is _SETTLED_CORE_V1:
                    ev.record_seq, ev.decision, ev.malformed = int(r.seq), None, True
                elif core is not None:
                    ev.record_seq = int(r.seq)
                    ev.decision = decision_of(p, core)
                    ev.malformed = ev.decision is None
                continue                              # unsigned / forged / wrong-epoch: ignored (fail-closed)
            eid = p.get("entry_id")
            if not isinstance(eid, str):
                continue
            hit = entries.get((po, sig, eid))
            if hit is None:
                continue
            lease, core, tag = hit
            ev = want[lease]
            if tag in ev.landed:
                continue
            if resolver is None:
                resolver = _kh.key_resolver(store, current=trusted_pubkey)
            if verify_signed(p, core, resolver.at(r.seq)):
                ev.landed.add(tag)
        for k in live:
            want[k].through = through
    return want, through, through_hash


def evidence_to_json(ev: SettlementEvidence) -> dict:
    """``ev`` as plain JSON (its ``through`` excluded: a caller that persists it records the seq it is good to)."""
    d = ev.decision
    dec = None if d is None else {
        "mode": d.mode, "reserved": d.reserved, "consumed": d.consumed, "refund_plan": d.refund_plan,
        "refund_wallet": d.refund_wallet, "refund_postpaid": d.refund_postpaid,
        "plan_period_end": d.plan_period_end, "basis": d.basis}
    if d is not None and dec is not None and d.exact:   # W2c-1: an exact decision round-trips with its exact fields
        dec.update(consumed_mc=d.consumed_mc, remainder_before=d.remainder_before, remainder_after=d.remainder_after)
    return {"record_seq": ev.record_seq, "malformed": bool(ev.malformed), "landed": sorted(ev.landed),
            "decision": dec}


def evidence_from_json(obj: Any, *, through: int) -> SettlementEvidence:
    """The inverse of :func:`evidence_to_json`, good to seq ``through``. Raises ``ValueError`` on anything that is not
    exactly what it writes: a decision failing an invariant, a decision without a record (or the reverse), an unknown
    landed tag."""
    if not isinstance(obj, dict) or set(obj) != {"record_seq", "malformed", "landed", "decision"}:
        raise ValueError("not a settlement evidence")
    rs, malformed, landed, dec = obj["record_seq"], obj["malformed"], obj["landed"], obj["decision"]
    if rs is not None and (isinstance(rs, bool) or not isinstance(rs, int) or not 0 <= rs <= through):
        raise ValueError("bad record_seq")
    if not isinstance(malformed, bool) or not isinstance(landed, list) or not set(landed) <= {"wallet", "plan",
                                                                                              "postpaid"}:
        raise ValueError("bad malformed / landed")
    decision = None
    if dec is not None:
        v2_keys = {"mode", "reserved", "consumed", "refund_plan", "refund_wallet", "refund_postpaid",
                   "plan_period_end", "basis"}
        exact_keys = v2_keys | {"consumed_mc", "remainder_before", "remainder_after"}
        keys = set(dec) if isinstance(dec, dict) else set()
        v = EXACT_RECORD_VERSION if keys == exact_keys else SETTLED_RECORD_VERSION
        decision = _decision_from({**dec, "v": v}) if isinstance(dec, dict) else None
        if decision is None or keys not in (v2_keys, exact_keys):
            raise ValueError("bad decision")
    if (rs is None) != (decision is None and not malformed) or (malformed and decision is not None):
        raise ValueError("decision / record mismatch")
    return SettlementEvidence(through=int(through), record_seq=rs, decision=decision, malformed=malformed,
                              landed={str(t) for t in landed})
