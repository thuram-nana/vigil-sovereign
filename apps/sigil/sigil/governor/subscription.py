"""Enterprise SaaS BILLING — the per-tenant PLAN / SUBSCRIPTION state-of-record (owner-signed, LWW).

The sovereign record of WHICH PLAN a paying tenant is on, for WHICH billing PERIOD, with WHAT monthly credit
ALLOTMENT, and in WHAT lifecycle STATUS. Owner-signed, append-only, folded from the spine keyed per
`org_id` (== `tenant_id`), with the SAME per-key LWW anti-replay high-water + hard-prune seed as
`accounts.py` / `orgs.py`. Sovereign-plane only (FATAL-2); the keyless offense plane consumes a *decision*,
never this store.

MODEL — a per-org LWW state machine, `status ∈ {active, past_due, canceled}`, with the SAME asymmetric-auth
idiom as orgs/accounts:
  * `subscribe` (the DANGEROUS / access-GRANTING direction: a new plan or a renewal period) is honored ONLY
    if OWNER-SIGNED and FRESH (`issued_at` strictly exceeds the per-org high-water). It sets the plan / period
    / allotment and `status=active`. A replayed/stale subscribe (issued_at <= high-water) is ignored, so a
    captured "active" grant cannot be replayed to resurrect a lapsed plan (the same replay-resurrection guard
    the identity wave closed) — and it survives a hard prune via the `SnapshotState` seed.
  * `mark_past_due` / `cancel` (the SAFE / access-REDUCING direction, dunning) only move `status` DOWN
    (payment failed → past_due; subscription ended → canceled), retaining the plan/period the last active set.
    They come in TWO forms, by `issued_at`:
      - the OWNER-MANUAL latch (fixed `issued_at` 0.0) is honored ON SIGHT — even unsigned — because gating the
        fail-safe direction would make it fail OPEN (a tenant whose payment lapsed could keep access);
      - the WEBHOOK-DRIVEN form (H4: a Flutterwave failed-charge event drives `mark_past_due`) carries the
        provider event's own `created` as a POSITIVE `issued_at`, and is applied only if FRESHER than the last
        honored activation. So an at-least-once / out-of-order / replayed failed-charge webhook can never
        re-suspend a tenant who already recovered (the fresh `active` won), while a genuine CURRENT failure —
        which always post-dates the activation it follows — still latches; the gate never fails OPEN.
    A later owner-signed FRESH `subscribe` (payment recovered / renewal) overrides a past_due/canceled back to
    active.

DRIVES THE OFFENSE LIFECYCLE (later slice): the offense-plane `entitlement.deployment.DeploymentLifecycle`
(DRAFT/ACTIVE/SUSPENDED/EXPIRED/REVOKED) is a separate m-of-n-signed object; a future bridge maps this
sovereign status onto it (active→ACTIVE, past_due/canceled→SUSPENDED) so a non-paying tenant's engagements are
refused. That cross-plane wiring + the signed-profile minting belong with the enforcement gates (Slice 6).

DEFERRED to the next step (needs a product decision, flagged to the owner): the PERIOD-REFILL bridge — at a
new period, grant `allotment` `subscription_refill` credits into the wallet (`governor/wallet.py`) — and the
NON-ROLLOVER rule (unspent plan credits expire at the period boundary; purchased top-ups persist). Non-rollover
requires per-kind balance attribution (the Slice-1 wallet tracks a single additive balance), so it is designed
as its own focused piece rather than baked in here with a wrong rollover default. This module is the
state-of-record + lifecycle/dunning ONLY.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

import re  # noqa: E402

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors accounts._fold)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id == tenant-id validation; same-plane reuse)
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402  (hard-prune seed — mirrors accounts._fold)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0c — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

SUBSCRIPTION_SIGNAL = "governor.subscription"

# Lifecycle states. `active` is the single access-granting state; past_due/canceled are the access-reducing
# (safe-direction) states dunning moves a tenant into.
STATUS_ACTIVE = "active"
STATUS_PAST_DUE = "past_due"
STATUS_CANCELED = "canceled"
_STATUSES = frozenset({STATUS_ACTIVE, STATUS_PAST_DUE, STATUS_CANCELED})
_DOWN_STATES = frozenset({STATUS_PAST_DUE, STATUS_CANCELED})   # honored on sight (safe direction)

# A plan identifier (which SKU: e.g. "trial", "starter", "pro"). A bounded slug — the price/allotment catalog
# (Slice 7) maps plan_id -> price; the authoritative allotment for THIS period is carried on the record so a
# later catalog edit never rewrites a committed subscription (frozen, like the wallet's frozen cost).
_PLAN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# The owner-signed authenticated CORE. plan_id/period/allotment are inside it so an owner-signed subscription
# cannot be re-labelled to another plan or have its allotment/period rewritten without breaking the signature;
# issued_at is inside it (the per-org anti-replay high-water, as in orgs/accounts).
_SUB_CORE = ("signal", "org_id", "plan_id", "period_start", "period_end", "allotment", "status", "issued_at")


def _check_plan_id(plan_id: str) -> str:
    p = str(plan_id or "").strip()
    if not _PLAN_ID_RE.fullmatch(p):
        raise ValueError("plan_id must be 1-64 chars of [a-z0-9._-], lowercase, alphanumeric start")
    return p


def _check_allotment(allotment: int) -> int:
    if isinstance(allotment, bool) or not isinstance(allotment, int):
        raise ValueError("allotment must be a non-negative integer")
    if allotment < 0:
        raise ValueError("allotment must be a non-negative integer")
    return allotment


def _as_allotment(v: object) -> int:
    """A folded allotment → non-negative int, clamped (mirrors wallet._as_credits): a forged negative/NaN/
    overflow value is neutralised to 0 rather than crashing the fold or under-counting."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


@dataclass(frozen=True)
class Subscription:
    org_id: str
    plan_id: str
    period_start: float
    period_end: float
    allotment: int
    status: str

    def is_active(self, now: Optional[float] = None) -> bool:
        """True iff the plan is `active` AND (when `now` is given) the current period has not elapsed. A
        lapsed period reads as not-active even before dunning flips the status (fail-closed)."""
        if self.status != STATUS_ACTIVE:
            return False
        return now is None or now < self.period_end


_SKIP = object()          # `_apply_sub_record`: the record did not touch any org


def _apply_sub_record(rec, resolver, signal: str, status: dict, issued: dict, row: dict):
    """Fold ONE record of the `signal` line into (status, issued, row) — THE subscription fold body, shared by
    the full `_fold` and the verified fold cache (Front C S0c). Returns the org_id it touched, or `_SKIP`."""
    p = rec.payload
    if not isinstance(p, dict) or p.get("signal") != signal:
        return _SKIP
    oid = p.get("org_id")
    if not isinstance(oid, str) or not oid:
        return _SKIP
    st = p.get("status")
    if st in _DOWN_STATES:
        # SAFE (access-reducing) direction. A FIXED 0.0 issued_at is the owner-manual latch: honored ON
        # SIGHT (never fail-open). A POSITIVE issued_at is a WEBHOOK-driven down-state (H4) carrying the
        # provider event's `created`: applied only if FRESHER than the last honored activation, so a
        # stale / out-of-order / replayed failed-charge webhook cannot re-suspend a recovered tenant
        # (the fold does NOT advance `issued` here — that stays the active high-water it compares to).
        dat = as_issued_at(p.get("issued_at"))
        if dat <= 0.0 or dat > issued.get(oid, NO_HIGHWATER):
            status[oid] = st
        return oid
    if st == STATUS_ACTIVE:
        if not verify_signed(p, _SUB_CORE, resolver.at(rec.seq)):
            return _SKIP                              # fail-closed: unsigned/forged/wrong-epoch
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(oid, NO_HIGHWATER):
            return _SKIP                              # REPLAY / stale re-append of an honored active
        issued[oid] = at
        status[oid] = STATUS_ACTIVE
        row[oid] = [str(p.get("plan_id") or ""), float(as_issued_at(p.get("period_start"))),
                    float(as_issued_at(p.get("period_end"))), _as_allotment(p.get("allotment"))]
        return oid
    return _SKIP


def _subscription_of(oid, stt, r) -> "Subscription":
    return Subscription(org_id=str(oid), plan_id=str(r[0]), period_start=float(r[1]),
                        period_end=float(r[2]), allotment=int(r[3]), status=str(stt))


class _SubView:
    """The cached subscription fold of ONE signal line: the full fold's (status, issued, row) plus `out` —
    exactly `_fold()`'s result, kept in step per touched org."""

    __slots__ = ("signal", "status", "issued", "row", "out")

    def __init__(self, signal: str, status: dict, issued: dict, row: dict) -> None:
        self.signal, self.status, self.issued, self.row = signal, status, issued, row
        self.out: dict = {}
        for oid in list(status):
            self.sync(oid)

    def sync(self, oid) -> None:
        stt = self.status.get(oid)
        r = self.row.get(oid)
        if stt is None or r is None:          # a bare safe-direction record never subscribed: ABSENT
            self.out.pop(oid, None)
        else:
            self.out[oid] = _subscription_of(oid, stt, r)


def _sub_step(view: _SubView, rec, resolver) -> None:
    oid = _apply_sub_record(rec, resolver, view.signal, view.status, view.issued, view.row)
    if oid is not _SKIP:
        view.sync(oid)


_SUB_FOLDS: "dict[str, FoldCache]" = {}


def _sub_fold(signal: str) -> FoldCache:
    """One cache per subscription LINE (the credit plan, and `MonitoringSubscriptionRegistry`'s own signal)."""
    c = _SUB_FOLDS.get(signal)
    if c is None:
        c = _SUB_FOLDS.setdefault(signal, FoldCache(f"governor.subscription:{signal}", step=_sub_step))
    return c


class SubscriptionRegistry:
    """Owner-signed per-tenant subscription state on the spine. Construction mirrors OrgRegistry/WalletRegistry.

    ``SIGNAL`` / ``_SNAP`` name the record line: the credit-plan line is ``governor.subscription``; a subclass
    (``monitoring_subscription.MonitoringSubscriptionRegistry``) folds a SEPARATE line under its own signal and
    snapshot sub-state, so the two never overwrite each other (the signal is inside the signed core)."""
    SIGNAL = SUBSCRIPTION_SIGNAL
    _SNAP = "subscription"

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def subscribe(self, org_id: str, plan_id: str, allotment: int, *,
                  period_start: float, period_end: float, issued_at: float) -> int:
        """Owner-sign a new plan / renewal period for a tenant — the DANGEROUS (access-granting) direction,
        honored only if it verifies AND is FRESH (`issued_at` strictly exceeds the per-org high-water). Sets
        the plan / period / allotment and `status=active`. Requires the owner signing key. A renewal is just a
        fresh `subscribe` with a strictly-greater issued_at and the new period."""
        if self.owner_key is None:
            raise ValueError("subscribe requires the owner signing key")
        oid = org_tenant_id(org_id)
        pid = _check_plan_id(plan_id)
        al = _check_allotment(allotment)
        ps, pe = float(period_start), float(period_end)
        if pe <= ps:
            raise ValueError("period_end must be strictly after period_start")
        core = {"signal": self.SIGNAL, "org_id": oid, "plan_id": pid, "period_start": ps,
                "period_end": pe, "allotment": al, "status": STATUS_ACTIVE, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"subscription {oid} -> plan {pid} (active, allotment {al})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def mark_past_due(self, org_id: str, *, issued_at: float = 0.0) -> int:
        """Move a tenant to `past_due` (dunning: a payment failed) — the SAFE (access-reducing) direction.

        `issued_at` selects the freshness semantics (see the module docstring + `_fold`):
          * the DEFAULT 0.0 is the OWNER-MANUAL latch: honored ON SIGHT, un-gated (fail-SAFE).
          * a POSITIVE `issued_at` is the WEBHOOK-DRIVEN form (H4) — pass the provider event's own `created`.
            The fold applies it only if FRESHER than the last honored activation, so a stale / out-of-order /
            replayed failed-charge webhook can never re-suspend a tenant who has since recovered. A genuine
            current failure always post-dates its activation, so it still latches (never fails OPEN).
        Retains the plan/period; only lowers access. A later owner-signed FRESH `subscribe` restores `active`."""
        return self._append_down(org_id, STATUS_PAST_DUE, issued_at=issued_at)

    def cancel(self, org_id: str) -> int:
        """Cancel a subscription — the SAFE direction, OWNER-MANUAL latch (honored on sight, fixed `issued_at`
        0.0). Idempotent and replay-safe; a replayed cancel merely re-cancels. (Webhook-driven cancel is not
        wired: a bare `subscription.cancelled` webhook cannot name the victim tenant soundly — see billing.py —
        so a cancelled plan instead EXPIRES at period_end via the meter's non-rollover check.)"""
        return self._append_down(org_id, STATUS_CANCELED, issued_at=0.0)

    def _append_down(self, org_id: str, status: str, *, issued_at: float = 0.0) -> int:
        oid = org_tenant_id(org_id)
        core = {"signal": self.SIGNAL, "org_id": oid, "plan_id": "", "period_start": 0.0,
                "period_end": 0.0, "allotment": 0, "status": status, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"subscription {oid} -> {status} (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _fold(self) -> dict[Any, Subscription]:
        """Fold the spine into {org_id: Subscription}. `active` is authenticated under the owner pubkey valid
        AT ITS SEQ and gated by the per-org high-water (stale/replayed active ignored); past_due/canceled are
        honored on sight (safe direction) and lower only the status, retaining the plan/period the last active
        set. HARD-PRUNE SEED (mirrors `accounts._fold` / `orgs._fold_orgs`): seed per-org status / high-water /
        plan-row from `SnapshotState`, then fold the LIVE window only; a rotated/empty anchor bypasses the seed
        and full-scans from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (status, issued, row), since = self._seed(snap)
        for rec in self.store.iter_records(since_seq=since):
            _apply_sub_record(rec, resolver, self.SIGNAL, status, issued, row)
        out: dict[Any, Subscription] = {}
        for oid, stt in status.items():
            r = row.get(oid)
            if r is None:
                # A tenant with ONLY a bare safe-direction record (a cancel/mark_past_due appended for an
                # org_id that never had an honored `active`) never genuinely subscribed — treat it as ABSENT,
                # honoring `subscription()`'s contract ("None if the tenant never subscribed") and matching
                # orgs/accounts (which drop non-active reads). `row` is set ONLY by the active branch, so a
                # plan canceled/past_due AFTER subscribing keeps its row and is still returned (dunning view).
                continue
            out[oid] = _subscription_of(oid, stt, r)
        return out

    def _seed(self, snap) -> "tuple[tuple[dict, dict, dict], int]":
        """((status, issued, row), since): the HARD-PRUNE SEED of this line from `snap`, or the empty genesis
        start when the trusted pubkey differs from the snapshot's."""
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}, {}), -1
        status = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_state")}
        issued = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_issued")}
        row = {r[0]: [r[1], r[2], r[3], r[4]] for r in getattr(snap, f"{self._SNAP}_row")}  # oid -> [plan,ps,pe,allot]
        return (status, issued, row), snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental fold of THIS line (`fold_read.cached_read`, flag-gated),
        else `_UNCACHED` (the caller then runs the full `_fold`)."""
        def seed(snap):
            st, since = self._seed(snap)
            return _SubView(self.SIGNAL, *st), since

        return cached_read(_sub_fold(self.SIGNAL), self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def subscription(self, org_id: str) -> Optional[Subscription]:
        """The current folded Subscription for `org_id` whatever its status (None if the tenant never
        subscribed). Fail-closed on an empty/invalid id."""
        if not isinstance(org_id, str) or not org_id:
            return None
        hit = self._cached(lambda v: v.out.get(org_id))
        if hit is not _UNCACHED:
            return hit
        return self._fold().get(org_id)

    def active_subscription(self, org_id: str, now: Optional[float] = None) -> Optional[Subscription]:
        """The Subscription for `org_id` only when it is currently `active` — the primitive a later gate asks
        'is this tenant on a live plan?'. None if not active (or, when `now` is given, if the period elapsed).

        FAIL-OPEN-BY-OMISSION WARNING: the billing-period check runs ONLY when `now` is supplied; with the
        default `now=None` a lapsed-but-not-yet-dunned plan still reads active (status-only liveness). The
        clock-free sovereign fold deliberately cannot source `now` itself (a wall-clock default would inject
        nondeterminism into a state-of-record read). So the Slice-6 enforcement gate — the only money-path
        caller — MUST pass the request `now`; a gate that omits it would grant a lapsed tenant access. Callers
        wanting a pure status probe (not period liveness) should read `subscription(org).status` explicitly."""
        s = self.subscription(org_id)
        return s if (s is not None and s.is_active(now)) else None

    def subscriptions(self) -> list[Subscription]:
        """Every tenant's current subscription, in org_id order (the billing roster)."""
        hit = self._cached(lambda v: [v.out[o] for o in sorted(v.out)])
        if hit is not _UNCACHED:
            return hit
        fold = self._fold()
        return [fold[o] for o in sorted(fold)]
