"""Enterprise SaaS BILLING — the deterministic CREDIT BURN-DOWN METER + period-scoped PLAN-CREDIT ledger.

Slice 3 composes the Slice-1 persistent wallet (`governor/wallet.py`: trial + top-up credits, LIFETIME
additive, never expiring) with a NEW period-scoped plan-credit ledger here, to realise the owner-chosen
credit policy: NON-ROLLOVER plan credits + PERSISTENT top-ups.

  * The WALLET stays the system-of-record for PERSISTENT credits (kinds `trial`, `topup`): once granted they
    live until spent, never expiring. Slice 1 is untouched — its signed cores, fold, snapshot sub-state and
    prune tripwire are exactly as merged.
  * This PLAN-CREDIT ledger is the system-of-record for the per-period monthly ALLOTMENT (the subscription's
    `allotment`, granted each billing period). Each plan tranche is keyed `(org_id, period_end)` and EXPIRES at
    its `period_end`: its UNSPENT remainder is void after that instant (non-rollover). A plan tranche's debits
    expire WITH it (they were already paid out of that tranche), so an expired period contributes 0 — never a
    negative — to the balance. Owner-signed, append-only, idempotent and prune-durable with the SAME anti-replay
    + `SnapshotState` seed + fail-closed prune tripwire as the wallet.

THE METER — `CreditMeter.available(org, now)` is the single deterministic number a later gate (Slice 6) tests:
    available(org, now) = wallet.available(org)                          # persistent: trial + topup, clamped >=0
                        + (the ACTIVE subscription's CURRENT-period plan tranche remainder at `now`, else 0)
Plan credits are SCOPED TO THE SUBSCRIPTION'S CURRENT PERIOD — exactly one allotment is ever live, so an overlapping
or prior-period tranche can never sum into a double allotment (the subscription is the LWW authority for which
period is current). The raw `PlanCreditLedger.available` (Σ over all unexpired tranches) is a ledger diagnostic,
NOT the spendable number.
`now` is supplied by the clock-bearing caller (the sovereign fold is clock-free and deterministic — a wall-clock
default would inject nondeterminism, exactly as `subscription.active_subscription` documents). A debit is charged
to a specific bucket by the gate: a `governor.plan_debit` names the `period_end` tranche it drains; persistent
spend is an ordinary `wallet` debit. The gate's PLAN-FIRST ordering (drain the live plan tranche before touching
persistent top-ups, so purchased credits are preserved) is a Slice-6 gate policy; this module is the ledger +
meter primitive it builds on, and never itself decides a spend.

THE REFILL BRIDGE — `refill_active_subscription(subs, org, now)` reads the sovereign subscription
(`governor/subscription.py`) and, for an ACTIVE tenant, grants its `allotment` as a plan tranche for the current
period, IDEMPOTENTLY per period (`entry_id = "refill:<org>:<period_end>"`), so running it repeatedly in a period
is a harmless no-op and a new period grants exactly one fresh tranche. It is the owner-signed EVIDENCE→grant
conversion for the recurring allotment (a payment webhook, converted upstream to the signed subscription, drives
the signed refill here); the LLM never grants credits.

SOVEREIGN PLANE ONLY (FATAL-2): framework-free, `assert_no_offense()` at import; the keyless offense plane
consumes a decision, never this store. org_id == tenant_id (validated via `orgs.org_tenant_id`).

DEFERRED (documented, not half-wired): GC of long-expired tranches. An expired tranche contributes 0 to the
meter and a replay into it is harmless (0 to available), so the snapshot MAY later drop fully-expired tranche
rows + their seen-keys to bound per-tenant growth. Carried in full for now (sound, if not maximally compact);
the tripwire already refuses a prune that would strand a tranche the seed does not carry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors wallet._fold)
from .authn import signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id == tenant-id validation; same-plane reuse)
from .wallet import _as_credits, _check_credits, _check_entry_id  # noqa: E402  (shared ledger helpers)
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed — mirrors wallet._fold)

PLAN_GRANT_SIGNAL = "governor.plan_grant"
PLAN_DEBIT_SIGNAL = "governor.plan_debit"

# The owner-signed authenticated CORE of each record. `period_end` is INSIDE the core: it is the tranche key
# AND the expiry instant, so a captured grant cannot be re-aimed at another period (extending its life) without
# breaking the signature. `credits`/`org_id`/`entry_id` are inside it for the same reasons as the wallet.
# `issued_at` is audit/ordering only (the ledger is additive per tranche, NOT LWW — idempotency is by entry_id).
_PLAN_GRANT_CORE = ("signal", "org_id", "entry_id", "credits", "period_end", "issued_at")
_PLAN_DEBIT_CORE = ("signal", "org_id", "entry_id", "credits", "period_end", "engagement_id", "issued_at")


def _as_period(v: object) -> float:
    """A folded period_end → float, fail-closed to 0.0 (an already-expired/never-live tranche) on junk/NaN/inf.
    A tranche with period_end <= any real `now` is expired, so a forged non-finite value cannot mint eternal
    credits."""
    import math
    if isinstance(v, bool):
        return 0.0
    if isinstance(v, (int, float, str)):
        try:
            f = float(v)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        return f if math.isfinite(f) else 0.0
    return 0.0


def _check_period_end(period_end: float) -> float:
    """Validate a plan tranche's expiry instant at BINDING time: a finite, strictly-positive float (0.0 would be
    born already expired; non-finite could defeat the expiry comparison)."""
    import math
    try:
        pe = float(period_end)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("period_end must be a finite positive number")
    if not math.isfinite(pe) or pe <= 0.0:
        raise ValueError("period_end must be a finite positive number")
    return pe


@dataclass(frozen=True)
class PlanTranche:
    """One billing period's plan-credit position for a tenant, derived from the spine (never a stored counter)."""
    org_id: str
    period_end: float
    granted: int
    debited: int

    @property
    def remaining(self) -> int:
        """Unspent credits in this tranche, clamped >= 0 (defence-in-depth against a forged over-debit, which
        can only harm the attacker's own tenant)."""
        return max(0, self.granted - self.debited)

    def is_live(self, now: Optional[float] = None) -> bool:
        """True iff the tranche has not expired (period_end > now). With now omitted, liveness is not asserted
        (the caller is asking only about the tranche's existence, not period liveness) — same fail-open-by-
        omission contract as `subscription.active_subscription`; the Slice-6 gate MUST pass `now`."""
        return now is None or now < self.period_end


class PlanCreditLedger:
    """Owner-signed per-tenant, per-period plan-credit ledger on the spine. Construction mirrors WalletRegistry:
    the owner signing key + trusted pubkey default to the persisted owner identity; tests inject explicit keys."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def grant(self, org_id: str, credits: int, *, period_end: float,
              entry_id: Optional[str] = None, issued_at: float) -> int:
        """Owner-sign a plan-credit tranche for a tenant's billing period — adds `credits`, expiring at
        `period_end`. Requires the owner signing key (an unsigned grant never verifies, so it is inert).
        Idempotent per `entry_id` (re-appending the same one is a no-op in the fold)."""
        if self.owner_key is None:
            raise ValueError("plan-credit grant requires the owner signing key")
        oid = org_tenant_id(org_id)
        c = _check_credits(credits)
        pe = _check_period_end(period_end)
        eid = _check_entry_id(entry_id)
        core = {"signal": PLAN_GRANT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "period_end": pe, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"plan credit grant {c} -> {oid} (period_end {pe})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def debit(self, org_id: str, credits: int, *, period_end: float, engagement_id: str = "",
              entry_id: Optional[str] = None, issued_at: float) -> int:
        """Record a plan-credit debit charged to the `(org, period_end)` tranche the gate names. Owner/gate-signed
        + verified so a forged debit cannot drain a victim; idempotent per `entry_id`; `credits` clamped > 0 at
        binding. A debit for work lost to a VIGIL-side failure is simply never appended (a crash never costs the
        customer credits)."""
        if self.owner_key is None:
            raise ValueError("plan-credit debit requires the owner signing key")
        oid = org_tenant_id(org_id)
        c = _check_credits(credits)
        pe = _check_period_end(period_end)
        eid = _check_entry_id(entry_id)
        core = {"signal": PLAN_DEBIT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "period_end": pe, "engagement_id": str(engagement_id or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"plan credit debit {c} <- {oid} (period_end {pe}, engagement {engagement_id or '-'})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _fold(self) -> tuple[dict[Any, int], dict[Any, int], set]:
        """Fold the spine into (granted, debited, seen) keyed per `(org_id, period_end)`, where `seen` holds the
        consumed `(signal, org_id, entry_id)` idempotency keys. Each signed record is authenticated under the
        owner pubkey valid AT ITS SEQ; a record whose key is already in `seen` is ignored (idempotent — the
        replay/double-count guard, namespaced by SIGNAL so a grant and a debit never collide). HARD-PRUNE SEED
        (mirrors `wallet._fold`): seed the per-tranche totals + `seen` from `SnapshotState`, then fold the LIVE
        window only — so a pruned tranche stays counted and its entry_id stays consumed. A rotated/empty anchor
        BYPASSES the snapshot and full-scans from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            granted: dict[Any, int] = {}
            debited: dict[Any, int] = {}
            seen: set = set()
            since = -1
        else:
            granted = dict(snap.plan_granted_map())
            debited = dict(snap.plan_debited_map())
            seen = set(snap.plan_seen_set())
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != PLAN_GRANT_SIGNAL and sig != PLAN_DEBIT_SIGNAL:
                continue
            oid = p.get("org_id")
            eid = p.get("entry_id")
            if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
                continue
            core = _PLAN_GRANT_CORE if sig == PLAN_GRANT_SIGNAL else _PLAN_DEBIT_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                  # fail-closed: unsigned/forged/wrong-epoch record
            key = (sig, oid, eid)
            if key in seen:
                continue                                  # idempotent: this entry already counted (replay)
            seen.add(key)
            tkey = (oid, _as_period(p.get("period_end")))
            amount = _as_credits(p.get("credits"))
            if sig == PLAN_GRANT_SIGNAL:
                granted[tkey] = granted.get(tkey, 0) + amount
            else:
                debited[tkey] = debited.get(tkey, 0) + amount
        return granted, debited, seen

    def tranches(self, org_id: str) -> list[PlanTranche]:
        """Every plan tranche for `org_id` (whatever its expiry), in period_end order. Fail-closed on empty id."""
        if not isinstance(org_id, str) or not org_id:
            return []
        granted, debited, _ = self._fold()
        keys = sorted({k for k in set(granted) | set(debited) if k[0] == org_id}, key=lambda k: k[1])
        return [PlanTranche(org_id=org_id, period_end=float(pe), granted=granted.get((org_id, pe), 0),
                            debited=debited.get((org_id, pe), 0)) for (_o, pe) in keys]

    def available(self, org_id: str, now: Optional[float] = None) -> int:
        """RAW ledger view: Σ over UNEXPIRED tranches (period_end > now) of the per-tranche remainder
        (granted − debited, clamped >= 0). This is a diagnostic over the ledger ALONE; it is NOT the authoritative
        spendable number, because a tenant may hold more than one unexpired tranche (e.g. a mid-cycle event that
        minted a second period). The authoritative 'how much can this tenant spend now' is `CreditMeter.available`,
        which scopes plan credits to the ACTIVE subscription's CURRENT period (one allotment live at a time). With
        `now` omitted every tranche counts (status-only); a caller testing spend MUST pass `now`."""
        return sum(t.remaining for t in self.tranches(org_id) if t.is_live(now))

    def remaining_for_period(self, org_id: str, period_end: float) -> int:
        """The remaining credits of the ONE tranche keyed `(org_id, period_end)` — granted − debited, clamped
        >= 0. Expiry is NOT applied here (the caller — CreditMeter, via the active subscription — has already
        established the period is current/unexpired). Fail-closed to 0 on an empty id."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        granted, debited, _ = self._fold()
        key = (org_id, _as_period(period_end))
        return max(0, granted.get(key, 0) - debited.get(key, 0))


@dataclass(frozen=True)
class CreditPosition:
    """A tenant's full spendable position at an instant: persistent (wallet) + live plan (unexpired tranches)."""
    org_id: str
    persistent: int     # wallet.available(org): trial + topup, never expiring
    plan_live: int      # the ACTIVE subscription's current-period plan tranche remainder at `now` (0 if none)

    @property
    def available(self) -> int:
        return self.persistent + self.plan_live


class CreditMeter:
    """The deterministic burn-down meter the Slice-6 gate asks 'how many credits can this tenant spend NOW?'.
    Pure composition over the persistent wallet + the period-scoped plan ledger + the subscription. Owns no state.

    PLAN CREDITS ARE SCOPED TO THE ACTIVE SUBSCRIPTION'S CURRENT PERIOD — exactly ONE allotment is ever live. The
    subscription (`governor/subscription.py`) is the LWW authority for which period is current; the meter counts
    the plan tranche keyed to THAT period and only while the subscription is active and in-period. This is what
    enforces NON-ROLLOVER at the money boundary: a prior period's tranche, or a stray tranche minted by a
    mid-cycle event, is simply not the current period and is not counted — so overlapping tranches can never sum
    to a double allotment. A tenant with no active, in-period subscription has no plan credits (fail-closed; this
    is also the dunning/cancel behaviour). PERSISTENT credits (wallet: trial + top-ups) are independent of any
    subscription and always spendable."""

    def __init__(self, wallet, plan: PlanCreditLedger, subscriptions):
        self.wallet = wallet
        self.plan = plan
        self.subscriptions = subscriptions

    def position(self, org_id: str, now: Optional[float] = None) -> CreditPosition:
        if not isinstance(org_id, str) or not org_id:
            return CreditPosition(org_id="", persistent=0, plan_live=0)
        persistent = self.wallet.available(org_id)
        sub = self.subscriptions.active_subscription(org_id, now)   # active AND in-period, else None (fail-closed)
        plan_live = self.plan.remaining_for_period(org_id, sub.period_end) if sub is not None else 0
        return CreditPosition(org_id=org_id, persistent=persistent, plan_live=plan_live)

    def available(self, org_id: str, now: Optional[float] = None) -> int:
        """Total spendable credits for `org_id` at `now` = persistent wallet + the ACTIVE subscription's current
        plan tranche remainder. The scalar the gate tests ( > 0 to proceed, fail-closed). Pass `now` so a lapsed
        period / expired tranche drops out (the fail-open-by-omission contract of `active_subscription`)."""
        return self.position(org_id, now).available


def _refill_entry_id(org_id: str, period_end: float) -> str:
    """The idempotency key for a period's plan refill: one tranche per (org, period), so re-running the bridge in
    the same period is a no-op and a new period grants exactly one fresh tranche."""
    return f"refill:{org_id}:{repr(float(period_end))}"


def refill_active_subscription(subs, plan: PlanCreditLedger, org_id: str, *, issued_at: float) -> Optional[int]:
    """The subscription→plan refill BRIDGE: for an ACTIVE tenant, grant its `allotment` as a plan tranche for the
    CURRENT period (`period_end` = the subscription's period_end), idempotently per period. Returns the appended
    record seq, or None when there is nothing to refill (no active subscription, or a zero allotment). Owner-
    signed; the LLM never grants. Non-rollover falls out for free: the prior period's tranche keeps its own
    `period_end` and simply expires; this grants a NEW tranche for the new period.

    `subs` is a `SubscriptionRegistry`; `now` is NOT needed for the grant (a tranche's liveness is read at meter
    time) — the bridge keys off the subscription's current ACTIVE period and is safe to re-run anytime."""
    sub = subs.subscription(org_id)
    if sub is None or sub.status != "active":
        return None                                       # only an active plan refills; dunning/canceled do not
    if sub.allotment <= 0 or sub.period_end <= 0.0:
        return None
    oid = org_tenant_id(org_id)
    pe = float(sub.period_end)
    # Append-level idempotency: skip the redundant no-op write when this period's tranche already carries its
    # refill (a scheduled caller re-running within a period must not bloat the spine). The FOLD-level dedup on
    # the `refill:<org>:<period_end>` entry_id remains the correctness guarantee (a racing double-append still
    # counts once), so this pre-check is a safe optimization, never the sole guard.
    if any(t.period_end == pe and t.granted > 0 for t in plan.tranches(oid)):
        return None
    return plan.grant(oid, int(sub.allotment), period_end=pe,
                      entry_id=_refill_entry_id(oid, pe), issued_at=float(issued_at))
