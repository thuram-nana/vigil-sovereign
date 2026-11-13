"""Enterprise SaaS POSTPAID — the per-tenant owner-signed CREDIT-LINE account mode + arrears ledger (PP-1).

Prepaid is the default everywhere else (wallet burn-down + period-scoped plan tranches). A POSTPAID
enterprise tenant instead draws against an owner-signed CREDIT LINE (`credit_limit`, in credits) and is
invoiced in ARREARS on NET terms (`net_terms_days`). This module holds TWO owner-signed sovereign stores:

  1. ``PostpaidRegistry`` — the ACCOUNT-MODE state-of-record (LWW): which tenants are postpaid, with what
     limit and terms, folded per `org_id` (== `tenant_id`) with the SAME owner-signed per-key LWW anti-replay
     high-water + hard-prune seed as `subscription.py` / `orgs.py` / `accounts.py`.
  2. ``PostpaidArrearsLedger`` — the ACCRUAL ledger (ADDITIVE, per-org): each launch the gate ADMITS against
     the line appends a signed ``governor.postpaid_debit`` (the arrears grows); a settle/cancel reverses the
     unconsumed part with a signed ``governor.postpaid_credit``. ``accrued(org)`` = Σ debits − Σ reversals
     (clamped >= 0) is the running unpaid balance the gate tests against the limit. Idempotent per `entry_id`,
     snapshot-seeded + prune-durable exactly like the wallet / plan ledger — a pruned debit stays counted, so a
     tenant can never draw past their line by waiting for a prune (the money-doctrine fail-closed invariant).

ACCOUNT-MODE MODEL (``PostpaidRegistry``) — the SAME asymmetric-auth idiom as subscription/orgs:
  * `set_account` (the access-GRANTING direction: open or raise a credit line) is honored ONLY if OWNER-SIGNED
    and FRESH (`issued_at` strictly exceeds the per-org high-water). It sets `enabled=True` + `credit_limit` +
    `net_terms_days`. A replayed/stale set is ignored (a captured "open line" cannot be replayed to re-open a
    line the owner closed), and it survives a hard prune via the `SnapshotState` seed.
  * `disable` (the SAFE / access-REDUCING direction) only turns the line OFF. It is honored ON SIGHT (fixed
    `issued_at` 0.0, even unsigned) because gating the fail-safe direction would make it fail OPEN. A later
    owner-signed FRESH `set_account` re-opens it. A WEBHOOK-driven positive `issued_at` form is applied only if
    FRESHER than the last honored open (mirrors subscription dunning).

ARREARS MODEL (``PostpaidArrearsLedger``) — ADDITIVE, never LWW:
  * `accrue` (a launch draws against the line) appends `governor.postpaid_debit`; `settle` (a launch settles —
    ALWAYS written, the refund 0..reserved) and `reverse` (PP-2 records a paid invoice) append
    `governor.postpaid_credit`. Both are owner/gate-signed + verified so a forged record cannot inflate OR deflate
    a victim's arrears; idempotent per `entry_id` (a replayed reserve/settle no-ops). The gate's accrual-delta
    invariant (accrued MUST rise by the reserved units, else refuse) makes a reused nonce fail-closed, mirroring
    the prepaid availability-delta. A settle is ALWAYS recorded (even a full-consumption refund of 0) so the
    in-flight set clears and PP-2 bills the real consumption.

PP-1 is the account mode + the accrual ledger + the launch-gate integration. The periodic owner-signed ARREARS
INVOICE (which issues a `postpaid_credit` on payment, resetting the drawn balance) is PP-2; the DUNNING↔gate
interaction (overdue/over-limit also refuses via the account's safe direction) is PP-3. Byte-identical when no
postpaid record exists — the default prepaid path is entirely untouched (a tenant with no enabled account folds
to `is_postpaid=False`, so the gate takes the unchanged `CreditMeter.available` branch).

FATAL-2: sovereign-plane (`assert_no_offense()` at import); imports only sovereign substrate.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors subscription._fold)
from .authn import NO_HIGHWATER, as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id == tenant-id validation; same-plane reuse)
from .wallet import _as_credits, _check_credits, _check_entry_id  # noqa: E402  (shared ledger helpers)
from ..spine.snapshot import SnapshotState, seed_applies  # noqa: E402  (hard-prune seed — mirrors subscription._fold)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402
from .ledger_view import PairedLedgerView  # noqa: E402

POSTPAID_SIGNAL = "governor.postpaid"
POSTPAID_DEBIT_SIGNAL = "governor.postpaid_debit"      # a launch drawn against the line (arrears grows)
POSTPAID_CREDIT_SIGNAL = "governor.postpaid_credit"    # a settle/cancel reversal or a paid invoice (arrears shrinks)

# The launch gate's entry_id scheme for a postpaid DRAW and its SETTLE reversal — SHARED by the gate (which
# writes them, ui/launch_gate.py) and the arrears ledger's in-flight pairing (which reads them), so the two can
# never drift. A postpaid_debit under RESERVE_ENTRY_PREFIX whose matching SETTLE_ENTRY_PREFIX credit has NOT yet
# landed is an IN-FLIGHT launch (reserved, not settled) — excluded from the PP-2 arrears INVOICING basis so a
# reserved-but-unconsumed (or later-cancelled) draw is never over-billed.
RESERVE_ENTRY_PREFIX = "reserve-postpaid:"
SETTLE_ENTRY_PREFIX = "settle-postpaid:"

# Sane bounds. A credit line is a non-negative credit count; net terms are whole days within a year
# (0 = due on issue; typical 15 / 30 / 60). Both live inside the signed core, so neither can be rewritten
# without breaking the owner signature.
_MAX_NET_TERMS_DAYS = 366

# The owner-signed authenticated CORE of the ACCOUNT record. credit_limit / net_terms_days / enabled are inside
# it so an owner-signed account cannot have its limit/terms rewritten or be flipped on without breaking the
# signature; issued_at is inside it (the per-org anti-replay high-water, as in subscription/orgs).
_PP_CORE = ("signal", "org_id", "credit_limit", "net_terms_days", "enabled", "issued_at")

# The owner-signed authenticated CORE of each ARREARS record. `credits`/`org_id`/`entry_id` are inside it for the
# same reasons as the wallet; `issued_at` is audit/ordering only (the ledger is ADDITIVE, idempotency is by
# entry_id). engagement_id (debit only) ties an accrual to the launch it funded (audit; PP-2 invoice line).
_PP_DEBIT_CORE = ("signal", "org_id", "entry_id", "credits", "engagement_id", "issued_at")
_PP_CREDIT_CORE = ("signal", "org_id", "entry_id", "credits", "issued_at")


def _check_credit_limit(credit_limit: int) -> int:
    if isinstance(credit_limit, bool) or not isinstance(credit_limit, int) or credit_limit < 0:
        raise ValueError("credit_limit must be a non-negative integer (credits)")
    return credit_limit


def _check_net_terms(net_terms_days: int) -> int:
    if isinstance(net_terms_days, bool) or not isinstance(net_terms_days, int):
        raise ValueError("net_terms_days must be an integer in [0, 366]")
    if not (0 <= net_terms_days <= _MAX_NET_TERMS_DAYS):
        raise ValueError("net_terms_days must be an integer in [0, 366]")
    return net_terms_days


def _as_nonneg_int(v: object) -> int:
    """A folded credit_limit / net_terms → non-negative int, clamped (mirrors subscription._as_allotment):
    a forged negative / NaN / overflow / non-numeric value is neutralised to 0 rather than crashing the
    fold or over-granting a credit line."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


def _check_refund(refund: int) -> int:
    """Validate a SETTLE refund amount at binding. Unlike `_check_credits` (which requires > 0), a settle refund
    may be 0: a FULL-consumption launch returns nothing to the line, yet its settle must still be RECORDED (the
    marker that clears the reserve from the in-flight set, so the launch is billed for its real consumption).
    Must be a non-negative whole number."""
    if isinstance(refund, bool) or not isinstance(refund, int):
        raise ValueError("refund must be a non-negative integer")
    if refund < 0:
        raise ValueError("refund must be a non-negative integer (>= 0)")
    return refund


@dataclass(frozen=True)
class PostpaidAccount:
    """A tenant's owner-signed postpaid account mode. `enabled` is the access-granting state; a disabled
    (or absent) account means the tenant is prepaid — no credit line."""
    org_id: str
    credit_limit: int        # the owner-signed arrears ceiling, in credits
    net_terms_days: int      # arrears invoice net terms, in days
    enabled: bool

    def is_enabled(self) -> bool:
        return bool(self.enabled) and self.credit_limit >= 0


_SKIP = object()          # the shared fold steps: the record changed nothing


def _apply_postpaid_record(rec, resolver, signal: str, enabled: dict, issued: dict, row: dict):
    """Fold ONE spine record into (enabled, issued, row) — THE postpaid account fold body, shared by the full
    `_fold` and the verified fold cache (Front C S0d) so the two can never diverge. Returns the org it touched,
    or `_SKIP`."""
    p = rec.payload
    if not isinstance(p, dict) or p.get("signal") != signal:
        return _SKIP
    oid = p.get("org_id")
    if not isinstance(oid, str) or not oid:
        return _SKIP
    if p.get("enabled") is True:
        # DANGEROUS (access-granting) direction: owner-signed + fresh only.
        if not verify_signed(p, _PP_CORE, resolver.at(rec.seq)):
            return _SKIP                              # fail-closed: unsigned / forged / wrong-epoch
        at = as_issued_at(p.get("issued_at"))
        if at <= issued.get(oid, NO_HIGHWATER):
            return _SKIP                              # REPLAY / stale re-append of an honored open
        issued[oid] = at
        enabled[oid] = True
        row[oid] = [_as_nonneg_int(p.get("credit_limit")), _as_nonneg_int(p.get("net_terms_days"))]
        return oid
    # SAFE (access-reducing) direction. A FIXED 0.0 issued_at is the owner-manual latch: honored
    # ON SIGHT (never fail-open). A POSITIVE issued_at is webhook-driven: applied only if FRESHER
    # than the last honored open (the fold does NOT advance `issued` here — that stays the open
    # high-water it compares against), so a stale/replayed close cannot shut a re-opened tenant.
    dat = as_issued_at(p.get("issued_at"))
    if dat <= 0.0 or dat > issued.get(oid, NO_HIGHWATER):
        enabled[oid] = False
        return oid
    return _SKIP


def _account_of(oid, enabled: dict, row: dict) -> Optional[PostpaidAccount]:
    """The folded PostpaidAccount for `oid`, or None. A bare disable for an org that never had an honored open
    never had a line — ABSENT (mirrors subscription's row==None drop), so `account()` reads None."""
    if oid not in enabled:
        return None
    r = row.get(oid)
    if r is None:
        return None
    return PostpaidAccount(org_id=str(oid), credit_limit=int(r[0]), net_terms_days=int(r[1]),
                           enabled=bool(enabled[oid]))


class _PostpaidView:
    """The cached postpaid account fold of ONE signal line: exactly the full fold's (enabled, issued, row);
    `_account_of` derives an account from it on read, as the full fold does for every org."""

    __slots__ = ("signal", "enabled", "issued", "row")

    def __init__(self, signal: str, enabled: dict, issued: dict, row: dict) -> None:
        self.signal, self.enabled, self.issued, self.row = signal, enabled, issued, row


def _postpaid_step(view: _PostpaidView, rec, resolver) -> None:
    _apply_postpaid_record(rec, resolver, view.signal, view.enabled, view.issued, view.row)


_PP_FOLDS: "dict[str, FoldCache]" = {}


def _pp_fold(signal: str) -> FoldCache:
    """One cache per postpaid account LINE (keyed by the class's SIGNAL, so a future line never shares one)."""
    c = _PP_FOLDS.get(signal)
    if c is None:
        c = _PP_FOLDS.setdefault(signal, FoldCache(f"governor.postpaid:{signal}", step=_postpaid_step))
    return c


def _apply_arrears_record(r, resolver, debited: dict, credited: dict, seen: set):
    """Fold ONE spine record into (debited, credited, seen) — THE arrears fold body, shared by the full `_fold`
    and the verified fold cache (Front C S0d). Returns the counted record's `(signal, org_id, entry_id,
    credits)`, or `_SKIP` (not an arrears record, malformed, unverified, or a replay)."""
    p = r.payload
    if not isinstance(p, dict):
        return _SKIP
    sig = p.get("signal")
    if sig != POSTPAID_DEBIT_SIGNAL and sig != POSTPAID_CREDIT_SIGNAL:
        return _SKIP
    oid = p.get("org_id")
    eid = p.get("entry_id")
    if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
        return _SKIP
    core = _PP_DEBIT_CORE if sig == POSTPAID_DEBIT_SIGNAL else _PP_CREDIT_CORE
    if not verify_signed(p, core, resolver.at(r.seq)):
        return _SKIP                                  # fail-closed: unsigned/forged/wrong-epoch record
    key = (sig, oid, eid)
    if key in seen:
        return _SKIP                                  # idempotent: this entry already counted (replay)
    seen.add(key)
    amount = _as_credits(p.get("credits"))
    if sig == POSTPAID_DEBIT_SIGNAL:
        debited[oid] = debited.get(oid, 0) + amount
    else:
        credited[oid] = credited.get(oid, 0) + amount
    return sig, oid, eid, amount


def _new_arrears_view(debited: dict, credited: dict, seen: set) -> PairedLedgerView:
    return PairedLedgerView(debited, credited, seen, up_signal=POSTPAID_DEBIT_SIGNAL,
                            reserve_prefix=RESERVE_ENTRY_PREFIX, settle_prefix=SETTLE_ENTRY_PREFIX)


def _arrears_step(view: PairedLedgerView, r, resolver) -> None:
    hit = _apply_arrears_record(r, resolver, view.up, view.down, view.seen)
    if hit is not _SKIP:
        view.pair(*hit)


_ARREARS_FOLD = FoldCache("governor.postpaid_arrears", step=_arrears_step)


class PostpaidRegistry:
    """Owner-signed per-tenant postpaid account-mode state on the spine. Construction mirrors
    SubscriptionRegistry / OrgRegistry / WalletRegistry (owner key + trusted pubkey, defaulting to the
    provisioned owner identity). The record line is ``governor.postpaid`` (inside the signed core), folded
    under its own snapshot sub-state so it never overwrites the credit-plan subscription line."""
    SIGNAL = POSTPAID_SIGNAL
    _SNAP = "postpaid"

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutations ---------------------------------------------------------------------------
    def set_account(self, org_id: str, credit_limit: int, net_terms_days: int, *, issued_at: float) -> int:
        """Owner-sign a tenant's postpaid credit line — the DANGEROUS (access-granting) direction, honored
        only if it verifies AND is FRESH (`issued_at` strictly exceeds the per-org high-water). Sets
        `enabled=True` + `credit_limit` + `net_terms_days`. Requires the owner signing key. Raising a limit
        or changing terms is just a fresh `set_account` with a strictly-greater issued_at."""
        if self.owner_key is None:
            raise ValueError("set_account requires the owner signing key")
        oid = org_tenant_id(org_id)
        cl = _check_credit_limit(credit_limit)
        nt = _check_net_terms(net_terms_days)
        core = {"signal": self.SIGNAL, "org_id": oid, "credit_limit": cl, "net_terms_days": nt,
                "enabled": True, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"postpaid {oid} -> enabled (limit {cl} credits, net {nt}d)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def disable(self, org_id: str, *, issued_at: float = 0.0) -> int:
        """Turn a tenant's postpaid line OFF — the SAFE (access-reducing) direction.

        `issued_at` selects the freshness semantics (mirrors subscription dunning):
          * the DEFAULT 0.0 is the OWNER-MANUAL latch: honored ON SIGHT, un-gated (fail-SAFE — closing a
            line must never fail open).
          * a POSITIVE `issued_at` is a webhook/automation-driven close, applied only if FRESHER than the
            last honored open, so a stale / out-of-order / replayed close can never shut a tenant the owner
            has since re-opened.
        A later owner-signed FRESH `set_account` re-opens the line."""
        oid = org_tenant_id(org_id)
        core = {"signal": self.SIGNAL, "org_id": oid, "credit_limit": 0, "net_terms_days": 0,
                "enabled": False, "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"postpaid {oid} -> disabled (governed latch)"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _seed(self, snap) -> "tuple[tuple[dict, dict, dict], int]":
        """((enabled, issued, row), since): the HARD-PRUNE SEED from `snap`, or the empty genesis start when the
        trusted pubkey differs from the snapshot's."""
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}, {}), -1
        enabled = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_state", [])}
        issued = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_issued", [])}
        row = {r[0]: [r[1], r[2]] for r in getattr(snap, f"{self._SNAP}_row", [])}  # oid -> [limit, net_terms]
        return (enabled, issued, row), snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental fold of THIS line (`fold_read.cached_read`, flag-gated),
        else `_UNCACHED` (the caller then runs the full `_fold`)."""
        def seed(snap):
            st, since = self._seed(snap)
            return _PostpaidView(self.SIGNAL, *st), since

        return cached_read(_pp_fold(self.SIGNAL), self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> dict[Any, PostpaidAccount]:
        """Fold the spine into {org_id: PostpaidAccount}. `enabled` is authenticated under the owner pubkey
        valid AT ITS SEQ and gated by the per-org high-water (stale/replayed open ignored); `disabled` is the
        safe direction (honored on sight at 0.0, or webhook-fresh), lowering only `enabled` and retaining the
        last-open limit/terms for the dunning/arrears view. HARD-PRUNE SEED (mirrors `subscription._fold`):
        seed per-org enabled / high-water / limit-row from `SnapshotState`, then fold the LIVE window only; a
        rotated/empty anchor bypasses the seed and full-scans from genesis (byte-identical under empty)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (enabled, issued, row), since = self._seed(snap)
        for rec in self.store.iter_records(since_seq=since):
            _apply_postpaid_record(rec, resolver, self.SIGNAL, enabled, issued, row)
        out: dict[Any, PostpaidAccount] = {}
        for oid in enabled:
            acct = _account_of(oid, enabled, row)
            if acct is not None:
                out[oid] = acct
        return out

    def account(self, org_id: str) -> Optional[PostpaidAccount]:
        """The current folded PostpaidAccount for `org_id` whatever its enabled state (None if the tenant was
        never set postpaid). Fail-closed on an empty/invalid id."""
        if not isinstance(org_id, str) or not org_id:
            return None
        hit = self._cached(lambda v: _account_of(org_id, v.enabled, v.row))
        if hit is not _UNCACHED:
            return hit
        return self._fold().get(org_id)

    def is_postpaid(self, org_id: str) -> bool:
        """True iff `org_id` has a currently-ENABLED postpaid credit line — the primitive the gate asks
        'does this tenant draw against a line instead of burning prepaid?'. Fail-closed (False) otherwise."""
        a = self.account(org_id)
        return a is not None and a.is_enabled()

    def accounts(self) -> list[PostpaidAccount]:
        """Every tenant's current postpaid account, in org_id order (the arrears roster)."""
        hit = self._cached(lambda v: [_account_of(o, v.enabled, v.row)
                                      for o in sorted(o for o in v.enabled if v.row.get(o) is not None)])
        if hit is not _UNCACHED:
            return hit
        fold = self._fold()
        return [fold[o] for o in sorted(fold)]


class PostpaidArrearsLedger:
    """Owner-signed per-tenant ADDITIVE arrears ledger on the spine — the running unpaid balance a postpaid
    tenant has drawn against their credit line. Construction mirrors WalletRegistry / PlanCreditLedger. Two
    signals share one per-(org) balance and one idempotency seen-set: ``governor.postpaid_debit`` (a launch
    accrues) and ``governor.postpaid_credit`` (a settle/cancel reversal, or a PP-2 paid invoice). ``accrued``
    = Σ debits − Σ credits, clamped >= 0. Prune-durable via the ``SnapshotState`` seed (a pruned debit stays
    counted — a tenant can never draw past their line by waiting out a prune)."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner/gate mutations ----------------------------------------------------------------------
    def accrue(self, org_id: str, credits: int, *, engagement_id: str = "",
               entry_id: Optional[str] = None, issued_at: float) -> int:
        """Record `credits` drawn against the tenant's credit line (arrears grows). Owner/gate-signed +
        verified so a forged accrual cannot inflate a victim's arrears; `credits` clamped > 0 at binding;
        idempotent per `entry_id` (a replayed reserve no-ops in the fold)."""
        if self.owner_key is None:
            raise ValueError("postpaid accrue requires the owner signing key")
        oid = org_tenant_id(org_id)
        c = _check_credits(credits)
        eid = _check_entry_id(entry_id)
        core = {"signal": POSTPAID_DEBIT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "engagement_id": str(engagement_id or ""), "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"postpaid accrue {c} -> {oid} (engagement {engagement_id or '-'})"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def reverse(self, org_id: str, credits: int, *, entry_id: Optional[str] = None, issued_at: float) -> int:
        """Record `credits` removed from the tenant's arrears (a settle/cancel refund of the unconsumed draw,
        or a PP-2 paid invoice). Owner/gate-signed + verified; `credits` clamped > 0; idempotent per `entry_id`
        (a re-settle no-ops). A reversal can never push `accrued` below 0 (clamped), so an over-reversal is
        inert — it can only harm the attacker's own tenant, never mint a credit elsewhere."""
        if self.owner_key is None:
            raise ValueError("postpaid reverse requires the owner signing key")
        oid = org_tenant_id(org_id)
        c = _check_credits(credits)
        eid = _check_entry_id(entry_id)
        core = {"signal": POSTPAID_CREDIT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": c,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"postpaid reverse {c} <- {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def settle(self, org_id: str, refund: int, *, entry_id: Optional[str] = None, issued_at: float) -> int:
        """Record a launch SETTLEMENT against the arrears — written on EVERY settle, including a full-consumption
        settle whose `refund` (= reserved - consumed, from the owner-signed lease) is 0. The `refund` is the
        unconsumed draw returned to the line and reduces `accrued` by exactly that much; the RECORD'S PRESENCE
        (a ``governor.postpaid_credit`` under the settle entry_id) is the marker that clears the reserve from the
        IN-FLIGHT set (`in_flight_reserved`), so a reserve is billed for its real consumption once it settles.

        SECURITY (red-pen HIGH): the gate previously wrote the reversal ONLY when `refund > 0`, so a launch that
        consumed its ENTIRE reservation (refund 0) left no settle record — `in_flight_reserved` treated it as
        perpetually in-flight and `net_settled_consumed` read 0, so PP-2 invoiced $0 for real, fully-consumed
        consumption (a silent revenue leak). This method is the fix: the gate calls it UNCONDITIONALLY, and a
        0-refund settle is a balance no-op (`_as_credits(0) == 0`) but a load-bearing in-flight-clearing marker.
        Owner/gate-signed + verified (a forged record is inert); idempotent per `entry_id`."""
        if self.owner_key is None:
            raise ValueError("postpaid settle requires the owner signing key")
        oid = org_tenant_id(org_id)
        r = _check_refund(refund)
        eid = _check_entry_id(entry_id)
        core = {"signal": POSTPAID_CREDIT_SIGNAL, "org_id": oid, "entry_id": eid, "credits": r,
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto", "reason": f"postpaid settle (refund {r}) <- {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    def was_accrued(self, org_id: str, entry_id: str) -> bool:
        """True iff an owner-signed postpaid DEBIT under (org_id, entry_id) has EVER been folded — the
        PRUNE-DURABLE discriminator the launch settle path uses to tell a POSTPAID reservation from a prepaid
        one (so a postpaid reservation is reversed against the arrears, never mis-refunded to the prepaid
        wallet). It reads the SnapshotState-SEEDED seen-set (via `_fold`), so it stays True after a hard prune
        that drops the individual debit record — the prune carries the per-org balance AND the seen-set into
        the seed (spine/prune.py `stranded_postpaid_arrears`), exactly as `accrued()` stays correct.

        SECURITY (red-pen HIGH): a non-seeded LIVE scan here read False after such a prune and mis-routed the
        settle to the prepaid bucket — MINTING `reserved - consumed` wallet credits that were never debited AND
        leaving the arrears un-reversed (net arrears change == reserved, not consumed; a cancel converted a
        deferred debt into immediately-spendable credits). The settle refund AMOUNT comes from the owner-signed
        lease, so only this durable EXISTENCE check is needed here. Fail-closed (False) on an empty id."""
        if not (isinstance(org_id, str) and org_id and isinstance(entry_id, str) and entry_id):
            return False
        key = (POSTPAID_DEBIT_SIGNAL, org_id, entry_id)
        hit = self._cached(lambda v: key in v.seen)
        if hit is not _UNCACHED:
            return hit
        _debited, _credited, seen = self._fold()
        return key in seen

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _seed(self, snap) -> "tuple[tuple[dict, dict, set], int]":
        """((debited, credited, seen), since): the HARD-PRUNE SEED from `snap`, or the empty genesis start when
        the trusted pubkey differs from the snapshot's."""
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            return ({}, {}, set()), -1
        return (dict(snap.postpaid_arrears_debited_map()), dict(snap.postpaid_arrears_credited_map()),
                set(snap.postpaid_arrears_seen_set())), snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental arrears fold (`fold_read.cached_read`, flag-gated), else
        `_UNCACHED` (the caller then runs the full `_fold` / pairing scan)."""
        def seed(snap):
            st, since = self._seed(snap)
            return _new_arrears_view(*st), since

        return cached_read(_ARREARS_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> tuple[dict[Any, int], dict[Any, int], set]:
        """Fold the spine into (debited, credited, seen) keyed per `org_id`, where `seen` holds the consumed
        `(signal, org_id, entry_id)` idempotency keys. Each signed record is authenticated under the owner
        pubkey valid AT ITS SEQ; a record whose key is already in `seen` is ignored (idempotent, namespaced by
        SIGNAL so a debit and a credit never collide). HARD-PRUNE SEED (mirrors `wallet._fold`): seed the
        per-org totals + `seen` from `SnapshotState`, then fold the LIVE window only. A rotated/empty anchor
        BYPASSES the snapshot and full-scans from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        (debited, credited, seen), since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_arrears_record(r, resolver, debited, credited, seen)
        return debited, credited, seen

    def accrued(self, org_id: str) -> int:
        """The tenant's current unpaid arrears = Σ debits − Σ reversals, clamped >= 0 (defence-in-depth: an
        over-reversal can never read as a negative balance / a credit the tenant is owed). Fail-closed to 0 on
        an empty id. This is the scalar the launch gate tests against the account's `credit_limit`."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: _accrued(v.up, v.down, org_id))
        if hit is not _UNCACHED:
            return hit
        debited, credited, _ = self._fold()
        return _accrued(debited, credited, org_id)

    def in_flight_reserved(self, org_id: str) -> int:
        """Σ reserved credits of this tenant's IN-FLIGHT launch draws — owner-signed postpaid DEBITs under
        ``RESERVE_ENTRY_PREFIX`` whose matching ``SETTLE_ENTRY_PREFIX`` credit has NOT yet landed (reserved,
        not yet settled or cancelled). The PP-2 invoicing basis holds these OUT (`net_settled_consumed` below),
        so a reserved-but-unconsumed — or later-cancelled — launch is never billed; once it settles, only its
        NET consumption (`reserved - refund`) remains in `accrued` and becomes billable. Pairing is by the
        entry_id SUFFIX (`{slug}:{nonce}`) shared by the gate's reserve/settle pair, so the two can never drift.
        A DEBIT under some other entry_id (a finalised direct accrual) is NOT a reservation and never counted
        here. Signature-verified fail-closed: a forged reserve can only ever SUPPRESS a tenant's own billing,
        so an unsigned/forged/wrong-epoch record is ignored (never allowed to deflate the basis). Fail-closed
        to 0 on an empty id.

        PRUNE SAFETY: the per-reserve AMOUNTS come from the LIVE window only — ``stranded_active_postpaid_reserves``
        (spine/prune.py, wired into ``check_prune_safe``) fail-closed REFUSES any prune that would archive an
        UNSETTLED reserve, so the live window always holds every genuinely in-flight reserve + its paired settle.
        But the consumed-entry_id SEEN-SET is SNAPSHOT-SEEDED exactly as :meth:`_fold`, so a replay whose entry_id
        was consumed BEFORE a hard prune is ignored here too. WITHOUT that seed a FULLY-SETTLED reserve (reserve
        debit + settle credit both below the prune boundary, hence prunable) whose reserve debit was then replayed
        above the boundary would be counted as in-flight (its pruned settle can no longer pair it live), inflating
        ``in_flight_reserved`` and so UNDER-counting ``net_settled_consumed = accrued - in_flight`` — an UNDER-BILL
        (a revenue leak). Seeding the seen-set closes that (symmetric with cost_ledger._in_flight / was_accrued)."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: v.in_flight.get(org_id, 0))
        if hit is not _UNCACHED:
            return hit
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        reserves: dict[str, int] = {}      # in-flight suffix -> reserved credits (first-mint-wins, idempotent)
        settled: set[str] = set()          # suffixes whose settle credit has landed
        if not seed_applies(snap, self.trusted_pubkey, self.store):
            seen: set = set()              # anchor mismatch (rotated/empty key) => genesis scan, mirror _fold
            since = -1
        else:
            seen = set(snap.postpaid_arrears_seen_set())   # seed consumed entry_ids so a pre-prune replay is ignored
            since = snap.base_seq - 1                       # live window only (tripwire keeps every real in-flight here)
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != POSTPAID_DEBIT_SIGNAL and sig != POSTPAID_CREDIT_SIGNAL:
                continue
            if p.get("org_id") != org_id:
                continue
            eid = p.get("entry_id")
            if not (isinstance(eid, str) and eid):
                continue
            core = _PP_DEBIT_CORE if sig == POSTPAID_DEBIT_SIGNAL else _PP_CREDIT_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                  # fail-closed: never let a forged record move the basis
            key = (sig, org_id, eid)
            if key in seen:
                continue                                  # idempotent (mirror `_fold`): first occurrence wins
            seen.add(key)
            if sig == POSTPAID_DEBIT_SIGNAL and eid.startswith(RESERVE_ENTRY_PREFIX):
                reserves[eid[len(RESERVE_ENTRY_PREFIX):]] = _as_credits(p.get("credits"))
            elif sig == POSTPAID_CREDIT_SIGNAL and eid.startswith(SETTLE_ENTRY_PREFIX):
                settled.add(eid[len(SETTLE_ENTRY_PREFIX):])
        return sum(amt for suf, amt in reserves.items() if suf not in settled)

    def net_settled_consumed(self, org_id: str) -> int:
        """The tenant's BILLABLE consumption = `accrued` − `in_flight_reserved` — the PP-2 invoicing basis. A
        launch that has reserved but not yet settled contributes its full reserve to `accrued` (the credit-line
        cap must count it) but is held OUT of billing until it settles, when only its net consumed amount remains
        in `accrued`. A finalised DIRECT accrual (no reserve/settle pairing) carries no in-flight reservation and
        is billable at once. Clamped >= 0; fail-closed to 0 on an empty id."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        hit = self._cached(lambda v: max(0, _accrued(v.up, v.down, org_id) - v.in_flight.get(org_id, 0)))
        if hit is not _UNCACHED:
            return hit                                # ONE cached read: both terms from the same spine prefix
        return max(0, self.accrued(org_id) - self.in_flight_reserved(org_id))


def _accrued(debited: dict, credited: dict, org_id: str) -> int:
    return max(0, debited.get(org_id, 0) - credited.get(org_id, 0))


# ---- PP-2: arrears invoicing (reuses the owner-signed invoice ledger; no new spine record) ---------------
def postpaid_invoice_period_end(now: float) -> float:
    """The human-readable `period_end` LABEL for an arrears billing run at wall-clock `now` (POSIX seconds): the
    START of `now`'s UTC calendar month, as a POSIX timestamp. The CLI stamps it on the invoice so a monthly run
    labels its invoice with the month it covers. It is NO LONGER the idempotency key — concurrency-safety and
    exactly-once are the invoice_id's job, and that is content-addressed on the billing high-water
    (`invoice_postpaid_arrears`), which both dedups concurrent runs AND lets a later same-month run bill its new
    delta. Keeping the label a stable month boundary (not raw `time.time()`) keeps repeated monthly invoices
    cleanly labelled. Fail-closed: a non-finite / non-positive / unconvertible `now` clamps to 0.0."""
    import math
    from datetime import datetime, timezone
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return 0.0
    try:
        f = float(now)
        if not math.isfinite(f) or f <= 0.0:
            return 0.0
        dt = datetime.fromtimestamp(f, tz=timezone.utc)
        return datetime(dt.year, dt.month, 1, tzinfo=timezone.utc).timestamp()
    except (ValueError, OverflowError, OSError):
        return 0.0

def invoiced_postpaid_total(invoices: Any, org_id: str) -> int:
    """Σ credits of the POSTPAID arrears invoices already minted for `org_id` — the billed high-water. The
    arrears minter bills only the UN-invoiced delta against this, so re-running it never double-bills. Reads
    the owner-signed invoice ledger, org-scoped. Fail-closed to 0 on an empty id."""
    if not isinstance(org_id, str) or not org_id:
        return 0
    return sum(int(inv.credits) for inv in invoices.invoices(org_id) if inv.kind == "postpaid")


def invoice_postpaid_arrears(postpaid: "PostpaidRegistry", arrears: "PostpaidArrearsLedger", invoices: Any,
                             org_id: str, *, period_end: float, issued_at: float) -> Optional[int]:
    """Mint ONE owner-signed POSTPAID arrears invoice for a tenant's UN-INVOICED drawn credits, or None when
    there is nothing new to bill (not postpaid, or no new draws). The billed amount comes from the owner CATALOG
    (`catalog.postpaid_invoice_amount_minor`), NEVER a wire value. Idempotent + concurrency-safe via a
    CONTENT-ADDRESSED invoice_id keyed on the per-org billing high-water (see below), so a billing run is safe to
    repeat OR race — `period_end` is only the invoice's period label.

    DELTA MODEL — bills `drawn - already_invoiced`, so re-running (or a mid-period re-run) never double-bills and
    each period captures only the new draws. The invoicing basis is `arrears.net_settled_consumed(org)` =
    `accrued - in_flight_reserved`, NOT the raw `accrued`: a launch that has RESERVED against the line but not
    yet SETTLED contributes its full reserve to `accrued` (the credit-line cap must count it) but is held OUT of
    billing until it settles — at which point only its NET consumed amount (`reserved - refund`) remains in
    `accrued` and becomes billable. This is the red-pen MED fix: billing raw `accrued` over-billed an in-flight
    reservation, and a LATER cancel (which lowers `accrued` below the already-invoiced total) could not claw the
    over-bill back (the delta model only ever bills forward). Holding in-flight reserves out means a launch is
    billed once, at net consumed, only after it settles — and a cancelled draw is never billed. PP-2b (invoice
    PAYMENT -> arrears reversal) MUST keep this basis as net consumption EXCLUDING payments (a payment settles the
    debt; it does not un-consume), so it will add a payment mechanism DISTINCT from this ledger's settle-refund
    credits rather than lowering the value this reads. The gate's credit-line cap (`accrued <= credit_limit`) is
    unchanged by invoicing."""
    if not postpaid.is_postpaid(org_id):
        return None
    oid = org_tenant_id(org_id)
    invoiced_before = invoiced_postpaid_total(invoices, oid)   # the billing HIGH-WATER before this mint
    drawn = arrears.net_settled_consumed(oid)         # PP-2: settled consumption only (in-flight reserves held out)
    delta = drawn - invoiced_before
    if delta <= 0:
        return None                                   # nothing new drawn since the last invoice
    from .catalog import postpaid_invoice_amount_minor
    amount, currency = postpaid_invoice_amount_minor(delta)
    # CONTENT-ADDRESSED idempotency key (red-pen HIGH): the invoice_id is the per-org billing HIGH-WATER this
    # invoice advances FROM (`invoiced_before`), NOT the wall-clock period. Two runs RACING on the same high-water
    # compute the SAME id, so the owner-signed invoice fold (first-mint-wins) dedups them -> no double-bill, and it
    # is deterministic ACROSS PROCESSES with no lock (the process-wide spine lock does not serialise a read-modify-
    # write across processes). A later run billing a NEW delta advances to a HIGHER high-water -> a DISTINCT id ->
    # it mints, so a same-month re-run's new consumption is never dropped (the month-key under-bill/leak is closed).
    # `period_end` is now purely the invoice's period LABEL, not the idempotency key.
    return invoices.record(oid, invoice_id=f"postpaid:{oid}:{invoiced_before}", kind="postpaid",
                           price_id="postpaid_arrears", amount_minor=amount, currency=currency,
                           credits=delta, period_start=0.0, period_end=float(period_end),
                           issued_at=float(issued_at))


# ---- PP-2b: invoice PAYMENT -> outstanding-balance tracking (receipts, DISTINCT from the consumption basis) ---
# A payment is money IN against a minted arrears invoice. It reduces what the tenant OWES (`postpaid_outstanding`)
# but it is NOT a change to consumption: it must NOT lower `accrued` / `net_settled_consumed` (the billing basis)
# NOR `invoiced_postpaid_total` (the billing high-water), or the delta model would under-bill future consumption.
# So a payment lives ONLY in the billing-history ledger as a `kind="payment"` receipt (owner-signed, idempotent,
# prune-durable like any invoice), never as an arrears-ledger credit. PP-3 dunning tests `postpaid_outstanding`.
_POSTPAID_PAYMENT_PRICE_ID = "postpaid_payment"
_POSTPAID_PAYMENT_ID_PREFIX = "pay:"    # a receipt's invoice_id is this + the paid invoice's id (single-sourced)


def paid_postpaid_total(invoices: Any, org_id: str) -> int:
    """Σ credits of the POSTPAID-invoice PAYMENTS (receipts) recorded for `org_id` — what the tenant has PAID
    against its arrears invoices. Reads `kind == "payment"` lines tagged `price_id == "postpaid_payment"` (so a
    future top-up/subscription payment can never be miscounted here). Org-scoped; fail-closed to 0 on empty."""
    if not isinstance(org_id, str) or not org_id:
        return 0
    return sum(int(inv.credits) for inv in invoices.invoices(org_id)
               if inv.kind == "payment" and inv.price_id == _POSTPAID_PAYMENT_PRICE_ID)


def postpaid_outstanding(invoices: Any, org_id: str) -> int:
    """What the tenant currently OWES on its postpaid arrears = Σ invoiced − Σ paid, clamped >= 0. This is the
    scalar PP-3 dunning will test (billed-but-unpaid drives access reduction). DISTINCT from `accrued` (the
    credit-line draw) and `net_settled_consumed` (the un-invoiced billing basis): outstanding is the
    billed-but-unpaid balance. Fail-closed to 0 on an empty id."""
    if not isinstance(org_id, str) or not org_id:
        return 0
    return max(0, invoiced_postpaid_total(invoices, org_id) - paid_postpaid_total(invoices, org_id))


def pay_postpaid_invoice(invoices: Any, org_id: str, invoice_id: str, *, issued_at: float) -> Optional[int]:
    """Record a PAYMENT settling ONE owner-signed POSTPAID arrears invoice in full, reducing the tenant's
    OUTSTANDING balance. Returns the receipt record's seq, or None when there is nothing to pay (no such postpaid
    invoice for this org, or it is already paid).

    MONEY DOCTRINE: the paid amount/credits come from the NAMED owner-signed invoice itself (catalog-derived at
    its mint), NEVER a wire value — the caller names WHICH invoice is paid, not how much. Idempotent per
    `pay:{invoice_id}` (paying the same invoice twice folds once — the invoice ledger is first-mint-wins, so even
    a concurrent double-pay credits once). The receipt is itself owner-signed (via `invoices.record`), so a forged
    payment cannot deflate a victim's outstanding. The arrears ledger (accrued / net_settled_consumed) is
    UNTOUCHED, so future arrears invoicing still bills real consumption. The real payment-provider path (a verified
    webhook whose amount is cross-checked against this invoice's catalog amount) is a prod-gated follow-up; this is
    the mock-first owner/operator receipt."""
    if not (isinstance(org_id, str) and org_id and isinstance(invoice_id, str) and invoice_id):
        return None                                   # fail-closed on an empty org / id (never raise into a caller)
    oid = org_tenant_id(org_id)
    invs = invoices.invoices(oid)                     # one org-scoped fold
    target = next((inv for inv in invs if inv.invoice_id == invoice_id and inv.kind == "postpaid"), None)
    if target is None:
        return None                                   # no such postpaid invoice for this tenant (fail-closed)
    pay_id = f"{_POSTPAID_PAYMENT_ID_PREFIX}{target.invoice_id}"
    if any(inv.invoice_id == pay_id for inv in invs):
        return None                                   # already paid (idempotent receipt already folded)
    return invoices.record(oid, invoice_id=pay_id, kind="payment", price_id=_POSTPAID_PAYMENT_PRICE_ID,
                           amount_minor=int(target.amount_minor), currency=target.currency,
                           credits=int(target.credits), period_start=0.0, period_end=float(target.period_end),
                           issued_at=float(issued_at))


# ---- PP-3: dunning -> credit-gate interaction (an OVERDUE line refuses NEW launches, the SAFE direction) ------
# An arrears invoice is OVERDUE when it is UNPAID and its due date has passed. The due date is the invoice's
# period_end plus the tenant's current owner-signed net_terms_days. A tenant with any overdue invoice is refused
# NEW launches by the launch gate (reserve-time only — an already in-flight launch still settles); paying the
# invoice (PP-2b) clears the overdue state and launches resume (reversible). Reading-only + fail-closed, so a
# replay (a re-appended invoice/payment folds once, content-addressed) can neither advance a period nor evade
# dunning. DISTINCT from the credit-line cap (accrued <= credit_limit, enforced at reserve by PP-1).
def postpaid_overdue_amount(invoices: Any, postpaid: "PostpaidRegistry", org_id: str, now: float) -> int:
    """Σ credits of the tenant's UNPAID postpaid invoices whose due date (period_end + net_terms_days) has passed
    at `now`. `net_terms_days` comes from the CURRENT owner-signed account. An invoice is PAID iff a
    `pay:{invoice_id}` receipt exists (PP-2b). Fail-closed to 0 on an empty id, an unknown/not-postpaid account,
    or a non-finite `now` (never spuriously overdue -> never wrongly refuses)."""
    if not isinstance(org_id, str) or not org_id:
        return 0
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return 0
    import math
    if not math.isfinite(float(now)):
        return 0
    acct = postpaid.account(org_id)
    if acct is None:
        return 0                                       # never postpaid -> no arrears invoices -> not overdue
    net_secs = max(0, int(acct.net_terms_days)) * 86400
    rows = invoices.invoices(org_id)
    paid: set = {inv.invoice_id[len(_POSTPAID_PAYMENT_ID_PREFIX):] for inv in rows
                 if inv.kind == "payment" and inv.price_id == _POSTPAID_PAYMENT_PRICE_ID
                 and inv.invoice_id.startswith(_POSTPAID_PAYMENT_ID_PREFIX)}
    overdue = 0
    for inv in rows:
        if inv.kind != "postpaid" or inv.invoice_id in paid:
            continue                                   # not an arrears invoice, or already settled
        if float(now) >= float(inv.period_end) + net_secs:
            overdue += int(inv.credits)                # unpaid AND past the net-terms due date
    return overdue


def postpaid_is_overdue(invoices: Any, postpaid: "PostpaidRegistry", org_id: str, now: float) -> bool:
    """True iff the tenant has ANY unpaid postpaid invoice past its net-terms due date at `now` — the dunning
    predicate the launch gate consults to refuse NEW launches (reversible on payment). Fail-closed (False) on a
    bad id / account / clock, so dunning never wrongly blocks a tenant in good standing."""
    return postpaid_overdue_amount(invoices, postpaid, org_id, now) > 0
