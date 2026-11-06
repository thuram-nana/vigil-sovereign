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
  * `accrue` (a launch draws against the line) appends `governor.postpaid_debit`; `reverse` (settle/cancel
    refunds the unconsumed part, or PP-2 records a paid invoice) appends `governor.postpaid_credit`. Both are
    owner/gate-signed + verified so a forged record cannot inflate OR deflate a victim's arrears; idempotent per
    `entry_id` (a replayed reserve/settle no-ops). The gate's accrual-delta invariant (accrued MUST rise by the
    reserved units, else refuse) makes a reused nonce fail-closed, mirroring the prepaid availability-delta.

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
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed — mirrors subscription._fold)

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
    def _fold(self) -> dict[Any, PostpaidAccount]:
        """Fold the spine into {org_id: PostpaidAccount}. `enabled` is authenticated under the owner pubkey
        valid AT ITS SEQ and gated by the per-org high-water (stale/replayed open ignored); `disabled` is the
        safe direction (honored on sight at 0.0, or webhook-fresh), lowering only `enabled` and retaining the
        last-open limit/terms for the dunning/arrears view. HARD-PRUNE SEED (mirrors `subscription._fold`):
        seed per-org enabled / high-water / limit-row from `SnapshotState`, then fold the LIVE window only; a
        rotated/empty anchor bypasses the seed and full-scans from genesis (byte-identical under empty)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            enabled: dict[Any, bool] = {}
            issued: dict[Any, float] = {}
            row: dict[Any, list] = {}
            since = -1
        else:
            enabled = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_state", [])}
            issued = {r[0]: r[1] for r in getattr(snap, f"{self._SNAP}_issued", [])}
            row = {r[0]: [r[1], r[2]] for r in getattr(snap, f"{self._SNAP}_row", [])}  # oid -> [limit, net_terms]
            since = snap.base_seq - 1
        for rec in self.store.iter_records(since_seq=since):
            p = rec.payload
            if not isinstance(p, dict) or p.get("signal") != self.SIGNAL:
                continue
            oid = p.get("org_id")
            if not isinstance(oid, str) or not oid:
                continue
            if p.get("enabled") is True:
                # DANGEROUS (access-granting) direction: owner-signed + fresh only.
                if not verify_signed(p, _PP_CORE, resolver.at(rec.seq)):
                    continue                                  # fail-closed: unsigned / forged / wrong-epoch
                at = as_issued_at(p.get("issued_at"))
                if at <= issued.get(oid, NO_HIGHWATER):
                    continue                                  # REPLAY / stale re-append of an honored open
                issued[oid] = at
                enabled[oid] = True
                row[oid] = [_as_nonneg_int(p.get("credit_limit")), _as_nonneg_int(p.get("net_terms_days"))]
            else:
                # SAFE (access-reducing) direction. A FIXED 0.0 issued_at is the owner-manual latch: honored
                # ON SIGHT (never fail-open). A POSITIVE issued_at is webhook-driven: applied only if FRESHER
                # than the last honored open (the fold does NOT advance `issued` here — that stays the open
                # high-water it compares against), so a stale/replayed close cannot shut a re-opened tenant.
                dat = as_issued_at(p.get("issued_at"))
                if dat <= 0.0 or dat > issued.get(oid, NO_HIGHWATER):
                    enabled[oid] = False
        out: dict[Any, PostpaidAccount] = {}
        for oid, en in enabled.items():
            r = row.get(oid)
            if r is None:
                # A bare disable for an org that never had an honored open never had a line — treat as ABSENT
                # (mirrors subscription's row==None drop), so `account()` reads None ("never postpaid").
                continue
            out[oid] = PostpaidAccount(org_id=str(oid), credit_limit=int(r[0]), net_terms_days=int(r[1]),
                                       enabled=bool(en))
        return out

    def account(self, org_id: str) -> Optional[PostpaidAccount]:
        """The current folded PostpaidAccount for `org_id` whatever its enabled state (None if the tenant was
        never set postpaid). Fail-closed on an empty/invalid id."""
        if not isinstance(org_id, str) or not org_id:
            return None
        return self._fold().get(org_id)

    def is_postpaid(self, org_id: str) -> bool:
        """True iff `org_id` has a currently-ENABLED postpaid credit line — the primitive the gate asks
        'does this tenant draw against a line instead of burning prepaid?'. Fail-closed (False) otherwise."""
        a = self.account(org_id)
        return a is not None and a.is_enabled()

    def accounts(self) -> list[PostpaidAccount]:
        """Every tenant's current postpaid account, in org_id order (the arrears roster)."""
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
        _debited, _credited, seen = self._fold()
        return (POSTPAID_DEBIT_SIGNAL, org_id, entry_id) in seen

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _fold(self) -> tuple[dict[Any, int], dict[Any, int], set]:
        """Fold the spine into (debited, credited, seen) keyed per `org_id`, where `seen` holds the consumed
        `(signal, org_id, entry_id)` idempotency keys. Each signed record is authenticated under the owner
        pubkey valid AT ITS SEQ; a record whose key is already in `seen` is ignored (idempotent, namespaced by
        SIGNAL so a debit and a credit never collide). HARD-PRUNE SEED (mirrors `wallet._fold`): seed the
        per-org totals + `seen` from `SnapshotState`, then fold the LIVE window only. A rotated/empty anchor
        BYPASSES the snapshot and full-scans from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        if self.trusted_pubkey != snap.trusted_pubkey:
            debited: dict[Any, int] = {}
            credited: dict[Any, int] = {}
            seen: set = set()
            since = -1
        else:
            debited = dict(snap.postpaid_arrears_debited_map())
            credited = dict(snap.postpaid_arrears_credited_map())
            seen = set(snap.postpaid_arrears_seen_set())
            since = snap.base_seq - 1
        for r in self.store.iter_records(since_seq=since):
            p = r.payload
            if not isinstance(p, dict):
                continue
            sig = p.get("signal")
            if sig != POSTPAID_DEBIT_SIGNAL and sig != POSTPAID_CREDIT_SIGNAL:
                continue
            oid = p.get("org_id")
            eid = p.get("entry_id")
            if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
                continue
            core = _PP_DEBIT_CORE if sig == POSTPAID_DEBIT_SIGNAL else _PP_CREDIT_CORE
            if not verify_signed(p, core, resolver.at(r.seq)):
                continue                                  # fail-closed: unsigned/forged/wrong-epoch record
            key = (sig, oid, eid)
            if key in seen:
                continue                                  # idempotent: this entry already counted (replay)
            seen.add(key)
            amount = _as_credits(p.get("credits"))
            if sig == POSTPAID_DEBIT_SIGNAL:
                debited[oid] = debited.get(oid, 0) + amount
            else:
                credited[oid] = credited.get(oid, 0) + amount
        return debited, credited, seen

    def accrued(self, org_id: str) -> int:
        """The tenant's current unpaid arrears = Σ debits − Σ reversals, clamped >= 0 (defence-in-depth: an
        over-reversal can never read as a negative balance / a credit the tenant is owed). Fail-closed to 0 on
        an empty id. This is the scalar the launch gate tests against the account's `credit_limit`."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        debited, credited, _ = self._fold()
        return max(0, debited.get(org_id, 0) - credited.get(org_id, 0))

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

        PRUNE EDGE (documented; PP-2b hardening): this is a LIVE pairing scan, not snapshot-seeded, because the
        per-reserve amounts it needs are not carried in the arrears seed (which keeps only per-org totals + the
        seen-set). A hard prune that dropped an UNSETTLED reserve debit would under-count here and let that
        reserve bill as consumed — but that degrades at worst to billing `accrued` (the pre-PP-2 behaviour,
        never WORSE), and is prevented in practice by the ``stranded_active_postpaid`` prune tripwire holding an
        active line's records. A snapshot-seeded per-reserve in-flight sub-state is deferred to PP-2b."""
        if not isinstance(org_id, str) or not org_id:
            return 0
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        reserves: dict[str, int] = {}      # in-flight suffix -> reserved credits (first-mint-wins, idempotent)
        settled: set[str] = set()          # suffixes whose settle credit has landed
        seen: set = set()
        for r in self.store.iter_records():
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
        return max(0, self.accrued(org_id) - self.in_flight_reserved(org_id))


# ---- PP-2: arrears invoicing (reuses the owner-signed invoice ledger; no new spine record) ---------------
def postpaid_invoice_period_end(now: float) -> float:
    """The canonical `period_end` for an arrears billing run at wall-clock `now` (POSIX seconds): the START of
    `now`'s UTC calendar month, as a POSIX timestamp. STABLE within a month, so every billing run in that month
    — concurrent, repeated, or in another process — derives the SAME invoice_id (`postpaid:{org}:{period_end}`),
    and the owner-signed invoice ledger's first-mint-wins fold collapses them to ONE invoice.

    SECURITY (red-pen HIGH): the CLI previously keyed `period_end` on raw `time.time()`, so two runs in one period
    got DISTINCT ids and minted TWO invoices for the same draws — a double-bill. A stable per-month key closes it
    with no cross-process lock. Fail-closed: a non-finite / non-positive / unconvertible `now` clamps to 0.0 (a
    still-stable, if degenerate, key — never a wall-clock value that would reopen the double-bill)."""
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
    (`catalog.postpaid_invoice_amount_minor`), NEVER a wire value. Idempotent per `(org, period_end)` via the
    invoice_id, so a billing run is safe to repeat.

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
    drawn = arrears.net_settled_consumed(oid)         # PP-2: settled consumption only (in-flight reserves held out)
    delta = drawn - invoiced_postpaid_total(invoices, oid)
    if delta <= 0:
        return None                                   # nothing new drawn since the last invoice
    from .catalog import postpaid_invoice_amount_minor
    amount, currency = postpaid_invoice_amount_minor(delta)
    return invoices.record(oid, invoice_id=f"postpaid:{oid}:{repr(float(period_end))}", kind="postpaid",
                           price_id="postpaid_arrears", amount_minor=amount, currency=currency,
                           credits=delta, period_start=0.0, period_end=float(period_end),
                           issued_at=float(issued_at))
