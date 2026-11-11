"""Enterprise SaaS BILLING — the per-tenant INVOICE / billing-history ledger (owner-signed, append-only).

Slice H. A customer's billing history is a first-class, durable, per-tenant financial record: one owner-signed
``governor.invoice`` record per confirmed billing event (a subscription period charged, a credit top-up), so a
customer can read exactly what they were billed, when, for what, and how much — independent of their CURRENT
credit balance.

Why a DEDICATED record and not a derivation (the load-bearing design choice): the subscription fold is LWW
(only the LATEST period's state survives) and the wallet/plan folds collapse to running totals, so NONE of them
can reconstruct a multi-period billing HISTORY, and after a hard prune the raw per-period records are gone
entirely. A billing history that survives a prune therefore needs its OWN additive, append-only, prune-seeded
record — modelled byte-for-byte on `governor/wallet.py` (the additive + idempotent + hard-prune-durable ledger),
differing only in that it carries ROWS (the history lines) rather than running totals.

MODEL (owner-signed + verified; no "honored-unsigned" direction — a forged invoice must not appear in a
tenant's history, and a tampered amount/price/period must not verify):
  * `governor.invoice` — ONE billing-history line. Each carries a globally-unique `invoice_id` (the provider
    event_id at the mint site, so a webhook REPLAY reuses it and folds ONCE — idempotent). A record whose
    (org_id, invoice_id) is already folded is IGNORED, so a captured/replayed invoice — including one replayed
    AFTER a hard prune — can never duplicate a history line.

MONEY DOCTRINE: `amount_minor` is the owner-CATALOG price for `price_id` (minor units, e.g. cents), decided by
the caller (`BillingSigner`) from the catalog, NEVER an on-the-wire amount. This module is the ledger primitive
— it stores + signs what it is given and validates it is well-formed; the catalog-binding lives at the mint
site. `amount_minor`/`price_id`/`currency`/`credits`/`period_*` are all INSIDE the signed core, so none can be
re-aimed or rewritten without breaking the signature (a later price-table edit never rewrites billed history).

ANTI-REPLAY ACROSS A HARD PRUNE (identical to the wallet): the history is a lifetime append-only list, so it
MUST be seeded from `SnapshotState` or the first hard prune would (1) LOSE every historical invoice and (2) drop
the consumed `invoice_id` set, re-opening invoice replay. The fold seeds the per-(org_id, invoice_id) rows from
`SnapshotState.invoice_row`, then folds the LIVE window only; `spine.prune` refuses any prune that would strand
an invoice the seed does not carry (`stranded_invoices`, the same fail-closed tripwire as `stranded_active_wallets`).
Owner-key-succession-aware exactly like the wallet fold: each record is verified under the owner pubkey valid AT
ITS SEQ; a rotated/empty anchor bypasses the snapshot and full-scans from genesis (byte-identical under the
empty snapshot). FATAL-2: sovereign-side, `assert_no_offense` at import; the keyless offense plane never reads it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

from . import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors wallet._fold)
from .authn import as_issued_at, signed_payload, verify_signed  # noqa: E402
from .identity import owner_keypair, owner_pubkey  # noqa: E402
from .orgs import org_tenant_id  # noqa: E402  (org_id validation == tenant-id validation; same-plane reuse)
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed — mirrors wallet._fold)
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from .fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402

INVOICE_SIGNAL = "governor.invoice"

# The kinds of billing-history line. `subscription` = a subscription period was charged; `topup` = a one-off
# paid credit purchase; `postpaid` = an enterprise arrears invoice (PP-2); `payment` = a RECEIPT against a
# postpaid arrears invoice (PP-2b) — money IN, reducing the tenant's OUTSTANDING balance, NOT a charge and NOT a
# change to the consumption basis the arrears invoicing bills from. Extendable later (refund, adjustment) WITHOUT
# a schema change — a fold ignores an unknown kind's row only if a reader opts to, but by default every
# well-formed signed row is retained as history (the kind is descriptive, not a gate).
INVOICE_KINDS = frozenset({"subscription", "topup", "postpaid", "payment"})

# The owner-signed authenticated CORE. `invoice_id` is inside it so a captured record cannot be re-stamped with
# a fresh idempotency key to forge a duplicate line. `amount_minor`/`currency`/`price_id`/`credits`/`period_*`
# are inside it so a line for (orgA, $49, pro) can never be re-aimed at another org or have its money/plan
# rewritten without breaking the signature. `issued_at` is inside it (ordering + audit; the ledger is additive,
# NOT LWW, so there is no per-key high-water — idempotency is by invoice_id, which is why it MUST be signed).
_INVOICE_CORE = ("signal", "org_id", "invoice_id", "kind", "price_id", "amount_minor", "currency",
                 "credits", "period_start", "period_end", "issued_at")


def _as_nonneg_int(v: object) -> int:
    """A money/credits value READ off the spine → a non-negative int (mirrors wallet._as_credits): a forged
    NEGATIVE amount must not read as a credit/refund, and junk / NaN / an over-large int folds to 0."""
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float, str)):
        try:
            n = int(v)
        except (TypeError, ValueError, OverflowError):
            return 0
        return n if n > 0 else 0
    return 0


def _check_nonneg_int(value: object, name: str) -> int:
    """Validate a money/credits amount at BINDING time (a clean ValueError now, never a silent bad record).
    An invoice may legitimately carry 0 (e.g. no catalog price configured, or a zero-credit line), so this is
    >= 0 (unlike a wallet grant, which must be > 0)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a non-negative integer")
    if value < 0:
        raise ValueError(f"{name} must be a non-negative integer (>= 0)")
    return value


def _check_invoice_id(invoice_id: str) -> str:
    """The globally-unique idempotency key for one billing-history line (the provider event_id at the mint
    site). REQUIRED (never generated — a line with no stable id could duplicate on replay). Bounded + non-control
    so it round-trips the signed core and the snapshot row verbatim."""
    e = str(invoice_id or "").strip()
    if not e or len(e) > 128 or any(ord(c) < 0x20 or ord(c) == 0x7f for c in e):
        raise ValueError("invoice_id must be a non-empty, non-control string of <= 128 chars")
    return e


def _check_kind(kind: str) -> str:
    k = str(kind or "").strip()
    if k not in INVOICE_KINDS:
        raise ValueError(f"invoice kind must be one of {sorted(INVOICE_KINDS)}")
    return k


def _check_currency(currency: str) -> str:
    """An ISO-4217-shaped code, uppercased, or empty (an invoice whose money amount the catalog does not price
    carries no currency). Bounded + alphabetic so it round-trips the signed core verbatim."""
    c = str(currency or "").strip().upper()
    if c and (len(c) > 8 or not c.isalpha()):
        raise ValueError("currency must be an alphabetic code of <= 8 chars, or empty")
    return c


@dataclass(frozen=True)
class Invoice:
    """One billing-history line, every field derived from an owner-signed spine record (never a mutable row)."""
    org_id: str
    invoice_id: str
    kind: str
    price_id: str
    amount_minor: int           # catalog price in minor units (e.g. cents); 0 when the catalog does not price it
    currency: str               # ISO-4217-shaped, uppercased; "" when amount_minor is 0/unpriced
    credits: int                # credits this billing event granted (the plan allotment / top-up amount)
    period_start: float         # subscription period start (POSIX); 0.0 for a top-up
    period_end: float           # subscription period end (POSIX); 0.0 for a top-up
    issued_at: float            # the billing event time (ordering + audit)


_SKIP = object()          # `_apply_invoice_record`: the record added no history line


def _apply_invoice_record(r, resolver, rows: dict):
    """Fold ONE spine record into `rows` — THE invoice fold body, shared by the full `_fold` and the verified
    fold cache (Front C S0d) so the two can never diverge. Returns the (org_id, invoice_id) it added, or
    `_SKIP`."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != INVOICE_SIGNAL:
        return _SKIP
    oid = p.get("org_id")
    iid = p.get("invoice_id")
    if not (isinstance(oid, str) and oid and isinstance(iid, str) and iid):
        return _SKIP
    key = (oid, iid)
    if key in rows:
        return _SKIP                                  # idempotent: first mint of this invoice_id wins
    if not verify_signed(p, _INVOICE_CORE, resolver.at(r.seq)):
        return _SKIP                                  # fail-closed: unsigned / forged / wrong-epoch record
    rows[key] = Invoice(
        org_id=oid, invoice_id=iid, kind=str(p.get("kind") or ""), price_id=str(p.get("price_id") or ""),
        amount_minor=_as_nonneg_int(p.get("amount_minor")), currency=str(p.get("currency") or ""),
        credits=_as_nonneg_int(p.get("credits")), period_start=as_issued_at(p.get("period_start")),
        period_end=as_issued_at(p.get("period_end")), issued_at=as_issued_at(p.get("issued_at")))
    return key


class _InvoicesView:
    """The cached invoice fold: exactly the full fold's `rows`, plus `by_org` (org_id -> its invoice ids) so a
    tenant's billing history is O(its own lines) instead of a scan of every tenant's. The ledger is additive
    (a line is never removed), so the index only ever grows."""

    __slots__ = ("rows", "by_org")

    def __init__(self, rows: dict) -> None:
        self.rows = rows
        self.by_org: "dict[str, list]" = {}
        for key in rows:
            self.index(key)

    def index(self, key) -> None:
        self.by_org.setdefault(key[0], []).append(key[1])

    def of_org(self, org_id: str) -> "list[Invoice]":
        return [self.rows[(org_id, iid)] for iid in self.by_org.get(org_id, ())]


def _invoices_step(view: _InvoicesView, r, resolver) -> None:
    key = _apply_invoice_record(r, resolver, view.rows)
    if key is not _SKIP:
        view.index(key)


_INVOICES_FOLD = FoldCache("governor.invoice", step=_invoices_step)


class InvoiceRegistry:
    """Owner-signed, append-only per-tenant invoice ledger on the spine. Construction mirrors `WalletRegistry` /
    `OrgRegistry`: the owner signing key + trusted pubkey default to the persisted owner identity; tests inject."""

    def __init__(self, store, *, owner_key=None, trusted_pubkey: Optional[str] = None):
        self.store = store
        self.owner_key = owner_key if owner_key is not None else owner_keypair()
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()

    # -- owner mutation ----------------------------------------------------------------------------
    def record(self, org_id: str, *, invoice_id: str, kind: str, price_id: str, amount_minor: int,
               currency: str = "", credits: int = 0, period_start: float = 0.0, period_end: float = 0.0,
               issued_at: float) -> int:
        """Owner-sign ONE billing-history line for a tenant. Requires the owner signing key (an unsigned invoice
        never verifies in the fold, so it would be inert). Idempotent: re-appending the same `invoice_id` is a
        harmless no-op in the fold. `amount_minor` is the CATALOG price (money doctrine — the caller derives it
        from the catalog, never from a wire amount). Returns the record seq."""
        if self.owner_key is None:
            raise ValueError("invoice record requires the owner signing key")
        oid = org_tenant_id(org_id)                       # validates org_id == a valid tenant id, fail-closed
        iid = _check_invoice_id(invoice_id)
        k = _check_kind(kind)
        amt = _check_nonneg_int(amount_minor, "amount_minor")
        cred = _check_nonneg_int(credits, "credits")
        cur = _check_currency(currency)
        core = {"signal": INVOICE_SIGNAL, "org_id": oid, "invoice_id": iid, "kind": k,
                "price_id": str(price_id or ""), "amount_minor": amt, "currency": cur, "credits": cred,
                "period_start": float(period_start), "period_end": float(period_end),
                "issued_at": float(issued_at)}
        payload = {**signed_payload(core, self.owner_key), "by": "owner", "requested_by": "owner",
                   "tier": "A0", "decision": "auto",
                   "reason": f"invoice {k} ({amt} {cur or '-'}) -> {oid}"}
        return self.store.append(kind="event", source="governor", actor="WARDEN", payload=payload)

    # -- reads (owner-key-succession-aware fold; seeded from SnapshotState across a hard prune) -----
    def _seed(self, snap) -> "tuple[dict, int]":
        """(rows, since): the HARD-PRUNE SEED from `snap`, or the empty genesis start when the trusted pubkey
        differs from the snapshot's (mirror wallet)."""
        rows: dict[tuple, Invoice] = {}
        if self.trusted_pubkey != snap.trusted_pubkey:
            return rows, -1                               # anchor mismatch ⇒ genesis full-scan (mirror wallet)
        for row in snap.invoice_row:                      # seed the pruned-prefix rows (prune durability)
            if isinstance(row, (list, tuple)) and len(row) >= 10:
                key = (row[0], row[1])
                if key not in rows:
                    rows[key] = Invoice(org_id=str(row[0]), invoice_id=str(row[1]), kind=str(row[2]),
                                        price_id=str(row[3]), amount_minor=_as_nonneg_int(row[4]),
                                        currency=str(row[5]), credits=_as_nonneg_int(row[6]),
                                        period_start=as_issued_at(row[7]), period_end=as_issued_at(row[8]),
                                        issued_at=as_issued_at(row[9]))
        return rows, snap.base_seq - 1

    def _cached(self, reader):
        """`reader(view)` over the verified incremental invoice fold (`fold_read.cached_read`, flag-gated), else
        `_UNCACHED` (the caller then runs the full `_fold`)."""
        def seed(snap):
            rows, since = self._seed(snap)
            return _InvoicesView(rows), since

        return cached_read(_INVOICES_FOLD, self.store, trusted_pubkey=self.trusted_pubkey, seed=seed,
                           reader=reader)

    def _fold(self) -> dict[tuple, Invoice]:
        """Fold the spine into {(org_id, invoice_id): Invoice}. Each signed record is authenticated under the
        owner pubkey valid AT ITS SEQ; a record whose (org_id, invoice_id) is ALREADY folded is ignored (the
        first mint wins — idempotency / replay guard). HARD-PRUNE SEED (mirrors `wallet._fold`): seed the rows
        from `SnapshotState.invoice_row`, then fold the LIVE window only — so a pruned invoice stays in the
        history AND its invoice_id stays consumed. A rotated/empty anchor BYPASSES the snapshot and full-scans
        from genesis (byte-identical under the empty snapshot)."""
        snap = SnapshotState.load(self.store)
        resolver = _kh.key_resolver(self.store, current=self.trusted_pubkey)
        rows, since = self._seed(snap)
        for r in self.store.iter_records(since_seq=since):
            _apply_invoice_record(r, resolver, rows)
        return rows

    @staticmethod
    def _sort_key(inv: Invoice) -> tuple:
        # Newest-first by issued_at, then invoice_id for a deterministic total order on ties.
        return (-inv.issued_at, inv.invoice_id)

    def invoices(self, org_id: str) -> list[Invoice]:
        """The billing history for `org_id`, newest-first (fail-closed: an unknown/empty org reads as empty).
        Scoped to the ONE tenant — the caller resolves `org_id` server-side (the IDOR-safe read; a customer
        never names another org)."""
        if not isinstance(org_id, str) or not org_id:
            return []
        org_id = str.__str__(org_id)            # an exact str: a str subclass's own __eq__ / __hash__ never decide
        hit = self._cached(lambda v: v.of_org(org_id))
        if hit is not _UNCACHED:
            return sorted(hit, key=self._sort_key)
        rows = self._fold()
        return sorted((inv for (o, _i), inv in rows.items() if o == org_id), key=self._sort_key)

    def has_purchased_credits(self, org_id: str) -> bool:
        """True iff ``org_id`` has completed at least one PURCHASE of credits (a credit pack or a custom top-up): an
        owner-signed billing-history line of kind ``topup`` that granted ``credits > 0``. The one producer of such a
        line is ``BillingSigner.apply``'s ``EVENT_TOPUP`` branch (``governor/billing.py``), after a provider-VERIFIED
        top-up payment mapped through the owner catalog, right after its wallet grant was written. So credits that
        were not bought as a top-up never count: a trial grant, a settle refund or any other ``WalletRegistry.grant``
        writes no invoice, and plan subscriptions, AEGIS monitoring subscriptions and postpaid lines are other kinds.
        Tenant-scoped by the owner-signed ``org_id`` (the caller resolves it server-side; a customer never names
        another org). Fail-closed on the input: an empty / non-string / unknown org reads as False. Store or
        snapshot errors are NOT swallowed: like every snapshot-seeded read (``invoices``, the wallet) this raises
        when the spine's committed snapshot cannot be read, so a caller gating access on it must treat an exception
        as False.

        Known gaps, all deliberate:

          * **A paying subscriber or postpaid customer who never bought a top-up reads False.** The question is
            "has this org bought credits", not "has this org ever paid VIGIL".
          * **A failure between the wallet grant and its invoice line reads as "not purchased".** ``BillingSigner``
            grants first and records the invoice second. The provider does NOT redeliver (the webhook proxy already
            answered 202 when it spooled the event). If the invoice write raises, the billing drain quarantines the
            envelope to ``rejected/`` (``inbound/billing_spool.py``) and alarms until an operator re-admits it; a hard
            crash between the two writes is instead reclaimed from ``working/`` on the next drain. Re-ingesting
            re-runs the same ``event_id``-idempotent mint, so the wallet is not credited twice and the missing line
            is written — provided the charge still re-verifies as successful and still matches the CURRENT catalog
            price; otherwise the re-ingest is archived as a no-op and this stays False for that payment.
          * **A purchase is never revoked.** There is no chargeback or purchase-refund record in this ledger, so a
            payment the provider later reverses still reads as purchased. Whatever was unlocked on it stays
            unlocked (an owner-accepted risk, not a guarantee)."""
        return any(inv.kind == "topup" and inv.credits > 0 for inv in self.invoices(org_id))

    def all_invoices(self) -> list[Invoice]:
        """Every invoice across all tenants (the owner/operator billing view), newest-first then org-stable."""
        hit = self._cached(lambda v: list(v.rows.values()))
        rows = self._fold().values() if hit is _UNCACHED else hit
        return sorted(rows, key=lambda i: (self._sort_key(i), i.org_id))
