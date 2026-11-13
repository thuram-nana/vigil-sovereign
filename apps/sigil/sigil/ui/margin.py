"""EC-6 — the billing<->cost RECONCILIATION projection + operator MARGIN view (sovereign plane, READ-ONLY).

A PURE, READ-ONLY reconciliation (modelled on ``ui/billing.py`` + ``ops_sweeps``): for each tenant it folds the
owner-signed BILLED revenue (``InvoiceRegistry`` -> Sum ``Invoice.amount_minor``) against the EC-4 ACTUAL token
COST (``CostEnvelopeLedger.committed_cost`` / ``.tenant_costs``) and, ONLY when the owner has ratified a cost
rate in the catalog, converts committed tokens -> money to compute ``margin = revenue - cost``. Per tenant
(primary) and per billing period (secondary). It mints/signs/appends NOTHING and mutates NO money state — it
constructs the registries exactly as ``ui/billing.py`` does and calls only READ methods; every signed record it
folds is verified under the trusted owner PUBKEY (``identity.owner_pubkey()``), never the signing key.

MONEY ANCHOR: billed revenue is the Sum of owner-signed ``Invoice.amount_minor`` (catalog-priced at mint), never
a recomputed / on-the-wire amount; the cost rate is an OWNER catalog input (``catalog.cost_rate_micro_minor_per_token``)
and the display TARGET line comes from the one pricing input, the target margin
(``vigil_core.model_metering.target_margin`` — a margin over METERED AI cost only; payment fees and hosting are
outside it), as ``target revenue = cost / (1 - target margin)`` — never numbers invented here. The cost the target
line divides is this view's cost column, today the per-token rate ESTIMATE (committed tokens × the owner's cost
rate), not each run's metered AI cost; the payload says so (``cost_basis``) until per-run metered cost is recorded and
replaces it. REVENUE
BASIS excludes the ``payment`` kind (a PP-2b receipt against postpaid arrears — money IN, not a charge):
``billed_revenue = Sum over {subscription, topup, postpaid}``; ``payment`` rows are the COLLECTED axis (the
billed-vs-collected AR gap), never added to revenue (the double-count guard). NOT-CONFIGURED FAIL-CLOSED: a
cost_rate unset (None) => ``cost_minor`` / ``margin_minor`` are None (omitted) and the view marks
``not configured``, while ``committed_tokens`` + ``billed_revenue`` are still shown — never a 0, never a
fabricated margin. IN-FLIGHT (reserved-but-unsettled) cost is shown separately and held OUT of committed cost
and final margin (mirrors the cost ledger's own in-flight / committed split).

INTEGER MONEY MATH on the cost basis: ``cost_minor = committed_tokens * rate_micro // 1_000_000``
(micro-minor-per-token — no float on the money cost); ``margin_pct`` is a DISPLAY-only float with a
billed==0 divide-by-zero guard (sound because this is a display projection — the determinism doctrine governs
the MINT path, never a display read, exactly as ``ui/billing.py`` states). PER-PERIOD FLOOR (books foot on
TOKENS, not cents): the per-TENANT headline cost is a SINGLE floor of the lifetime committed tokens, while each
per-PERIOD cost is floored INDEPENDENTLY, so the per-period cost columns (and the margin derived from them) can
sum to a few minor units BELOW the single-floored headline — only TOKENS reconcile EXACTLY; the per-period
cost / margin are DISPLAY-APPROXIMATE (off by at most one minor unit per period), never the authoritative figure.

MIXED-CURRENCY FAIL-CLOSED: a margin is ``revenue - cost``, so when a tenant's billed invoices span MORE THAN
ONE currency (``currency == 'mixed'``) that subtraction is a cross-currency fabrication — ``margin_minor`` /
``margin_pct`` / the display target are WITHHELD (None), per tenant AND in the grand totals; committed tokens +
the raw per-currency billed sum are still shown (labelled 'mixed'), never a fabricated cross-currency margin.
Unreachable under the USD-only catalog today — a defence-in-depth guard for a future multi-currency catalog.

The HTTP route authorizes the caller OWNER-tier (``role_can(principal.role, 'manage_billing')``) BEFORE calling
these helpers — this is the OPERATOR's own cross-tenant margin view, never a customer surface. The gate is sound
because it checks the caller's GLOBAL ACCOUNT role (``principal.role`` from ``AccountsRegistry`` — viewer /
analyst / operator / owner), where ``manage_billing`` is OWNER-ONLY; it does NOT consult a per-org membership
role via ``admit()``. (The per-org ``org_admin`` role DOES carry ``manage_billing`` in the RBAC table, but a
per-org role is never a global ``principal.role`` on this operator route, and a customer has no global account
role at all ⇒ ``role_can`` is False.) So this module does no authorization of its own (it assumes that gate
already passed), exactly like ``ui/billing.py``.

FATAL-2: sovereign-side (``assert_no_offense()`` at import); imports only governor registries + spine substrate
+ stdlib (no framework/offense import). Folds only EXISTING owner-signed records through existing read APIs — no
new signed record, no snapshot bump, and ``cost_ledger.py`` is UNTOUCHED (consumed via its read API + the public
signal / signed-core constants, so per-period verification can never drift from the ledger's own fold).
"""
from __future__ import annotations

import math
from fractions import Fraction
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import catalog as _catalog  # noqa: E402  (owner-input cost rate — the money anchor)
from ..governor import key_history as _kh  # noqa: E402  (succession-aware owner-key resolver, mirrors the folds)
from ..governor.authn import as_issued_at, verify_signed  # noqa: E402
from ..governor.cost_ledger import (  # noqa: E402  (CONSUMED read-only — the ledger itself is NOT modified)
    COST_SETTLE_SIGNAL, CostEnvelopeLedger, _SETTLE_CORE, _as_tokens)
from ..governor.identity import owner_pubkey  # noqa: E402  (reads verify under the trusted pubkey, never the key)
from ..governor.invoices import InvoiceRegistry  # noqa: E402
from ..governor.orgs import OrgRegistry  # noqa: E402
from ..spine.snapshot import SnapshotState  # noqa: E402  (hard-prune seed for the settle seen-set, mirrors _fold)
from ..governor.fold_read import UNCACHED as _UNCACHED, cached_read  # noqa: E402
from ..spine.fold_cache import FoldCache  # noqa: E402  (Front C S0d — the verified incremental fold)
from vigil_core import model_metering as _mm  # noqa: E402  (the one pricing input: the target margin)

# The REVENUE basis — the owner-signed invoice kinds that are a CHARGE. The ``payment`` kind (a PP-2b receipt
# against postpaid arrears: money IN, reducing outstanding, NOT a charge) is DELIBERATELY excluded from revenue
# so a postpaid invoice + its payment are never double-counted; payments are surfaced as the COLLECTED / AR axis.
_REVENUE_KINDS = frozenset({"subscription", "topup", "postpaid"})
_MICRO = 1_000_000                       # micro-minor per minor unit (the integer cost-rate denominator)
_UNSET = object()                        # sentinel: "read the owner catalog" vs an explicit caller/test override


def _cost_minor(committed_tokens: int, rate_micro: Optional[int]) -> Optional[int]:
    """``committed_tokens`` -> cost in MINOR units via INTEGER floor-division (no float on the money cost), or
    None when the rate is unset ('not configured' — never a fabricated 0). Fail-closed: a bad / negative token
    count or rate contributes 0, never a negative cost."""
    if rate_micro is None:
        return None
    t = (committed_tokens if (isinstance(committed_tokens, int) and not isinstance(committed_tokens, bool)
                              and committed_tokens > 0) else 0)
    r = rate_micro if (isinstance(rate_micro, int) and not isinstance(rate_micro, bool) and rate_micro >= 0) else 0
    return t * r // _MICRO


def _margin_pct(billed_minor: int, margin_minor: Optional[int]) -> Optional[float]:
    """The DISPLAY-only margin percentage (margin / billed * 100), or None when the rate is unset OR billed is
    0 (the divide-by-zero guard). Rounded for display; a display read, never a signed/minted number."""
    if margin_minor is None or billed_minor <= 0:
        return None
    return round((margin_minor / billed_minor) * 100.0, 2)


def _apply_settle_event(r, resolver, seen: set, out: dict) -> None:
    """Fold ONE spine record into (seen, out) — THE settle-stream body, shared by `_settle_events`' full scan and
    the verified fold cache (Front C S0d) so the two can never diverge."""
    p = r.payload
    if not isinstance(p, dict) or p.get("signal") != COST_SETTLE_SIGNAL:
        return
    oid = p.get("org_id")
    eid = p.get("entry_id")
    if not (isinstance(oid, str) and oid and isinstance(eid, str) and eid):
        return
    if not verify_signed(p, _SETTLE_CORE, resolver.at(r.seq)):
        return                                    # fail-closed: unsigned / forged / wrong-epoch record
    key = (COST_SETTLE_SIGNAL, oid, eid)
    if key in seen:
        return                                    # idempotent (replay / pre-prune) guard, mirrors the fold
    seen.add(key)
    out.setdefault(oid, []).append((as_issued_at(p.get("issued_at")), _as_tokens(p.get("tokens"))))


class _SettleView:
    """The cached settle stream: exactly the scan's (seen, out)."""

    __slots__ = ("seen", "out")

    def __init__(self, seen: set) -> None:
        self.seen = seen
        self.out: dict = {}


def _settle_step(view: _SettleView, r, resolver) -> None:
    _apply_settle_event(r, resolver, view.seen, view.out)


_SETTLE_FOLD = FoldCache("ui.margin.settle_events", step=_settle_step)


def _settle_seed(snap, trusted_pubkey: Optional[str]) -> "tuple[set, int]":
    if trusted_pubkey != snap.trusted_pubkey:
        return set(), -1
    return set(snap.cost_seen_set()), snap.base_seq - 1


def _settle_events(store, trusted_pubkey: Optional[str]) -> dict[str, list[tuple[float, int]]]:
    """Per-tenant list of ``(issued_at, tokens)`` for every owner-signed ``governor.cost_settle`` on the spine —
    the raw settle stream the per-PERIOD view attributes by ``issued_at``. There is NO public per-period read on
    the cost ledger and EC-6 must not add one, so this folds the SAME owner-signed records the ledger does,
    READ-ONLY, reusing the ledger's ``COST_SETTLE_SIGNAL`` + ``_SETTLE_CORE`` constants so verification can never
    drift from the ledger's own fold. Each record is verified under the owner pubkey valid AT ITS SEQ and deduped
    by ``(org, entry_id)`` (replay guard), with the consumed-entry_id seen-set SNAPSHOT-SEEDED exactly as the
    ledger's ``_fold`` so a pre-prune replay is ignored here too.

    The per-settle AMOUNTS come from the LIVE window only (a hard prune archives individual settle rows into the
    snapshot per-org aggregate, which carries no per-settle ``issued_at``). The per-TENANT ``committed_tokens``
    total uses the snapshot-durable ``committed_cost()``, and the per-period view reconciles any difference as the
    ``unscoped`` bucket, so the periods always sum back to the durable lifetime total. A rotated/empty anchor
    genesis-scans (byte-identical under the empty snapshot). Front C S0d: through the verified fold cache when on."""
    def seed(snap):
        seen, since = _settle_seed(snap, trusted_pubkey)
        return _SettleView(seen), since

    hit = cached_read(_SETTLE_FOLD, store, trusted_pubkey=trusted_pubkey, seed=seed,
                      reader=lambda v: {oid: list(events) for oid, events in v.out.items()})
    if hit is not _UNCACHED:
        return hit
    snap = SnapshotState.load(store)
    resolver = _kh.key_resolver(store, current=trusted_pubkey)
    seen, since = _settle_seed(snap, trusted_pubkey)
    out: dict[str, list[tuple[float, int]]] = {}
    for r in store.iter_records(since_seq=since):
        _apply_settle_event(r, resolver, seen, out)
    return out


def _find_window(windows: list[tuple[float, float]], t: float) -> Optional[tuple[float, float]]:
    """The FIRST subscription period window ``[period_start, period_end)`` (sorted) that contains instant ``t``,
    or None. Half-open so adjacent periods never both claim a boundary instant; 'first match' makes overlapping
    owner-issued periods deterministic (normal sequential periods are disjoint, so unambiguous)."""
    for ps, pe in windows:
        if ps <= t < pe:
            return (ps, pe)
    return None


def _tenant_periods(tenant_invoices: list, settles: list[tuple[float, int]], committed_tokens: int,
                    rate_micro: Optional[int], *, margin_ok: bool = True) -> list[dict[str, Any]]:
    """The per-PERIOD breakdown for ONE tenant: billed revenue + attributed cost per billing period. Period
    windows are the distinct ``[period_start, period_end)`` of the tenant's ``subscription`` invoices (the
    canonical per-period billing unit). A subscription invoice's ``amount_minor`` goes to its OWN window;
    top-up / postpaid revenue and each settle's cost are attributed by ``issued_at`` into the containing window,
    else an ``unscoped`` bucket. The ``unscoped`` cost is ``committed_tokens - Sum(windowed cost)`` (>= 0), so the
    periods always reconcile EXACTLY to the durable lifetime ``committed_tokens`` (it absorbs both live settles
    outside any window and any prune-archived settles). Cost/margin are None per period when the rate is unset."""
    windows = sorted({(inv.period_start, inv.period_end) for inv in tenant_invoices
                      if inv.kind == "subscription" and inv.period_end > inv.period_start})
    win_rev: dict[tuple[float, float], int] = {w: 0 for w in windows}
    win_tok: dict[tuple[float, float], int] = {w: 0 for w in windows}
    unscoped_rev = 0
    for inv in tenant_invoices:
        if inv.kind not in _REVENUE_KINDS:
            continue                                  # 'payment' is the collected axis, never revenue
        if inv.kind == "subscription" and inv.period_end > inv.period_start:
            win_rev[(inv.period_start, inv.period_end)] += inv.amount_minor
        else:
            w = _find_window(windows, inv.issued_at)   # top-up / postpaid -> by issued_at into a period
            if w is not None:
                win_rev[w] += inv.amount_minor
            else:
                unscoped_rev += inv.amount_minor
    for issued_at, tokens in settles:
        w = _find_window(windows, issued_at)
        if w is not None:
            win_tok[w] += tokens
    windowed_tok = sum(win_tok.values())
    unscoped_tok = max(0, committed_tokens - windowed_tok)   # the durable remainder (live-no-window + pruned)

    def _row(ps: float, pe: float, scoped: bool, rev: int, tok: int) -> dict[str, Any]:
        cm = _cost_minor(tok, rate_micro)
        # margin withheld when the rate is unset (cm is None) OR the tenant bills mixed currencies (margin_ok
        # False) — a per-period cost is still a real single-currency figure, but revenue-cost would fabricate.
        mm = None if (cm is None or not margin_ok) else rev - cm
        return {"period_start": ps, "period_end": pe, "scoped": scoped,
                "committed_tokens": tok, "billed_revenue_minor": rev,
                "cost_minor": cm, "margin_minor": mm}

    rows = [_row(ps, pe, True, win_rev[(ps, pe)], win_tok[(ps, pe)]) for (ps, pe) in windows]
    if unscoped_rev or unscoped_tok:
        rows.append(_row(0.0, 0.0, False, unscoped_rev, unscoped_tok))
    return rows


def _target_margin() -> "tuple[Optional[Fraction], Optional[str]]":
    """The deploy's target margin, or None and the reason there is none (unset, malformed, or a retired pricing
    setting still present — the same refusal billing gives). The reason never carries the value."""
    try:
        return _mm.target_margin(), None
    except _mm.MeteringError as exc:
        return None, str(exc)


def _target_revenue(cost_minor: int, m: Fraction) -> int:
    """The revenue at which ``cost_minor`` earns the target margin ``m``: ``cost / (1 - m)``, exact, rounded UP to
    a whole minor unit (the same direction the metered charge rounds)."""
    return math.ceil(Fraction(cost_minor) / (1 - m))


def margin_overview(store, *, cost_rate: Any = _UNSET, target_margin: Any = _UNSET) -> dict[str, Any]:
    """The OPERATOR margin reconciliation across ALL tenants (per-tenant primary + per-period secondary), a pure
    READ-ONLY projection of the owner-signed spine. ``cost_rate`` defaults to the OWNER catalog (the money anchor —
    ``catalog.cost_rate_micro_minor_per_token``) and ``target_margin`` to the deploy's one pricing input
    (``vigil_core.model_metering.target_margin``, a margin over METERED AI cost only); an explicit value (incl.
    None) overrides for testing. When ``cost_rate`` is None the view is 'not configured': every ``cost_minor`` /
    ``margin_minor`` is None and only committed tokens + billed revenue are shown (never a fabricated number). The
    target line is display-only: it never changes a price or the actual margin. The margin's value is never in
    the payload. Assumes the route already authorized the caller owner-tier."""
    rate_micro = _catalog.cost_rate_micro_minor_per_token() if cost_rate is _UNSET else cost_rate
    if target_margin is _UNSET:
        m, m_issue = _target_margin()
    else:
        m, m_issue = target_margin, (None if target_margin is not None else "no target margin given")
    configured = rate_micro is not None

    trusted = owner_pubkey()                           # the trust anchor reads verify under (never the signing key)
    invoices = InvoiceRegistry(store, trusted_pubkey=trusted).all_invoices()
    costs = {tc.org_id: tc for tc in CostEnvelopeLedger(store, trusted_pubkey=trusted).tenant_costs()}
    settle_events = _settle_events(store, trusted)
    names = {o.org_id: o.name for o in OrgRegistry(store).orgs()}

    inv_by_org: dict[str, list] = {}
    for inv in invoices:
        inv_by_org.setdefault(inv.org_id, []).append(inv)

    tenant_ids = sorted(set(costs) | set(inv_by_org))
    tenants: list[dict[str, Any]] = []
    tot_tokens = tot_inflight = tot_billed = tot_collected = tot_cost = 0
    all_currencies: set[str] = set()
    for oid in tenant_ids:
        tc = costs.get(oid)
        committed = tc.committed_tokens if tc is not None else 0
        in_flight = tc.in_flight_tokens if tc is not None else 0
        rows = inv_by_org.get(oid, [])
        rev_by_kind = {"subscription": 0, "topup": 0, "postpaid": 0}
        collected = 0
        currencies: set[str] = set()
        for inv in rows:
            if inv.kind in _REVENUE_KINDS:
                rev_by_kind[inv.kind] += inv.amount_minor
                if inv.amount_minor and inv.currency:
                    currencies.add(inv.currency)
            elif inv.kind == "payment":
                collected += inv.amount_minor
        billed = sum(rev_by_kind.values())
        currency = (next(iter(currencies)) if len(currencies) == 1 else ("mixed" if currencies else ""))
        mixed = len(currencies) > 1          # billed spans >1 currency -> revenue-cost is a cross-currency fabrication
        cost_m = _cost_minor(committed, rate_micro)
        # MIXED-CURRENCY FAIL-CLOSED: withhold the (revenue - cost) margin + its target/pct when billed spans
        # >1 currency — never fabricate a cross-currency margin (cost + the raw billed sum are still shown).
        margin_m = None if (cost_m is None or mixed) else billed - cost_m
        # Display-only TARGET line from the target margin (target revenue = cost / (1 - m)); never affects the
        # actual margin or any price.
        target_rev = None if (cost_m is None or m is None or mixed) else _target_revenue(cost_m, m)
        all_currencies |= currencies
        tenants.append({
            "org_id": oid, "name": names.get(oid, oid),
            "committed_tokens": committed, "in_flight_tokens": in_flight,
            "billed_revenue_minor": billed, "revenue_by_kind": rev_by_kind,
            "collected_minor": collected, "currency": currency,
            "cost_minor": cost_m, "margin_minor": margin_m, "margin_pct": _margin_pct(billed, margin_m),
            "target_revenue_minor": target_rev,
            "cost_status": "configured" if configured else "not configured",
            "periods": _tenant_periods(rows, settle_events.get(oid, []), committed, rate_micro,
                                       margin_ok=not mixed),
        })
        tot_tokens += committed
        tot_inflight += in_flight
        tot_billed += billed
        tot_collected += collected
        if cost_m is not None:
            tot_cost += cost_m

    totals_mixed = len(all_currencies) > 1   # billed across tenants spans >1 currency -> grand margin not reconcilable
    total_cost = tot_cost if configured else None
    # MIXED-CURRENCY FAIL-CLOSED (totals): the grand margin subtracts cost from a cross-currency billed sum when
    # tenants bill in different currencies -> withhold it (committed tokens + the raw billed sum are still shown).
    total_margin = None if (total_cost is None or totals_mixed) else tot_billed - total_cost
    return {
        "rate_configured": configured,
        "cost_status": "configured" if configured else "not configured",
        "cost_rate_micro_minor_per_token": rate_micro,
        "target_margin_set": m is not None,
        "target_margin_basis": "metered AI cost only (payment fees and hosting are outside it)",
        "target_margin_issue": m_issue,
        "cost_basis": "per-token rate estimate (committed tokens x the owner's cost rate), not metered AI cost",
        "currency": (next(iter(all_currencies)) if len(all_currencies) == 1
                     else ("mixed" if all_currencies else "")),
        "tenants": tenants,
        "totals": {
            "tenant_count": len(tenants),
            "committed_tokens": tot_tokens, "in_flight_tokens": tot_inflight,
            "billed_revenue_minor": tot_billed, "collected_minor": tot_collected,
            "cost_minor": total_cost, "margin_minor": total_margin,
            "margin_pct": _margin_pct(tot_billed, total_margin),
        },
    }
