"""UI read projections for the SaaS billing surface — the OWNER/operator billing-admin view (Slice B).

PURE, READ-ONLY projections of the owner-signed billing spine (wallet / plan-credit meter / subscription),
tenant-scoped by org_id. No owner key is used (a read never mints) and no secret is surfaced. The HTTP routes in
`server.py` authorize the caller for the requested org via `OrgRegistry.admit` BEFORE calling these helpers, so a
caller only ever projects a tenant they are entitled to — this module assumes that check already passed and does
no authorization of its own.

`now` is the DISPLAY instant (wall-clock from the request). A balance read is not a signed/replayed decision, so a
wall-clock read is sound here — the determinism doctrine governs the MINT path (BillingSigner), never a display
projection. Passing `now` makes a lapsed subscription / expired plan tranche correctly read as not-live.

FATAL-2: sovereign-side (`assert_no_offense()` at import); imports only governor billing registries + orgs.
"""
from __future__ import annotations

import itertools
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.invoices import InvoiceRegistry  # noqa: E402
from ..governor.metering import CreditMeter, PlanCreditLedger  # noqa: E402
from ..governor.orgs import OrgRegistry, org_tenant_id  # noqa: E402
from ..governor.subscription import SubscriptionRegistry  # noqa: E402
from ..governor.wallet import WalletRegistry  # noqa: E402


def valid_org(org_id: object) -> Optional[str]:
    """Validate + normalise a client-supplied org_id to a tenant id, FAIL-CLOSED (None on anything invalid). The
    route rejects None with a 400 before any lookup, so a malformed/empty/oversized org id never reaches a fold."""
    if not isinstance(org_id, str) or not org_id:
        return None
    try:
        return org_tenant_id(org_id)
    except ValueError:
        return None


def _sub_json(sub) -> Optional[dict[str, Any]]:
    if sub is None:
        return None
    return {"plan_id": sub.plan_id, "status": sub.status, "period_start": sub.period_start,
            "period_end": sub.period_end, "allotment": sub.allotment}


def billing_overview(store, org_id: str, *, now: float) -> dict[str, Any]:
    """The billing overview for ONE org: spendable credit position (persistent wallet + the active subscription's
    live plan tranche), lifetime wallet totals, and the current subscription. Every number is DERIVED from the
    spine (never a stored counter). Assumes the caller was already authorized for `org_id` by the route.

    W2c-2 (behind ``VIGIL_METERED_BILLING``; the flag OFF ⇒ this output is byte-identical): adds the wallet's EXACT
    balance — ``exact_available_mc`` (milli-credits = ``1000 x available - remainder``) and ``exact_available`` (its
    floor in whole credits, never more than the customer holds). No existing field changes. This exact figure is the
    statement's ``available_to_start_mc`` (``billing_usage``) — the number I4 reconciles the latest balance-after to."""
    from .. import config

    wallet = WalletRegistry(store)
    plan = PlanCreditLedger(store)
    subs = SubscriptionRegistry(store)
    meter = CreditMeter(wallet, plan, subs)
    bal = wallet.balance(org_id)
    pos = meter.position(org_id, now)
    sub = subs.subscription(org_id)                     # current subscription (may be past_due/lapsed) — display
    active = subs.active_subscription(org_id, now)      # the ACTIVE + in-period one (None when lapsed/dunning)
    out: dict[str, Any] = {
        "org_id": org_id,
        "credits": {"available": pos.available, "persistent": pos.persistent, "plan_live": pos.plan_live},
        "wallet": {"granted": bal.granted, "debited": bal.debited, "available": bal.available},
        "subscription": _sub_json(sub),
        "active": active is not None,                   # is the plan live right now (in-period + active)?
        "now": now,
    }
    if config.billing_reversals_enabled():
        # W5: a billing HOLD (credits owed after a chargeback or refund) — in credits; absent while reversals are off
        from ..governor.billing_reversal import BillingReversalLedger
        owed = BillingReversalLedger(store, wallet=wallet).owed(org_id)
        out["hold"] = {"on_hold": owed > 0, "owed": owed}
    if config.metered_billing_enabled():
        out["exact_available_mc"] = bal.exact_available_mc
        out["exact_available"] = bal.exact_available_mc // 1000   # floor (display never shows more than is held)
    return out


def billing_rates() -> dict[str, Any]:
    """The published usage rates (pricing design §0.2), in credits only. Rates are public: the same card for every
    tenant, read from ``vigil_core.rate_card`` (the owner's ``VIGIL_RATE_CARD`` override when set). Nothing here
    estimates or quotes what an assessment will cost (design §0.9)."""
    from vigil_core.rate_card import rate_card
    return {"rates": rate_card().published()}


def _priced_lines(rec: "dict[str, Any]", card) -> "tuple[list[dict[str, Any]], int]":
    """One metered response's statement lines and its charge (mc). A response the gateway priced (W2a) is shown at
    the charge and the rates RECORDED with it — a later change to the card never re-prices past usage; one recorded
    before W2a is priced with the card in force. A response the meter could not read was charged its reservation
    (§10.4): the part above its unit lines is its own line, so the lines always add up to the charge (I4)."""
    from vigil_core.rate_card import AI_UNITS, ChargeLine, Rate, format_credits

    if "charge_mc" not in rec:
        lines = card.ai_lines(rec["usage"])
        return [ln.as_dict() for ln in lines], sum(ln.amount_mc for ln in lines)
    labels = {unit: (field, label) for unit, field, label, _per in AI_UNITS}
    out: "list[dict[str, Any]]" = []
    total = 0
    for unit, (mc, per) in rec.get("rates", {}).items():
        if unit not in labels:
            continue                                        # a unit this build does not know: shown in the total
        field, label = labels[unit]
        qty = int(getattr(rec["usage"], field))
        rate = Rate(unit, mc, per, label)
        ln = ChargeLine(unit, label, qty, rate, rate.amount(qty))
        out.append(ln.as_dict())
        total += ln.amount_mc
    charge = int(rec["charge_mc"])
    if charge != total:
        extra = charge - total
        unread = bool(rec.get("charged_reservation"))
        out.append({"unit": "reserved_maximum" if unread else "other",
                    "label": ("Response the meter could not read: charged its reserved maximum" if unread
                              else "Other charges recorded with this response"),
                    "quantity": 1, "rate": format_credits(extra), "rate_per": 1,
                    "credits": format_credits(extra), "amount_mc": extra})
    return out, charge


def _balance_after_mc(grants, plan_grants, plan_tranches, charge_events, now: float) -> int:
    """W2c-2 — the EXACT remaining credit (milli-credits) after each metered charge, in timestamp order, and the
    final remaining (returned). Each event is a signed delta at an instant:
      * a PURCHASE / trial grant — ``+1000 x credits`` at its ``issued_at`` (``grants``: ``(issued_at, credits)``);
      * a PLAN tranche ENTER — ``+1000 x credits`` at its ``issued_at``
        (``plan_grants``: ``(issued_at, credits, period_end)``);
      * a PLAN tranche EXPIRY — ``-1000 x unspent`` at its ``period_end``, applied ONLY once it has expired
        (``period_end <= now``) — non-rollover, exactly ``PlanCreditLedger`` / ``CreditMeter``
        (``plan_tranches``: ``(period_end, unspent_credits)``);
      * a metered CHARGE — ``-amount_mc`` at its ``ts`` (``charge_events``: ``(ts, tiebreak, amount_mc, charge)``).
    A scan's reserve DRAW and its settlement RETURN net to its metered consumption, so they are NOT separate events:
    the charges ARE the consumption, and ``purchased - consumed`` reconciles to the wallet's exact balance (I4). The
    running balance starts at 0 and, on a complete (un-pruned) spine, ends at the wallet's ``exact_available_mc``.
    Events at the same instant order grants (then plan enters) before charges before expiries, deterministically.
    Mutates each ``charge`` dict with ``balance_after_mc``; returns the final running balance (``remaining_mc``)."""
    from vigil_core.rate_card import MC_PER_CREDIT
    events: "list[tuple[tuple, int, Optional[dict[str, Any]]]]" = []
    ctr = itertools.count()
    for iss, credits in grants:
        events.append(((iss, 0, next(ctr)), MC_PER_CREDIT * int(credits), None))
    for iss, credits, _pe in plan_grants:
        events.append(((iss, 0, next(ctr)), MC_PER_CREDIT * int(credits), None))
    for pe, unspent in plan_tranches:
        if pe <= now:                                    # a tranche expires only once its period has passed
            events.append(((pe, 2, next(ctr)), -MC_PER_CREDIT * int(unspent), None))
    for ts, tiebreak, amount_mc, charge in charge_events:
        events.append(((ts, 1, tiebreak), -int(amount_mc), charge))
    events.sort(key=lambda e: e[0])
    bal = 0
    for _k, delta, charge in events:
        bal += delta
        if charge is not None:
            charge["balance_after_mc"] = bal
    return bal


def billing_usage(store, org_id: str, *, trusted_pubkey: Optional[str], meter_dir, limit: int = 500,
                  now: Optional[float] = None) -> dict[str, Any]:
    """The per-charge usage statement of ONE org, newest first: each metered AI request of each of the org's scans,
    priced line by line from the published rate card (operation, time, quantity, unit rate, credits). Tenant-scoped:
    only the org's own owner-signed launch reservations are read, and each scan's meter is found from its
    ``(slug, nonce)`` alone, so another tenant's usage is structurally never in the result. A meter whose hash chain
    does not verify is reported as unavailable, never priced (and never in the balance). Every amount is in credits;
    the model is never named. PURE read: no key, no lock, no write.

    W2c-2 (behind ``VIGIL_METERED_BILLING``; the flag OFF ⇒ this output is byte-identical): each charge also carries
    ``balance_after_mc`` — the org's EXACT remaining credit (milli-credits) right after that charge, reconstructed in
    timestamp order over the org's purchases/trial grants, plan-period tranches (entering and expiring, non-rollover)
    and metered charges (:func:`_balance_after_mc`). Two top-level numbers: ``remaining_mc`` (bought - consumed, exact)
    and ``available_to_start_mc`` (= ``remaining_mc - held_mc``, the allowances the org's running scans still hold:
    each running scan's reserved units + extensions, less what it has consumed so far). ``held_mc`` is reported too.
    Invariant I4 (tested): on a complete spine the latest ``balance_after_mc`` == ``remaining_mc`` ==
    ``available_to_start_mc`` (no scan running) == the wallet's exact balance == what ``billing_overview`` reports as
    exact; ``remaining_mc`` and ``balance_after_mc`` are over the LIVE spine window (like the charges), the
    prune-durable exact balance being the wallet fold (``billing_overview``)."""
    from vigil_core.model_grant import meter_id
    from vigil_core.rate_card import MC_PER_CREDIT, format_credits, rate_card

    from .. import config
    from ..governor.launch_reservations import scan_reservations
    from ..governor.metering import PlanCreditLedger
    from ..governor.wallet import WalletRegistry
    from ..model_gateway import GrantMeter

    card = rate_card()
    meter = GrantMeter(meter_dir)
    ix = scan_reservations(store, trusted_pubkey, org_id=org_id)
    metered = config.metered_billing_enabled()
    scans: list[dict[str, Any]] = []
    charges: list[dict[str, Any]] = []
    charge_events: list[tuple] = []                      # (ts, (seq, idx), amount_mc, charge) for the timeline
    held_mc = 0
    total_mc = 0
    for r in sorted(ix.reservations.values(), key=lambda r: r.seq, reverse=True):
        if r.org_id != org_id:
            continue
        scan: dict[str, Any] = {"scan": r.slug, "launch": r.nonce, "started_at": r.issued_at}
        running = metered and r.key not in ix.settled    # a reserved-but-not-yet-settled launch still holds credit
        try:
            records = meter.usage_records(meter_id(r.slug, r.nonce))
        except ValueError:
            # a meter that fails its integrity check: never PRICED (no charge, not in remaining) and flagged
            # unavailable for the operator to quarantine. But its owner-signed RESERVATION is a real debit, so while
            # it is still running it HOLDS its whole allowance (its consumption cannot be read, so none is assumed) —
            # otherwise available_to_start would drift above the wallet's authoritative exact balance.
            scan.update(status="unavailable", detail="this scan's usage record failed its integrity check")
            scans.append(scan)
            if running:
                held_mc += MC_PER_CREDIT * r.reserved
            continue
        scan_mc = 0
        for idx, rec in enumerate(records):
            lines, amount = _priced_lines(rec, card)
            scan_mc += amount
            charge = {"ts": rec["ts"], "scan": r.slug, "launch": r.nonce, "operation": "AI analysis",
                      "lines": lines, "credits": format_credits(amount), "amount_mc": amount}
            charges.append(charge)
            if metered:
                charge_events.append((rec["ts"], (r.seq, idx), amount, charge))
        total_mc += scan_mc
        if running:
            # a RUNNING scan holds its allowance (reserved units + extensions) less what it has consumed so far —
            # credits earmarked for it, so unavailable to START new work.
            held_mc += max(0, MC_PER_CREDIT * r.reserved - scan_mc)
        scan.update(status="ok", requests=len(records), credits=format_credits(scan_mc), amount_mc=scan_mc)
        scans.append(scan)
    charges.sort(key=lambda c: c["ts"], reverse=True)
    n = max(1, min(int(limit), 5000))
    out: dict[str, Any] = {"org_id": org_id, "currency": "credits", "scans": scans, "charges": charges[:n],
                           "count": len(charges), "credits": format_credits(total_mc), "amount_mc": total_mc}
    if metered:
        import time as _time
        t = float(now) if now is not None else _time.time()
        plan = PlanCreditLedger(store)
        plan_tranches = [(tr.period_end, tr.remaining) for tr in plan.tranches(org_id)]
        remaining_mc = _balance_after_mc(WalletRegistry(store).purchase_events(org_id),
                                         plan.grant_events(org_id), plan_tranches, charge_events, t)
        available_to_start_mc = remaining_mc - held_mc   # the running scans' held allowances are not startable
        out.update(remaining_mc=remaining_mc, available_to_start_mc=available_to_start_mc, held_mc=held_mc)
    return out


def _invoice_json(inv) -> dict[str, Any]:
    return {"invoice_id": inv.invoice_id, "kind": inv.kind, "price_id": inv.price_id,
            "amount_minor": inv.amount_minor, "currency": inv.currency, "credits": inv.credits,
            "period_start": inv.period_start, "period_end": inv.period_end, "issued_at": inv.issued_at}


def billing_invoices(store, org_id: str, *, limit: int = 200) -> dict[str, Any]:
    """The billing HISTORY (invoices) for ONE org, newest-first (Slice H). PURE read; tenant-scoped by org_id —
    returns ONLY that org's lines (the IDOR class). Assumes the caller was already authorized for `org_id` by
    the route (the route's `admit`/`admit_customer` gate + this org-scoping is the IDOR defense: a line for
    another tenant is structurally never in the fold result for this org). `limit` caps the returned page;
    `count` is the true total so a client can page, without ever leaking another tenant's lines."""
    invs = InvoiceRegistry(store).invoices(org_id)
    n = max(1, min(int(limit), 1000))
    return {"org_id": org_id, "invoices": [_invoice_json(i) for i in invs[:n]], "count": len(invs)}


def org_list(store) -> list[dict[str, Any]]:
    """The active orgs (the billing-admin tenant picker). Owner-tier route (`manage_org`); attribution only, no
    billing figures — the per-org overview is a separate authorized read."""
    return [{"org_id": o.org_id, "name": o.name, "owner": o.owner, "created_at": o.created_at}
            for o in OrgRegistry(store).orgs()]
