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
    spine (never a stored counter). Assumes the caller was already authorized for `org_id` by the route."""
    wallet = WalletRegistry(store)
    plan = PlanCreditLedger(store)
    subs = SubscriptionRegistry(store)
    meter = CreditMeter(wallet, plan, subs)
    bal = wallet.balance(org_id)
    pos = meter.position(org_id, now)
    sub = subs.subscription(org_id)                     # current subscription (may be past_due/lapsed) — display
    active = subs.active_subscription(org_id, now)      # the ACTIVE + in-period one (None when lapsed/dunning)
    return {
        "org_id": org_id,
        "credits": {"available": pos.available, "persistent": pos.persistent, "plan_live": pos.plan_live},
        "wallet": {"granted": bal.granted, "debited": bal.debited, "available": bal.available},
        "subscription": _sub_json(sub),
        "active": active is not None,                   # is the plan live right now (in-period + active)?
        "now": now,
    }


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


def billing_usage(store, org_id: str, *, trusted_pubkey: Optional[str], meter_dir, limit: int = 500) -> dict[str, Any]:
    """The per-charge usage statement of ONE org, newest first: each metered AI request of each of the org's scans,
    priced line by line from the published rate card (operation, time, quantity, unit rate, credits). Tenant-scoped:
    only the org's own owner-signed launch reservations are read, and each scan's meter is found from its
    ``(slug, nonce)`` alone, so another tenant's usage is structurally never in the result. A meter whose hash chain
    does not verify is reported as unavailable, never priced. Every amount is in credits; the model is never named.
    PURE read: no key, no lock, no write."""
    from vigil_core.model_grant import meter_id
    from vigil_core.rate_card import format_credits, rate_card

    from ..governor.launch_reservations import scan_reservations
    from ..model_gateway import GrantMeter

    card = rate_card()
    meter = GrantMeter(meter_dir)
    ix = scan_reservations(store, trusted_pubkey, org_id=org_id)
    scans: list[dict[str, Any]] = []
    charges: list[dict[str, Any]] = []
    total_mc = 0
    for r in sorted(ix.reservations.values(), key=lambda r: r.seq, reverse=True):
        if r.org_id != org_id:
            continue
        scan: dict[str, Any] = {"scan": r.slug, "launch": r.nonce, "started_at": r.issued_at}
        try:
            records = meter.usage_records(meter_id(r.slug, r.nonce))
        except ValueError:
            scan.update(status="unavailable", detail="this scan's usage record failed its integrity check")
            scans.append(scan)
            continue
        scan_mc = 0
        for rec in records:
            lines, amount = _priced_lines(rec, card)
            scan_mc += amount
            charges.append({"ts": rec["ts"], "scan": r.slug, "launch": r.nonce, "operation": "AI analysis",
                            "lines": lines, "credits": format_credits(amount), "amount_mc": amount})
        total_mc += scan_mc
        scan.update(status="ok", requests=len(records), credits=format_credits(scan_mc), amount_mc=scan_mc)
        scans.append(scan)
    charges.sort(key=lambda c: c["ts"], reverse=True)
    n = max(1, min(int(limit), 5000))
    return {"org_id": org_id, "currency": "credits", "scans": scans, "charges": charges[:n],
            "count": len(charges), "credits": format_credits(total_mc), "amount_mc": total_mc}


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
