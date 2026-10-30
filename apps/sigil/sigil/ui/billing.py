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


def org_list(store) -> list[dict[str, Any]]:
    """The active orgs (the billing-admin tenant picker). Owner-tier route (`manage_org`); attribution only, no
    billing figures — the per-org overview is a separate authorized read."""
    return [{"org_id": o.org_id, "name": o.name, "owner": o.owner, "created_at": o.created_at}
            for o in OrgRegistry(store).orgs()]
