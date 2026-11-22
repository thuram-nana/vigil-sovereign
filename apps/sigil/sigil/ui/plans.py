"""PR-G (Area 6) — the customer PLANS read: a tier comparison over the OWNER CATALOG, the workspace's current plan,
any change already scheduled for its renewal, and which actions this member may take right now.

WHAT IT COMPARES. The trial (its credits and its one rule — every finding visible, one in full, until the first
purchase), pay-as-you-go (the offered top-up packs; bought credits never expire) and every credit plan ON SALE (price
per period, the credits it adds each period, the period length). Prices and credits are the catalog's own values —
the money anchor — never computed here, and a plan's credits are what the plan ADDS, never an estimate of what an
assessment will cost. The assessment depths the deployment offers are listed by name only (no units, no price), since
every tier runs the same depths.

WHAT IT DECIDES: nothing. It is a pure read (no spine write, no owner key, no processor call). The upgrade it offers is
the EXISTING hosted checkout (shown only where checkout would accept it: the plan flags on, the member may spend money,
no live plan and no plan checkout in progress); the change it offers is ``governor.plan_change`` (shown only where that
would be attempted). The scheduled change shown comes from the owner-signed display record, and only for the CURRENT
period. TENANT-SCOPED: every read names the session org the provisioner admitted; nothing comes from the client.

FATAL-2: sovereign-side — stdlib + governor/vigil_core reads; ``assert_no_offense`` at import.
"""
from __future__ import annotations

from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor import catalog as _catalog  # noqa: E402
from ..governor import plan_change as _pc  # noqa: E402
from ..governor.billing import EVENT_TOPUP  # noqa: E402
from ..governor.invoices import InvoiceRegistry  # noqa: E402
from ..governor.subscription import STATUS_ACTIVE, SubscriptionRegistry  # noqa: E402
from ..governor.wallet import WalletRegistry  # noqa: E402

# The limits every credit plan shares (the comparison's fine print) — fixed words, no number, no estimate.
PLAN_RULES = (("Plan credits are added at the start of each period and expire at its end; credits you buy "
               "separately never expire."),
              ("A workspace has one plan at a time. A change takes effect at your next renewal, so the period you "
               "have paid for is never cut short or charged twice."),
              ("Every plan runs the same assessments; a plan sets how many credits arrive each period, not what an "
               "assessment can do."))
TRIAL_RULES = ("One trial per workspace and per email address.",
               "During the trial you see every finding, and one of them in full.",
               "Your first purchase unlocks the proof and the fix of every finding.")
PAYG_RULES = ("Buy credits when you need them. Bought credits never expire.",)


def _period_days(period_s: float) -> float:
    return round(float(period_s) / 86400.0, 2)


def _plan_tier(e) -> "dict[str, Any]":
    return {"id": e.price_id, "kind": "plan", "price_id": e.price_id, "name": e.display_name,
            "amount_minor": int(e.amount_minor), "currency": e.currency, "credits_per_period": int(e.allotment),
            "period_days": _period_days(e.period_s)}


def _current(store, org_id: str, *, now: float) -> "tuple[Optional[Any], Optional[Any]]":
    """(the sovereign credit subscription, the catalog line that paid its CURRENT period) — either may be None."""
    sub = SubscriptionRegistry(store).subscription(org_id)
    if sub is None:
        return None, None
    known = _pc.known_plans()
    for inv in InvoiceRegistry(store).invoices(org_id):
        if (inv.kind == "subscription" and inv.price_id in known
                and float(inv.period_start) == float(sub.period_start)
                and float(inv.period_end) == float(sub.period_end)):
            return sub, known[inv.price_id]
    same = [e for e in known.values() if e.plan_id == sub.plan_id]
    return sub, (same[0] if len(same) == 1 else None)


def plans_view(store, org_id: str, *, now: float, can_manage: bool, preview_locked: bool, checkout_on: bool,
               change_on: bool, plan_checkout_pending: bool, trial_credits: int = 0,
               ledger=None) -> "dict[str, Any]":
    """The Plans screen's data for ONE org. ``checkout_on`` = the base AND plan checkout flags; ``change_on`` = the plan
    change flag AND a provisioned processor; ``trial_credits`` = the server-constant trial size; ``ledger`` = the
    plan-change display ledger (None = none shown). PURE read; assumes the caller already authorized ``org_id`` for
    ``view_billing``."""
    sub, cur = _current(store, org_id, now=now)
    live = sub is not None and sub.status == STATUS_ACTIVE and now < float(sub.period_end)
    in_force = sub is not None and sub.status in (STATUS_ACTIVE, "past_due") and now < float(sub.period_end)
    scheduled = None
    if in_force and ledger is not None and sub is not None:
        scheduled = ledger.scheduled(org_id, period_end=float(sub.period_end))
    offered = list(_catalog.credit_plan_entries(offered_only=True))
    can_upgrade = bool(can_manage and checkout_on and not in_force and not plan_checkout_pending)
    change_reason = ""
    can_change = False
    if can_manage and change_on and in_force:
        try:
            _pc.current_plan(sub, InvoiceRegistry(store).invoices(org_id), now=now)
            can_change = True
        except _pc.PlanChangeRefused as exc:
            change_reason = str(exc)
    tiers: "list[dict[str, Any]]" = []
    for e in offered:
        t = _plan_tier(e)
        t["current"] = bool(in_force and cur is not None and cur.price_id == e.price_id)
        t["scheduled"] = bool(scheduled and scheduled["kind"] == _pc.KIND_CHANGE
                              and scheduled["to_price_id"] == e.price_id)
        if t["current"]:
            t["action"] = "current"
        elif can_upgrade:
            t["action"] = "checkout"
        elif can_change and cur is not None and _pc.plan_days(e) == _pc.plan_days(cur):
            t["action"] = "upgrade" if e.amount_minor > cur.amount_minor else "downgrade"
        else:
            t["action"] = "none"
        t["rules"] = list(PLAN_RULES)
        tiers.append(t)
    current = None
    if sub is not None:
        current = {"plan_id": sub.plan_id, "status": sub.status, "period_end": float(sub.period_end),
                   "credits_per_period": int(sub.allotment), "active": live}
        if cur is not None:
            current.update(price_id=cur.price_id, name=cur.display_name, amount_minor=int(cur.amount_minor),
                           currency=cur.currency, period_days=_period_days(cur.period_s),
                           retired=cur.price_id not in {e.price_id for e in offered})
    if scheduled:
        tgt = _pc.known_plans().get(scheduled["to_price_id"]) if scheduled["kind"] == _pc.KIND_CHANGE else None
        scheduled = {"kind": scheduled["kind"], "effective_at": scheduled["effective_at"],
                     **({"price_id": tgt.price_id, "name": tgt.display_name} if tgt is not None else {})}
    offered_topups = _catalog.expected_amounts()
    names = {p.get("price_id"): p.get("name") for p in _catalog.plans()}
    packs = [{"price_id": pid, "name": names.get(pid) or pid, "credits": int(ent.credits),
              "amount_minor": int(offered_topups[pid][0]), "currency": offered_topups[pid][1]}
             for pid, ent in _catalog.entitlements().items() if ent.kind == EVENT_TOPUP and pid in offered_topups]
    wallet = WalletRegistry(store, owner_key=None)
    had_trial = (wallet.has_grant_entry(org_id, f"trial-preview:{org_id}")
                 or wallet.has_grant_entry(org_id, f"trial:{org_id}"))
    depths = [{"run_tier": p.run_tier, "name": p.display_name} for p in _catalog.launch_products()]
    return {
        "org_id": org_id,
        "tiers": tiers,
        "trial": {"credits": max(0, int(trial_credits)), "had_trial": bool(had_trial),
                  "preview_locked": bool(preview_locked), "rules": list(TRIAL_RULES)},
        "pay_as_you_go": {"packs": packs, "rules": list(PAYG_RULES)},
        "current": current,
        "scheduled_change": scheduled,
        "depths": depths,
        "can_manage": bool(can_manage),
        "actions": {"checkout": can_upgrade, "change": can_change, "cancel": bool(can_change and not (
            scheduled and scheduled["kind"] == _pc.KIND_CANCEL)), "change_unavailable_reason": change_reason,
            "plan_checkout_pending": bool(plan_checkout_pending)},
    }
