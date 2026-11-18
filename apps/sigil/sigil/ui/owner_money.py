"""O1 — the OWNER's money view: rate-card revenue vs the gateway's confirmed provider cost (sovereign plane,
READ-ONLY).

A PURE, READ-ONLY reconciliation (modelled on ``ui/margin.py``): per org, per UTC-day period and in total it folds
what customers were BILLED for metered work against what the provider actually COST, so the owner sees revenue,
cost, margin and loss at a glance. Everything is derived from the signed spine + the gateway meters — never a stored
counter:

  * **rate-card revenue** — the published-rate charge of the confirmed responses (``GrantMeter`` ``charge_mc``, in
    milli-credits): a quantity of billable units times the published rate, i.e. what the customer was billed. The
    signed-spine SETTLED figure (the wallet's exact metered consumption, ``WalletRegistry.balances`` ->
    ``Balance.usage_mc``) is shown beside it per org as the authoritative cross-check.
  * **confirmed provider cost** — the gateway meter's CONFIRMED spend (``GrantMeter`` ``cost_nano``, nano-USD): the
    usage the provider reported, priced.
  * **gross margin** — revenue minus cost. Revenue converts to nano-USD at the published credit unit (one credit is
    ``model_metering.CREDIT_NANO_USD`` nano-USD), so a milli-credit is :data:`_NANO_PER_MC` nano-USD; the margin is
    an integer nano-USD subtraction (it may be negative — a run that cost more than it billed).
  * **at-risk / unconfirmed spend** — provider spend VIGIL must assume but cannot bill (a cut-off response's
    ``held_nano`` + an ``orphan``'s reservation): VIGIL's own cost, never the customer's (the G1 loss split). It is
    the provider-side loss the owner watches.
  * **arrears / owed** — the PURCHASE-SIDE loss, BESIDE the provider-side at-risk and never conflated with it: the
    credits an org OWES after a dispute / refund (W5) removed credits it had already SPENT (so they could not leave
    the wallet, ``governor/billing_reversal.py``), net of repayments. Folded per org from the owner-signed reversal
    ledger (``BillingReversalLedger.holds`` / ``.owed`` — booked minus repaid), never a stored counter; an absent /
    empty ledger owes nothing, so with W5's reversals off the column is inert. Reported in credits (the ledger's unit)
    and, at the published credit unit, in nano-USD for a dollar view next to the provider-side loss.

This is an OWNER / OPERATOR surface, never a customer one, so it MAY show currency and the owner's target line: the
HTTP route authorizes the caller OWNER-tier (``role_can(principal.role, 'manage_billing')``) BEFORE calling these
helpers, exactly as ``ui/margin.py`` does, and the ``sigil owner-money`` verb (``vigil sigil owner-money``) runs on
the owner's host over the local spine. It MINTS / signs / appends NOTHING and mutates NO money state.

TARGET LINE (owner's private input, NEVER in this repo): the deploy's target margin
(``vigil_core.model_metering.target_margin`` — a margin over the run's metered provider cost, set at deploy via
``VIGIL_BILLING_TARGET_MARGIN`` and never committed) gives a display-only ``target_revenue_nano = ceil(cost / (1 -
m))`` — the revenue the cost would earn at the target. The payload carries whether a target is set and, when it is
not, the one-sentence reason (never the value); the margin VALUE itself is never in the payload, a commit or a
fixture.

FAIL-CLOSED: an unreadable / hash-broken meter file is skipped and COUNTED (``meter_errors``) — never guessed, never
a crash, and surfaced so the owner knows the view is partial; a target margin that is unset / malformed / shadowed by
a retired pricing setting withholds the target line (with its reason), never a fabricated number. Tenant isolation
(I6): every meter is attributed to its own launch's org and every wallet read is org-scoped — one tenant's money
never appears for another. Admin-key reconciliation is scaffolded as an OWNER-PROVIDED interface (the provider's own
Usage & Cost figure), unconfigured until the owner supplies it — never derived here.

FATAL-2: sovereign-side (``assert_no_offense()`` at import); imports only sovereign registries + the sovereign model
gateway's read-only money methods + ``vigil_core`` + stdlib (no framework/offense import). Folds only EXISTING
owner-signed records + hash-chained meter files through existing read APIs — no new signed record, no snapshot bump.
"""
from __future__ import annotations

import math
from fractions import Fraction
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from ..governor.billing_reversal import BillingReversalLedger  # noqa: E402  (W5's owner-signed reversal ledger: the per-org OWED / arrears balance, read-only)
from ..governor.identity import owner_pubkey  # noqa: E402  (reads verify under the trusted pubkey, never the key)
from ..governor.orgs import OrgRegistry  # noqa: E402
from ..governor.wallet import WalletRegistry  # noqa: E402  (the signed-spine SETTLED metered-revenue cross-check)
from ..model_gateway import GrantMeter  # noqa: E402  (the gateway meter's read-only money methods)
from vigil_core import model_metering as _mm  # noqa: E402  (the one pricing input: the target margin; nano math)
from vigil_core.rate_card import MC_PER_CREDIT  # noqa: E402  (one credit = 1,000 milli-credits)

_UNSET = object()                        # sentinel: "read the deploy's target margin" vs an explicit test override

#: One milli-credit in nano-USD. A credit is ``model_metering.CREDIT_NANO_USD`` nano-USD and a whole number of
#: milli-credits, so this division is exact (asserted — a change to either constant that broke it would raise here,
#: never silently mis-convert revenue).
_NANO_PER_MC = _mm.CREDIT_NANO_USD // MC_PER_CREDIT
assert _mm.CREDIT_NANO_USD % MC_PER_CREDIT == 0, "a credit must be a whole number of milli-credits"


def _usd(nano: int) -> str:
    """``nano`` nano-USD as a signed dollar string for display only (``format_usd`` handles only non-negatives, but a
    gross margin may be negative)."""
    return ("-" if nano < 0 else "") + _mm.format_usd(abs(int(nano)))


def _margin_pct(revenue_nano: int, margin_nano: int) -> Optional[float]:
    """The display-only gross-margin percentage (margin / revenue), or None when revenue is 0 (the divide-by-zero
    guard). A display read, never a signed / minted number."""
    if revenue_nano <= 0:
        return None
    return round((margin_nano / revenue_nano) * 100.0, 2)


def _target_margin(override: Any) -> "tuple[Optional[Fraction], Optional[str]]":
    """The deploy's target margin (or an explicit test override), and the reason there is none (unset, malformed, or
    a retired pricing setting still present). The reason never carries the value."""
    if override is not _UNSET:
        return override, (None if override is not None else "no target margin given")
    try:
        return _mm.target_margin(), None
    except _mm.MeteringError as exc:
        return None, str(exc)


def _target_revenue(cost_nano: int, m: Fraction) -> int:
    """The revenue at which ``cost_nano`` earns the target margin ``m``: ``cost / (1 - m)``, exact, rounded UP to a
    whole nano-USD. Display-only — it never changes a price or the actual margin."""
    return math.ceil(Fraction(cost_nano) / (1 - m))


def _row_money(charge_mc: int, cost_nano: int, at_risk_nano: int, responses: int,
               m: Optional[Fraction]) -> "dict[str, Any]":
    """The money columns shared by a period row, an org headline and the grand totals: revenue (from the rate-card
    charge), confirmed cost, gross margin, at-risk spend and — when a target margin is set — the display target
    revenue. Pure arithmetic; no I/O."""
    revenue_nano = charge_mc * _NANO_PER_MC
    margin_nano = revenue_nano - cost_nano
    return {
        "rate_card_revenue_mc": charge_mc,
        "rate_card_revenue_nano": revenue_nano,
        "rate_card_revenue_usd": _usd(revenue_nano),
        "provider_cost_nano": cost_nano,
        "provider_cost_usd": _usd(cost_nano),
        "gross_margin_nano": margin_nano,
        "gross_margin_usd": _usd(margin_nano),
        "gross_margin_pct": _margin_pct(revenue_nano, margin_nano),
        "at_risk_nano": at_risk_nano,
        "at_risk_usd": _usd(at_risk_nano),
        "responses": responses,
        "target_revenue_nano": (None if m is None else _target_revenue(cost_nano, m)),
    }


def _arrears(owed_credits: int) -> "dict[str, Any]":
    """The customer-side ARREARS an org OWES after reversals (W5): credits a dispute / refund removed that were
    already SPENT (so could not leave the wallet) and are not yet repaid — the PURCHASE-SIDE loss, a DIFFERENT loss
    from the provider-side ``at_risk`` spend it sits beside. Reported in credits (the reversal ledger's native unit)
    and, at the published credit unit (one credit is ``model_metering.CREDIT_NANO_USD`` nano-USD), in nano-USD for a
    dollar display next to the provider-side loss. Pure arithmetic; no I/O."""
    nano = owed_credits * _mm.CREDIT_NANO_USD
    return {
        "arrears_credits": owed_credits,
        "arrears_nano": nano,
        "arrears_usd": _usd(nano),
    }


def _meter_spend(meter_dir, org_filter: Optional[str] = None) -> "tuple[dict, int]":
    """Fold every launch meter under ``meter_dir`` into ``{(org_id, day): [cost_nano, at_risk_nano, charge_mc,
    responses]}`` and the count of meter files that could not be read. A PURE read: a read-only ``GrantMeter``
    (no gateway lock) hash-chain-checks each file; a corrupt / unreadable one is skipped and counted (fail-closed —
    never guessed, never a crash). ``org_filter`` keeps only that org's launches (tenant isolation)."""
    per_org_day: "dict[tuple[str, str], list[int]]" = {}
    errors = 0
    meter = GrantMeter(meter_dir)                    # read-only: gateway=False takes no lock and mutates nothing
    for mid in meter.meter_ids():
        try:
            rows = meter.spend_by_day(mid)
        except (ValueError, OSError):
            errors += 1                              # a corrupt / unreadable meter is surfaced, never fabricated
            continue
        for s in rows:
            if org_filter is not None and s.org_id != org_filter:
                continue
            slot = per_org_day.setdefault((s.org_id, s.day), [0, 0, 0, 0])
            slot[0] += s.cost_nano
            slot[1] += s.at_risk_nano
            slot[2] += s.charge_mc
            slot[3] += s.responses
    return per_org_day, errors


def money_overview(store, *, meter_dir, target_margin: Any = _UNSET,
                   admin_api_cost_nano: Optional[int] = None) -> "dict[str, Any]":
    """The OWNER money reconciliation across ALL tenants (per org, per UTC-day period, and in total): rate-card
    revenue vs confirmed provider cost, the gross margin between them, and the at-risk (unconfirmed) provider spend
    — a pure READ-ONLY projection of the signed spine + the gateway meters.

    ``meter_dir`` is the model gateway's meter directory (``config.MODEL_METER_DIR``). ``target_margin`` defaults to
    the deploy's one pricing input (``model_metering.target_margin``); an explicit value (incl. None) overrides for
    testing so no test ever sets the private value in the environment. ``admin_api_cost_nano`` is the OWNER-PROVIDED
    reconciliation figure (the provider's own Usage & Cost total) — None until the owner supplies it; it is surfaced,
    never derived. The margin's value is never in the payload. Assumes the route already authorized the caller
    owner-tier."""
    per_org_day, meter_errors = _meter_spend(meter_dir)
    m, m_issue = _target_margin(target_margin)

    trusted = owner_pubkey()                          # the trust anchor reads verify under (never the signing key)
    # ``positions`` (not ``balances``): an org whose metered runs were funded from plan credits alone has settled
    # usage but no wallet grant / debit, and its settled revenue must not drop out of the reconciliation.
    balances = {b.org_id: b for b in WalletRegistry(store, trusted_pubkey=trusted).positions()}
    names = {o.org_id: o.name for o in OrgRegistry(store).orgs()}
    # W5 arrears (the PURCHASE-SIDE loss): per org the credits it OWES after a dispute / refund removed already-spent
    # credits, net of repayments — folded from the owner-signed reversal ledger (``ReversalFold.owed`` = booked minus
    # repaid), never a stored counter. A read, not a mint. An absent / empty ledger owes nothing, so with W5's
    # reversals off every org's arrears is 0 and the column is inert. It sits BESIDE the provider-side at-risk spend.
    arrears = dict(BillingReversalLedger(store, trusted_pubkey=trusted).holds())

    org_ids = sorted({oid for (oid, _day) in per_org_day} | set(balances) | set(arrears))
    orgs: "list[dict[str, Any]]" = []
    tot_charge = tot_cost = tot_risk = tot_responses = tot_settled = tot_arrears = 0
    for oid in org_ids:
        days = sorted(day for (o, day) in per_org_day if o == oid)
        periods: "list[dict[str, Any]]" = []
        o_charge = o_cost = o_risk = o_responses = 0
        for day in days:
            c, a, ch, r = per_org_day[(oid, day)]
            periods.append({"day": day, **_row_money(ch, c, a, r, m)})
            o_charge += ch
            o_cost += c
            o_risk += a
            o_responses += r
        bal = balances.get(oid)
        settled_mc = bal.usage_mc if bal is not None else 0
        o_arrears = arrears.get(oid, 0)               # this org's OWN arrears (tenant isolation) — 0 when it owes none
        orgs.append({
            "org_id": oid, "name": names.get(oid, oid),
            **_row_money(o_charge, o_cost, o_risk, o_responses, m),
            # the customer-side arrears beside the provider-side at-risk above (two DIFFERENT losses, not conflated)
            **_arrears(o_arrears),
            # the signed-spine SETTLED metered revenue (the authoritative cross-check) + the current wallet position
            "settled_revenue_mc": settled_mc,
            "balance_credits": (bal.available if bal is not None else 0),
            "balance_exact_mc": (bal.exact_available_mc if bal is not None else 0),
            "periods": periods,
        })
        tot_charge += o_charge
        tot_cost += o_cost
        tot_risk += o_risk
        tot_responses += o_responses
        tot_settled += settled_mc
        tot_arrears += o_arrears

    return {
        "revenue_basis": "rate-card charge for metered work (credits charged x the published rate), from the meters",
        "settled_revenue_basis": "the signed spine's exact metered consumption (the wallet), per org — the "
                                 "authoritative cross-check",
        "cost_basis": "the model gateway meter's confirmed provider spend (nano-USD)",
        "at_risk_basis": "unconfirmed provider spend VIGIL cannot bill (cut-off + orphaned requests) — VIGIL's cost",
        "arrears_basis": "credits an org OWES after a dispute / refund removed already-spent credits (the W5 reversal "
                         "ledger), net of repayments — the purchase-side loss, distinct from the provider-side at-risk",
        "credits_per_usd": 100,
        "nano_per_mc": _NANO_PER_MC,
        "target_margin_set": m is not None,
        "target_margin_basis": "the run's metered provider cost only (payment fees and hosting are outside it)",
        "target_margin_issue": m_issue,            # the reason there is no target line — never the value
        "meter_errors": meter_errors,              # unreadable meter files skipped (fail-closed; the view is partial)
        "admin_api_reconciliation": {
            # SCAFFOLD: the owner reconciles the meters' confirmed provider cost against the provider's OWN billing
            # (the Usage & Cost Admin API, read with the owner's admin key). That figure is OWNER-PROVIDED — it is
            # not derived from the spine or the meters — and is unconfigured until the owner supplies it.
            "configured": admin_api_cost_nano is not None,
            "source": "owner-provided (the provider's Usage & Cost Admin API)",
            "provider_cost_nano": admin_api_cost_nano,
            "note": "owner-provided; reconcile the meters' confirmed provider cost against the provider's own "
                    "billing total (not derived here)",
        },
        "orgs": orgs,
        "totals": {
            "tenant_count": len(orgs),
            **_row_money(tot_charge, tot_cost, tot_risk, tot_responses, m),
            **_arrears(tot_arrears),           # total arrears across tenants — the sum of the orgs' own arrears
            "settled_revenue_mc": tot_settled,
        },
    }
