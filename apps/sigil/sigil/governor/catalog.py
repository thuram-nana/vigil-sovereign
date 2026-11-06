"""The owner-controlled PRICE -> ENTITLEMENT catalog — the money anchor (SaaS Slice D).

Billing doctrine: NO on-the-wire amount decides money; the OWNER CATALOG keyed by `price_id` does
(`billing.BillingSigner` mints `catalog[event.price_id]`, never a field off the webhook). This module IS that
catalog. It is owner-controlled BY CONSTRUCTION: it lives in the reviewed sovereign codebase, so changing a
price or a grant takes an owner-reviewed commit + deploy — the same trust root as the owner Ed25519 key. (A
later enhancement may promote it to an owner-SIGNED spine record for deploy-free pricing changes; until then the
reviewed-code catalog is the authoritative, tamper-evident source.)

Each `CatalogEntry` maps a provider price/plan id to three things:
  * the sovereign `Entitlement` the signer mints (credits for a top-up; plan_id + allotment + period for a
    subscription) — consumed via `entitlements()`;
  * the PUBLIC pricing-page fields (display name, fiat price) — projected via `plans()`;
  * the EXPECTED fiat amount (`amount_minor` + `currency`) for the Slice-F defense-in-depth cross-check — a
    verified transaction whose amount is below the catalog's expected price for its price_id is refused at
    checkout-reconciliation time (belt-and-suspenders on top of "the price_id we set at checkout"). Exposed via
    `expected_amounts()`; the cross-check itself lands with the outbound checkout slice that establishes the
    price_id -> amount binding.

THE NUMBERS BELOW ARE PLACEHOLDER (clearly-marked): the structure is authoritative; the owner sets the real
prices/allotments and the real provider price/plan ids before production. The catalog is VALIDATED at import
(fail-closed): a malformed entry raises immediately, so a bad catalog can never ship (import + CI fail loudly).

FATAL-2: sovereign-side (`assert_no_offense()` at import); imports only the billing `Entitlement`/kinds.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from ..reuse import assert_no_offense

assert_no_offense()

from .billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, Entitlement  # noqa: E402
from .subscription import _check_plan_id  # noqa: E402  (mirror the mint-path plan_id validator — fail-closed at import, red-pen D/C2)

_PERIOD_MONTH_S = 30 * 24 * 3600.0          # a monthly subscription period, in seconds
_AEGIS_OBSERVE_PER_HOST = 4900             # PLACEHOLDER per-protected-host monthly price (minor units)
_AEGIS_RESPOND_PER_HOST = 9900
_KNOWN_KINDS = frozenset({EVENT_TOPUP, EVENT_SUBSCRIPTION_ACTIVE})


@dataclass(frozen=True)
class CatalogEntry:
    """One owner-controlled offering. `price_id` is the provider key the webhook carries (a Flutterwave
    payment_plan id for a subscription; our checkout meta.price_id for a top-up)."""
    price_id: str
    kind: str                  # EVENT_TOPUP | EVENT_SUBSCRIPTION_ACTIVE
    display_name: str          # the public pricing-page label
    amount_minor: int          # the fiat price in MINOR units (e.g. cents) — EXPECTED amount for the cross-check
    currency: str              # ISO-4217 (e.g. "USD")
    credits: int = 0           # top-up credits (EVENT_TOPUP)
    plan_id: str = ""          # subscription plan id (EVENT_SUBSCRIPTION_ACTIVE)
    allotment: int = 0         # subscription per-period credit allotment
    period_s: float = 0.0      # subscription period length in seconds
    monitor_hosts: int = 0     # AEGIS monitoring plan: protected-host slots included (0 = not a monitoring plan)
    monitor_respond: bool = False  # AEGIS monitoring plan tier includes respond (mode=block)

    def entitlement(self) -> Entitlement:
        """The sovereign Entitlement the signer mints for this price_id."""
        return Entitlement(kind=self.kind, credits=self.credits, plan_id=self.plan_id,
                           allotment=self.allotment, period_s=self.period_s)

    def public(self) -> dict:
        """The PUBLIC pricing-page projection — no sovereign internals, just what a customer sees."""
        out = {"price_id": self.price_id, "kind": self.kind, "name": self.display_name,
               "amount_minor": self.amount_minor, "currency": self.currency}
        if self.kind == EVENT_TOPUP:
            out["credits"] = self.credits
        else:
            out.update(plan_id=self.plan_id, allotment=self.allotment,
                       period_days=round(self.period_s / 86400.0, 2))
            if self.monitor_hosts:
                out.update(monitor_hosts=self.monitor_hosts, monitor_respond=self.monitor_respond)
        return out


@dataclass(frozen=True)
class MonitoringPlan:
    """What a monitoring subscription buys: protected-host slots + whether respond (block) is included."""
    plan_id: str
    host_slots: int
    respond: bool


# ==================================================================================================
# THE CATALOG. PLACEHOLDER numbers — the owner sets the real prices / allotments / provider ids.
# ==================================================================================================
_CATALOG: tuple[CatalogEntry, ...] = (
    # one-time wallet top-ups (prepaid credits; EVENT_TOPUP -> wallet grant)
    CatalogEntry("vigil_topup_1k", EVENT_TOPUP, "1,000 credit top-up", 1000, "USD", credits=1_000),
    CatalogEntry("vigil_topup_6k", EVENT_TOPUP, "6,000 credit top-up", 5000, "USD", credits=6_000),
    # monthly subscriptions (EVENT_SUBSCRIPTION_ACTIVE -> subscribe + per-period plan allotment)
    CatalogEntry("vigil_research_monthly", EVENT_SUBSCRIPTION_ACTIVE, "Research (monthly)", 2900, "USD",
                 plan_id="research", allotment=2_000, period_s=_PERIOD_MONTH_S),
    CatalogEntry("vigil_pro_monthly", EVENT_SUBSCRIPTION_ACTIVE, "Pro (monthly)", 9900, "USD",
                 plan_id="pro", allotment=6_000, period_s=_PERIOD_MONTH_S),
    CatalogEntry("vigil_team_monthly", EVENT_SUBSCRIPTION_ACTIVE, "Team (monthly)", 29900, "USD",
                 plan_id="team", allotment=20_000, period_s=_PERIOD_MONTH_S),
    # AEGIS monitoring: priced PER PROTECTED HOST PER MONTH (amount = per-host price x included hosts). No credit
    # allotment (allotment=0 => no plan-credit refill); the plan buys host slots, and the respond tier buys block.
    CatalogEntry("vigil_aegis_observe_1h_monthly", EVENT_SUBSCRIPTION_ACTIVE, "AEGIS Observe, 1 host (monthly)",
                 1 * _AEGIS_OBSERVE_PER_HOST, "USD", plan_id="aegis_observe_1h", period_s=_PERIOD_MONTH_S,
                 monitor_hosts=1),
    CatalogEntry("vigil_aegis_observe_5h_monthly", EVENT_SUBSCRIPTION_ACTIVE, "AEGIS Observe, 5 hosts (monthly)",
                 5 * _AEGIS_OBSERVE_PER_HOST, "USD", plan_id="aegis_observe_5h", period_s=_PERIOD_MONTH_S,
                 monitor_hosts=5),
    CatalogEntry("vigil_aegis_respond_1h_monthly", EVENT_SUBSCRIPTION_ACTIVE, "AEGIS Respond, 1 host (monthly)",
                 1 * _AEGIS_RESPOND_PER_HOST, "USD", plan_id="aegis_respond_1h", period_s=_PERIOD_MONTH_S,
                 monitor_hosts=1, monitor_respond=True),
    CatalogEntry("vigil_aegis_respond_5h_monthly", EVENT_SUBSCRIPTION_ACTIVE, "AEGIS Respond, 5 hosts (monthly)",
                 5 * _AEGIS_RESPOND_PER_HOST, "USD", plan_id="aegis_respond_5h", period_s=_PERIOD_MONTH_S,
                 monitor_hosts=5, monitor_respond=True),
)


def _validate(catalog: tuple[CatalogEntry, ...]) -> None:
    """Fail-closed at import: a malformed catalog raises, so a bad deploy fails loudly (never ships silent)."""
    seen: set[str] = set()
    for e in catalog:
        if not e.price_id or e.price_id in seen:
            raise ValueError(f"catalog price_id must be non-empty and unique: {e.price_id!r}")
        seen.add(e.price_id)
        if e.kind not in _KNOWN_KINDS:
            raise ValueError(f"catalog entry {e.price_id!r}: unknown kind {e.kind!r}")
        if not isinstance(e.amount_minor, int) or e.amount_minor < 0:
            raise ValueError(f"catalog entry {e.price_id!r}: amount_minor must be a non-negative int")
        if not (isinstance(e.currency, str) and len(e.currency) == 3 and e.currency.isalpha()
                and e.currency.isupper()):
            raise ValueError(f"catalog entry {e.price_id!r}: currency must be an uppercase ISO-4217 alpha-3 code")
        if e.kind == EVENT_TOPUP:
            if e.credits <= 0 or e.plan_id or e.allotment or e.period_s or e.monitor_hosts or e.monitor_respond:
                raise ValueError(f"top-up {e.price_id!r}: needs credits>0 and no plan/allotment/period")
        else:  # EVENT_SUBSCRIPTION_ACTIVE
            if isinstance(e.monitor_hosts, bool) or not isinstance(e.monitor_hosts, int) or e.monitor_hosts < 0:
                raise ValueError(f"subscription {e.price_id!r}: monitor_hosts must be a non-negative int")
            if e.monitor_respond and not e.monitor_hosts:
                raise ValueError(f"subscription {e.price_id!r}: monitor_respond requires monitor_hosts>0")
            min_allot = 0 if e.monitor_hosts else 1      # a monitoring plan buys host slots, not credits
            if not e.plan_id or e.allotment < min_allot or not math.isfinite(e.period_s) or e.period_s <= 0.0 or e.credits:
                raise ValueError(f"subscription {e.price_id!r}: needs plan_id + allotment>0 + finite period_s>0, no credits")
            # mirror the mint-path validator (subscription._check_plan_id): a malformed-but-nonempty plan_id must
            # fail HERE at import, never detonate inside subscribe() at webhook-mint time (red-pen D/C2).
            try:
                _check_plan_id(e.plan_id)
            except ValueError as exc:
                raise ValueError(f"subscription {e.price_id!r}: {exc}") from exc


_validate(_CATALOG)


# Enterprise POSTPAID arrears pricing (PP-2). The owner catalog is the money anchor: an arrears invoice bills
# `drawn_credits * this per-credit rate`, NEVER a wire value. PLACEHOLDER (1 minor unit/credit in USD, ~the 1k
# top-up rate) — the owner sets the real net-terms rate before production, exactly like every other price here.
_POSTPAID_PER_CREDIT_MINOR = 1
_POSTPAID_CURRENCY = "USD"
if (isinstance(_POSTPAID_PER_CREDIT_MINOR, bool) or not isinstance(_POSTPAID_PER_CREDIT_MINOR, int)
        or _POSTPAID_PER_CREDIT_MINOR < 0 or len(_POSTPAID_CURRENCY) != 3 or not _POSTPAID_CURRENCY.isalpha()
        or not _POSTPAID_CURRENCY.isupper()):
    raise ValueError("postpaid arrears price must be a non-negative int (minor units) + an ISO-4217 currency")


_plan_seen: set[str] = set()
for _e in _CATALOG:
    if _e.monitor_hosts:
        if _e.plan_id in _plan_seen:
            raise ValueError(f"monitoring plan_id must be unique: {_e.plan_id!r}")
        _plan_seen.add(_e.plan_id)


def monitoring_plan(plan_id: str) -> "MonitoringPlan | None":
    """The catalog's monitoring entitlement for a subscription plan_id (None if it is not a monitoring plan).
    The CATALOG decides what a plan buys — never a client field."""
    for e in _CATALOG:
        if e.monitor_hosts and e.plan_id == plan_id:
            return MonitoringPlan(plan_id=e.plan_id, host_slots=e.monitor_hosts, respond=e.monitor_respond)
    return None


def monitoring_price_ids() -> frozenset[str]:
    """EVERY AEGIS monitoring price_id in the FULL catalog, flag-independent — used to ROUTE down events
    (cancel / payment_failed) to the monitoring line so they can never touch the credit-plan subscription,
    whatever VIGIL_CUSTOMER_MONITORING_ENABLED says (the flag gates SALE, not routing)."""
    return frozenset(e.price_id for e in _CATALOG if e.monitor_hosts)


def _offered() -> tuple[CatalogEntry, ...]:
    """The entries ON SALE on this deployment: AEGIS monitoring plans only while VIGIL_CUSTOMER_MONITORING_ENABLED
    is on (default OFF => the catalog is exactly the pre-AEGIS one: not priced, not listed, not mintable)."""
    from .. import config
    if config.customer_monitoring_enabled():
        return _CATALOG
    return tuple(e for e in _CATALOG if not e.monitor_hosts)


def entitlements() -> dict[str, Entitlement]:
    """The `{price_id: Entitlement}` mapping the BillingSigner consumes — the owner catalog that decides money."""
    return {e.price_id: e.entitlement() for e in _offered()}


def expected_amounts() -> dict[str, tuple[int, str]]:
    """`{price_id: (amount_minor, currency)}` — the EXPECTED fiat price per offering, for the Slice-F
    checkout-reconciliation amount cross-check (a verified amount below this is refused)."""
    return {e.price_id: (e.amount_minor, e.currency) for e in _offered()}


def plans() -> list[dict]:
    """The PUBLIC pricing projection for the pricing page / list-plans endpoint, in catalog order."""
    return [e.public() for e in _offered()]


def postpaid_per_credit_minor() -> int:
    """The owner-catalog price per drawn credit (minor units) a POSTPAID arrears invoice bills (PP-2).
    Placeholder until the owner sets the real net-terms rate (same convention as the catalog prices)."""
    return _POSTPAID_PER_CREDIT_MINOR


def postpaid_invoice_amount_minor(credits: int) -> "tuple[int, str]":
    """`(amount_minor, currency)` a postpaid arrears invoice bills for `credits` drawn — `credits` times the
    catalog per-credit rate, clamped non-negative. The money anchor for PP-2 (the amount is derived from the
    owner catalog, NEVER a wire value); a forged/negative credits value folds to a 0 amount."""
    c = credits if (isinstance(credits, int) and not isinstance(credits, bool) and credits > 0) else 0
    return c * _POSTPAID_PER_CREDIT_MINOR, _POSTPAID_CURRENCY
