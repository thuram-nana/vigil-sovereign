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

from dataclasses import dataclass

from ..reuse import assert_no_offense

assert_no_offense()

from .billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_TOPUP, Entitlement  # noqa: E402

_PERIOD_MONTH_S = 30 * 24 * 3600.0          # a monthly subscription period, in seconds
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
        return out


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
        if not (isinstance(e.currency, str) and len(e.currency) == 3 and e.currency.isalpha()):
            raise ValueError(f"catalog entry {e.price_id!r}: currency must be an ISO-4217 alpha-3 code")
        if e.kind == EVENT_TOPUP:
            if e.credits <= 0 or e.plan_id or e.allotment or e.period_s:
                raise ValueError(f"top-up {e.price_id!r}: needs credits>0 and no plan/allotment/period")
        else:  # EVENT_SUBSCRIPTION_ACTIVE
            if not e.plan_id or e.allotment <= 0 or e.period_s <= 0.0 or e.credits:
                raise ValueError(f"subscription {e.price_id!r}: needs plan_id + allotment>0 + period_s>0, no credits")


_validate(_CATALOG)


def entitlements() -> dict[str, Entitlement]:
    """The `{price_id: Entitlement}` mapping the BillingSigner consumes — the owner catalog that decides money."""
    return {e.price_id: e.entitlement() for e in _CATALOG}


def expected_amounts() -> dict[str, tuple[int, str]]:
    """`{price_id: (amount_minor, currency)}` — the EXPECTED fiat price per offering, for the Slice-F
    checkout-reconciliation amount cross-check (a verified amount below this is refused)."""
    return {e.price_id: (e.amount_minor, e.currency) for e in _CATALOG}


def plans() -> list[dict]:
    """The PUBLIC pricing projection for the pricing page / list-plans endpoint, in catalog order."""
    return [e.public() for e in _CATALOG]
