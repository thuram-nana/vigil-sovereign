"""W5 — the LOW-BALANCE condition: an org's available credits fell below max(100, 20% of its last top-up).

Pure read (no key, no write): the notification centre (``ui/provision.py``) and the email sweep
(``ui/billing_alerts.py``) ask the same question here, so they cannot disagree.

  * the balance is the org's AVAILABLE credits as the customer sees them (``CreditMeter.available``: the live plan
    tranche plus the wallet);
  * the threshold is ``max(LOW_BALANCE_FLOOR, 20% of the credits of the org's last top-up)`` — compared exactly in
    integers (``5 x available < last`` instead of a rounded 20%);
  * the alert KEY is the org plus the last top-up's billing-history id (``"none"`` before the first one): the
    condition fires once per key, and the next top-up re-arms it (a new key);
  * an org that never received a credit is never "low" (it has no credits to run low on).

It states a balance threshold in credits and nothing else: never an estimate of what anything will cost (design §0.9).
FATAL-2: sovereign-side, ``assert_no_offense`` at import.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..reuse import assert_no_offense

assert_no_offense()

#: The floor of the threshold, in credits (owner decision, 2026-11-16: max(100 credits, 20% of the last top-up)).
LOW_BALANCE_FLOOR = 100
#: The share of the last top-up below which the balance is low: 1/5 = 20% (compared as ``5 x available < last``).
_TOPUP_SHARE_DIVISOR = 5
NO_TOPUP_KEY = "none"


@dataclass(frozen=True)
class LowBalance:
    """An org whose available credits are below its threshold: ``key`` identifies the crossing (the last top-up)."""
    org_id: str
    available: int
    threshold: int
    key: str


def last_topup(invoices, org_id: str):
    """The org's most recent credit top-up (its owner-signed billing-history line), or None."""
    for inv in invoices.invoices(org_id):                 # newest first
        if inv.kind == "topup" and inv.credits > 0:
            return inv
    return None


def threshold_for(last_credits: int) -> int:
    """``max(100, 20% of last_credits)``, rounded up to a whole credit for display (the test itself is exact)."""
    return max(LOW_BALANCE_FLOOR, -(-int(last_credits) // _TOPUP_SHARE_DIVISOR))


def low_balance(org_id: str, *, now: float, meter, wallet, invoices) -> Optional[LowBalance]:
    """The org's low-balance condition at ``now``, or None when it is not low (or never had a credit)."""
    if not isinstance(org_id, str) or not org_id:
        return None
    if wallet.balance(org_id).granted <= 0:
        return None
    available = int(meter.available(org_id, now))
    last = last_topup(invoices, org_id)
    last_credits = int(last.credits) if last is not None else 0
    if available >= LOW_BALANCE_FLOOR and _TOPUP_SHARE_DIVISOR * available >= last_credits:
        return None
    return LowBalance(org_id=org_id, available=max(0, available), threshold=threshold_for(last_credits),
                      key=str(last.invoice_id) if last is not None else NO_TOPUP_KEY)


def low_balance_of(store, org_id: str, *, now: float) -> Optional[LowBalance]:
    """:func:`low_balance` over the owner-identity registries of ``store`` (the readers ``ui.billing.billing_overview``
    uses, so the notice and the overview read the same balance)."""
    from .invoices import InvoiceRegistry
    from .metering import CreditMeter, PlanCreditLedger
    from .subscription import SubscriptionRegistry
    from .wallet import WalletRegistry
    wallet = WalletRegistry(store)
    meter = CreditMeter(wallet, PlanCreditLedger(store), SubscriptionRegistry(store))
    return low_balance(org_id, now=now, meter=meter, wallet=wallet, invoices=InvoiceRegistry(store))
