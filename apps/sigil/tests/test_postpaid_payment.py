"""PP-2b — enterprise POSTPAID invoice PAYMENT -> outstanding-balance tracking.

Load-bearing invariants (a false-green would corrupt the billing basis, or let a tenant evade / duplicate / forge
a payment, or cross tenants):
  * a payment reduces OUTSTANDING (invoiced - paid) but NEVER accrued / net_settled_consumed / invoiced_total,
    so future arrears invoicing still bills real consumption (the money-doctrine separation PP-2 mandates);
  * the paid amount/credits come from the owner-signed INVOICE, not the caller (no wire value);
  * idempotent per invoice (paying twice credits once); a non-existent / non-postpaid / cross-tenant / empty
    invoice is refused and records nothing; tenants are isolated.
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.postpaid import (PostpaidArrearsLedger, PostpaidRegistry, invoice_postpaid_arrears,
                                     invoiced_postpaid_total, paid_postpaid_total, pay_postpaid_invoice,
                                     postpaid_outstanding)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(s):
    return PostpaidRegistry(s, owner_key=OWNER, trusted_pubkey=OP)


def _arr(s):
    return PostpaidArrearsLedger(s, owner_key=OWNER, trusted_pubkey=OP)


def _inv(s):
    return InvoiceRegistry(s, owner_key=OWNER, trusted_pubkey=OP)


def _postpaid_inv_id(inv, org):
    return next(i.invoice_id for i in inv.invoices(org) if i.kind == "postpaid")


def _bill(reg, arr, inv, org, credits, *, period_end):
    """Accrue `credits` as a FINALISED direct draw (no in-flight reserve) and mint the arrears invoice."""
    arr.accrue(org, credits, entry_id=f"r:{org}:{credits}:{period_end}", issued_at=_issue())
    return invoice_postpaid_arrears(reg, arr, inv, org, period_end=period_end, issued_at=_issue())


# ---- outstanding = invoiced - paid --------------------------------------------------------------------
def test_outstanding_is_invoiced_minus_paid():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    assert invoiced_postpaid_total(inv, "acme") == 100 and paid_postpaid_total(inv, "acme") == 0
    assert postpaid_outstanding(inv, "acme") == 100         # billed, unpaid
    assert pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue()) is not None
    assert paid_postpaid_total(inv, "acme") == 100
    assert postpaid_outstanding(inv, "acme") == 0           # paid in full
    assert postpaid_outstanding(inv, "") == 0               # fail-closed on empty id


# ---- the money-doctrine separation: a payment NEVER moves the billing basis ---------------------------
def test_payment_does_not_lower_consumption_basis_or_billing_high_water():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    iid = _postpaid_inv_id(inv, "acme")
    pay_postpaid_invoice(inv, "acme", iid, issued_at=_issue())
    # the payment moved OUTSTANDING only; consumption + billing high-water are untouched
    assert arr.net_settled_consumed("acme") == 100 and arr.accrued("acme") == 100
    assert invoiced_postpaid_total(inv, "acme") == 100
    assert postpaid_outstanding(inv, "acme") == 0


def test_future_invoicing_bills_new_consumption_after_payment():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)                                  # invoice #1: 100
    pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue())   # paid in full
    seq = _bill(reg, arr, inv, "acme", 40, period_end=2000.0)   # MORE consumption -> a new invoice must bill 40
    assert seq is not None
    assert invoiced_postpaid_total(inv, "acme") == 140          # 100 + 40 billed (high-water advanced past payment)
    assert paid_postpaid_total(inv, "acme") == 100              # only invoice #1 paid
    assert postpaid_outstanding(inv, "acme") == 40              # the new 40 is owed


# ---- money doctrine: the amount comes from the owner-signed invoice, not the caller -------------------
def test_payment_amount_comes_from_the_owner_signed_invoice():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 150, period_end=1000.0)
    target = next(i for i in inv.invoices("acme") if i.kind == "postpaid")
    pay_postpaid_invoice(inv, "acme", target.invoice_id, issued_at=_issue())
    receipt = next(i for i in inv.invoices("acme") if i.kind == "payment")
    assert receipt.credits == target.credits == 150
    assert receipt.amount_minor == target.amount_minor and receipt.currency == target.currency
    assert receipt.price_id == "postpaid_payment" and receipt.invoice_id == f"pay:{target.invoice_id}"


# ---- idempotent; refuse bad targets; isolation -------------------------------------------------------
def test_pay_is_idempotent():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    iid = _postpaid_inv_id(inv, "acme")
    assert pay_postpaid_invoice(inv, "acme", iid, issued_at=_issue()) is not None
    assert pay_postpaid_invoice(inv, "acme", iid, issued_at=_issue()) is None   # already paid -> no-op
    assert paid_postpaid_total(inv, "acme") == 100                              # credited ONCE
    assert len([i for i in inv.invoices("acme") if i.kind == "payment"]) == 1


def test_pay_refuses_unknown_non_postpaid_cross_tenant_or_empty():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    iid = _postpaid_inv_id(inv, "acme")
    # a topup invoice is NOT payable via the postpaid path
    inv.record("acme", invoice_id="tp:1", kind="topup", price_id="vigil_topup_1k", amount_minor=1000,
               currency="USD", credits=1000, issued_at=_issue())
    assert pay_postpaid_invoice(inv, "acme", "tp:1", issued_at=_issue()) is None     # not a postpaid invoice
    assert pay_postpaid_invoice(inv, "acme", "nope", issued_at=_issue()) is None     # unknown id
    assert pay_postpaid_invoice(inv, "", iid, issued_at=_issue()) is None            # empty org
    assert pay_postpaid_invoice(inv, "acme", "", issued_at=_issue()) is None         # empty id
    # a DIFFERENT org cannot pay acme's invoice (org-scoped read finds nothing for it)
    reg.set_account("other", 1000, 30, issued_at=_issue())
    assert pay_postpaid_invoice(inv, "other", iid, issued_at=_issue()) is None
    assert paid_postpaid_total(inv, "acme") == 0 and postpaid_outstanding(inv, "acme") == 100


def test_tenant_isolation_of_payments():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("org_a", 1000, 30, issued_at=_issue())
    reg.set_account("org_b", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "org_a", 100, period_end=1000.0)
    _bill(reg, arr, inv, "org_b", 50, period_end=1000.0)
    pay_postpaid_invoice(inv, "org_a", _postpaid_inv_id(inv, "org_a"), issued_at=_issue())
    assert postpaid_outstanding(inv, "org_a") == 0 and postpaid_outstanding(inv, "org_b") == 50
    assert paid_postpaid_total(inv, "org_a") == 100 and paid_postpaid_total(inv, "org_b") == 0


def test_paid_total_ignores_a_non_postpaid_payment_tag():
    # a payment row with a DIFFERENT price_id (e.g. a future top-up receipt) is NOT counted toward postpaid paid
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    inv.record("acme", invoice_id="pay:other:1", kind="payment", price_id="topup_payment", amount_minor=500,
               currency="USD", credits=500, issued_at=_issue())
    assert paid_postpaid_total(inv, "acme") == 0            # the non-postpaid payment tag is excluded
    assert postpaid_outstanding(inv, "acme") == 100
