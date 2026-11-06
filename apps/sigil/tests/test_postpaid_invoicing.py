"""PP-2 — enterprise POSTPAID arrears invoicing (`governor/postpaid.invoice_postpaid_arrears` + catalog pricing).

Load-bearing invariants (a false-green would double-bill a tenant, bill the wrong amount, or bill a
non-postpaid/cancelled draw):
  * an arrears invoice bills the tenant's UN-INVOICED drawn credits (delta), amount from the owner CATALOG
    (never a wire value), owner-signed, kind `postpaid`;
  * idempotent per (org, period_end) — a repeated billing run in a period mints nothing new;
  * the DELTA model never double-bills across periods (each period bills only the new draws);
  * a settle refund reduces what is billed (a cancelled draw is netted out of `accrued`);
  * a non-postpaid / disabled tenant is never invoiced; tenants are isolated.
The arrears/invoice ledgers' prune-survival lives in their own fold tests; PP-2 adds no new spine record.
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor import catalog
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.postpaid import (PostpaidArrearsLedger, PostpaidRegistry, invoice_postpaid_arrears,
                                     invoiced_postpaid_total)
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


def _postpaid_invs(inv, org):
    return sorted((i for i in inv.invoices(org) if i.kind == "postpaid"), key=lambda i: i.period_end)


# ---- catalog pricing --------------------------------------------------------------------------------
def test_catalog_amount_minor_is_credits_times_rate_clamped():
    rate = catalog.postpaid_per_credit_minor()
    assert isinstance(rate, int) and rate >= 0
    amt, cur = catalog.postpaid_invoice_amount_minor(150)
    assert amt == 150 * rate and len(cur) == 3 and cur.isalpha() and cur.isupper()
    assert catalog.postpaid_invoice_amount_minor(0)[0] == 0
    assert catalog.postpaid_invoice_amount_minor(-5)[0] == 0        # forged negative -> 0 amount
    assert catalog.postpaid_invoice_amount_minor(True)[0] == 0      # bool is not a credit count


# ---- arrears invoicing ------------------------------------------------------------------------------
def test_arrears_invoice_bills_accrued_from_catalog():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    arr.accrue("acme", 50, entry_id="r:2", issued_at=_issue())
    seq = invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    assert seq is not None
    invs = _postpaid_invs(inv, "acme")
    assert len(invs) == 1
    amt, cur = catalog.postpaid_invoice_amount_minor(150)
    assert invs[0].credits == 150 and invs[0].amount_minor == amt and invs[0].currency == cur
    assert invs[0].kind == "postpaid" and invs[0].price_id == "postpaid_arrears" and invs[0].period_end == 1000.0
    assert invoiced_postpaid_total(inv, "acme") == 150


def test_invoice_idempotent_per_period():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    # re-run in the SAME period -> delta 0 -> no new invoice
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue()) is None
    assert len(_postpaid_invs(inv, "acme")) == 1


def test_delta_billed_across_periods_no_double_bill():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())   # bills 100
    arr.accrue("acme", 40, entry_id="r:2", issued_at=_issue())                                # accrued 140
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=2000.0, issued_at=_issue())   # bills ONLY 40
    invs = _postpaid_invs(inv, "acme")
    assert [i.credits for i in invs] == [100, 40], "second period bills the delta, never re-bills the 100"
    assert invoiced_postpaid_total(inv, "acme") == 140


def test_settle_refund_reduces_what_is_billed():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    arr.reverse("acme", 30, entry_id="settle-postpaid:cust:r1", issued_at=_issue())   # a cancel refund
    # accrued is now 70 -> the arrears invoice bills the NET consumption, not the gross draw
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    invs = _postpaid_invs(inv, "acme")
    assert len(invs) == 1 and invs[0].credits == 70


def test_not_postpaid_and_nothing_new_return_none():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    # never postpaid
    assert invoice_postpaid_arrears(reg, arr, inv, "ghost", period_end=1000.0, issued_at=_issue()) is None
    # postpaid but no draws
    reg.set_account("acme", 500, 30, issued_at=_issue())
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue()) is None
    assert _postpaid_invs(inv, "acme") == []


def test_disabled_account_not_invoiced():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    reg.disable("acme")                                   # line closed -> not postpaid
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue()) is None


def test_invoiced_total_counts_only_postpaid_kind():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    # a non-postpaid invoice (a topup) in the same tenant's history must NOT count toward the postpaid total
    inv.record("acme", invoice_id="tp:1", kind="topup", price_id="vigil_topup_1k", amount_minor=1000,
               currency="USD", credits=1000, issued_at=_issue())
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 80, entry_id="r:1", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    assert invoiced_postpaid_total(inv, "acme") == 80     # the 1000-credit topup is excluded
    assert invoiced_postpaid_total(inv, "") == 0


def test_tenant_isolation():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("org_a", 500, 30, issued_at=_issue())
    reg.set_account("org_b", 500, 30, issued_at=_issue())
    arr.accrue("org_a", 100, entry_id="a:1", issued_at=_issue())
    arr.accrue("org_b", 20, entry_id="b:1", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "org_a", period_end=1000.0, issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "org_b", period_end=1000.0, issued_at=_issue())
    assert invoiced_postpaid_total(inv, "org_a") == 100 and invoiced_postpaid_total(inv, "org_b") == 20
    assert _postpaid_invs(inv, "org_a")[0].credits == 100 and _postpaid_invs(inv, "org_b")[0].credits == 20
