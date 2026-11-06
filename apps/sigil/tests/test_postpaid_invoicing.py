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
                                     invoiced_postpaid_total, postpaid_invoice_period_end)
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


# ---- HIGH (red-pen): a stable per-month period key, so two runs in one period never double-bill -----------
def test_period_end_is_stable_within_utc_month():
    import datetime as _dt
    jan2 = _dt.datetime(2026, 1, 2, 3, 4, tzinfo=_dt.timezone.utc).timestamp()
    jan29 = _dt.datetime(2026, 1, 29, 23, 0, tzinfo=_dt.timezone.utc).timestamp()
    feb1 = _dt.datetime(2026, 2, 1, 0, 0, tzinfo=_dt.timezone.utc).timestamp()
    # distinct wall-clocks in ONE UTC month collapse to one key (the HIGH fix); the next month is a new key
    assert postpaid_invoice_period_end(jan2) == postpaid_invoice_period_end(jan29)
    assert postpaid_invoice_period_end(jan2) != postpaid_invoice_period_end(feb1)
    # the key IS the UTC calendar-month start
    assert postpaid_invoice_period_end(jan29) == _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc).timestamp()
    # fail-closed: a garbage clock clamps to a still-STABLE 0.0 (never a wall-clock value that reopens the bug)
    assert postpaid_invoice_period_end(float("nan")) == 0.0
    assert postpaid_invoice_period_end(float("inf")) == 0.0
    assert postpaid_invoice_period_end(-1.0) == 0.0
    assert postpaid_invoice_period_end(True) == 0.0            # bool is not a clock


def test_two_same_month_runs_mint_one_invoice():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    import datetime as _dt
    pe_a = postpaid_invoice_period_end(_dt.datetime(2026, 3, 10, tzinfo=_dt.timezone.utc).timestamp())
    pe_b = postpaid_invoice_period_end(_dt.datetime(2026, 3, 20, tzinfo=_dt.timezone.utc).timestamp())
    assert pe_a == pe_b                                        # same month -> same invoice_id
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=pe_a, issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=pe_b, issued_at=_issue())
    # the two runs mint ONE invoice, not two (the owner-signed fold dedups the shared invoice_id)
    assert len(_postpaid_invs(inv, "acme")) == 1
    assert invoiced_postpaid_total(inv, "acme") == 100


# ---- MED (red-pen): bill NET SETTLED consumption — an in-flight reserve is never over-billed ---------------
def test_in_flight_reserve_is_not_billed():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    # a launch RESERVES 100 against the line (reserved, not yet settled) — the gate's reserve entry-id scheme
    arr.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())
    assert arr.accrued("acme") == 100                 # the credit-line cap DOES count the full reserve
    assert arr.in_flight_reserved("acme") == 100
    assert arr.net_settled_consumed("acme") == 0      # ...but nothing is billable while in-flight
    # a billing run that fires mid-flight mints NOTHING (the MED over-bill is closed)
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue()) is None
    assert _postpaid_invs(inv, "acme") == []


def test_settled_consumption_billed_at_net_not_reserved():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())        # reserve 100
    # the launch settles having consumed 40 -> the gate reverses reserved-consumed = 60 under the settle id
    arr.reverse("acme", 60, entry_id="settle-postpaid:acme:n1", issued_at=_issue())
    assert arr.accrued("acme") == 40
    assert arr.in_flight_reserved("acme") == 0         # the settle landed -> no longer in-flight
    assert arr.net_settled_consumed("acme") == 40
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    invs = _postpaid_invs(inv, "acme")
    assert len(invs) == 1 and invs[0].credits == 40    # billed the NET consumed, never the 100 reserved


def test_cancelled_in_flight_draw_is_never_billed():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())        # reserve 100
    # a mid-period run fires while the draw is in-flight -> bills nothing
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue()) is None
    # the launch is CANCELLED: consumed 0 -> the gate reverses the FULL 100 under the settle id
    arr.reverse("acme", 100, entry_id="settle-postpaid:acme:n1", issued_at=_issue())
    assert arr.accrued("acme") == 0 and arr.net_settled_consumed("acme") == 0
    # a LATER run (a new period) still bills nothing — a cancelled draw never bills, so no claw-back is needed
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=2000.0, issued_at=_issue()) is None
    assert _postpaid_invs(inv, "acme") == []


def test_in_flight_reserve_withheld_but_prior_settled_draw_still_billed():
    """A settled draw (billable) and a fresh in-flight reserve coexist: only the settled net is billed, and the
    in-flight reserve is withheld until it too settles — the delta model never re-bills or over-bills."""
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())        # reserve 100
    arr.reverse("acme", 60, entry_id="settle-postpaid:acme:n1", issued_at=_issue())         # settle: consumed 40
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())  # bills 40
    arr.accrue("acme", 50, entry_id="reserve-postpaid:acme:n2", issued_at=_issue())         # a NEW in-flight 50
    assert arr.accrued("acme") == 90 and arr.in_flight_reserved("acme") == 50
    assert arr.net_settled_consumed("acme") == 40      # only the settled 40 is billable
    # a run now adds nothing (40 already invoiced; the 50 reserve is in-flight)
    assert invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=2000.0, issued_at=_issue()) is None
    assert [i.credits for i in _postpaid_invs(inv, "acme")] == [40]
    assert invoiced_postpaid_total(inv, "acme") == 40


# ---- HIGH (red-pen FOLD): a FULL-consumption launch (refund==0) is billed, not treated as in-flight forever ---
def test_full_consumption_settle_is_billed():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 500, 30, issued_at=_issue())
    # a launch RESERVES 100 then consumes ALL 100 -> the gate's settle refund is 0 -> settle() STILL records it
    arr.accrue("acme", 100, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())
    arr.settle("acme", 0, entry_id="settle-postpaid:acme:n1", issued_at=_issue())   # full consumption, refund 0
    assert arr.accrued("acme") == 100                    # refund 0 -> balance unchanged (== consumed)
    assert arr.in_flight_reserved("acme") == 0           # the settle MARKER cleared it from in-flight
    assert arr.net_settled_consumed("acme") == 100       # ...so the full consumption is billable (was 0 pre-fix)
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    invs = _postpaid_invs(inv, "acme")
    assert len(invs) == 1 and invs[0].credits == 100     # billed the full consumed 100 — the revenue leak is closed


def test_settle_marker_zero_refund_is_balance_noop_but_clears_in_flight():
    s = _store()
    arr = _arr(s)
    arr.accrue("acme", 80, entry_id="reserve-postpaid:acme:n1", issued_at=_issue())
    before = arr.accrued("acme")
    arr.settle("acme", 0, entry_id="settle-postpaid:acme:n1", issued_at=_issue())
    assert before == 80 and arr.accrued("acme") == 80    # a 0-refund settle does NOT move the balance
    assert arr.in_flight_reserved("acme") == 0           # ...but it DOES clear the reserve from in-flight
    # a positive-refund settle reduces the arrears like a reverse (consumed 30 of 50)
    arr.accrue("acme", 50, entry_id="reserve-postpaid:acme:n2", issued_at=_issue())
    arr.settle("acme", 20, entry_id="settle-postpaid:acme:n2", issued_at=_issue())
    assert arr.accrued("acme") == 110 and arr.in_flight_reserved("acme") == 0
    # fail-closed: a negative refund is refused at binding
    import pytest
    with pytest.raises(ValueError):
        arr.settle("acme", -1, entry_id="settle-postpaid:acme:n3", issued_at=_issue())


# ---- HIGH (red-pen FOLD): a same-month re-run bills its NEW delta — content-addressed id, no month-key drop ----
def test_late_same_month_delta_is_billed_not_dropped():
    import datetime as _dt
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    jan = postpaid_invoice_period_end(_dt.datetime(2026, 1, 5, tzinfo=_dt.timezone.utc).timestamp())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=jan, issued_at=_issue())        # bills 100
    # MORE settled consumption LATER in the SAME month, then a second run with the SAME month label
    arr.accrue("acme", 40, entry_id="r:2", issued_at=_issue())
    jan2 = postpaid_invoice_period_end(_dt.datetime(2026, 1, 25, tzinfo=_dt.timezone.utc).timestamp())
    assert jan == jan2                                   # same month label — the OLD month key would collide + DROP
    seq = invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=jan2, issued_at=_issue())
    assert seq is not None                               # the new 40 IS billed (content id advances), not dropped
    invs = _postpaid_invs(inv, "acme")                   # two invoices share the Jan period LABEL (order-indifferent)
    assert len(invs) == 2 and sorted(i.credits for i in invs) == [40, 100]
    assert invoiced_postpaid_total(inv, "acme") == 140


def test_invoice_id_is_content_addressed_on_billing_high_water():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:1", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    arr.accrue("acme", 40, entry_id="r:2", issued_at=_issue())
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=2000.0, issued_at=_issue())
    # the id is the billing high-water this invoice advances FROM (0, then 100): distinct per delta (no leak),
    # identical for concurrent racers on the same high-water (first-mint-wins dedup -> no double-bill)
    assert [i.invoice_id for i in _postpaid_invs(inv, "acme")] == ["postpaid:acme:0", "postpaid:acme:100"]
