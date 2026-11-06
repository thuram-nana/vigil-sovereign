"""PP-3 — enterprise POSTPAID dunning predicate (`postpaid_overdue_amount` / `postpaid_is_overdue`).

Load-bearing invariants (a false-green would let a non-paying tenant keep running, or wrongly block a tenant in
good standing):
  * an UNPAID arrears invoice past its net-terms due date (period_end + net_terms_days) is OVERDUE;
  * within terms, or once PAID (PP-2b), it is NOT overdue -- reversible;
  * net_terms 0 => due at period_end; only the overdue unpaid invoice's credits count;
  * fail-closed (NOT overdue) on an empty id / never-postpaid account / non-finite clock.
The gate-level refusal + reversibility is in test_postpaid_gate.py.
"""
from __future__ import annotations

import itertools
import tempfile

from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.postpaid import (PostpaidArrearsLedger, PostpaidRegistry, invoice_postpaid_arrears,
                                     pay_postpaid_invoice, postpaid_is_overdue, postpaid_overdue_amount)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)
_DAY = 86400


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


def _bill(reg, arr, inv, org, credits, *, period_end):
    arr.accrue(org, credits, entry_id=f"r:{org}:{credits}:{period_end}", issued_at=_issue())
    return invoice_postpaid_arrears(reg, arr, inv, org, period_end=period_end, issued_at=_issue())


def _inv_id_by_credits(inv, org, credits):
    return next(i.invoice_id for i in inv.invoices(org) if i.kind == "postpaid" and i.credits == credits)


def test_unpaid_invoice_is_overdue_past_net_terms():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())          # net 30 days
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    due = 1000.0 + 30 * _DAY
    assert not postpaid_is_overdue(inv, reg, "acme", now=due - 1)  # within terms -> not overdue
    assert postpaid_is_overdue(inv, reg, "acme", now=due)          # at/after the due date -> overdue
    assert postpaid_overdue_amount(inv, reg, "acme", now=due + 1) == 100


def test_paying_the_invoice_clears_overdue():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    due = 1000.0 + 30 * _DAY
    assert postpaid_is_overdue(inv, reg, "acme", now=due)          # overdue before payment
    pay_postpaid_invoice(inv, "acme", _inv_id_by_credits(inv, "acme", 100), issued_at=_issue())
    assert not postpaid_is_overdue(inv, reg, "acme", now=due)      # paid -> no longer overdue (reversible)
    assert postpaid_overdue_amount(inv, reg, "acme", now=due) == 0


def test_net_terms_zero_is_due_at_period_end():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 0, issued_at=_issue())           # net 0 -> due at period_end
    _bill(reg, arr, inv, "acme", 100, period_end=5000.0)
    assert not postpaid_is_overdue(inv, reg, "acme", now=4999.0)
    assert postpaid_is_overdue(inv, reg, "acme", now=5000.0)


def test_only_the_overdue_unpaid_invoice_counts():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 10000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)                  # invoice #1 (older): due 1000 + 30d
    _bill(reg, arr, inv, "acme", 40, period_end=1000.0 + 60 * _DAY)       # invoice #2 (newer): due 1000 + 90d
    now = 1000.0 + 45 * _DAY                                              # past #1's due, before #2's due
    assert postpaid_overdue_amount(inv, reg, "acme", now=now) == 100      # only #1 is overdue
    pay_postpaid_invoice(inv, "acme", _inv_id_by_credits(inv, "acme", 100), issued_at=_issue())
    assert postpaid_overdue_amount(inv, reg, "acme", now=now) == 0        # paying #1 clears it; #2 still within terms


def test_overdue_is_fail_closed_on_bad_inputs():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    assert postpaid_overdue_amount(inv, reg, "", now=1e12) == 0           # empty org
    assert postpaid_overdue_amount(inv, reg, "ghost", now=1e12) == 0      # never postpaid
    assert postpaid_overdue_amount(inv, reg, "acme", now=float("nan")) == 0   # non-finite clock -> fail-closed
    assert postpaid_overdue_amount(inv, reg, "acme", now=float("inf")) == 0
    assert postpaid_is_overdue(inv, reg, "acme", now=True) is False       # bool is not a clock
