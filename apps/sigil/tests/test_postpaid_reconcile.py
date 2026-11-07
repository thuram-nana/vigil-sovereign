"""PP-4 — enterprise POSTPAID reconciliation sweep (report-only invoiced-vs-paid vs real consumption).

``ops_sweeps.sweep_postpaid_reconciliation`` is a PURE READ: per enabled postpaid org it folds the owner-signed
postpaid scalars and flags any discrepancy an operator should chase — uninvoiced consumption, an outstanding
balance, an overdue invoice. Load-bearing invariants (a false-green would send an operator to bill phantom
revenue, or hide a real shortfall, or leak across tenants):
  * billable == net_settled_consumed (accrued MINUS in-flight reserves), NEVER raw accrued, so an in-flight
    (reserved-but-unsettled) launch is never mis-reported as un-billed consumption;
  * a payment moves OUTSTANDING but never the billing basis (billable / invoiced);
  * the sweep writes NOTHING (no mint, no settle); rows are strictly org-scoped; the read is idempotent.
The RETIRE half of PP-4 (full-refunding genuinely-abandoned reserves) is the EXISTING owner-keyed
``reservations --apply`` path — reconcile is report-only and refuses its own --apply.
"""
from __future__ import annotations

import itertools
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sigil import ops_sweeps
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.postpaid import (
    RESERVE_ENTRY_PREFIX,
    PostpaidArrearsLedger,
    PostpaidRegistry,
    invoice_postpaid_arrears,
    pay_postpaid_invoice,
)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
_iss = itertools.count(1)


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    """Isolate the spine / home to fresh temp dirs so the CLI subprocess sees a clean (segment-layout)
    store and clears the fail-closed migration startup gate (mirrors test_ops_sweeps._iso)."""
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())


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


def _row(reg, arr, inv, org, *, now):
    out = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=now)
    return next((r for r in out["items"] if r["org_id"] == org), None)


# --------------------------------------------------------------- the three discrepancy classes


def test_reconcile_flags_uninvoiced_consumption_and_clears_when_billed_and_paid():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    arr.accrue("acme", 100, entry_id="r:acme:1", issued_at=_issue())     # finalised draw, NOT invoiced
    row = _row(reg, arr, inv, "acme", now=1000.0)
    assert row["billable"] == 100 and row["invoiced"] == 0
    assert row["billable_uninvoiced"] == 100
    assert "uninvoiced_consumption" in row["status"]
    # NEGATIVE CONTROL: invoice it AND pay it -> fully reconciled
    invoice_postpaid_arrears(reg, arr, inv, "acme", period_end=1000.0, issued_at=_issue())
    pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue())
    row2 = _row(reg, arr, inv, "acme", now=1000.0)
    assert row2["billable_uninvoiced"] == 0 and row2["status"] == ["reconciled"]


def test_reconcile_holds_in_flight_reserves_out_of_billable():
    """MUTATION TARGET: the classifier reads net_settled_consumed, NOT raw accrued. A reserved-but-unsettled
    launch has accrued==80 but billable==0 — it must NOT read as un-billed consumption (which would send an
    operator to bill a launch that may still cancel). Swap net_settled_consumed->accrued and this test reds."""
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    # an in-flight launch == a reserve DEBIT with no matching settle credit (the gate's reserve-postpaid: scheme)
    arr.accrue("acme", 80, entry_id=f"{RESERVE_ENTRY_PREFIX}cust_x:n1", issued_at=_issue())
    row = _row(reg, arr, inv, "acme", now=1000.0)
    assert row["drawn"] == 80 and row["in_flight"] == 80      # counted against the credit line
    assert row["billable"] == 0 and row["billable_uninvoiced"] == 0
    assert "uninvoiced_consumption" not in row["status"]
    assert row["status"] == ["reconciled"]


def test_reconcile_flags_outstanding_then_overdue_then_clears_on_payment():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 0, issued_at=_issue())     # net_terms 0 -> due AT period_end
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)     # billed, unpaid
    within = _row(reg, arr, inv, "acme", now=999.0)
    assert "outstanding" in within["status"] and "overdue" not in within["status"]
    past = _row(reg, arr, inv, "acme", now=1001.0)
    assert "outstanding" in past["status"] and "overdue" in past["status"]
    pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue())
    cleared = _row(reg, arr, inv, "acme", now=1001.0)
    assert cleared["outstanding"] == 0 and cleared["overdue"] == 0 and cleared["status"] == ["reconciled"]


def test_reconcile_payment_does_not_move_the_billing_basis():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    before = _row(reg, arr, inv, "acme", now=1000.0)
    pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue())
    after = _row(reg, arr, inv, "acme", now=1000.0)
    assert after["billable"] == before["billable"] and after["invoiced"] == before["invoiced"]   # basis fixed
    assert after["paid"] == 100 and after["outstanding"] == 0                                     # only these move


# --------------------------------------------------------------- report-only / scope / idempotence


def test_reconcile_is_report_only_appends_nothing():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    n_before = len(list(s.iter_records()))
    out = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)
    assert out["applied"] is False
    assert len(list(s.iter_records())) == n_before           # pure read — appended nothing


def test_reconcile_covers_accounts_drops_only_closed_zero_lines_and_honours_the_orgs_filter():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    reg.set_account("globex", 1000, 30, issued_at=_issue())
    reg.set_account("initech", 1000, 30, issued_at=_issue())   # will be disabled with ZERO balance
    arr.accrue("acme", 10, entry_id="r:acme:1", issued_at=_issue())
    arr.accrue("globex", 20, entry_id="r:globex:1", issued_at=_issue())
    both = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)
    assert {r["org_id"] for r in both["items"]} == {"acme", "globex", "initech"}
    # a DISABLED line that still OWES stays visible (its debt is real); a disabled ZERO-balance line drops
    reg.disable("globex", issued_at=_issue())                  # globex still has 20 uninvoiced consumption
    reg.disable("initech", issued_at=_issue())                 # initech never drew anything -> fully closed
    after = {r["org_id"]: r for r in
             ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)["items"]}
    assert set(after) == {"acme", "globex"}                    # initech (closed, zero) dropped; globex KEPT
    assert after["globex"]["enabled"] is False
    assert "closed_with_balance" in after["globex"]["status"]
    assert "uninvoiced_consumption" in after["globex"]["status"]
    assert after["acme"]["enabled"] is True
    # orgs filter still scopes
    filtered = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0, orgs=["acme"])
    assert {r["org_id"] for r in filtered["items"]} == {"acme"}


def test_reconcile_surfaces_a_disabled_line_that_still_owes():
    """RED-PEN MED (w3xmqrepj): `postpaid disable` closes a delinquent account but does NOT erase its
    arrears — it writes only the account-mode record, never the arrears/invoice ledgers. The audit sweep
    MUST still surface a closed line that owes (outstanding/overdue), else the highest-risk receivable
    goes invisible. MUTATION TARGET: restore a blanket `if not enabled: continue` skip -> this test reds."""
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("globex", 1000, 0, issued_at=_issue())     # net_terms 0 -> due at period_end
    _bill(reg, arr, inv, "globex", 100, period_end=1000.0)     # billed, unpaid
    reg.disable("globex", issued_at=_issue())                  # operator closes the delinquent account
    row = _row(reg, arr, inv, "globex", now=1001.0)            # past due
    assert row is not None                                     # NOT hidden by the close
    assert row["enabled"] is False
    assert row["outstanding"] == 100 and row["overdue"] == 100
    assert "outstanding" in row["status"] and "overdue" in row["status"]
    assert "closed_with_balance" in row["status"]


def test_reconcile_rows_are_strictly_org_scoped():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 0, issued_at=_issue())
    reg.set_account("globex", 1000, 0, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    pay_postpaid_invoice(inv, "acme", _postpaid_inv_id(inv, "acme"), issued_at=_issue())    # acme fully paid
    arr.accrue("globex", 20, entry_id="r:globex:1", issued_at=_issue())                     # globex: uninvoiced
    rows = {r["org_id"]: r for r in ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)["items"]}
    assert rows["acme"]["billable"] == 100 and rows["acme"]["paid"] == 100 and rows["acme"]["outstanding"] == 0
    assert rows["acme"]["status"] == ["reconciled"]
    assert rows["globex"]["billable"] == 20 and rows["globex"]["invoiced"] == 0 and rows["globex"]["paid"] == 0
    assert "uninvoiced_consumption" in rows["globex"]["status"]       # globex's state never bleeds into acme


def test_reconcile_read_is_idempotent():
    s = _store()
    reg, arr, inv = _reg(s), _arr(s), _inv(s)
    reg.set_account("acme", 1000, 30, issued_at=_issue())
    _bill(reg, arr, inv, "acme", 100, period_end=1000.0)
    a = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)
    b = ops_sweeps.sweep_postpaid_reconciliation(reg, arr, inv, now=1000.0)
    assert a == b                                            # pure fold of first-mint-wins invoices + clamped arrears


# --------------------------------------------------------------- CLI: reconcile is report-only


def _cli(*args, env_extra=None):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run([sys.executable, "-m", "sigil.cli", *args], capture_output=True, text=True, env=env,
                          cwd=str(Path(__file__).resolve().parents[1]))


def test_cli_reconcile_refuses_apply_and_points_to_reservations():
    p = _cli("ops-sweep", "reconcile", "--apply")
    assert p.returncode == 2
    assert "report-only" in p.stderr and "reservations --apply" in p.stderr


def test_cli_reconcile_without_owner_identity_fails_closed():
    """RED-PEN LOW (w3xmqrepj): on a box with no owner identity the reconcile branch must refuse (like
    `reservations`), not print an empty all-clear over a spine it cannot verify. The _iso fixture gives a
    fresh, keyless SIGIL_HOME."""
    p = _cli("ops-sweep", "reconcile")
    assert p.returncode == 2
    assert "no owner identity" in p.stderr
