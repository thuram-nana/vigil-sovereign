"""W5 — ``sigil billing-reversal`` (the owner refund of unused credits + the hold status), default-OFF.

The verb refuses while ``VIGIL_BILLING_REVERSALS`` is off. With it on: ``refund`` removes UNUSED credits of a credited
top-up through the same reversal path (reason ``refund``), refused when it would exceed the spendable balance;
``status`` lists the orgs on a hold.
"""
from __future__ import annotations

import tempfile
from types import SimpleNamespace

import pytest

from sigil import cli
from sigil.governor.billing_reversal import BillingReversalLedger
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS", raising=False)
    # SpineStore()'s default path is bound at import (HANDOFF §0.7) — give this test its own private spine so the
    # CLI (which constructs SpineStore()) and the test's helpers read the same, isolated store.
    path = tempfile.mktemp(suffix=".jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: SpineStore(path) if not a else SpineStore(*a, **k))


def _seed(credits=1000, spent=0):
    owner = ensure_owner_keypair()
    s = cli.SpineStore()
    w = WalletRegistry(s, owner_key=owner)
    inv = InvoiceRegistry(s, owner_key=owner)
    w.grant("acme", credits, "topup", entry_id="cs_1", issued_at=1.0)
    inv.record("acme", invoice_id="cs_1", kind="topup", price_id="p", amount_minor=credits, currency="USD",
               credits=credits, issued_at=1.0)
    if spent:
        w.debit("acme", spent, entry_id="d1", issued_at=1.5)
    return owner, s, w


def _ns(**kw):
    base = dict(reversal_cmd="refund", org="acme", topup="cs_1", credits=None, reason="customer request", sync=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_the_verb_is_refused_while_the_flag_is_off(capsys):
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(credits=100))
    assert e.value.code == 2 and "disabled" in capsys.readouterr().err


def test_an_owner_refund_removes_unused_credits(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000)
    cli.cmd_billing_reversal(_ns(credits=400))
    assert w.available("acme") == 600 and "400 credits removed" in capsys.readouterr().out
    assert not BillingReversalLedger(s, wallet=w).on_hold("acme")


def test_an_owner_refund_over_the_spendable_balance_is_refused(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=700)         # spendable 300
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(credits=400))
    assert e.value.code == 2 and "unused credits only" in capsys.readouterr().err
    assert w.available("acme") == 300                    # nothing moved


def test_a_refund_of_an_unknown_top_up_is_refused(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    _seed(credits=1000)
    with pytest.raises(SystemExit) as e:
        cli.cmd_billing_reversal(_ns(topup="cs_nope", credits=100))
    assert e.value.code == 2 and "not a credited top-up" in capsys.readouterr().err


def test_status_lists_the_orgs_on_a_hold(monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    owner, s, w = _seed(credits=1000, spent=900)
    BillingReversalLedger(s, wallet=w).reconcile("acme", "cs_1", cap=1000, reason="dispute", now=2.0, disputed=1000)
    cli.cmd_billing_reversal(SimpleNamespace(reversal_cmd="status", org=None, topup=None, credits=None,
                                             reason="", sync=True))
    out = capsys.readouterr().out
    assert "acme" in out and "ON HOLD" in out and "900 credits" in out
