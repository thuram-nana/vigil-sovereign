"""W5 — the customer notification centre shows the billing HOLD and the LOW-BALANCE notice, each behind its flag.

Both derive from owner-signed states (the reversal ledger's owed total; the wallet balance vs the last top-up) — no
invented threshold decides a notification. With the flags off neither item appears (byte-identical).
"""
from __future__ import annotations

import tempfile

import pytest

from sigil.governor.billing_reversal import BillingReversalLedger, REASON_DISPUTE
from sigil.governor.customers import CustomerRegistry
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.orgs import OrgRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
from sigil.ui.login_ratelimit import LoginRateLimiter
from sigil.ui.provision import Provisioner

NOW = 1000.0


def _store():
    s = tempfile.mktemp(suffix=".jsonl")
    from sigil.spine.store import SpineStore
    st = SpineStore(s)
    st.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    return st


def _prov(store, owner):
    return Provisioner(
        store, customers=CustomerRegistry(store, owner_key=owner), orgs=OrgRegistry(store, owner_key=owner),
        wallet=WalletRegistry(store, owner_key=owner), email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: NOW)


def _member(store, owner, org="acme", user="cust_u", role="org_admin"):
    orgs = OrgRegistry(store, owner_key=owner)
    orgs.create_org(org, org.upper(), owner="owner", issued_at=1.0)
    orgs.grant_membership(org, user, role, issued_at=2.0)


def _ids(resp):
    return {n["id"] for n in resp["notifications"]}


def test_a_hold_shows_a_billing_hold_notice_only_when_reversals_are_on(monkeypatch):
    s = _store()
    owner = ensure_owner_keypair()
    _member(s, owner)
    w = WalletRegistry(s, owner_key=owner)
    w.grant("acme", 1000, "topup", entry_id="cs_1", issued_at=1.0)
    w.debit("acme", 900, entry_id="d1", issued_at=1.5)
    BillingReversalLedger(s, wallet=w, owner_key=owner).reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE,
                                                                  now=2.0, disputed=1000)   # owes 900
    p = _prov(s, owner)
    monkeypatch.delenv("VIGIL_BILLING_REVERSALS", raising=False)
    assert "billing:hold" not in _ids(p.customer_notifications("cust_u", "acme"))   # flag off: absent
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    hit = [n for n in p.customer_notifications("cust_u", "acme")["notifications"] if n["id"] == "billing:hold"]
    assert len(hit) == 1 and hit[0]["severity"] == "high" and "900" in hit[0]["body"]


def test_the_low_balance_notice_appears_once_per_crossing_only_when_the_flag_is_on(monkeypatch):
    s = _store()
    owner = ensure_owner_keypair()
    _member(s, owner)
    w = WalletRegistry(s, owner_key=owner)
    inv = InvoiceRegistry(s, owner_key=owner)
    w.grant("acme", 1000, "topup", entry_id="cs_1", issued_at=NOW - 10)
    inv.record("acme", invoice_id="cs_1", kind="topup", price_id="p", amount_minor=1000, currency="USD",
               credits=1000, issued_at=NOW - 10)
    w.debit("acme", 900, entry_id="d1", issued_at=NOW - 5)          # available 100 < threshold 200
    p = _prov(s, owner)
    monkeypatch.delenv("VIGIL_BILLING_LOW_BALANCE_ALERT", raising=False)
    assert not any(i.startswith("billing:low_balance") for i in _ids(p.customer_notifications("cust_u", "acme")))
    monkeypatch.setenv("VIGIL_BILLING_LOW_BALANCE_ALERT", "1")
    hit = [n for n in p.customer_notifications("cust_u", "acme")["notifications"]
           if n["id"].startswith("billing:low_balance")]
    assert len(hit) == 1 and hit[0]["id"] == "billing:low_balance:cs_1" and "200" in hit[0]["body"]
    body = hit[0]["body"].lower()
    assert "estimat" not in body and "$" not in hit[0]["body"]


def test_a_billing_only_admin_still_sees_the_hold(monkeypatch):
    # the hold/low-balance items live under view_billing; an org_admin (billing, no testing) sees them
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    s = _store()
    owner = ensure_owner_keypair()
    _member(s, owner, role="org_admin")
    w = WalletRegistry(s, owner_key=owner)
    w.grant("acme", 1000, "topup", entry_id="cs_1", issued_at=1.0)
    w.debit("acme", 900, entry_id="d1", issued_at=1.5)
    BillingReversalLedger(s, wallet=w, owner_key=owner).reconcile("acme", "cs_1", cap=1000, reason=REASON_DISPUTE,
                                                                  now=2.0, disputed=1000)
    p = _prov(s, owner)
    assert "billing:hold" in _ids(p.customer_notifications("cust_u", "acme"))


def test_a_non_member_sees_no_billing_notices(monkeypatch):
    monkeypatch.setenv("VIGIL_BILLING_REVERSALS", "1")
    monkeypatch.setenv("VIGIL_BILLING_LOW_BALANCE_ALERT", "1")
    s = _store()
    owner = ensure_owner_keypair()
    _member(s, owner)
    p = _prov(s, owner)
    assert _ids(p.customer_notifications("cust_someone_else", "acme")) == set()
