"""W5 — the LOW-BALANCE condition and its once-per-crossing email.

The threshold is max(100, 20% of the last top-up); the condition fires once per crossing (key = org + the last top-up's
id) and re-arms after the next top-up. The sweep emails the org's billing administrators once per crossing (an injected
sender; the Null sender sends nothing). It states a credit threshold, never an estimate.

Mutation-verify targets:
  * the threshold floor / the 20% test     -> test_the_threshold_is_the_max_of_100_and_20_percent_of_the_last_topup
  * the key is not the last top-up          -> test_the_alert_re_arms_after_the_next_topup
  * the email is sent more than once        -> test_the_email_is_sent_once_per_crossing
"""
from __future__ import annotations

import tempfile

from sigil.governor.invoices import InvoiceRegistry
from sigil.governor.low_balance import LOW_BALANCE_FLOOR, low_balance, threshold_for
from sigil.governor.metering import CreditMeter, PlanCreditLedger
from sigil.governor.subscription import SubscriptionRegistry
from sigil.governor.wallet import WalletRegistry
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore
from sigil.ui.billing_alerts import LowBalanceAlerts, email_body

OWNER = generate_keypair()
_K = {"owner_key": OWNER, "trusted_pubkey": OWNER.public_key_b64}
NOW = 1000.0


class _Recorder:
    def __init__(self):
        self.sent: list = []

    def send(self, to, subject, body):
        self.sent.append((to, subject, body))
        return True


def _rig():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="x", actor="user", payload={"text": "hi"})
    w = WalletRegistry(s, **_K)
    inv = InvoiceRegistry(s, **_K)
    meter = CreditMeter(w, PlanCreditLedger(s, **_K), SubscriptionRegistry(s, **_K))
    return s, w, inv, meter


def _topup(w, inv, org, credits, eid, *, at=NOW - 10):
    w.grant(org, credits, "topup", entry_id=eid, issued_at=at)
    inv.record(org, invoice_id=eid, kind="topup", price_id="p", amount_minor=credits, currency="USD",
               credits=credits, issued_at=at)


def _lb(org, w, inv, meter):
    return low_balance(org, now=NOW, meter=meter, wallet=w, invoices=inv)


# ---- the threshold ---------------------------------------------------------------------------------------------
def test_the_threshold_is_the_max_of_100_and_20_percent_of_the_last_topup():
    assert threshold_for(10_000) == 2_000       # 20% dominates
    assert threshold_for(400) == LOW_BALANCE_FLOOR     # 20% = 80 < the 100 floor
    assert threshold_for(0) == LOW_BALANCE_FLOOR


def test_low_when_below_twenty_percent_of_the_last_topup():
    s, w, inv, meter = _rig()
    _topup(w, inv, "acme", 10_000, "cs_1")      # threshold 2,000
    w.debit("acme", 8_100, entry_id="d1", issued_at=NOW - 5)    # available 1,900 < 2,000
    lb = _lb("acme", w, inv, meter)
    assert lb is not None and lb.available == 1_900 and lb.threshold == 2_000 and lb.key == "cs_1"


def test_not_low_when_at_or_above_the_threshold():
    s, w, inv, meter = _rig()
    _topup(w, inv, "acme", 10_000, "cs_1")
    w.debit("acme", 8_000, entry_id="d1", issued_at=NOW - 5)    # available 2,000 == threshold
    assert _lb("acme", w, inv, meter) is None


def test_the_floor_of_100_applies_when_twenty_percent_is_small():
    s, w, inv, meter = _rig()
    _topup(w, inv, "acme", 400, "cs_1")         # 20% = 80, but the floor is 100
    w.debit("acme", 305, entry_id="d1", issued_at=NOW - 5)      # available 95 < 100
    lb = _lb("acme", w, inv, meter)
    assert lb is not None and lb.threshold == LOW_BALANCE_FLOOR
    # at 100+ it is NOT low even though 20% of 400 is 80
    s2, w2, inv2, m2 = _rig()
    _topup(w2, inv2, "acme", 400, "cs_1")
    w2.debit("acme", 300, entry_id="d1", issued_at=NOW - 5)     # available 100
    assert _lb("acme", w2, inv2, m2) is None


def test_an_org_that_never_had_a_credit_is_never_low():
    s, w, inv, meter = _rig()
    assert _lb("acme", w, inv, meter) is None    # no grant, no top-up -> nothing to run low on


def test_the_alert_re_arms_after_the_next_topup():
    s, w, inv, meter = _rig()
    _topup(w, inv, "acme", 1_000, "cs_1")        # threshold 200
    w.debit("acme", 900, entry_id="d1", issued_at=NOW - 5)      # available 100 < 200
    lb1 = _lb("acme", w, inv, meter)
    assert lb1.key == "cs_1"
    _topup(w, inv, "acme", 1_000, "cs_2", at=NOW - 2)        # a new top-up: available 1,100 now; and the key would change
    assert _lb("acme", w, inv, meter) is None     # no longer low
    w.debit("acme", 1_000, entry_id="d2", issued_at=NOW - 4)    # available 100 < 200 again
    lb2 = _lb("acme", w, inv, meter)
    assert lb2 is not None and lb2.key == "cs_2"   # a NEW crossing keyed by the NEW top-up (re-armed)


# ---- the email sweep -------------------------------------------------------------------------------------------
def _alerts(s, w, inv, meter, sender, directory):
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    orgs = OrgRegistry(s, **_K)
    custs = CustomerRegistry(s, **_K)
    orgs.create_org("acme", "ACME", owner="u", issued_at=1.0)
    uname, _seq = custs.create("admin@acme.test", issued_at=1.0, password="x" * 12)
    orgs.grant_membership("acme", uname, "org_admin", issued_at=2.0)
    return LowBalanceAlerts(s, sender=sender, directory=directory, wallet=w, meter=meter, invoices=inv,
                            orgs=orgs, customers=custs)


def test_the_email_is_sent_once_per_crossing_and_goes_to_billing_admins(tmp_path):
    s, w, inv, meter = _rig()
    rec = _Recorder()
    al = _alerts(s, w, inv, meter, rec, tmp_path / "alerts")
    _topup(w, inv, "acme", 1_000, "cs_1")
    w.debit("acme", 900, entry_id="d1", issued_at=NOW - 5)      # low
    out1 = al.sweep(NOW)
    assert [o["status"] for o in out1] == ["sent"] and len(rec.sent) == 1
    to, subject, body = rec.sent[0]
    assert to == "admin@acme.test" and body == email_body(200)
    assert "200" in body and "estimat" not in body.lower() and "$" not in body
    out2 = al.sweep(NOW + 1)                      # a second sweep -> already sent, no second email
    assert [o["status"] for o in out2] == ["already_sent"] and len(rec.sent) == 1


def test_the_email_re_arms_after_the_next_topup(tmp_path):
    s, w, inv, meter = _rig()
    rec = _Recorder()
    al = _alerts(s, w, inv, meter, rec, tmp_path / "alerts")
    _topup(w, inv, "acme", 1_000, "cs_1")
    w.debit("acme", 900, entry_id="d1", issued_at=NOW - 5)
    al.sweep(NOW)
    assert len(rec.sent) == 1
    _topup(w, inv, "acme", 1_000, "cs_2", at=NOW - 2)
    w.debit("acme", 1_000, entry_id="d2", issued_at=NOW - 4)    # low again, new key
    out = al.sweep(NOW + 10)
    assert [o["status"] for o in out] == ["sent"] and len(rec.sent) == 2    # a new crossing -> a new email


def test_a_null_sender_marks_the_crossing_unsent_and_retries():
    from sigil.ui.email_channel import NullEmailSender
    import tempfile as _t
    s, w, inv, meter = _rig()
    d = _t.mkdtemp()
    al = _alerts(s, w, inv, meter, NullEmailSender(), d)
    _topup(w, inv, "acme", 1_000, "cs_1")
    w.debit("acme", 900, entry_id="d1", issued_at=NOW - 5)
    out1 = al.sweep(NOW)
    assert out1[0]["status"] == "unsent"         # the Null sender delivered nothing
    out2 = al.sweep(NOW + 1)
    assert out2[0]["status"] == "unsent"         # retried (not latched as sent)
