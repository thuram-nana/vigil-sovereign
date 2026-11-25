"""AEGIS plan SALE — sell AEGIS monitoring plans through customer checkout, end to end.

The merged Monitoring slice priced + minted the AEGIS plans on their OWN owner-signed line
(``governor.monitoring_subscription``) but kept the SALE off: checkout excluded ``monitoring_price_ids()`` and
the billing drain did not wire the monitoring line. THIS is the sale slice. Behind
``VIGIL_CUSTOMER_MONITORING_ENABLED`` (default OFF, byte-identical when off):

  * an AEGIS plan is OFFERED (``customer_billing_offers``) and CHECKOUTABLE (``billing_checkout`` posts the
    recurring ``payment_plan`` at the owner-catalog amount) on the monitoring flag, INDEPENDENT of the
    credit-plan flag — AEGIS plans are monthly, billed on their own line, never credits;
  * the billing drain (``cli._billing_signer``) MINTS the monitoring subscription (host slots + respond) from a
    verified event, on ``governor.monitoring_subscription`` ONLY — never the credit-plan subscription, never the
    wallet; a cancel / payment_failed routes to the same line;
  * the SECOND-PLAN guard is split PER KIND — a live/pending AEGIS plan blocks a second AEGIS plan but NOT a
    credit plan, and vice-versa (one plan per kind);
  * ``customer_billing_offers`` emits ``has_monitoring_plan`` / ``monitoring_checkout_pending`` (the SPA's
    ``offerShown`` consumes them), ONLY while the flag is on (off -> byte-identical response);
  * over the REAL edge -> cockpit hop the offers list the AEGIS plans and a checkout opens one.

Fake payment providers only (no network, no real card): the Flutterwave ``_real_provider`` (outbound poster
faked) for the checkout edge, and the ``MockBillingProvider`` for the inbound drain.
"""
from __future__ import annotations

import json

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_checkout import _LINK, _iso, _on, _provisioner, _real_provider  # noqa: F401  (_iso autouse)
from test_customer_checkout_guards import _CHECKOUT, _signup

from sigil.governor import catalog
from sigil.governor.billing import _to_major

_AEGIS = "vigil_aegis_observe_1h_monthly"           # 1 host, observe
_AEGIS2 = "vigil_aegis_respond_5h_monthly"          # 5 hosts, respond (slots + respond)
_CREDIT = "vigil_pro_monthly"


def _rig(monkeypatch, *, monitoring=True, plans=True):
    """A provisioner with the fake Flutterwave checkout poster; the credit-plan flag and the monitoring flag set
    as asked (base checkout always on). ``ensure_owner_keypair`` so the per-kind subscription reads resolve."""
    from sigil.governor.identity import ensure_owner_keypair
    _on(monkeypatch)
    if plans:
        monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    if monitoring:
        monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    ensure_owner_keypair()
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    return p, admin, org, posted


def _live_aegis(p, org, plan_id="aegis_observe_1h", *, pe=1e12):
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    MonitoringSubscriptionRegistry(p.store).subscribe(org, plan_id, 0, period_start=100.0, period_end=pe,
                                                      issued_at=100.0)


def _live_credit(p, org, plan_id="pro", *, pe=1e12):
    from sigil.governor.subscription import SubscriptionRegistry
    SubscriptionRegistry(p.store).subscribe(org, plan_id, 6000, period_start=100.0, period_end=pe, issued_at=100.0)


# ============================================================================================================
# 1. offered + checkoutable on the monitoring flag (independent of the credit-plan flag)
# ============================================================================================================
def test_an_aegis_plan_is_offered_and_checkoutable(monkeypatch):
    p, admin, org, posted = _rig(monkeypatch)
    d = p.customer_billing_offers(admin, org, now=5000.0)
    ids = {o["price_id"] for o in d["offers"]}
    assert catalog.monitoring_price_ids() <= ids                     # every AEGIS plan is offered
    r = p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    amount_minor, currency = catalog.expected_amounts()[_AEGIS]
    assert r["checkout_url"] == _LINK and r["price_id"] == _AEGIS
    assert posted[-1]["payment_plan"] == _AEGIS                       # a RECURRING subscription (monthly)
    assert posted[-1]["amount"] == _to_major(amount_minor, currency)  # the OWNER-catalog amount, never a figure
    assert posted[-1]["currency"] == currency and posted[-1]["meta"]["org_id"] == org


def test_an_aegis_plan_sells_without_the_credit_plan_flag(monkeypatch):
    """AEGIS sale rides its OWN flag: the credit-plan flag being OFF does not block it (nor does it sell a credit
    plan)."""
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch, plans=False)           # monitoring ON, credit-plan flag OFF
    r = p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    assert r["price_id"] == _AEGIS and posted[-1]["payment_plan"] == _AEGIS
    with pytest.raises(ProvisionDenied, match="checkout refused"):    # a credit plan still needs its own flag
        p.billing_checkout(admin, org, _CREDIT, now=5000.0)


def test_an_aegis_plan_is_refused_while_the_monitoring_flag_is_off(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch, monitoring=False)       # credit-plan ON, monitoring OFF
    assert not (catalog.monitoring_price_ids()
                & {o["price_id"] for o in p.customer_billing_offers(admin, org)["offers"]})
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    assert posted == []                                              # never reached the processor


# ============================================================================================================
# 2. the drain mints the monitoring line (slots + respond) from a verified event — never the credit line/wallet
# ============================================================================================================
def _drain_signer(tmp_path, *, alarm=False):
    from sigil import cli
    from sigil.governor.billing import MockBillingProvider
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    ensure_owner_keypair()
    s = SpineStore(str(tmp_path / "spine.jsonl"))
    s.migrate()
    mock = MockBillingProvider("sek")
    return cli._billing_signer(mock, s, alarm=alarm), mock, s


def _mock_event(mock, eid, kind, created, price, org="org_sale"):
    body = json.dumps({"event_id": eid, "kind": kind, "org_id": org, "created": created,
                       "price_id": price}).encode()
    return body, mock.sign(body)


def test_the_drain_signer_mints_the_monitoring_line_never_the_wallet_or_credit_plan(tmp_path):
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    from sigil.governor.wallet import WalletRegistry
    signer, mock, s = _drain_signer(tmp_path)
    seq = signer.ingest(*_mock_event(mock, "m1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, _AEGIS2), now=100.0)
    assert seq is not None
    msub = MonitoringSubscriptionRegistry(s).subscription("org_sale")
    assert msub is not None and msub.plan_id == "aegis_respond_5h" and msub.status == "active"
    plan = catalog.monitoring_plan("aegis_respond_5h")               # slots + respond, as the catalog defines them
    assert plan is not None and plan.host_slots == 5 and plan.respond is True
    assert SubscriptionRegistry(s).subscription("org_sale") is None  # the credit-plan line is UNTOUCHED
    assert WalletRegistry(s).available("org_sale") == 0              # the wallet is NEVER credited


def test_the_drain_signer_routes_a_monitoring_cancel_to_the_monitoring_line_only(tmp_path):
    from sigil.governor.billing import EVENT_SUBSCRIPTION_ACTIVE, EVENT_SUBSCRIPTION_CANCELED, EVENT_PAYMENT_FAILED
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.governor.subscription import SubscriptionRegistry
    signer, mock, s = _drain_signer(tmp_path)
    # a credit plan AND an AEGIS plan for the same org
    assert signer.ingest(*_mock_event(mock, "c1", EVENT_SUBSCRIPTION_ACTIVE, 100.0, _CREDIT), now=100.0)
    assert signer.ingest(*_mock_event(mock, "a1", EVENT_SUBSCRIPTION_ACTIVE, 150.0, _AEGIS), now=150.0)
    # cancel the AEGIS plan: only the monitoring line moves
    signer.ingest(*_mock_event(mock, "a2", EVENT_SUBSCRIPTION_CANCELED, 200.0, _AEGIS), now=200.0)
    assert SubscriptionRegistry(s).subscription("org_sale").status == "active"
    assert MonitoringSubscriptionRegistry(s).subscription("org_sale").status == "canceled"
    # a failed AEGIS renewal latches the monitoring line past_due, never the credit plan
    signer.ingest(*_mock_event(mock, "a3", EVENT_PAYMENT_FAILED, 1e15, _AEGIS), now=1e15)
    assert SubscriptionRegistry(s).subscription("org_sale").status == "active"
    assert MonitoringSubscriptionRegistry(s).subscription("org_sale").status == "past_due"


def test_the_shared_signer_builder_wires_the_monitoring_line():
    import inspect

    from sigil import cli
    src = inspect.getsource(cli._billing_signer)
    assert "monitoring_subscriptions=MonitoringSubscriptionRegistry(store)" in src


# ============================================================================================================
# 3. the second-plan guard is split PER KIND (live subscription) — both directions
# ============================================================================================================
def test_a_live_aegis_plan_blocks_a_second_aegis_but_not_a_credit_plan(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    _live_aegis(p, org)
    with pytest.raises(ProvisionDenied, match="already has an AEGIS monitoring plan"):
        p.billing_checkout(admin, org, _AEGIS, now=5000.0)           # a second AEGIS plan is refused
    assert posted == []
    r = p.billing_checkout(admin, org, _CREDIT, now=5000.0)          # a credit plan is NOT blocked by the AEGIS one
    assert r["price_id"] == _CREDIT and posted[-1]["payment_plan"] == _CREDIT


def test_a_live_credit_plan_blocks_a_second_credit_but_not_an_aegis_plan(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    _live_credit(p, org)
    with pytest.raises(ProvisionDenied, match="already has a plan"):
        p.billing_checkout(admin, org, _CREDIT, now=5000.0)          # a second credit plan is refused
    assert posted == []
    r = p.billing_checkout(admin, org, _AEGIS, now=5000.0)           # an AEGIS plan is NOT blocked by the credit one
    assert r["price_id"] == _AEGIS and posted[-1]["payment_plan"] == _AEGIS


# ============================================================================================================
# 3b. the pending-checkout record is split PER KIND — both directions
# ============================================================================================================
def test_a_pending_aegis_checkout_blocks_a_second_aegis_but_not_a_credit(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    p.billing_checkout(admin, org, _AEGIS, now=5000.0)               # first AEGIS: a pending record is claimed
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _AEGIS, now=5001.0)           # a second AEGIS is refused while it is pending
    r = p.billing_checkout(admin, org, _CREDIT, now=5001.0)          # a credit checkout is NOT blocked
    assert r["price_id"] == _CREDIT
    assert [x.get("payment_plan") for x in posted] == [_AEGIS, _CREDIT]


def test_a_pending_credit_checkout_blocks_a_second_credit_but_not_an_aegis(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    p.billing_checkout(admin, org, _CREDIT, now=5000.0)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, _CREDIT, now=5001.0)
    r = p.billing_checkout(admin, org, _AEGIS, now=5001.0)           # the AEGIS checkout is NOT blocked
    assert r["price_id"] == _AEGIS
    assert [x.get("payment_plan") for x in posted] == [_CREDIT, _AEGIS]


@pytest.mark.parametrize("status", ["past_due", "canceled"])
def test_a_past_due_aegis_plan_still_blocks_a_second_one_a_canceled_one_does_not(monkeypatch, status):
    """Dunning must not open a double-billing window: a past_due AEGIS plan (period not over) still refuses a second
    AEGIS plan, exactly like the credit twin; a canceled one frees the kind."""
    from sigil.governor.monitoring_subscription import MonitoringSubscriptionRegistry
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    _live_aegis(p, org)
    reg = MonitoringSubscriptionRegistry(p.store)
    if status == "past_due":
        reg.mark_past_due(org, issued_at=1e9)                        # fresher than the activation: latched
        with pytest.raises(ProvisionDenied, match="already has an AEGIS monitoring plan"):
            p.billing_checkout(admin, org, _AEGIS, now=5000.0)
        assert posted == []
    else:
        reg.cancel(org)
        assert p.billing_checkout(admin, org, _AEGIS, now=5000.0)["price_id"] == _AEGIS


def test_the_credit_pending_marker_is_byte_identical_and_aegis_has_its_own(monkeypatch):
    import hashlib
    p, _admin, org, _posted = _rig(monkeypatch)
    led = p.pending_checkouts
    assert led._marker(org) == led.dir / hashlib.sha256(f"org:{org}".encode()).hexdigest()   # the pre-AEGIS key
    assert led._marker(org, "") == led._marker(org)
    assert led._marker(org, "monitoring") == led.dir / hashlib.sha256(f"monitoring:org:{org}".encode()).hexdigest()
    assert led._marker(org, "monitoring") != led._marker(org)


# ============================================================================================================
# 3c. the spine-audit backstop (a deleted pending record) is split PER KIND; every refusal frees ITS OWN claim
# ============================================================================================================
def _created_row(p, admin, org, price, tx_ref, expires_at):
    p.store.append(kind="event", source="provision", actor="WARDEN", payload={
        "signal": "provision.audit", "action": "billing_checkout", "requester": admin, "org_id": org,
        "target": price, "outcome": "created", "reason": "", "tx_ref": tx_ref, "expires_at": expires_at})


@pytest.mark.parametrize("row_price,same,other", [(_AEGIS, _AEGIS, _CREDIT), (_CREDIT, _CREDIT, _AEGIS)])
def test_the_spine_backstop_holds_only_its_own_kind(monkeypatch, row_price, same, other):
    """With no pending record, the tamper-evident spine audit of a CREATED plan checkout still refuses a second plan —
    of the SAME kind only: a live AEGIS row never gates a credit checkout, and vice-versa. The refused attempt frees
    its own claim."""
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    _created_row(p, admin, org, row_price, f"vigil:{org}:x", 9e9)
    with pytest.raises(ProvisionDenied, match="already in progress"):
        p.billing_checkout(admin, org, same, now=5000.0)            # held by the spine row of its kind
    assert not p.pending_checkouts._marker(org, "monitoring" if same == _AEGIS else "").exists()
    assert posted == []
    r = p.billing_checkout(admin, org, other, now=5000.0)          # the other kind is not gated by that row
    assert r["price_id"] == other and [x.get("payment_plan") for x in posted] == [other]


def test_the_spine_backstop_matches_a_long_aegis_price_at_the_audited_cap(monkeypatch):
    """The audit row caps ``target`` at 64 chars; the kind filter compares at the same cap, so a long AEGIS price id
    is still read as AEGIS (never mis-filed as a credit row)."""
    from sigil.governor import catalog as cat
    p, admin, org, _posted = _rig(monkeypatch)
    long_id = "vigil_aegis_" + "x" * 70
    monkeypatch.setattr(cat, "monitoring_price_ids", lambda: frozenset({long_id}))
    p._audit("billing_checkout", requester=admin, org_id=org, target=long_id, outcome="created",
             tx_ref=f"vigil:{org}:long", expires_at=9e9)             # the REAL audit writer (it truncates target)
    assert p._spine_plan_checkouts(org, 5000.0, monitoring=True) == (f"vigil:{org}:long", [])
    assert p._spine_plan_checkouts(org, 5000.0, monitoring=False) == ("", [])


def test_an_undrained_earlier_aegis_payment_refuses_a_second_aegis_and_frees_the_claim(monkeypatch):
    from test_customer_checkout_guards import _spool_webhook
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    paid = f"vigil:{org}:paid"
    _created_row(p, admin, org, _AEGIS, paid, 10.0)                  # an EARLIER AEGIS checkout, window ended ...
    _spool_webhook(p.pending_checkouts.billing_spools[0], paid, 9001)   # ... whose payment waits undrained
    with pytest.raises(ProvisionDenied, match="has not been confirmed yet"):
        p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    assert not p.pending_checkouts._marker(org, "monitoring").exists()   # the refused attempt left no claim
    assert p.billing_checkout(admin, org, _CREDIT, now=5000.0)["price_id"] == _CREDIT   # the credit kind is free
    assert [x.get("payment_plan") for x in posted] == [_CREDIT]


def test_an_aegis_plan_that_drains_mid_checkout_refuses_and_frees_the_claim(monkeypatch):
    """The AEGIS plan may DRAIN between the pre-claim check and the claim: the re-check under the claim (same kind)
    refuses with the AEGIS reason and frees the AEGIS claim."""
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)
    answers = iter([False, True])                                     # pre-check: none yet; re-check: drained
    p._org_has_live_monitoring_plan = lambda _o, _t: next(answers)
    with pytest.raises(ProvisionDenied, match="already has an AEGIS monitoring plan"):
        p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    assert posted == [] and not p.pending_checkouts._marker(org, "monitoring").exists()


def test_a_processor_refusal_frees_the_aegis_claim_for_a_retry(monkeypatch):
    from sigil.governor.billing import FlutterwaveBillingProvider
    from sigil.ui.provision import ProvisionDenied
    p, admin, org, posted = _rig(monkeypatch)

    def refusing(_payload):
        raise ConnectionError("processor down")
    p._checkout_provider = lambda: FlutterwaveBillingProvider("verif-hash-test", lambda *a, **k: None,
                                                              checkout_creator=refusing)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    assert not p.pending_checkouts._marker(org, "monitoring").exists()   # the customer never got a link: freed
    p._checkout_provider = lambda: _real_provider(posted)
    assert p.billing_checkout(admin, org, _AEGIS, now=5001.0)["price_id"] == _AEGIS   # the retry is not "in progress"


def test_checkout_never_offers_an_aegis_price_with_the_flag_off_even_if_the_catalog_surfaced_it(monkeypatch):
    """Defense in depth: the AEGIS sale is gated in checkout's OWN offered set, not only by the catalog's
    flag-filtered view — a catalog regression that surfaced an AEGIS price with the flag OFF still sells nothing."""
    from sigil.governor import catalog as cat
    p, _admin, _org, _posted = _rig(monkeypatch, monitoring=False)
    full = {e.price_id: (e.amount_minor, e.currency) for e in cat._CATALOG}
    monkeypatch.setattr(cat, "expected_amounts", lambda: dict(full))
    offered, _ents = p._checkout_offered()
    assert not offered.keys() & cat.monitoring_price_ids()


# ============================================================================================================
# 4. has_monitoring_plan / monitoring_checkout_pending emitted correctly (and only on the flag)
# ============================================================================================================
def test_offers_report_a_live_aegis_plan(monkeypatch):
    p, admin, org, _posted = _rig(monkeypatch)
    assert p.customer_billing_offers(admin, org, now=5000.0)["has_monitoring_plan"] is False
    _live_aegis(p, org, pe=10_000.0)
    assert p.customer_billing_offers(admin, org, now=5000.0)["has_monitoring_plan"] is True
    # PL01 CHK-1b: live through the 72h renewal/retry grace past period_end, lapsed only after it elapses.
    assert p.customer_billing_offers(admin, org, now=10_001.0)["has_monitoring_plan"] is True            # within grace
    assert p.customer_billing_offers(admin, org, now=10_000.0 + 72 * 3600 + 1.0)["has_monitoring_plan"] is False  # lapsed
    assert p.customer_billing_offers(admin, org, now=5000.0)["has_active_plan"] is False          # credit independent


def test_offers_report_a_pending_aegis_checkout(monkeypatch):
    p, admin, org, _posted = _rig(monkeypatch)
    p.billing_checkout(admin, org, _AEGIS, now=5000.0)
    d = p.customer_billing_offers(admin, org, now=5001.0)
    assert d["monitoring_checkout_pending"] is True
    assert d["plan_checkout_pending"] is False                        # the credit line's pending is independent


def test_an_unwired_pending_ledger_reads_as_an_aegis_checkout_in_progress(monkeypatch):
    p, admin, org, _posted = _rig(monkeypatch)
    p.pending_checkouts = None
    assert p.customer_billing_offers(admin, org, now=5000.0)["monitoring_checkout_pending"] is True   # fail-closed


# ============================================================================================================
# 5. flag OFF => byte-identical offers response (no monitoring offers, no monitoring keys)
# ============================================================================================================
def test_monitoring_off_offers_is_byte_identical(monkeypatch):
    from sigil.governor.identity import ensure_owner_keypair
    ensure_owner_keypair()
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")    # credit plans on; monitoring OFF
    p, admin, _t, org, _o, _w = _provisioner()
    off = p.customer_billing_offers(admin, org, now=5000.0)
    assert set(off) == {"offers", "has_active_plan", "plans_enabled", "plan_checkout_pending"}
    assert not (catalog.monitoring_price_ids() & {o["price_id"] for o in off["offers"]})
    # turning the flag ON adds EXACTLY the AEGIS offers + the two keys; everything else is byte-identical
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    on = p.customer_billing_offers(admin, org, now=5000.0)
    assert set(on) - set(off) == {"has_monitoring_plan", "monitoring_checkout_pending"}
    assert ({o["price_id"] for o in on["offers"]} - {o["price_id"] for o in off["offers"]}
            == catalog.monitoring_price_ids())
    non_mon = [o for o in on["offers"] if o["price_id"] not in catalog.monitoring_price_ids()]
    assert json.dumps(non_mon) == json.dumps(off["offers"])           # the non-AEGIS offers are unchanged
    assert (on["has_active_plan"], on["plans_enabled"], on["plan_checkout_pending"]) == \
           (off["has_active_plan"], off["plans_enabled"], off["plan_checkout_pending"])


# ============================================================================================================
# 6. the real edge -> cockpit hop: offers list the AEGIS plans, a checkout opens one
# ============================================================================================================
def test_aegis_offers_and_checkout_over_the_real_hop(tmp_path, monkeypatch):
    from sigil.ui import provision
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    posted: list = []
    monkeypatch.setattr(provision.Provisioner, "_checkout_provider", lambda self: _real_provider(posted))
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _signup(ep, "aegis@acme.com")
        c, d = _get(op, ep, "/api/customer/billing/offers")
        assert c == 200, (c, d)
        aegis = sorted(catalog.monitoring_price_ids())
        assert set(aegis) <= {o["price_id"] for o in d["offers"]}
        assert d["has_monitoring_plan"] is False and d["monitoring_checkout_pending"] is False
        c2, r2 = _post(op, ep, _CHECKOUT, {"price_id": aegis[0]})     # buy an AEGIS plan through the edge
        assert c2 == 200 and r2["price_id"] == aegis[0], (c2, r2)
        assert posted[-1]["payment_plan"] == aegis[0]                 # ONE recurring AEGIS subscription posted
        _c, d2 = _get(op, ep, "/api/customer/billing/offers")         # offers now report the pending AEGIS checkout
        assert d2["monitoring_checkout_pending"] is True and d2["plan_checkout_pending"] is False
    finally:
        sov.shutdown(); edge.shutdown()
