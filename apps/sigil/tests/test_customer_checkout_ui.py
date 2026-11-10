"""Front B CHK-2 — the customer app's BUY surface: the ``billing_offers`` read + the SPA's buy / return flow.

What these pin:
  * the offers read is gated EXACTLY like checkout (checkout flag default-OFF -> absent; ``admit_customer``
    ``manage_billing`` for the SESSION org) and lists EXACTLY the set ``billing_checkout`` accepts — so the UI can
    never show a buy button that checkout refuses, nor hide one it would accept (one shared helper);
  * prices come from the OWNER catalog (the page sends no amount), monitoring plans are never offered, plans
    only with the plan flag, and an org with a live plan is told so (checkout refuses a second plan);
  * over the REAL edge -> cockpit HTTP hop: a billing admin gets the list, a testing-only member is refused,
    and the route is a 404 while checkout is off;
  * the SPA only ever navigates to an https checkout link, sends only a ``price_id``, and its return page never
    claims or grants credit (credit comes only from the verified webhook drain).
"""
from __future__ import annotations

import inspect
import shutil
import subprocess
from pathlib import Path

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_checkout import _iso, _on, _provisioner, _real_provider  # noqa: F401  (_iso is autouse)

_APP_JS = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app" / "app.js"


def _plans_on(monkeypatch):
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED", "1")


# --- the provisioner read ---------------------------------------------------------------------------------------

def test_offers_are_absent_while_checkout_is_off():
    from sigil.ui.provision import ProvisionDenied
    p, admin, _t, org, _o, _w = _provisioner()
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.customer_billing_offers(admin, org)


def test_offers_are_exactly_what_checkout_accepts_at_catalog_prices(monkeypatch):
    from sigil.governor import catalog
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    d = p.customer_billing_offers(admin, org)
    ids = {o["price_id"] for o in d["offers"]}
    assert ids and d["has_active_plan"] is False and d["plans_enabled"] is False
    exp = catalog.expected_amounts()
    for o in d["offers"]:                                         # the OWNER catalog's price, never another figure
        assert (o["amount_minor"], o["currency"]) == exp[o["price_id"]]
        assert o["kind"] == "topup_purchased"                     # plans only with the extra plan flag
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    for pid in sorted(exp):                                       # every listed id is accepted; nothing else is
        if pid in ids:
            p.billing_checkout(admin, org, pid)
        else:
            with pytest.raises(ProvisionDenied):
                p.billing_checkout(admin, org, pid)
    assert {x["meta"]["price_id"] for x in posted} == ids


def test_plans_are_listed_only_with_the_plan_flag_and_monitoring_never(monkeypatch):
    from sigil.governor import catalog
    _plans_on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")       # monitoring ON for sale elsewhere...
    p, admin, _t, org, _o, _w = _provisioner()
    d = p.customer_billing_offers(admin, org)
    kinds = {o["kind"] for o in d["offers"]}
    assert d["plans_enabled"] is True and kinds == {"topup_purchased", "subscription_active"}
    assert not {o["price_id"] for o in d["offers"]} & catalog.monitoring_price_ids()   # ...but never sold here
    assert {o["price_id"] for o in d["offers"]} == set(p._checkout_offered()[0])


@pytest.mark.parametrize("who", ["tester", "other_tenant", "nonexistent"])
def test_offers_are_refused_to_anyone_who_cannot_spend(monkeypatch, who):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, tester, org, other, _w = _provisioner()
    requester, org_id = {"tester": (tester, org), "other_tenant": (admin, "org_nobody"),
                         "nonexistent": ("cust_ghost0000000000000000", org)}[who]
    with pytest.raises(ProvisionDenied):
        p.customer_billing_offers(requester, org_id)


def test_an_org_with_a_live_plan_is_told_so(monkeypatch):
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.subscription import SubscriptionRegistry
    _plans_on(monkeypatch)
    ensure_owner_keypair()
    p, admin, _t, org, _o, _w = _provisioner()
    SubscriptionRegistry(p.store).subscribe(org, "research", 2000, period_start=100.0, period_end=10_000.0,
                                            issued_at=100.0)
    assert p.customer_billing_offers(admin, org, now=5000.0)["has_active_plan"] is True
    assert p.customer_billing_offers(admin, org, now=10_001.0)["has_active_plan"] is False   # lapsed


def test_the_offers_hop_and_route_are_flag_gated_and_session_scoped():
    from sigil.ui import custui, server
    src = inspect.getsource(server)
    i = src.index('if action == "billing_offers":')
    assert "customer_checkout_enabled()" in src[i:i + 300] and "return None" in src[i:i + 300]
    esrc = inspect.getsource(custui)
    assert 'if path == "/api/customer/billing/offers" and _checkout_on():' in esrc
    assert '_customer_read_relay("billing_offers")' in esrc         # org from the SERVER-side session, never query


# --- over the REAL edge -> cockpit hop ------------------------------------------------------------------------------

def test_offers_over_the_edge(tmp_path, monkeypatch):
    from sigil.governor import catalog
    _on(monkeypatch)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        c, d = _get(op, ep, "/api/customer/billing/offers")         # the signup org_admin may spend
        assert c == 200, (c, d)
        assert {o["price_id"] for o in d["offers"]} == {pid for pid, e in catalog.entitlements().items()
                                                         if e.kind == "topup_purchased"
                                                         and pid not in catalog.monitoring_price_ids()}
        assert _get(_opener(), ep, "/api/customer/billing/offers")[0] == 401   # no session -> no price list
    finally:
        sov.shutdown(); edge.shutdown()


def test_offers_route_is_404_while_checkout_is_off(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "b@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "B"})
        assert _get(op, ep, "/api/customer/billing/offers")[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()


# --- the SPA (static + executed) ----------------------------------------------------------------------------------

def _js() -> str:
    return _APP_JS.read_text(encoding="utf-8")


def _fn(src: str, name: str) -> str:
    i = src.index(f"function {name}(")
    j = src.index("\n  }\n", i)
    return src[i:j + 4]


def test_spa_sends_only_a_price_id_and_navigates_only_through_the_https_guard():
    js = _js()
    body = _fn(js, "startCheckout")
    assert 'VUI.postJSON(API + "/billing/checkout", { price_id: o.price_id })' in body   # no amount, no org
    assert "isCheckoutUrl(r.checkout_url)" in body and body.count("location.assign(") == 1
    assert body.index("isCheckoutUrl(r.checkout_url)") < body.index("location.assign(")
    assert "step_up_required" in body                                   # honest step-up message, not a login bounce


def test_return_page_never_claims_or_grants_credit():
    js = _js()
    view = _fn(js, "viewBillingReturn")
    assert '"#/billing/return": function () { return authed() ? viewBillingReturn() : viewLogin(); }' in js
    assert "postJSON" not in view                                       # a read-only page: it changes nothing
    assert 'getJSON(API + "/billing")' in view                         # it only WATCHES the balance
    for claim in ("credits added", "credited", "payment successful", "success!"):
        assert claim not in view.lower()


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_https_guard_executed():
    """Execute the SPA's own isCheckoutUrl under node: only an absolute https link with a host and no credentials."""
    guard = _fn(_js(), "isCheckoutUrl")
    cases = {"https://checkout.flutterwave.com/v3/hosted/pay/x": True, "http://checkout.flutterwave.com/x": False,
             "javascript:alert(1)": False, "https://user:pw@evil.example/": False, "//evil.example/x": False,
             "data:text/html,hi": False, "": False, "https://": False}
    prog = guard + "\nconst c = " + __import__("json").dumps(cases) + ";\n" + \
        "for (const [u, want] of Object.entries(c)) { if (isCheckoutUrl(u) !== want) { console.log('BAD', u); " \
        "process.exit(1); } }\nconsole.log('ok');\n"
    r = subprocess.run(["node", "-e", prog], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0 and r.stdout.strip() == "ok", (r.stdout, r.stderr)
