"""Front B CHK-1 — the CUSTOMER hosted-checkout action (`provision.billing_checkout` + the server hop + the custui
route). The outbound checkout primitive (`FlutterwaveBillingProvider.create_checkout`, Slice F) existed but nothing
reached it; this is the gated edge it explicitly delegates authorization to.

Pinned:
  * DEFAULT-OFF — `VIGIL_CUSTOMER_CHECKOUT_ENABLED` unset ⇒ refused before any admit / provider work (and the hop
    returns None ⇒ the unknown-action 404).
  * ADMIT-FIRST with `manage_billing` — a billing `org_admin` may open a checkout for THEIR org; an `operator`
    (runs tests, no money authority) and a non-member are refused (billing-authz != testing-authz).
  * MONEY DOCTRINE — the customer names ONLY a catalog price id; the amount/currency posted are the OWNER CATALOG's;
    an unknown price is refused; the tenant is bound into tx_ref; NOTHING is credited by checkout.
  * FAIL-CLOSED — processor not provisioned, an invalid return URL, or a provider refusal ⇒ ProvisionDenied.
"""
from __future__ import annotations

import itertools
import tempfile
from pathlib import Path

import pytest

_LINK = "https://checkout.flutterwave.com/v3/hosted/pay/abc123"


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    for k in ("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "VIGIL_CUSTOMER_BILLING_RETURN_URL",
              "VIGIL_BILLING_WEBHOOK_SECRET", "VIGIL_FLW_SECRET_KEY", "VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED",
              "VIGIL_CUSTOMER_MONITORING_ENABLED"):
        monkeypatch.delenv(k, raising=False)


def _provisioner():
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.reuse import generate_keypair
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.pending_checkout import PendingPlanCheckouts
    from sigil.ui.provision import Provisioner
    owner = generate_keypair()
    # a fresh path inside a private (0700, atomically created) dir — never tempfile.mktemp (CodeQL
    # py/insecure-temporary-file: mktemp returns a name another process can claim first).
    s = SpineStore(str(Path(tempfile.mkdtemp()) / "spine.jsonl"))
    custs = CustomerRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    orgs = OrgRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    clock = itertools.count(1)
    wallet = WalletRegistry(s, owner_key=owner, trusted_pubkey=owner.public_key_b64)
    p = Provisioner(
        s, customers=custs, orgs=orgs, wallet=wallet,
        email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
        rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=50, window_s=1e4, base_lock_s=50.0),
        checkout_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=Provisioner._CHECKOUT_MAX,
                                          window_s=Provisioner._CHECKOUT_WINDOW_S,
                                          base_lock_s=Provisioner._CHECKOUT_WINDOW_S),
        pending_checkouts=PendingPlanCheckouts(tempfile.mkdtemp(), owner_key=owner,
                                               trusted_pubkey=owner.public_key_b64,
                                               billing_spools=[tempfile.mkdtemp()]),   # an (empty) webhook spool
        email_sender=NullEmailSender(), trial_credits=100, now_fn=lambda: float(next(clock)))
    admin, tester, org, other = ("cust_admin000000000000001", "cust_tester00000000000001", "org_chk1", "org_other")
    custs.create("admin@acme.com", issued_at=1.0, password="password-xyz", username=admin)
    custs.create("tester@acme.com", issued_at=1.5, password="password-xyz", username=tester)
    orgs.create_org(org, "Acme", owner=admin, issued_at=2.0)
    orgs.create_org(other, "Other", owner=admin, issued_at=2.5)
    orgs.grant_membership(org, admin, "org_admin", issued_at=3.0)
    orgs.grant_membership(org, tester, "operator", issued_at=4.0)
    return p, admin, tester, org, other, wallet


def _real_provider(posted: list):
    """The REAL FlutterwaveBillingProvider with only the outbound HTTPS poster faked (captures the body it would
    POST) — proves the catalog amount + tenant binding end to end, offline."""
    from sigil.governor.billing import FlutterwaveBillingProvider

    def creator(payload):
        posted.append(dict(payload))
        return {"status": "success", "data": {"link": _LINK}}
    return FlutterwaveBillingProvider("verif-hash-test", lambda *a, **k: None, checkout_creator=creator)


def _on(monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")


def test_default_off_refuses_before_any_work(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    p, admin, _t, org, _o, _w = _provisioner()
    p._checkout_provider = lambda: pytest.fail("the provider must not even be built while the flag is off")
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.billing_checkout(admin, org, "vigil_topup_1k")


def test_billing_admin_gets_a_catalog_priced_tenant_bound_checkout(monkeypatch):
    from sigil.governor import catalog
    _on(monkeypatch)
    p, admin, _t, org, _o, wallet = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    before = wallet.available(org)
    r = p.billing_checkout(admin, org, "vigil_topup_1k")
    amount_minor, currency = catalog.expected_amounts()["vigil_topup_1k"]
    assert r["checkout_url"] == _LINK and r["tx_ref"].startswith(f"vigil:{org}:")
    assert r["amount_minor"] == amount_minor and r["currency"] == currency
    assert len(posted) == 1 and posted[0]["tx_ref"] == r["tx_ref"]
    assert posted[0]["customer"] == {"email": "admin@acme.com"}    # the account's OWN registered email
    from sigil.governor.billing import _to_major
    assert posted[0]["amount"] == _to_major(amount_minor, currency)  # the CATALOG amount, never a caller figure
    assert posted[0]["currency"] == currency and posted[0]["meta"] == {"org_id": org, "price_id": "vigil_topup_1k"}
    assert wallet.available(org) == before                     # checkout NEVER credits — only the verified drain does


@pytest.mark.parametrize("who", ["tester", "other_tenant", "nonexistent"])
def test_non_billing_requesters_are_refused_by_admit(monkeypatch, who):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, tester, org, other, _w = _provisioner()
    p._checkout_provider = lambda: pytest.fail("never reached past admit")
    requester, target_org = {"tester": (tester, org),             # operator: runs tests, no money authority
                             "other_tenant": (admin, other),      # a REAL org the admin is not a member of
                             "nonexistent": (admin, "org_nonexistent")}[who]
    with pytest.raises(ProvisionDenied, match="may not manage billing"):
        p.billing_checkout(requester, target_org, "vigil_topup_1k")


def test_an_unknown_price_is_refused_never_charged(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, "free_money_9999")
    assert posted == []                                      # nothing was ever posted to the processor


def test_processor_not_provisioned_is_refused(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()                 # real _checkout_provider; no secrets in env
    with pytest.raises(ProvisionDenied, match="not configured"):
        p.billing_checkout(admin, org, "vigil_topup_1k")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "x")    # one of the two is still not enough
    with pytest.raises(ProvisionDenied, match="not configured"):
        p.billing_checkout(admin, org, "vigil_topup_1k")


@pytest.mark.parametrize("bad", ["http://app.example.com/#/billing/return", "javascript:alert(1)",
                                 "https://user@evil.example/", "app.example.com/return", "https:// x"])
def test_an_invalid_return_url_fails_closed(monkeypatch, bad):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_BILLING_RETURN_URL", bad)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="https"):
        p.billing_checkout(admin, org, "vigil_topup_1k")
    assert posted == []


def test_a_valid_return_url_is_handed_to_the_processor(monkeypatch):
    _on(monkeypatch)
    url = "https://app.example.com/#/billing/return"
    monkeypatch.setenv("VIGIL_CUSTOMER_BILLING_RETURN_URL", url)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    p.billing_checkout(admin, org, "vigil_topup_1k")
    assert posted[0]["redirect_url"] == url


def test_a_provider_refusal_is_a_provision_denial(monkeypatch):
    from sigil.governor.billing import FlutterwaveBillingProvider
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()

    def down(payload):
        raise TimeoutError("processor down")
    p._checkout_provider = lambda: FlutterwaveBillingProvider("h", lambda *a, **k: None, checkout_creator=down)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, "vigil_topup_1k")


def test_the_hop_is_absent_while_the_flag_is_off(monkeypatch):
    """server._customer_action returns None (⇒ the unknown-action 404) for billing_checkout when OFF."""
    import inspect

    from sigil.ui import server
    src = inspect.getsource(server)
    i = src.index('if action == "billing_checkout":')
    window = src[i:i + 400]
    assert "customer_checkout_enabled()" in window and "return None" in window


def test_the_edge_route_is_absent_while_the_flag_is_off(monkeypatch):
    """custui only routes billing/checkout when the flag is ON (else it falls through to the unknown-action 404),
    and the body org is never used — the org comes from the SERVER-side session."""
    import inspect

    from sigil.ui import custui
    src = inspect.getsource(custui)
    assert 'if action == "billing/checkout" and _checkout_on():' in src
    monkeypatch.delenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", raising=False)
    assert custui._checkout_on() is False
    monkeypatch.setenv("VIGIL_CUSTOMER_CHECKOUT_ENABLED", "1")
    assert custui._checkout_on() is True
    body = inspect.getsource(custui.CustomerHandler._checkout) if hasattr(custui, "CustomerHandler") else \
        next(inspect.getsource(v._checkout) for v in vars(custui).values()
             if inspect.isclass(v) and hasattr(v, "_checkout"))
    assert '"org_id": str(rec.get("org_id")' in body and 'body.get("org_id"' not in body


# --- red-pen folds ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("plan", ["vigil_research_monthly", "vigil_pro_monthly", "vigil_team_monthly"])
def test_a_subscription_plan_is_refused_never_charged_for_nothing(monkeypatch, plan):
    """Red-pen HIGH: a plan sold through this ONE-TIME payment would carry no payment_plan, so the inbound mapper
    would mint NOTHING — the customer charged, granted nothing. The edge offers top-ups only."""
    from sigil.governor import catalog
    from sigil.ui.provision import ProvisionDenied
    assert plan in catalog.expected_amounts()                 # it IS a priced catalog item ...
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionDenied, match="checkout refused"):
        p.billing_checkout(admin, org, plan)
    assert posted == []                                       # ... yet nothing is ever posted to the processor


def test_every_offered_price_is_a_topup(monkeypatch):
    from sigil.governor import catalog
    from sigil.governor.billing import EVENT_TOPUP
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    ents = catalog.entitlements()
    for pid in catalog.expected_amounts():
        posted: list = []
        p._checkout_provider = lambda posted=posted: _real_provider(posted)
        try:
            p.billing_checkout(admin, org, pid)
        except Exception:  # noqa: BLE001
            pass
        assert bool(posted) == (ents[pid].kind == EVENT_TOPUP), pid


def test_step_up_is_required_when_enforced(monkeypatch):
    from sigil.ui.provision import ProvisionStepUpRequired
    _on(monkeypatch)
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    with pytest.raises(ProvisionStepUpRequired):                # the edge prompts for a factor + retries
        p.billing_checkout(admin, org, "vigil_topup_1k", mfa_at=0.0, now=1000.0)      # no fresh second factor
    assert posted == []
    r = p.billing_checkout(admin, org, "vigil_topup_1k", mfa_at=990.0, now=1000.0)   # fresh step-up ⇒ allowed
    assert r["checkout_url"] == _LINK


def test_checkout_creation_is_rate_limited_per_org_and_requester(monkeypatch):
    from sigil.ui.provision import ProvisionDenied
    _on(monkeypatch)
    p, admin, _t, org, _o, _w = _provisioner()
    posted: list = []
    p._checkout_provider = lambda: _real_provider(posted)
    for _ in range(p._CHECKOUT_MAX):
        p.billing_checkout(admin, org, "vigil_topup_1k", now=5000.0)
    with pytest.raises(ProvisionDenied, match="too many checkout attempts"):
        p.billing_checkout(admin, org, "vigil_topup_1k", now=5001.0)
    assert len(posted) == p._CHECKOUT_MAX                     # the refused attempt never reached the processor
    p.billing_checkout(admin, org, "vigil_topup_1k", now=5000.0 + p._CHECKOUT_WINDOW_S + 1)   # window slides
    assert len(posted) == p._CHECKOUT_MAX + 1
