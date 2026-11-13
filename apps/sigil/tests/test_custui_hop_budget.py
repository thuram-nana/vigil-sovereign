"""LOW follow-up (CHK-1 red-pen) — the customer edge waits on its cockpit hop LONGER than the action's own
outbound worst case, so a slow-but-healthy action is never reported as failed after it actually happened.

Before: one flat 10 s wait. A hosted checkout whose Flutterwave POST took 12 s was CREATED by the cockpit while the
edge told the customer "provisioner unreachable" (a retry made a second checkout); the same race applied to an
inline SMTP verification / reset email and to a single-use OIDC code (consumed, then the login "failed").
"""
from __future__ import annotations

import inspect
import time

import pytest
from test_custui import _scrub_shared_owner_state  # noqa: F401  (autouse: keep the shared SIGIL_HOME pristine)
from test_custui import _get, _opener, _post, _stack
from test_customer_checkout import _iso, _on, _real_provider  # noqa: F401  (_iso is autouse)

from sigil.ui import custui


def _default(fn, name):
    return float(inspect.signature(fn).parameters[name].default)


def test_each_slow_action_outwaits_its_own_downstream_worst_case():
    from sigil.governor import flutterwave_egress, stripe_egress
    from sigil.ui import email_channel, oidc, ownership_fetch
    t = custui._SLOW_HOP_TIMEOUTS_S
    assert t["billing_checkout"] > 2 * flutterwave_egress._DEFAULT_TIMEOUT_S          # connect + read
    assert t["billing_checkout"] > 2 * stripe_egress._DEFAULT_TIMEOUT_S               # the same, when Stripe serves it
    assert t["oidc_finish"] > 2 * (_default(oidc._http_post_form, "timeout") + _default(oidc._http_get_json, "timeout"))
    assert t["target_verify"] > ownership_fetch._DEFAULT_TOTAL_TIMEOUT_S              # an ABSOLUTE budget
    smtp = _default(email_channel.SmtpEmailSender.__init__, "timeout")
    for a in ("signup_request", "recover_request"):
        assert t[a] > 5 * smtp                                                     # connect/EHLO/STARTTLS/AUTH/DATA
    assert custui._hop_timeout("login") == custui._HOP_TIMEOUT_S == 10.0           # local actions still fail fast
    assert all(v > custui._HOP_TIMEOUT_S for v in t.values())


def _slow(monkeypatch, cls, name, delay):
    real = getattr(cls, name)

    def wrapped(self, *a, **k):
        time.sleep(delay)
        return real(self, *a, **k)
    monkeypatch.setattr(cls, name, wrapped)


def test_a_slow_checkout_is_not_reported_failed_but_a_wedged_local_action_still_fails_fast(tmp_path, monkeypatch):
    """Over the REAL edge -> cockpit hop, scaled down: the default wait is 0.5 s and checkout's is 4 s; both cockpit
    actions take 1.2 s. The checkout succeeds (it outwaits its own slow processor call); the plain read is a 502."""
    from sigil.governor import catalog
    from sigil.ui import provision
    _on(monkeypatch)
    monkeypatch.setattr(custui, "_HOP_TIMEOUT_S", 0.5)
    monkeypatch.setattr(custui, "_SLOW_HOP_TIMEOUTS_S", {"billing_checkout": 4.0})
    posted: list = []
    monkeypatch.setattr(provision.Provisioner, "_checkout_provider", lambda self: _real_provider(posted))
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "slow@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm", {"token": t, "password": "customer-pw-1", "org_name": "S"})
        pid = next(p for p, e in catalog.entitlements().items() if e.kind == "topup_purchased"
                   and p not in catalog.monitoring_price_ids())
        _slow(monkeypatch, provision.Provisioner, "billing_checkout", 1.2)
        _slow(monkeypatch, provision.Provisioner, "customer_billing_offers", 1.2)
        c, r = _post(op, ep, "/api/customer/billing/checkout", {"price_id": pid})
        assert c == 200 and r.get("checkout_url"), (c, r)                     # not a false "unreachable"
        assert len(posted) == 1                                                # exactly one checkout created
        assert _get(op, ep, "/api/customer/billing/offers")[0] == 502          # a wedged read still fails fast
    finally:
        sov.shutdown(); edge.shutdown()


@pytest.mark.parametrize("action", ["billing_checkout", "oidc_finish", "target_verify", "signup_request",
                                    "recover_request"])
def test_every_slow_action_name_is_a_real_hop_action(action):
    assert f'"{action}"' in inspect.getsource(custui)
