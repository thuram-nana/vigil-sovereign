"""Consumer PR-C — the flag-off golden: with VIGIL_CUSTOMER_CONNECT off the unified connect surface is ABSENT.

Master flag ``VIGIL_CUSTOMER_CONNECT`` (and the cloud leg's ``VIGIL_CUSTOMER_CLOUD_CONNECT``) are OFF by default. This
pins that, off:
  * ``config.customer_connect_enabled()`` / ``customer_cloud_connect_enabled()`` are False, and the cloud flag can never
    be on without the master flag;
  * the SOVEREIGN dispatch answers every new action with ``None`` — the "unknown provision action" 404, exactly as an
    action that does not exist — and never reaches the provisioner (the cloud actions also while only the cloud flag
    is off);
  * the customer EDGE 404s every new route before any hop (GET api/customer/connect, POST api/customer/connect/*);
  * EVERY provisioner connect action still refuses on its own (defence in depth under the dispatch's 404) — BEFORE any
    admit, so even a fully-entitled member is refused and NOTHING is minted;
so a customer's effective reach is byte-identical to a build without PR-C.
"""
from __future__ import annotations

import http.client
import itertools
import json
import tempfile
import threading

import pytest

from sigil import config
from sigil.governor.cloud_connect import CloudConnectRegistry
from sigil.ui.provision import ProvisionDenied, ProvisionError

_iss = itertools.count(1)
_ACTIONS = ("connect_overview", "connect_ownership_poll", "cloud_connect_challenge", "cloud_connect_verify",
            "cloud_disconnect")


@pytest.fixture(autouse=True)
def _off(monkeypatch):
    monkeypatch.setenv("VIGIL_BASE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_SPINE_DIR", tempfile.mkdtemp())
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_CUSTOMER_CONNECT", raising=False)
    monkeypatch.delenv("VIGIL_CUSTOMER_CLOUD_CONNECT", raising=False)


def _prov():
    from sigil.governor.customers import CustomerRegistry
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.governor.orgs import OrgRegistry
    from sigil.governor.wallet import WalletRegistry
    from sigil.spine.store import SpineStore
    from sigil.ui.email_channel import EmailTokenLedger, NullEmailSender
    from sigil.ui.login_ratelimit import LoginRateLimiter
    from sigil.ui.provision import Provisioner
    ensure_owner_keypair()
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    orgs = OrgRegistry(s)
    p = Provisioner(s, customers=CustomerRegistry(s), orgs=orgs, wallet=WalletRegistry(s),
                    email_tokens=EmailTokenLedger(tempfile.mkdtemp(), ttl_s=1e4),
                    rate_limiter=LoginRateLimiter(tempfile.mkdtemp(), max_fails=1000, window_s=1e4, base_lock_s=1.0),
                    email_sender=NullEmailSender(), now_fn=lambda: float(next(_iss)))
    return p, s, orgs


def _seat(orgs, org, user, role):
    orgs.create_org(org, org, owner=user, issued_at=float(next(_iss)))
    orgs.grant_membership(org, user, role, issued_at=float(next(_iss)))


def test_both_flags_are_off_by_default_and_cloud_needs_the_master(monkeypatch):
    assert config.customer_connect_enabled() is False
    assert config.customer_cloud_connect_enabled() is False
    monkeypatch.setenv("VIGIL_CUSTOMER_CLOUD_CONNECT", "1")             # the cloud flag ALONE turns nothing on
    assert config.customer_cloud_connect_enabled() is False
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")
    assert config.customer_cloud_connect_enabled() is True
    for v in ("0", "", "no", "maybe"):
        monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", v)
        assert config.customer_connect_enabled() is False and config.customer_cloud_connect_enabled() is False, v


class _Untouchable:
    """A provisioner the dispatch must never reach while the flags are off."""

    def __getattr__(self, name):
        raise AssertionError(f"the dispatch reached the provisioner ({name}) with the flag off")


def _dispatch(action):
    from sigil.ui.server import Handler
    body = {"org_id": "org_a", "host": "apme.cm", "provider": "aws", "account_id": "123456789012",
            "role_ref": "arn:aws:iam::123456789012:role/R", "recheck": True, "authorized": True}
    return Handler._provision_dispatch(None, _Untouchable(), action, "u_f", body)


def test_the_sovereign_dispatch_treats_every_new_action_as_unknown_when_off(monkeypatch):
    for a in _ACTIONS:
        assert _dispatch(a) is None, a                                 # None => "unknown provision action" 404
    monkeypatch.setenv("VIGIL_CUSTOMER_CONNECT", "1")                  # connect on, cloud leg still off
    for a in ("cloud_connect_challenge", "cloud_connect_verify", "cloud_disconnect"):
        assert _dispatch(a) is None, a


def _edge_request(method, path, body=None):
    from sigil.ui.custui import build_customer_server
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=tempfile.mkdtemp())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        data = json.dumps(body or {}).encode() if method == "POST" else None
        c.request(method, path, body=data, headers={"Host": f"127.0.0.1:{port}", "Origin": f"http://127.0.0.1:{port}",
                                                    "Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read()
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_edge_404s_every_new_route_when_off():
    assert _edge_request("GET", "/api/customer/connect")[0] == 404
    for route in ("connect/ownership", "connect/cloud/challenge", "connect/cloud/verify", "connect/cloud/disconnect"):
        status, raw = _edge_request("POST", "/api/customer/" + route, {"host": "apme.cm"})
        assert status == 404 and json.loads(raw) == {"error": "unknown action"}, route


def test_every_connect_action_refuses_when_off_even_for_a_member():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")           # fully entitled: run_engagement + view_assessments
    for call in (
        lambda: p.customer_connect_overview("u_f", "org_a"),
        lambda: p.customer_ownership_poll("u_f", "org_a", "apme.cm"),
        lambda: p.customer_ownership_poll("u_f", "org_a", "apme.cm", recheck=True, authorized=True),
        lambda: p.cloud_connect_challenge("u_f", "org_a", "aws", "123456789012"),
        lambda: p.cloud_disconnect("u_f", "org_a", "aws", "123456789012"),
    ):
        with pytest.raises(ProvisionDenied):
            call()
    with pytest.raises((ProvisionDenied, ProvisionError)):
        p.cloud_connect_verify("u_f", "org_a", "aws", "123456789012", "arn:aws:iam::123456789012:role/R")


def test_nothing_is_minted_when_off():
    p, s, orgs = _prov()
    _seat(orgs, "org_a", "u_f", "operator")
    with pytest.raises(ProvisionDenied):
        p.cloud_connect_challenge("u_f", "org_a", "aws", "123456789012")
    reg = CloudConnectRegistry(s, owner_key=None)
    assert reg.challenge("org_a", "aws", "123456789012") is None
    assert reg.grants_of_org("org_a") == []


def test_the_flag_gate_fires_before_admit():
    # a NON-member is refused by the flag gate (connect_off), proving the flag is checked ahead of membership
    p, s, orgs = _prov()
    with pytest.raises(ProvisionDenied, match="not enabled"):
        p.cloud_connect_challenge("nobody", "ghost_org", "aws", "123456789012")
