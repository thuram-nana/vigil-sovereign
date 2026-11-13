"""Stripe parity ST-7: the INBOUND Stripe webhook route on the pure-stdlib reverse proxy, over loopback.

Pins: a valid `Stripe-Signature` -> 202 and one inert envelope {schema, body_b64, stripe_signature, received_at}
that never holds the secret; fail-closed refusals (404 unconfigured, 405, 413, 503 without a secret, 401 for a bad /
stale / future / missing / Flutterwave-only signature) spool nothing; a spool write failure is 503, never 202; the
Stripe and Flutterwave routes are separate; and the proxy's signature check accepts and rejects exactly what the
sovereign `StripeBillingProvider._verify_signature` does.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from vigil_integration import uiproxy
from vigil_integration.uiproxy import make_proxy_server, stripe_signature_ok

_SECRET = "whsec_" + "proxy-st7-test"
_SECRET_ENV = "VIGIL_STRIPE_WEBHOOK_SECRET"


def _serve(tmp_path: Path, *, stripe: bool = True, billing: bool = False):
    serve_dir = tmp_path / "ui"
    serve_dir.mkdir(parents=True, exist_ok=True)
    sspool, bspool = tmp_path / "sspool", tmp_path / "bspool"
    srv = make_proxy_server("127.0.0.1", 0, serve_dir,
                            webhook_stripe_spool_dir=str(sspool) if stripe else None,
                            webhook_billing_spool_dir=str(bspool) if billing else None)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1], sspool, bspool


def _post(port: int, body: bytes, headers: dict, path: str = "/webhooks/stripe", method: str = "POST"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body if method == "POST" else None,
                                 method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _sig(body: bytes, t: int, secret: str = _SECRET) -> str:
    mac = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


_BODY = json.dumps({"id": "evt_1", "type": "checkout.session.completed", "livemode": False,
                    "data": {"object": {"id": "cs_test_a1"}}}).encode()


def _spooled(spool: Path) -> list:
    inc = spool / "incoming"
    return [json.loads(p.read_text()) for p in inc.glob("*.json")] if inc.is_dir() else []


def test_a_signed_delivery_spools_the_body_signature_and_receive_time(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool, _b = _serve(tmp_path)
    try:
        hdr = _sig(_BODY, int(time.time()))
        before = time.time()
        assert _post(port, _BODY, {"Stripe-Signature": hdr}) == 202
        (env,) = _spooled(spool)
        assert set(env) == {"schema", "body_b64", "stripe_signature", "received_at"}
        assert env["schema"] == "vigil.webhook.stripe.v1" and env["stripe_signature"] == hdr
        assert base64.b64decode(env["body_b64"]) == _BODY
        assert before - 1 <= env["received_at"] <= time.time() + 1
        assert _SECRET not in json.dumps(env)                    # the secret never reaches the spool
    finally:
        srv.shutdown()


@pytest.mark.parametrize("make_hdr", [
    lambda t: "",                                                # missing
    lambda t: _sig(_BODY, t, "whsec_" + "other"),                # wrong secret
    lambda t: _sig(_BODY + b"x", t),                             # signed a different body
    lambda t: _sig(_BODY, t - 301),                              # stale
    lambda t: _sig(_BODY, t + 301),                              # future
    lambda t: _sig(_BODY, t).replace("t=", "t=+"),               # not plain digits
    lambda t: f"t={t}",                                          # no v1
    lambda t: _sig(_BODY, t) + ",v1=" + "a" * 2100,              # over the header cap
])
def test_a_bad_signature_is_401_and_spools_nothing(monkeypatch, tmp_path, make_hdr):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool, _b = _serve(tmp_path)
    try:
        hdrs = {"Stripe-Signature": make_hdr(int(time.time()))}
        if not hdrs["Stripe-Signature"]:
            hdrs = {}
        assert _post(port, _BODY, hdrs) == 401
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_a_flutterwave_style_delivery_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool, _b = _serve(tmp_path)
    try:
        assert _post(port, _BODY, {"verif-hash": _SECRET}) == 401
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_unset_secret_503_get_405_oversize_413(monkeypatch, tmp_path):
    monkeypatch.delenv(_SECRET_ENV, raising=False)
    srv, port, spool, _b = _serve(tmp_path)
    try:
        assert _post(port, _BODY, {"Stripe-Signature": _sig(_BODY, int(time.time()))}) == 503
        monkeypatch.setenv(_SECRET_ENV, _SECRET)
        assert _post(port, b"", {}, method="GET") == 405
        huge = b'{"x":"' + b"A" * (128 * 1024 + 10) + b'"}'
        assert _post(port, huge, {"Stripe-Signature": _sig(huge, int(time.time()))}) == 413
        assert _spooled(spool) == []
    finally:
        srv.shutdown()


def test_a_spool_write_failure_is_503_never_202(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    srv, port, spool, _b = _serve(tmp_path)

    def boom(self, envelope, *, spool_dir=None):
        raise OSError("disk full")
    monkeypatch.setattr(uiproxy.ProxyHandler, "_spool_billing_event", boom)
    try:
        assert _post(port, _BODY, {"Stripe-Signature": _sig(_BODY, int(time.time()))}) == 503
    finally:
        srv.shutdown()


def test_the_stripe_and_flutterwave_routes_are_separate(monkeypatch, tmp_path):
    monkeypatch.setenv(_SECRET_ENV, _SECRET)
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", "flw-" + "secret")
    srv, port, sspool, bspool = _serve(tmp_path, stripe=False, billing=True)
    try:
        hdr = {"Stripe-Signature": _sig(_BODY, int(time.time()))}
        assert _post(port, _BODY, hdr) == 404                    # only the Flutterwave spool is configured
        assert _post(port, _BODY, hdr, path="/webhooks/billing") == 401   # a Stripe signature is not a verif-hash
        assert _spooled(sspool) == [] and _spooled(bspool) == []
    finally:
        srv.shutdown()
    srv, port, sspool, bspool = _serve(tmp_path / "b", stripe=True, billing=False)
    try:
        assert _post(port, _BODY, {"verif-hash": "flw-" + "secret"}, path="/webhooks/billing") == 404
    finally:
        srv.shutdown()


def test_the_proxy_check_matches_the_sovereign_check():
    """Same (secret, body, header, now) vectors through both checkers: identical accept / reject."""
    from sigil.governor.billing import StripeBillingProvider
    provider = StripeBillingProvider(_SECRET, fetcher=lambda k, o: {}, expected_mode="test",
                                     enable_reference_adapter=True)
    t = 1_700_000_000
    good = _sig(_BODY, t)
    mac = good.split("v1=")[1]
    vectors = [
        (good, t), (good, t + 300), (good, t - 300), (good, t + 301), (good, t - 301),
        (f"t={t},v1=deadbeef,v1={mac}", t), (f"v1={mac},t={t}", t), (f" t={t} , v1={mac} ", t),
        (f"t={t},v1={mac.upper()}", t), (f"t={t},v1={mac[:-1]}", t), (f"t={t},v1=ｆ{mac[1:]}", t),
        (f"t=١٧٠٠٠٠٠٠٠٠,v1={mac}", t), (f"t=1e9,v1={mac}", t), (f"t={t}.0,v1={mac}", t), (f"t=,v1={mac}", t),
        (f"t={t}", t), (f"v1={mac}", t), ("", t), (f"t={t},v1={mac},t=1", t), (f"t=1,t={t},v1={mac}", t),
        (_sig(_BODY, t, "whsec_" + "x"), t), ("t=" + "1" * 13 + f",v1={mac}", t), ("garbage", t),
    ]
    for hdr, now in vectors:
        ours = stripe_signature_ok(_SECRET, _BODY, hdr, float(now))
        theirs = provider._verify_signature(_BODY, hdr, float(now))
        assert ours == theirs, (hdr, now, ours, theirs)
    assert stripe_signature_ok(_SECRET, _BODY, good, float(t)) is True
    assert stripe_signature_ok("", _BODY, good, float(t)) is False
