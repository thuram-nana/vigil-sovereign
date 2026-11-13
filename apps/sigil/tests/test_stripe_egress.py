"""Stripe parity ST-4: the outbound Stripe egress (object re-fetch + checkout create), default-off + fail-closed.

Pins: the https + exact-host guard (and its separation from the Flutterwave egress); the key only ever in the
Authorization header (never a URL, never an error message) and read at call time; the API version required and
sent as Stripe-Version; form-encoded bodies (never JSON) with a strict bracket-key encoder; the Idempotency-Key on
create; transient vs definitive errors; a 3xx never followed with the key; the per-kind anchored id shapes; and a
fetched object that must be the requested type and id.

Fake keys are assembled at runtime so no key-shaped literal is committed.
"""
from __future__ import annotations

import io
import json
import urllib.error
from urllib.parse import parse_qsl

import pytest

from sigil.governor import flutterwave_egress as fe
from sigil.governor import stripe_egress as se


def _key(mode: str = "test", kind: str = "sk") -> str:
    return "_".join([kind, mode, "dummy" + "0" * 6 + "notreal"])


_VERSION = "2000-01-01"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    monkeypatch.delenv("VIGIL_STRIPE_SECRET_KEY", raising=False)
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", _VERSION)


class _FakeResp:
    def __init__(self, body: bytes):
        self._b = io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture(monkeypatch, response):
    seen: dict = {}

    def fake_open(req, timeout=None):
        seen.update(url=req.full_url, method=req.get_method(), headers=dict(req.header_items()), data=req.data)
        return _FakeResp(json.dumps(response).encode())

    monkeypatch.setattr(se, "_do_open", fake_open)
    return seen


def _http_error(code):
    def fake_open(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)   # type: ignore[arg-type]
    return fake_open


# ---- default-off gate + key mode ---------------------------------------------------------------------
def test_secret_configured_and_key_mode(monkeypatch):
    assert se.stripe_secret_configured() is False and se.stripe_key_mode() is None
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", "   ")
    assert se.stripe_secret_configured() is False
    for key, mode in ((_key("live"), "live"), (_key("test"), "test"), (_key("live", "rk"), "live"),
                      (_key("test", "rk"), "test"), ("dummy-unknown-shape", None), (_key("prod"), None),
                      (_key("liveish"), None), ("dummy-latest-shape", None)):
        monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", key)
        assert se.stripe_secret_configured() is True
        assert se.stripe_key_mode() == mode


# ---- the egress guard ----------------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://api.stripe.com/v1/invoices/in_1",              # not https
    "https://user@api.stripe.com/v1/invoices/in_1",        # userinfo
    "https://api.stripe.com:8443/v1/invoices/in_1",        # non-default port
    "https://checkout.stripe.com/v1/invoices/in_1",        # the link host is never an API host
    "https://api.flutterwave.com/v3/payments",             # another provider's host
    "https://api.stripe.com.evil.io/v1/x",
    "https://evil.io/v1/x",
])
def test_guard_refuses_everything_but_https_api_stripe_com(url):
    with pytest.raises(se.StripeEgressError):
        se._guard(url)


def test_guard_admits_the_api_host_and_the_providers_are_separate():
    se._guard("https://api.stripe.com/v1/invoices/in_1")
    se._guard("https://API.Stripe.com:443/v1/invoices/in_1")
    with pytest.raises(fe.FlutterwaveEgressError):
        fe._guard("https://api.stripe.com/v1/invoices/in_1")   # the Flutterwave egress never reaches Stripe


# ---- the one request -----------------------------------------------------------------------------------
def test_post_is_form_encoded_with_version_idempotency_and_key_in_header_only(monkeypatch):
    seen = _capture(monkeypatch, {"object": "checkout.session"})
    key = _key()
    se._request("POST", "https://api.stripe.com/v1/checkout/sessions", secret=key,
                form={"mode": "payment", "metadata": {"price_id": "p1"}, "line_items": [{"quantity": 1}]},
                idempotency_key="vigil:acme:n1")
    h = {k.lower(): v for k, v in seen["headers"].items()}
    assert h["authorization"] == f"Bearer {key}" and key not in seen["url"]
    assert h["stripe-version"] == _VERSION
    assert h["idempotency-key"] == "vigil:acme:n1"
    assert h["content-type"] == "application/x-www-form-urlencoded"
    body = seen["data"].decode("ascii")
    assert not body.lstrip().startswith("{")                       # never JSON
    assert parse_qsl(body) == [("mode", "payment"), ("metadata[price_id]", "p1"), ("line_items[0][quantity]", "1")]


def test_get_carries_no_body_and_no_content_type(monkeypatch):
    seen = _capture(monkeypatch, {"object": "invoice", "id": "in_1"})
    se._request("GET", "https://api.stripe.com/v1/invoices/in_1", secret=_key())
    h = {k.lower(): v for k, v in seen["headers"].items()}
    assert seen["data"] is None and "content-type" not in h and "idempotency-key" not in h


@pytest.mark.parametrize("version", ["", "latest", "2000-1-1", "2000-01-01.ACACIA", "2000-01-01;x",
                                     "\u0662000-01-01"])
def test_an_unpinned_or_malformed_api_version_refuses_before_any_socket(monkeypatch, version):
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", version)
    monkeypatch.setattr(se, "_do_open", lambda *a, **k: pytest.fail("opened a socket"))
    with pytest.raises(se.StripeEgressError):
        se._request("GET", "https://api.stripe.com/v1/invoices/in_1", secret=_key())


def test_a_named_release_version_is_accepted(monkeypatch):
    monkeypatch.setenv("VIGIL_STRIPE_API_VERSION", "2000-01-01.release")
    seen = _capture(monkeypatch, {})
    se._request("GET", "https://api.stripe.com/v1/invoices/in_1", secret=_key())
    assert {k.lower(): v for k, v in seen["headers"].items()}["stripe-version"] == "2000-01-01.release"


@pytest.mark.parametrize("code,transient", [(408, True), (425, True), (429, True), (500, True), (503, True),
                                            (400, False), (401, False), (402, False), (404, False), (409, False)])
def test_http_errors_are_transient_only_when_a_retry_may_cure_them(monkeypatch, code, transient):
    monkeypatch.setattr(se, "_do_open", _http_error(code))
    key = _key()
    with pytest.raises(se.StripeEgressError) as ei:
        se._request("GET", "https://api.stripe.com/v1/invoices/in_1", secret=key)
    assert ei.value.transient is transient and key not in str(ei.value)


def test_a_transport_fault_is_transient_and_never_carries_the_key(monkeypatch):
    def boom(req, timeout=None):
        raise ConnectionResetError(req.get_header("Authorization"))      # even if the cause echoes the header
    monkeypatch.setattr(se, "_do_open", boom)
    key = _key()
    with pytest.raises(se.StripeEgressError) as ei:
        se._request("GET", "https://api.stripe.com/v1/invoices/in_1", secret=key)
    assert ei.value.transient is True and key not in str(ei.value) and ei.value.__cause__ is None


def test_oversize_and_non_json_responses_are_definitive(monkeypatch):
    monkeypatch.setattr(se, "_MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(se, "_do_open", lambda req, timeout=None: _FakeResp(b"x" * 64))
    with pytest.raises(se.StripeEgressError) as ei:
        se._request("GET", "https://api.stripe.com/v1/x", secret=_key())
    assert ei.value.transient is False
    monkeypatch.setattr(se, "_MAX_RESPONSE_BYTES", 4096)
    monkeypatch.setattr(se, "_do_open", lambda req, timeout=None: _FakeResp(b"<html>"))
    with pytest.raises(se.StripeEgressError) as ei:
        se._request("GET", "https://api.stripe.com/v1/x", secret=_key())
    assert ei.value.transient is False


def test_a_redirect_is_never_followed_with_the_key(monkeypatch):
    """Two loopback servers: the pinned host answers 302 to another host; the target must never be reached."""
    import http.server
    import threading

    hits = {"origin_auth": None, "target": False}

    class _Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits["target"] = True
            self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    tgt = http.server.HTTPServer(("127.0.0.1", 0), _Target)

    class _Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits["origin_auth"] = self.headers.get("Authorization")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{tgt.server_address[1]}/v1/invoices/in_1")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    org = http.server.HTTPServer(("127.0.0.1", 0), _Origin)
    threading.Thread(target=tgt.serve_forever, daemon=True).start()
    threading.Thread(target=org.serve_forever, daemon=True).start()
    monkeypatch.setattr(se, "_guard", lambda url: None)      # reach the opener; the guard is tested above
    key = _key("live")
    try:
        with pytest.raises(se.StripeEgressError):
            se._request("GET", f"http://127.0.0.1:{org.server_address[1]}/v1/invoices/in_1", secret=key)
        assert hits["origin_auth"] == f"Bearer {key}" and hits["target"] is False
    finally:
        org.shutdown(); tgt.shutdown()


# ---- the strict form encoder ----------------------------------------------------------------------------
def test_form_encoder_flattens_and_refuses_unsafe_shapes():
    assert se.encode_form({"a": True, "b": False, "c": 7, "d": {"e": [1, "x"]}}) == [
        ("a", "true"), ("b", "false"), ("c", "7"), ("d[e][0]", "1"), ("d[e][1]", "x")]
    for bad in ({"amount": 1.5}, {"a[b]": "x"}, {"a&b": "x"}, {"": "x"}, {"a": None}, {"a": b"x"}, {1: "x"}):
        with pytest.raises(se.StripeEgressError):
            se.encode_form(bad)
    with pytest.raises(se.StripeEgressError):
        se.encode_form(["x"])                                                  # type: ignore[arg-type]


# ---- the object fetcher -----------------------------------------------------------------------------------
def _stub(captured, response):
    def send(method, url, *, secret, form=None, idempotency_key=None, timeout=15.0):
        captured.update(method=method, url=url, secret=secret, form=form, idempotency_key=idempotency_key)
        return response
    return send


@pytest.mark.parametrize("kind,oid,path,otype", [
    ("checkout_session", "cs_test_a1B2", "/v1/checkout/sessions/cs_test_a1B2", "checkout.session"),
    ("checkout_session", "cs_live_Z9", "/v1/checkout/sessions/cs_live_Z9", "checkout.session"),
    ("invoice", "in_1Abc", "/v1/invoices/in_1Abc", "invoice"),
    ("subscription", "sub_1Abc", "/v1/subscriptions/sub_1Abc", "subscription"),
])
def test_fetch_gets_the_named_object_and_reads_the_key_at_call_time(monkeypatch, kind, oid, path, otype):
    cap: dict = {}
    fetch = se.make_object_fetcher(transport=_stub(cap, {"object": otype, "id": oid}))
    key = _key()
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", key)          # set AFTER the fetcher was built
    assert fetch(kind, oid) == {"object": otype, "id": oid}
    assert cap["method"] == "GET" and cap["url"] == "https://api.stripe.com" + path and cap["secret"] == key


@pytest.mark.parametrize("kind,oid", [
    ("invoice", "../v1/charges"), ("invoice", "in_a/b"), ("invoice", "in_"), ("invoice", "pi_123"),
    ("invoice", "evt_123"), ("invoice", "in_١٢"), ("subscription", "sub_abc\n"), ("subscription", ""),
    ("checkout_session", "cs_abc"), ("checkout_session", "cs_prod_abc"), ("checkout_session", "cs_test_a%2F"),
    ("invoice", "in_" + "a" * 256), ("charge", "ch_1"), ("invoice", None),
])
def test_fetch_refuses_a_malformed_id_or_kind_before_any_call(monkeypatch, kind, oid):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    fetch = se.make_object_fetcher(transport=lambda *a, **k: pytest.fail("called the API"))
    with pytest.raises(se.StripeEgressError):
        fetch(kind, oid)


@pytest.mark.parametrize("resp", [None, [], {"object": "invoice"}, {"object": "charge", "id": "in_1"},
                                  {"object": "invoice", "id": "in_2"}])
def test_fetch_refuses_an_object_that_is_not_the_one_requested(monkeypatch, resp):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    fetch = se.make_object_fetcher(transport=_stub({}, resp))
    with pytest.raises(se.StripeEgressError):
        fetch("invoice", "in_1")


def test_fetch_404_is_a_definitive_refusal_not_a_no_op(monkeypatch):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    monkeypatch.setattr(se, "_do_open", _http_error(404))
    with pytest.raises(se.StripeEgressError) as ei:
        se.make_object_fetcher()("invoice", "in_1")
    assert ei.value.transient is False


def test_fetch_without_a_key_refuses_at_call_time():
    fetch = se.make_object_fetcher(transport=lambda *a, **k: pytest.fail("called the API"))
    with pytest.raises(se.StripeEgressError):
        fetch("invoice", "in_1")


# ---- the checkout creator -----------------------------------------------------------------------------------
def test_checkout_create_posts_the_form_with_the_idempotency_key(monkeypatch):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    cap: dict = {}
    create = se.make_checkout_creator(transport=_stub(cap, {"object": "checkout.session", "url": "u"}))
    params = {"mode": "payment", "client_reference_id": "vigil:acme:n1"}
    assert create(params, idempotency_key="vigil:acme:n1")["url"] == "u"
    assert cap["method"] == "POST" and cap["url"] == "https://api.stripe.com/v1/checkout/sessions"
    assert cap["form"] == params and cap["idempotency_key"] == "vigil:acme:n1"


@pytest.mark.parametrize("ikey", ["", " ", "a b", "a\nb", "é", "x" * 256, None])
def test_checkout_create_requires_a_valid_idempotency_key(monkeypatch, ikey):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    create = se.make_checkout_creator(transport=lambda *a, **k: pytest.fail("called the API"))
    with pytest.raises(se.StripeEgressError):
        create({"mode": "payment"}, idempotency_key=ikey)


def test_checkout_create_refuses_an_unexpected_response(monkeypatch):
    monkeypatch.setenv("VIGIL_STRIPE_SECRET_KEY", _key())
    create = se.make_checkout_creator(transport=_stub({}, {"object": "payment_intent"}))
    with pytest.raises(se.StripeEgressError):
        create({"mode": "payment"}, idempotency_key="k1")
