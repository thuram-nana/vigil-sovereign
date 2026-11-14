"""Slice A1 — OUTBOUND Flutterwave egress (checkout POST + transaction-verify GET), DEFAULT-OFF + fail-closed.

Pins, in order of the slice's doctrine:
  (a) FAIL-CLOSED / DEFAULT-OFF: no ``VIGIL_FLW_SECRET_KEY`` ⇒ the cli hooks wire NEITHER callable
      (``_billing_transaction_verifier()`` / ``_billing_checkout_creator()`` return None) ⇒ ``create_checkout``
      keeps raising ``UnsupportedCapability`` and ``billing-drain`` keeps refusing — unchanged behavior.
  (b) WIRED (dummy key + injected transport, never the network): the creator POSTs the OWNER-CATALOG-priced,
      tenant-bound ``tx_ref`` body to ``/v3/payments`` and returns the hosted link; the verifier GETs
      ``/v3/transactions/{id}/verify`` and returns the parsed AUTHORITATIVE transaction object (the response
      ``data``), reading the secret AT CALL TIME.
  (c) SECRET HYGIENE: the secret rides ONLY the ``Authorization: Bearer`` header — never the URL, never an
      exception message, never any drain output or spool/home file.
  SSRF pin: the stdlib transport refuses a non-https scheme / an off-allowlist host BEFORE the socket opens, and
  the verifier refuses a non-numeric transaction id (no path traversal from a hostile webhook).

No real or realistic key appears anywhere here — the secret is a throwaway DUMMY set via monkeypatch.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil import cli
from sigil.governor import catalog, flutterwave_egress as fe
from sigil.governor.billing import (CheckoutSession, FlutterwaveBillingProvider, UnsupportedCapability)
from sigil.governor.identity import ensure_owner_keypair
from sigil.governor.wallet import WalletRegistry
from sigil.spine.store import SpineStore

# A throwaway, obviously-fake value — NOT the shape or entropy of a real Flutterwave secret key.
_DUMMY = "dummy-not-a-real-key-DO-NOT-PRINT"
_FLW_HASH = "flw-verif-hash-xyz"               # the (separate) webhook verif-hash — also fake
_LINK = "https://checkout.flutterwave.com/pay/abc"
_EXPECTED = {"price_topup_200": (20000, "USD"), "flwplan_pro": (5000, "XAF")}


@pytest.fixture(autouse=True)
def _no_ambient_flw_key(monkeypatch):
    """Hermetic: never let an ambient ``VIGIL_FLW_SECRET_KEY`` (or a sandbox base override) bleed in."""
    monkeypatch.delenv("VIGIL_FLW_SECRET_KEY", raising=False)
    monkeypatch.delenv("VIGIL_FLW_API_BASE", raising=False)


def _capturing_transport(captured, response):
    def send(method, url, *, secret, json_body=None, timeout=15.0):
        captured.update(method=method, url=url, secret=secret, json_body=json_body)
        return response
    return send


# ---- (a) DEFAULT-OFF / fail-closed -------------------------------------------------------------------
def test_secret_configured_reflects_env(monkeypatch):
    assert fe.flutterwave_secret_configured() is False            # unset (fixture)
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", "   ")             # blank/whitespace ⇒ still OFF
    assert fe.flutterwave_secret_configured() is False
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    assert fe.flutterwave_secret_configured() is True


def test_transaction_verifier_hook_is_none_without_env_key():
    """MUTATION TARGET — the no-key fail-closed guard in ``cli._billing_transaction_verifier``. Break it (so the
    hook returns a callable without a key) and THIS test must go red; the drain would then run keyless."""
    assert cli._billing_transaction_verifier() is None


def test_checkout_creator_hook_is_none_without_env_key():
    assert cli._billing_checkout_creator() is None


def test_create_checkout_without_wired_creator_still_refuses():
    # No key ⇒ hook returns None ⇒ provider has no creator ⇒ create_checkout REFUSES (never simulates).
    provider = FlutterwaveBillingProvider(_FLW_HASH, lambda t: None,
                                          checkout_creator=cli._billing_checkout_creator())
    with pytest.raises(UnsupportedCapability):
        provider.create_checkout("acme", "price_topup_200", expected=_EXPECTED)


def test_hooks_wire_callables_with_env_key(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    assert callable(cli._billing_transaction_verifier())
    assert callable(cli._billing_checkout_creator())


# ---- (b) WIRED: creator posts the catalog-priced tx_ref body + returns the link ----------------------
def test_checkout_creator_posts_catalog_priced_payload_and_returns_link(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    cap = {}
    creator = fe.make_checkout_creator(transport=_capturing_transport(cap, {"status": "success",
                                                                            "data": {"link": _LINK}}))
    provider = FlutterwaveBillingProvider(_FLW_HASH, lambda t: None, checkout_creator=creator)
    sess = provider.create_checkout("acme-corp", "price_topup_200", expected=_EXPECTED,
                                    customer_email="a@acme.com", redirect_url="https://app.vigil/return",
                                    nonce="N1")
    assert isinstance(sess, CheckoutSession)
    assert sess.hosted_link == _LINK
    assert sess.amount_minor == 20000 and sess.currency == "USD"        # from the CATALOG, never the caller
    # the poster got a POST to /v3/payments on the pinned host, Bearer secret read AT CALL TIME
    assert cap["method"] == "POST"
    assert cap["url"] == "https://api.flutterwave.com/v3/payments"
    assert cap["secret"] == _DUMMY
    body = cap["json_body"]
    assert body["tx_ref"] == "vigil:acme-corp:N1"                       # tenant bound into the echoed field
    assert body["amount"] == 200.0 and body["currency"] == "USD"        # 20000 minor USD -> 200.00 major (catalog)
    assert body["meta"] == {"org_id": "acme-corp", "price_id": "price_topup_200"}


# ---- (b) WIRED: verifier returns the parsed AUTHORITATIVE transaction object -------------------------
def test_transaction_verifier_returns_data_object(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    txn = {"id": 9911, "status": "successful", "tx_ref": "vigil:acme:n1", "amount": 200.0, "currency": "USD"}
    cap = {}
    verify = fe.make_transaction_verifier(transport=_capturing_transport(cap, {"status": "success", "data": txn}))
    got = verify("9911")
    assert got == txn                                                   # the INNER data object, unwrapped
    assert cap["method"] == "GET"
    assert cap["url"] == "https://api.flutterwave.com/v3/transactions/9911/verify"
    assert cap["secret"] == _DUMMY


def test_transaction_verifier_non_success_envelope_is_none(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    # a definitive non-success lookup (bad id / API error) -> None (no-op; the signer mints nothing). Never raises.
    verify = fe.make_transaction_verifier(transport=lambda *a, **k: {"status": "error", "message": "not found"})
    assert verify("9911") is None


def test_transaction_verifier_raises_on_transient_transport_failure(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)

    def boom(*a, **k):
        raise fe.FlutterwaveEgressError("GET transport failure (URLError)")

    verify = fe.make_transaction_verifier(transport=boom)
    with pytest.raises(fe.FlutterwaveEgressError):                      # transient -> raise -> drain QUARANTINES
        verify("9911")


def test_transaction_verifier_refuses_non_numeric_txid(monkeypatch):
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    reached = {"n": 0}

    def tripwire(*a, **k):
        reached["n"] += 1
        return {"status": "success", "data": {}}

    verify = fe.make_transaction_verifier(transport=tripwire)
    for hostile in ("../admin", "9911/../../x", "1 OR 1", "", "0x10"):
        with pytest.raises(fe.FlutterwaveEgressError):
            verify(hostile)
    assert reached["n"] == 0                                            # refused BEFORE any egress (no SSRF)


def test_verifier_without_env_key_raises_at_call_time(monkeypatch):
    # The callable may be built, but with the key cleared it refuses AT CALL TIME (read-at-call, never cached).
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)
    verify = fe.make_transaction_verifier(transport=lambda *a, **k: {"status": "success", "data": {"id": 1}})
    monkeypatch.delenv("VIGIL_FLW_SECRET_KEY", raising=False)
    with pytest.raises(fe.FlutterwaveEgressError):
        verify("9911")


# ---- SSRF pin: the real stdlib transport guards https + the host allowlist BEFORE the socket ---------
def test_request_json_guard_refuses_non_https_and_off_allowlist():
    for bad in ("http://api.flutterwave.com/v3/x",                      # non-https
                "https://evil.example/v3/x",                            # off-allowlist host
                "https://api.flutterwave.com.evil.example/x",           # suffix-spoof (not an exact match)
                "https://user:pass@api.flutterwave.com/x"):             # embedded userinfo
        with pytest.raises(fe.FlutterwaveEgressError) as ei:
            fe._request_json("GET", bad, secret=_DUMMY)
        assert _DUMMY not in str(ei.value)                             # (c) secret never in a refusal message


# ---- (c) the secret rides the Bearer header ONLY — never the URL, parsed response returned -----------
class _FakeResp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self, n: int = -1) -> bytes:
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_request_json_puts_secret_in_bearer_header_not_url(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["auth"] = req.get_header("Authorization")
        captured["ctype"] = req.get_header("Content-type")
        return _FakeResp(json.dumps({"status": "success", "data": {"ok": True}}).encode("utf-8"))

    monkeypatch.setattr(fe, "_do_open", fake_urlopen)
    out = fe._request_json("POST", "https://api.flutterwave.com/v3/payments", secret=_DUMMY,
                           json_body={"tx_ref": "vigil:acme:n"})
    assert out == {"status": "success", "data": {"ok": True}}
    assert captured["auth"] == f"Bearer {_DUMMY}"                       # secret rides the header
    assert _DUMMY not in captured["url"]                               # never the URL
    assert captured["ctype"] == "application/json"


def test_request_json_refuses_oversize_response(monkeypatch):
    monkeypatch.setattr(fe, "_MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(fe, "_do_open",
                        lambda req, timeout=None: _FakeResp(b"x" * 64))
    with pytest.raises(fe.FlutterwaveEgressError):
        fe._request_json("GET", "https://api.flutterwave.com/v3/x", secret=_DUMMY)


# ---- secret-exfil defense: a hostile 3xx is NOT followed WITH the Bearer secret (the red-pen HIGH) --
def test_request_json_does_not_follow_a_redirect_with_the_bearer_secret(monkeypatch):
    """A compromised / MITM'd provider that answers the pinned call with a 302 to an off-allowlist host must
    NOT make the egress follow it WITH ``Authorization: Bearer <secret>`` attached — that would exfiltrate the
    LIVE payment key past the egress pin (``_guard`` only ever sees the INITIAL url). The redirect-blocking
    opener turns the 3xx into a fail-closed error and the redirect TARGET is never contacted. Exercises the
    REAL ``_request_json`` transport over two loopback servers."""
    import http.server
    import threading

    hits = {"origin_auth": None, "target_contacted": False, "target_auth": None}

    class _Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self):                                          # the off-allowlist redirect target
            hits["target_contacted"] = True
            hits["target_auth"] = self.headers.get("Authorization")
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"status":"success","data":{}}')

        def log_message(self, *a):                                 # keep the test output clean
            pass

    tgt = http.server.HTTPServer(("127.0.0.1", 0), _Target)
    tport = tgt.server_address[1]

    class _Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):                                          # the pinned host: 302 -> the target (cross-host http)
            hits["origin_auth"] = self.headers.get("Authorization")
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{tport}/v3/transactions/9911/verify")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    org = http.server.HTTPServer(("127.0.0.1", 0), _Origin)
    oport = org.server_address[1]
    threading.Thread(target=tgt.serve_forever, daemon=True).start()
    threading.Thread(target=org.serve_forever, daemon=True).start()

    # Bypass ONLY _guard (its https+allowlist check is covered separately) so the request reaches the opener,
    # where we observe REDIRECT handling. The secret rides the REAL Bearer header, exactly as in production.
    monkeypatch.setattr(fe, "_guard", lambda url: None)
    canary = "FLWSECK-live-REDPEN-canary-DO-NOT-FORWARD"
    try:
        with pytest.raises(fe.FlutterwaveEgressError):            # the 302 is a fail-closed non-2xx, never a follow
            fe._request_json("GET", f"http://127.0.0.1:{oport}/v3/transactions/9911/verify", secret=canary)
        assert hits["origin_auth"] == f"Bearer {canary}"          # the secret WAS on the initial call (test is real)
        assert hits["target_contacted"] is False                  # ...but the redirect target was NEVER reached
        assert hits["target_auth"] is None                        # ...so the live key was never relayed onward
    finally:
        org.shutdown(); tgt.shutdown()


def test_request_json_raises_fail_closed_on_a_transient_transport_failure(monkeypatch):
    """The money-safety contract (so the inbound drain QUARANTINES + retries rather than minting on a lost
    call): a transient transport failure RAISES a FlutterwaveEgressError whose message carries NO secret.
    Exercises the REAL ``_request_json`` transport — a connection refused to a closed loopback port."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = s.getsockname()[1]
    s.close()                                                     # the port is now closed ⇒ connection refused
    monkeypatch.setattr(fe, "_guard", lambda url: None)
    with pytest.raises(fe.FlutterwaveEgressError) as ei:
        fe._request_json("GET", f"http://127.0.0.1:{dead}/v3/x", secret=_DUMMY)
    assert _DUMMY not in str(ei.value)                            # (c) the secret never rides a failure message


# ---- (c) end-to-end: the outbound secret never leaks through the real billing drain ------------------
@pytest.fixture()
def _home(monkeypatch):
    d = tempfile.mkdtemp()
    monkeypatch.setenv("SIGIL_HOME", d)
    monkeypatch.setenv("HOME", tempfile.mkdtemp())   # hermetic: the drain compares with ~/.sigil/cockpit.env
    from sigil import config
    monkeypatch.setattr(config, "SPINE_PATH", Path(d) / "spine" / "spine.jsonl")
    monkeypatch.delenv("VIGIL_BILLING_DRAIN_ENABLED", raising=False)
    monkeypatch.delenv("VIGIL_BILLING_WEBHOOK_SECRET", raising=False)
    ensure_owner_keypair()
    return d


def _spool_charge(root: Path, txid: int):
    import base64
    raw = json.dumps({"event": "charge.completed", "data": {"id": txid, "amount": 1}}).encode()
    env = json.dumps({"schema": "vigil.webhook.billing.v1", "body_b64": base64.b64encode(raw).decode("ascii")})
    (root / "incoming").mkdir(parents=True, exist_ok=True)
    (root / "incoming" / f"{txid}.json").write_text(env, encoding="utf-8")


def test_outbound_secret_never_leaks_through_drain(_home, capsys, monkeypatch):
    pid = next(p for p, e in catalog.entitlements().items() if e.credits)
    credits = catalog.entitlements()[pid].credits
    amt, ccy = catalog.expected_amounts()[pid]

    # Drive the REAL cli hook (not a monkeypatched lambda): a dummy key wires fe.make_transaction_verifier,
    # whose transport we replace so NO socket opens while proving the secret flows to it at call time.
    monkeypatch.setenv("VIGIL_BILLING_DRAIN_ENABLED", "1")
    monkeypatch.setenv("VIGIL_BILLING_WEBHOOK_SECRET", _FLW_HASH)
    monkeypatch.setenv("VIGIL_FLW_SECRET_KEY", _DUMMY)

    def fake_transport(method, url, *, secret, json_body=None, timeout=15.0):
        assert secret == _DUMMY and method == "GET"                    # secret read AT CALL TIME, flows to egress
        txid = url.rstrip("/").split("/")[-2]                          # /v3/transactions/<id>/verify
        return {"status": "success", "data": {"id": int(txid), "status": "successful", "tx_ref": "vigil:acme:n1",
                "created_at": 100.0, "amount": amt / 100, "currency": ccy, "meta": {"price_id": pid}}}

    monkeypatch.setattr(fe, "_request_json", fake_transport)

    spool = Path(tempfile.mkdtemp())
    _spool_charge(spool, 9911)
    cli.cmd_billing_drain(SimpleNamespace(billing_cmd="drain", spool=str(spool), interval=0.1))
    out = capsys.readouterr()
    text = out.out + out.err
    assert "1 minted" in text and _DUMMY not in text and _FLW_HASH not in text
    assert WalletRegistry(SpineStore()).available("acme") == credits   # catalog decides, credited once
    for base in (spool, Path(os.environ["SIGIL_HOME"])):
        for p in base.rglob("*"):
            if p.is_file():
                assert _DUMMY.encode() not in p.read_bytes()           # never persisted on the spine / spool
