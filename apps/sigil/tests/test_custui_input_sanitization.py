"""Edge integration: the central request-boundary sanitizer (``custui._read_body``) seen end-to-end over the real
edge -> provisioner hop.

A recording stand-in for the cockpit captures the EXACT JSON body the edge forwards for each action, so these tests
prove, through the real HTTP path (not just the unit of ``input_safety``):

  * ordinary user-text fields (``org_name`` / ``host`` / ``note`` / nested ``preferences.*``) arrive SANITIZED — the
    zero-width / bidi / control characters are gone — while the rest of the value is intact;
  * credential / token / WebAuthn fields (``password`` / ``token`` / ``code`` / ``client_data_json`` /
    ``authenticator_data`` / ``credential_id`` / ``signature``) arrive BYTE-EXACT, so login / signup / WebAuthn are
    never corrupted by the pass;
  * a deeply-nested (JSON-bomb) body is refused 4xx before it is dispatched.

Dangerous characters are written as ``\\u`` escapes (never raw in source — ruff PLE2502 / Trojan-Source).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server

HOP = "test-provision-hop-key-xyz"


class _RecordingProvisioner(ThreadingHTTPServer):
    """A loopback cockpit stand-in that records the last JSON body received per ``/api/provision/<action>`` path and
    answers every hop 200 ``{"ok": true}`` (no username -> the edge mints nothing, it just relays + records)."""
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.received: dict[str, dict] = {}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):           # silence the test console
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {"_unparsable": raw.decode("utf-8", "replace")}
        self.server.received[self.path] = body       # recorded on the _RecordingProvisioner subclass
        out = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def _recording_provisioner():
    srv = _RecordingProvisioner()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _edge(provision_base, sessions_dir):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key=HOP, provision_base=provision_base,
                                sessions_dir=sessions_dir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _post(port, path, body, *, cookie=None, raw_body=None):
    data = raw_body if raw_body is not None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    prov, pport = _recording_provisioner()
    edge, eport = _edge(f"http://127.0.0.1:{pport}", str(tmp_path / "custsessions"))
    try:
        yield edge, eport, prov
    finally:
        edge.shutdown()
        prov.shutdown()


# ---------------------------------------------------------------- public route: org_name sanitized, creds byte-exact ---
def test_signup_confirm_sanitizes_text_but_passes_credentials_byte_exact(stack):
    edge, eport, prov = stack
    org = "Ac\u202eme\u200b Corp"               # bidi override + zero-width in a display name
    password = "S3cr3t\x07pa\u200bss"            # control + zero-width bytes in the password
    token = "tok\x00en-value"                    # NUL inside a single-use token
    code = "12\u200b34"                          # zero-width inside the emailed code
    status, _ = _post(eport, "/api/customer/signup/confirm",
                      {"email": "a@acme.com", "org_name": org, "password": password,
                       "token": token, "code": code})
    assert status == 200
    body = prov.received["/api/provision/signup_confirm"]
    # ordinary text field: the dangerous characters are stripped, the real name survives
    assert body["org_name"] == "Acme Corp"
    # credentials: forwarded BYTE-EXACT (a single altered byte would break auth)
    assert body["password"] == password
    assert body["token"] == token
    assert body["code"] == code


# ----------------------------------------------------------------------- authenticated route: host / note sanitized ---
def test_authorization_request_host_and_note_sanitized(stack, monkeypatch):
    edge, eport, prov = stack
    monkeypatch.setenv("VIGIL_CUSTOMER_AUTHORIZATIONS", "1")
    sid = edge.sessions.create("cust1", "customer", org_id="org1")
    host = "ex\u200bam\u202eple.com"
    note = "please\u0007 review\u200d this"
    status, _ = _post(eport, "/api/customer/authorizations/request", {"host": host, "note": note},
                      cookie=f"{CUSTOMER_COOKIE}={sid}")
    assert status == 200
    body = prov.received["/api/provision/customer_authorization_request"]
    assert body["host"] == "example.com"
    assert body["note"] == "please review this"
    assert body["org_id"] == "org1"             # still server-bound, never body-supplied


# --------------------------------------------------------------- authenticated route: nested preferences.* sanitized ---
def test_preferences_nested_strings_sanitized(stack, monkeypatch):
    edge, eport, prov = stack
    monkeypatch.setenv("VIGIL_CUSTOMER_SETTINGS", "1")
    sid = edge.sessions.create("cust2", "customer", org_id="org2")
    prefs = {"legal_entity_name": "Ac\u202eme GmbH", "registered_address": "1 Main\u200b St",
             "emergency_contact_name": "Jo\u0000hn Doe"}
    status, _ = _post(eport, "/api/customer/preferences", {"preferences": prefs},
                      cookie=f"{CUSTOMER_COOKIE}={sid}")
    assert status == 200
    body = prov.received["/api/provision/preferences_set"]
    assert body["preferences"]["legal_entity_name"] == "Acme GmbH"
    assert body["preferences"]["registered_address"] == "1 Main St"
    assert body["preferences"]["emergency_contact_name"] == "John Doe"


# ---------------------------------------------------------------------- WebAuthn: assertion blobs arrive byte-exact ---
def test_passkey_login_webauthn_blobs_byte_exact(stack, monkeypatch):
    edge, eport, prov = stack
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", "1")
    # 1) mint a single-use challenge through the real edge route
    status, r = _post(eport, "/api/customer/passkey/login/challenge", {})
    assert status == 200 and r.get("challenge")
    challenge = r["challenge"]
    # 2) present an assertion whose crypto blobs carry control-ish bytes — they MUST reach the provisioner unaltered
    cdj = '{"type":"webauthn.get","challenge":"AAAA\u0000","origin":"https://x"}'
    authdata = "SZYN5YgOjGh0NBcPZHZgW4\u200b_krrmihjLHmVzzuoMdl2M"
    credential_id = "cred\u0007id-xyz"
    signature = "MEUCIQ\u202eDsignaturebytes"
    status, _ = _post(eport, "/api/customer/passkey/login/verify",
                      {"challenge": challenge, "credential_id": credential_id,
                       "authenticator_data": authdata, "client_data_json": cdj, "signature": signature})
    assert status == 200
    body = prov.received["/api/provision/passkey_login"]
    assert body["challenge"] == challenge          # passthrough (base64url, unchanged anyway)
    assert body["credential_id"] == credential_id  # byte-exact
    assert body["authenticator_data"] == authdata  # byte-exact
    assert body["client_data_json"] == cdj         # byte-exact — a single altered byte breaks signature verify
    assert body["signature"] == signature          # byte-exact


# ---------------------------------------------------------------------------------- JSON-bomb body is refused 4xx ---
def test_deeply_nested_body_is_rejected_4xx(stack):
    edge, eport, prov = stack
    # build a body nested far deeper than the edge's structure guard allows (depth cap is 8)
    node: dict = {}
    cur = node
    for _ in range(40):
        cur["a"] = {}
        cur = cur["a"]
    raw = json.dumps({"preferences": node}).encode()
    status, resp = _post(eport, "/api/customer/signup/confirm", None, raw_body=raw)
    assert 400 <= status < 500, (status, resp)
    # the bomb never reached the provisioner
    assert "/api/provision/signup_confirm" not in prov.received
