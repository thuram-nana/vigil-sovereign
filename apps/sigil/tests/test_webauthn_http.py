"""Slice 1c-iii — WebAuthn passkey OWNER login end-to-end over the HTTP handler (synthetic ES256 authenticator).

Enroll a passkey via the owner action plane, then log in with a signed assertion → an OWNER cookie session;
replay and signCount-regression and wrong-key are all refused 401.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sigil.governor.identity import ensure_owner_keypair
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-webauthn"


@pytest.fixture(autouse=True)
def _isolate_passkey_store(monkeypatch, tmp_path):
    # the passkey store lives at SIGIL_HOME/.vigil-live/... which is process-global; isolate it per test so
    # one test's enrolled credential / signCount cannot leak into the next (the server thread reads this
    # module global at call time).
    monkeypatch.setattr("sigil.ui.webauthn_store.SIGIL_HOME", tmp_path)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _serve(spine_path):
    ensure_owner_keypair()
    s = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = s.server_address[1]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return s, port


def _req(port, path, *, method="GET", body=None, token=None, cookie=None):
    h = {"Origin": f"http://127.0.0.1:{port}", "Host": f"127.0.0.1:{port}"}
    if token is not None:
        h["X-SIGIL-Token"] = token
    if cookie is not None:
        h["Cookie"] = cookie
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            j = json.loads(e.read().decode() or "{}")
        except Exception:  # noqa: BLE001
            j = {}
        return e.code, dict(e.headers), j


def _spki(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _enroll(port, key, cid):
    code, _h, j = _req(port, "/api/action", method="POST", token=TOKEN,
                       body={"action": "enroll_webauthn", "credential_id": cid, "cose_alg": -7,
                             "public_key_spki_b64": _b64u(_spki(key.public_key()))})
    assert code == 200 and j["ok"], j


def _challenge(port):
    code, _h, j = _req(port, "/api/login/challenge", method="POST", body={})
    assert code == 200
    return j["challenge"]


def _assert_body(port, key, *, cid, challenge, sign_count=1, up=True, rp_id="127.0.0.1"):
    origin = f"http://127.0.0.1:{port}"
    cd = {"type": "webauthn.get", "challenge": _b64u(challenge.encode("utf-8")), "origin": origin}
    client_data = json.dumps(cd).encode("utf-8")
    flags = 0x01 if up else 0x00
    authdata = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", sign_count)
    sig = key.sign(authdata + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    return {"credential_id": cid, "authenticator_data": _b64u(authdata),
            "client_data_json": _b64u(client_data), "signature": _b64u(sig)}


def test_webauthn_login_mints_an_owner_session():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    key = ec.generate_private_key(ec.SECP256R1())
    _enroll(port, key, "c_login")
    ch = _challenge(port)
    code, headers, j = _req(port, "/api/webauthn/assert", method="POST",
                            body=_assert_body(port, key, cid="c_login", challenge=ch, sign_count=1))
    assert code == 200 and j["authenticated"] and j["role"] == "owner", j
    sc = headers.get("Set-Cookie", "")
    assert "sigil_session=" in sc
    sid = sc.split("sigil_session=", 1)[1].split(";", 1)[0]
    # the cookie authenticates as OWNER on a subsequent request
    code, _h, who = _req(port, "/api/whoami", cookie=f"sigil_session={sid}")
    assert code == 200 and who["authenticated"] and who["role"] == "owner"


def test_webauthn_replay_and_signcount_regression_refused():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    key = ec.generate_private_key(ec.SECP256R1())
    _enroll(port, key, "c_replay")
    ch = _challenge(port)
    body = _assert_body(port, key, cid="c_replay", challenge=ch, sign_count=5)
    assert _req(port, "/api/webauthn/assert", method="POST", body=body)[0] == 200
    # replay the SAME assertion → its single-use challenge is consumed → 401
    assert _req(port, "/api/webauthn/assert", method="POST", body=body)[0] == 401
    # a fresh challenge but signCount <= stored(5) → clone refused
    body2 = _assert_body(port, key, cid="c_replay", challenge=_challenge(port), sign_count=5)
    assert _req(port, "/api/webauthn/assert", method="POST", body=body2)[0] == 401
    # a strictly-greater signCount on a fresh challenge is accepted again
    body3 = _assert_body(port, key, cid="c_replay", challenge=_challenge(port), sign_count=6)
    assert _req(port, "/api/webauthn/assert", method="POST", body=body3)[0] == 200


def test_webauthn_wrong_key_refused():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    key = ec.generate_private_key(ec.SECP256R1())
    _enroll(port, key, "c_wrong")
    other = ec.generate_private_key(ec.SECP256R1())           # attacker signs with a DIFFERENT key
    body = _assert_body(port, other, cid="c_wrong", challenge=_challenge(port), sign_count=1)
    assert _req(port, "/api/webauthn/assert", method="POST", body=body)[0] == 401


def test_webauthn_unknown_credential_refused():
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    key = ec.generate_private_key(ec.SECP256R1())
    body = _assert_body(port, key, cid="never-enrolled", challenge=_challenge(port), sign_count=1)
    assert _req(port, "/api/webauthn/assert", method="POST", body=body)[0] == 401


def test_non_object_body_fails_closed_not_crash():
    # RED-PEN BLOCK-1: a body that is valid JSON of the WRONG TYPE (5/"x"/[]/true) must fail CLOSED (401),
    # never crash the pre-auth route with an uncaught AttributeError (which would drop the connection, leak a
    # stderr traceback, and write no audit). Also covers the sibling /api/login.
    _s, port = _serve(tempfile.mktemp(suffix=".jsonl"))
    for bad in (5, "x", [1, 2], True):
        code, _h, _j = _req(port, "/api/webauthn/assert", method="POST", body=bad)
        assert code == 401, f"/api/webauthn/assert non-object body {bad!r} must be 401, got {code}"
    for bad in (5, "x", [1, 2]):
        code, _h, _j = _req(port, "/api/login", method="POST", body=bad)
        assert code == 401, f"/api/login non-object body {bad!r} must be 401 (not a crash), got {code}"
