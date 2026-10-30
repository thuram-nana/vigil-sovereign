"""Slice E1 — the keyless custui edge, end-to-end over the edge→provisioner hop.

Two in-process servers: the sovereign cockpit (serving `/api/provision/*`, hop-key gated) and the custui
edge pointed at it. Load-bearing invariants (a false-green is the sharpest isolation break in the program):
  * the full customer flow works over the edge's cookie plane (signup→confirm→login→whoami→logout);
  * member management takes the REQUESTER and the active ORG from the SERVER-side session — a body `org_id`
    is IGNORED (Finding D + tenant isolation at the edge);
  * cross-plane cookie isolation: a customer session id presented to the cockpit as `sigil_session` does NOT
    authenticate (distinct ledger) and the custui cookie name is distinct;
  * POSTs are CSRF-gated (a cross-origin Origin is refused);
  * a password reset severs the account's existing sessions;
  * a dead provisioner is a 502 (the edge never crashes or mints anything itself).
"""
from __future__ import annotations

import http.cookiejar
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server
from sigil.ui.server import build_server

TOKEN = "owner-shared-token-xyz789"
HOP = "test-provision-hop-key-xyz"


def _sovereign(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _edge(provision_base, sessions_dir):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key=HOP, provision_base=provision_base,
                                sessions_dir=sessions_dir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, srv.server_address[1]


def _opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def _stack(tmp_path, monkeypatch):
    """A sovereign cockpit + a custui edge pointed at it over the hop key, with isolated ledgers."""
    from sigil import config
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    ensure_owner_keypair()
    sov, sport = _sovereign(path)
    edge, eport = _edge(f"http://127.0.0.1:{sport}", str(tmp_path / "custsessions"))
    return sov, edge, eport, sport


def _post(opener, port, path, body, *, origin=None):
    o = origin if origin is not None else f"http://127.0.0.1:{port}"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                 method="POST", headers={"Content-Type": "application/json", "Origin": o})
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def _get(opener, port, path, *, cookie=None):
    h = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    with opener.open(req, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def test_signup_confirm_login_whoami_logout_over_edge(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        c, r = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})
        assert c == 200 and "dev_token" in r, (c, r)
        c, r2 = _post(op, ep, "/api/customer/signup/confirm",
                      {"token": r["dev_token"], "password": "customer-pw-1", "org_name": "Acme"})
        assert c == 200 and r2["org_id"].startswith("org_"), (c, r2)
        c, who = _get(op, ep, "/api/customer/whoami")
        assert who["authenticated"] is True and who["username"] == r2["username"]
        assert who["org_id"] == r2["org_id"]                      # session bound to the new org, server-side
        c, _ = _post(op, ep, "/api/customer/logout", {})
        c, who = _get(op, ep, "/api/customer/whoami")
        assert who["authenticated"] is False                      # cookie cleared → no session
        c, r3 = _post(op, ep, "/api/customer/login", {"email": "a@acme.com", "password": "customer-pw-1"})
        assert c == 200 and r3["active_org"] == r2["org_id"], (c, r3)
        c, who = _get(op, ep, "/api/customer/whoami")
        assert who["authenticated"] is True and who["username"] == r2["username"]
    finally:
        sov.shutdown(); edge.shutdown()


def test_member_grant_uses_session_org_and_requester_not_body(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin = _opener()
        t = _post(admin, ep, "/api/customer/signup/request", {"email": "admin@acme.com"})[1]["dev_token"]
        a = _post(admin, ep, "/api/customer/signup/confirm",
                  {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        # a teammate signs up in a SEPARATE browser (its own org)
        mate = _opener()
        t2 = _post(mate, ep, "/api/customer/signup/request", {"email": "mate@acme.com"})[1]["dev_token"]
        m = _post(mate, ep, "/api/customer/signup/confirm",
                  {"token": t2, "password": "customer-pw-2", "org_name": "Mate"})[1]
        mu, mate_org = m["username"], m["org_id"]
        # the admin grants the teammate — passing a BOGUS org_id in the body (the teammate's OWN org). The edge
        # IGNORES the body org and uses the session's bound org, so the grant lands in Acme, never the body's
        # org: a customer can only ever act on their own session-bound tenant (isolation enforced at the edge).
        c, r = _post(admin, ep, "/api/customer/member/grant",
                     {"member_username": mu, "role": "analyst", "org_id": mate_org})
        assert c == 200 and r["role"] == "analyst", (c, r)
        assert r["org_id"] == a["org_id"] and r["org_id"] != mate_org   # session org won; body org ignored
    finally:
        sov.shutdown(); edge.shutdown()


def test_member_management_requires_a_session(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        c, r = _post(_opener(), ep, "/api/customer/member/grant",
                     {"member_username": "cust_whoever", "role": "analyst"})
        assert c == 401, (c, r)                                   # no customer session → refused before the hop
    finally:
        sov.shutdown(); edge.shutdown()


def test_cross_plane_cookie_isolation(tmp_path, monkeypatch):
    sov, edge, ep, sp = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "iso@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm",
              {"token": t, "password": "customer-pw-1", "org_name": "Iso"})
        # pull the edge's session id out of the jar
        jar = op.handlers[[type(h).__name__ for h in op.handlers].index("HTTPCookieProcessor")].cookiejar
        sid = next(ck.value for ck in jar if ck.name == CUSTOMER_COOKIE)
        # present that id to the COCKPIT as `sigil_session` — the operator ledger does not hold it ⇒ anon
        plain = urllib.request.build_opener()
        c, who = _get(plain, sp, "/api/whoami", cookie=f"sigil_session={sid}")
        assert who.get("authenticated") in (False, None), who     # no cross-plane authentication
        # and a bogus operator-style cookie presented to the EDGE is likewise nothing
        c, who = _get(plain, ep, "/api/customer/whoami", cookie=f"sigil_session={sid}")
        assert who["authenticated"] is False                      # edge reads vigil_customer_session only
    finally:
        sov.shutdown(); edge.shutdown()


def test_csrf_cross_origin_post_refused(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        c, r = _post(_opener(), ep, "/api/customer/signup/request", {"email": "x@acme.com"},
                     origin="http://evil.example.com")
        assert c == 403, (c, r)                                   # cross-origin Origin → refused
    finally:
        sov.shutdown(); edge.shutdown()


def test_password_reset_severs_existing_sessions(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "res@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm",
              {"token": t, "password": "old-password-1", "org_name": "Res"})
        assert _get(op, ep, "/api/customer/whoami")[1]["authenticated"] is True
        rt = _post(op, ep, "/api/customer/recover/request", {"email": "res@acme.com"})[1]["dev_token"]
        c, r = _post(op, ep, "/api/customer/recover/confirm", {"token": rt, "new_password": "new-password-2"})
        assert c == 200, (c, r)
        # the pre-reset session is now dead (revoke_all_for_user) — the same cookie no longer authenticates
        assert _get(op, ep, "/api/customer/whoami")[1]["authenticated"] is False
        # and the new password works
        c, r = _post(_opener(), ep, "/api/customer/login", {"email": "res@acme.com", "password": "new-password-2"})
        assert c == 200 and r["username"], (c, r)
    finally:
        sov.shutdown(); edge.shutdown()


def test_dead_provisioner_is_502(tmp_path, monkeypatch):
    from sigil import config
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    # point the edge at a closed loopback port (no sovereign there)
    edge, ep = _edge("http://127.0.0.1:1", str(tmp_path / "custsessions"))
    try:
        c, r = _post(_opener(), ep, "/api/customer/signup/request", {"email": "x@acme.com"})
        assert c == 502, (c, r)                                   # edge stays up; never crashes or mints
    finally:
        edge.shutdown()
