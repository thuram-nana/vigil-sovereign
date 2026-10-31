"""Slice E1 — the sovereign `/api/provision/*` HTTP surface: the hop-key-gated door to the owner-signed
customer provisioner (the keyless `custui` edge is its only legitimate caller).

Load-bearing invariants (a false-green here would expose the owner-signed mint to the browser or let a
caller forge the acting requester):
  * gated SOLELY by the edge→provisioner hop key (`VIGIL_PROVISION_HOP_KEY`) — NOT operator RBAC, NOT
    browser Origin/CSRF. An unset/blank key, a forged/stale assertion, or an authenticated OPERATOR token
    WITHOUT a valid hop assertion all 403 (fail-closed);
  * Finding D at the transport: the member-management REQUESTER is the HMAC-bound hop principal, never a
    body field — a caller cannot name another admin's username to borrow authority;
  * `/api/provision/*` is NEVER a BOOTSTRAP path (the operator proxy never forwards it);
  * the full signup→confirm→login flow owner-signs end-to-end over HTTP.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.server import BOOTSTRAP_PATHS, build_server
from vigil_core.hopauth import stamp_hop_assertion

TOKEN = "owner-shared-token-xyz789"
HOP = "test-provision-hop-key-abc123"


def _seed():
    """A fresh spine + the persisted owner identity (so build_provisioner's registries can owner-sign). The
    customer GRANTS land on this tempfile spine; the owner KEY is the persisted ~/.sigil identity."""
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    ensure_owner_keypair()
    return path


def _isolate(monkeypatch, tmp_path, *, hop_key=HOP):
    """Set the server's hop key and isolate the provisioner's filesystem ledgers into a per-test tmp dir
    (so rate-limit / token markers never accumulate under a shared SIGIL_HOME — deterministic + no pollution).
    Also opt into dev-token exposure (now off-by-default, CO13) so the test can complete signup without SMTP."""
    from sigil import config
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", hop_key)
    monkeypatch.setenv("VIGIL_PROVISION_DEV_TOKENS", "1")
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())


def _serve(spine_path):
    srv = build_server(token=TOKEN, port=0, spine_path=spine_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.05)
    return srv, port


def _call(port, hop_key, principal, action, body, *, ts=None, extra_headers=None):
    """Stamp a hop assertion the way the custui edge would (role == action, binding principal+method+path+ts)
    and POST it. `extra_headers` lets a test add e.g. an operator token to prove it does NOT help."""
    path = f"/api/provision/{action}"
    tss = str(int(time.time())) if ts is None else str(ts)
    data = json.dumps(body).encode()
    # mirror the edge: role binds the action AND the exact body bytes (NH-1), matching the cockpit's recompute
    bound_role = f"{action}:{hashlib.sha256(data).hexdigest()}"
    sig = stamp_hop_assertion(hop_key, principal, bound_role, "POST", path, tss)
    h = {"Content-Type": "application/json", "X-VIGIL-Provision-Principal": principal,
         "X-VIGIL-Provision-Ts": tss, "X-VIGIL-Provision-Sig": sig}
    if extra_headers:
        h.update(extra_headers)
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def test_signup_then_confirm_then_login_over_http(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    srv, port = _serve(_seed())
    try:
        c, r = _call(port, HOP, "", "signup_request", {"email": "a@acme.com", "ip": "1.1.1.1"})
        assert c == 200 and "dev_token" in r, (c, r)          # email off ⇒ dev token surfaced (dev posture)
        c, r2 = _call(port, HOP, "", "signup_confirm",
                      {"token": r["dev_token"], "password": "customer-pw-1", "org_name": "Acme"})
        assert c == 200 and r2["org_id"].startswith("org_"), (c, r2)
        c, r3 = _call(port, HOP, "", "login", {"email": "a@acme.com", "password": "customer-pw-1"})
        assert c == 200 and r3["username"] == r2["username"] and r3["orgs"] == [r2["org_id"]], (c, r3)
    finally:
        srv.shutdown()


def test_provision_fails_closed_when_hop_key_unset(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path, hop_key="")               # server has NO hop key configured
    srv, port = _serve(_seed())
    try:
        # even a "well-formed" assertion stamped under some key is refused: with no server key, verify → False
        c, _ = _call(port, "any-client-key", "", "signup_request", {"email": "x@acme.com"})
        assert c == 403, c
    finally:
        srv.shutdown()


def test_operator_token_without_hop_is_refused(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    srv, port = _serve(_seed())
    try:
        # an authenticated OPERATOR token but NO hop headers → 403 (provision is hop-gated, never RBAC-gated)
        path = "/api/provision/signup_request"
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     data=json.dumps({"email": "x@acme.com"}).encode(),
                                     headers={"Content-Type": "application/json", "X-SIGIL-Token": TOKEN},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as rr:
                code = rr.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403, code
    finally:
        srv.shutdown()


def test_forged_or_stale_hop_assertion_refused(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    srv, port = _serve(_seed())
    try:
        c, _ = _call(port, "WRONG-KEY", "", "signup_request", {"email": "x@acme.com"})   # forged sig
        assert c == 403, c
        c, _ = _call(port, HOP, "", "signup_request", {"email": "x@acme.com"},
                     ts=int(time.time()) - 10_000)                                        # stale ts (replay)
        assert c == 403, c
    finally:
        srv.shutdown()


def test_member_grant_requester_is_hop_bound_not_a_body_field(tmp_path, monkeypatch):
    _isolate(monkeypatch, tmp_path)
    srv, port = _serve(_seed())
    try:
        t = _call(port, HOP, "", "signup_request", {"email": "admin@acme.com"})[1]["dev_token"]
        admin = _call(port, HOP, "", "signup_confirm",
                      {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        au, oid = admin["username"], admin["org_id"]
        t2 = _call(port, HOP, "", "signup_request", {"email": "mate@acme.com"})[1]["dev_token"]
        mu = _call(port, HOP, "", "signup_confirm",
                   {"token": t2, "password": "customer-pw-2", "org_name": "Mate"})[1]["username"]
        # the admin (hop principal == au) grants the teammate into acme → authorized + owner-signed
        c, r = _call(port, HOP, au, "member_grant", {"org_id": oid, "member_username": mu, "role": "analyst"})
        assert c == 200 and r["role"] == "analyst", (c, r)
        # Finding D: a caller whose hop principal is the NON-admin teammate cannot grant — even though the
        # body names the real admin as "requester". The body field is IGNORED; the HMAC-bound principal wins.
        c, r = _call(port, HOP, mu, "member_grant",
                     {"org_id": oid, "member_username": mu, "role": "org_admin", "requester": au})
        assert c == 403, (c, r)
    finally:
        srv.shutdown()


def test_provision_paths_are_not_bootstrap_paths():
    # design-pass requirement: /api/provision/* is NEVER a token-optional bootstrap route (the operator proxy
    # forwards only BOOTSTRAP_PATHS unauthenticated; the provision surface is hop-gated and edge-only).
    for a in ("signup_request", "signup_confirm", "login", "recover_request", "recover_confirm",
              "member_grant", "member_revoke"):
        assert f"/api/provision/{a}" not in BOOTSTRAP_PATHS


def test_hop_assertion_is_bound_to_the_body_rejecting_a_swapped_body(tmp_path, monkeypatch):
    # NH-1: the hop binds sha256(body). A sig stamped over body B1 but POSTed with a DIFFERENT body B2 (a
    # replay-with-swapped-body) is refused — the recomputed role/MAC no longer matches.
    _isolate(monkeypatch, tmp_path)
    srv, port = _serve(_seed())
    try:
        action, path, tss = "signup_request", "/api/provision/signup_request", str(int(time.time()))
        b1 = json.dumps({"email": "real@acme.com"}).encode()
        bound = f"{action}:{hashlib.sha256(b1).hexdigest()}"       # sig is over B1...
        sig = stamp_hop_assertion(HOP, "", bound, "POST", path, tss)
        b2 = json.dumps({"email": "attacker@evil.com"}).encode()   # ...but we POST B2
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=b2, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "X-VIGIL-Provision-Principal": "",
                                              "X-VIGIL-Provision-Ts": tss, "X-VIGIL-Provision-Sig": sig})
        code = None
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403, code                                   # body-bound hop refuses the swapped body
    finally:
        srv.shutdown()


def test_store_or_audit_fault_returns_clean_500_not_a_handler_crash(tmp_path, monkeypatch):
    # P3 / CO12: Finding B made the critical audit re-raise. A store/audit fault on a provision op must yield
    # a controlled 500 (the catch-all), never an uncaught exception that aborts the ThreadingHTTPServer thread.
    _isolate(monkeypatch, tmp_path)

    class _BoomProvisioner:
        def request_signup(self, *a, **k):
            raise RuntimeError("simulated audit/store fault")

    monkeypatch.setattr("sigil.ui.provision.build_provisioner", lambda *a, **k: _BoomProvisioner())
    srv, port = _serve(_seed())
    try:
        c, r = _call(port, HOP, "", "signup_request", {"email": "x@acme.com"})
        assert c == 500, (c, r)                                    # clean 5xx, connection intact (no crash)
    finally:
        srv.shutdown()
