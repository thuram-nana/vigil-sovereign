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

import base64
import http.client
import http.cookiejar
import http.cookies
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sigil.governor import totp as _totp
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui.custui import CUSTOMER_COOKIE, build_customer_server
from sigil.ui.server import build_server

from test_secrets_sealed import make_fake_tpm   # fake-TPM vault provisioner (for the MFA seal)

TOKEN = "owner-shared-token-xyz789"
HOP = "test-provision-hop-key-xyz"


@pytest.fixture(autouse=True)
def _scrub_shared_owner_state():
    """These full-stack tests call ensure_owner_keypair()/build_server() against the shared SIGIL_HOME, so
    they leave an owner keypair there with NO sealed vault KEK. In the shared-SIGIL_HOME CI process (the P7
    governor job / the full apps/sigil run) that half-provisioned home breaks the later-collected
    test_ui_durability, whose backup can only self-provision a KEK on a CLEAN home. Scrub the owner-key +
    vault state before AND after each test (the same before/after idiom test_ui_durability uses for its own
    HEAD/SPINE state) so the shared home is left pristine; every helper here re-provisions what it needs."""
    import shutil
    from sigil import config
    from sigil.platform import vault as _vault

    def _scrub():
        shutil.rmtree(config.KEYS_DIR, ignore_errors=True)
        shutil.rmtree(config.SIGIL_HOME / "vault", ignore_errors=True)
        _vault.reset_owner_vault_for_test()

    _scrub()
    yield
    _scrub()


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
    monkeypatch.setenv("VIGIL_PROVISION_DEV_TOKENS", "1")   # dev-token exposure is now off-by-default (CO13)
    # isolate every SIGIL_HOME-rooted provisioner ledger to the test tmp dir — including the E3b MFA replay +
    # the passkey sign-count floor, else their persistent markers leak stale state across test runs (a stale
    # (username,step) or a stale sign-count floor would spuriously refuse a fresh enroll/login).
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR",
                 "CUSTOMER_MFA_REPLAY_DIR", "CUSTOMER_PASSKEY_SIGNCOUNT_DIR", "CHECKOUT_RATELIMIT_DIR",
                 "PENDING_PLAN_CHECKOUT_DIR"):
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
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def _get_raw(port, path, *, cookie=None):
    """A RAW GET returning (status, headers-dict, body-bytes) — for the static SPA (non-JSON) responses."""
    h = {"Cookie": cookie} if cookie else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _owner_lease(org_id, host, *, units=5, nonce="edge-nonce-1", now=None):
    """Mint an owner-signed ``CreditLaunchLease`` directly (no gate) with the SAME owner key the cockpit uses
    (``ensure_owner_keypair`` in ``_stack``). This exercises the edge's cancel/settle RELAY + its tenant
    binding without standing up the full 4-conjunct reserve (ownership proof + seam authority + credits) —
    that success path is ``test_launch_gate.py``'s job; here we pin only what the EDGE adds."""
    from datetime import datetime, timedelta, timezone

    from sigil.governor.identity import owner_keypair
    from sigil.ui.target_authorization import _customer_slug
    from vigil_core import CreditLaunchLease, sign_credit_launch_lease
    t = datetime.now(timezone.utc) if now is None else now
    kp = owner_keypair()
    doc = CreditLaunchLease(
        engagement_slug=_customer_slug(org_id, host), org_id=org_id, scope_host=host, units_reserved=units,
        not_before=t - timedelta(hours=1), not_after=t + timedelta(hours=1), nonce=nonce, issued_at=t.timestamp())
    return sign_credit_launch_lease(doc, {"owner": kp.private_key_b64}).model_dump(mode="json")


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


def test_target_requires_session(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        c, r = _post(_opener(), ep, "/api/customer/target/challenge", {"host": "apme.cm"})
        assert c == 401, (c, r)                                   # no customer session → refused before the hop
    finally:
        sov.shutdown(); edge.shutdown()


def test_target_challenge_gated_on_run_engagement_and_bound_to_session_org(tmp_path, monkeypatch):
    """Slice G0 over the edge: a billing-only org_admin is DENIED (billing != testing); an operator member
    gets a challenge; and the challenge binds the SESSION's org, never a body-supplied one (tenant isolation);
    target/verify is fail-closed when ownership verification is disabled."""
    from sigil.governor.asset_ownership import AssetOwnershipRegistry
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "own@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        u, oid = conf["username"], conf["org_id"]
        # the default signup role is org_admin (billing) — it may NOT register assessment targets
        c, r = _post(op, ep, "/api/customer/target/challenge", {"host": "apme.cm"})
        assert c == 403, (c, r)                                   # billing != testing, enforced at the sovereign gate
        # the owner promotes the member to operator (carries run_engagement) — an owner act on the sovereign store
        OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 1e6)
        # now a challenge is issued — and a BOGUS body org_id is IGNORED (the session's org is authoritative)
        c, ch = _post(op, ep, "/api/customer/target/challenge", {"host": "apme.cm", "org_id": "org_EVIL"})
        assert c == 200 and ch["dns_name"] == "_vigil-challenge.apme.cm", (c, ch)
        reg = AssetOwnershipRegistry(sov.store())
        assert reg.challenge(oid, "apme.cm") is not None          # recorded under the SESSION org
        assert reg.challenge("org_EVIL", "apme.cm") is None       # never the body-supplied org (isolation)
        # verify is fail-closed while ownership verification is disabled (no fetcher configured)
        c, r = _post(op, ep, "/api/customer/target/verify", {"host": "apme.cm", "method": "well-known"})
        assert c == 400, (c, r)                                   # fail-closed through the edge
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


def test_an_edge_without_a_hop_key_refuses_every_verb_cleanly(tmp_path, monkeypatch):
    """Audit E1c: an edge with a BLANK hop key used to surface `body_binding`'s ValueError — a 400 on POST and, on
    GET (no catch-all there), a traceback and a DROPPED connection. Both verbs now get the cockpit's own clean 403
    over a connection that answers, and nothing is stamped or sent."""
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "nokey@acme.com"})[1]["dev_token"]
        assert _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "N"})[0] == 200
        jar = next(h for h in op.handlers if hasattr(h, "cookiejar")).cookiejar
        cookie = "; ".join(f"{c.name}={c.value}" for c in jar)
        edge.hop_key = ""                                         # the edge lost its hop key
        assert _post(op, ep, "/api/customer/login", {"email": "nokey@acme.com", "password": "customer-pw-1"}) \
            == (403, {"error": "provision denied (hop)"})
        conn = http.client.HTTPConnection("127.0.0.1", ep, timeout=5)
        try:
            conn.request("GET", "/api/customer/billing", headers={"Cookie": cookie})
            r = conn.getresponse()                                # (main: RemoteDisconnected)
            assert (r.status, json.loads(r.read())) == (403, {"error": "provision denied (hop)"})
        finally:
            conn.close()
    finally:
        sov.shutdown(); edge.shutdown()


def _bad_provisioner(reply: bytes):
    """A loopback stand-in for the cockpit that answers every hop with 200 + ``reply`` VERBATIM (raw bytes, so
    the reply can lie about its length — a truncated body — or not be JSON at all)."""
    import socketserver

    class _H(socketserver.StreamRequestHandler):
        def handle(self):
            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                pass                                              # (headers; the body is never read)
            self.wfile.write(reply)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


_UNREADABLE = (502, {"error": "provisioner reply unreadable"})


@pytest.mark.parametrize("reply,want", [
    (b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>", _UNREADABLE),
    (b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"ok\": tr", _UNREADABLE),
    (b"HTTP/1.0 403 Forbidden\r\nContent-Length: 400\r\n\r\n{\"error\": \"pro",          # a truncated REFUSAL keeps
     (403, {"error": "provision error"})),                                                  # its status
], ids=["not_json", "truncated", "truncated_refusal"])
def test_an_unreadable_provisioner_reply_is_one_clean_answer_on_every_verb(tmp_path, monkeypatch, reply, want):
    """Audit E1c (root cause): a hop reply the edge cannot read used to raise out of `_provision` — a 400 on POST
    and, on GET, a handler traceback and a DROPPED connection. Both verbs now answer the same clean status."""
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    bad, bport = _bad_provisioner(reply)
    edge, ep = _edge(f"http://127.0.0.1:{bport}", str(tmp_path / "custsessions"))
    try:
        assert _post(_opener(), ep, "/api/customer/login", {"email": "x@acme.com", "password": "pw"}) == want
        sid = edge.sessions.create("cust_reader", "customer", org_id="org_reader")
        assert _get(_opener(), ep, "/api/customer/billing", cookie=f"{CUSTOMER_COOKIE}={sid}") == want
    finally:
        edge.shutdown(); bad.shutdown()


def test_an_unexpected_get_fault_answers_a_clean_500(tmp_path, monkeypatch):
    """Any other GET-handler fault gets do_POST's catch-all treatment: one JSON error, no internals, never a
    dropped connection."""
    from sigil.ui.custui import CustomerHandler

    def boom(self, action):
        raise RuntimeError("internal detail that must not leak")
    monkeypatch.setattr(CustomerHandler, "_customer_read_relay", boom)
    edge, ep = _edge("http://127.0.0.1:1", str(tmp_path / "custsessions"))
    try:
        assert _get(_opener(), ep, "/api/customer/billing") == (500, {"error": "request failed"})
    finally:
        edge.shutdown()


def test_serve_customer_cli_fails_closed_on_a_public_bind():
    """The `sigil serve-customer` CLI must REFUSE a public/unspecified bind (exit 2) — the customer edge
    sets a session cookie, so it may never face the internet directly; it binds loopback/private behind a
    reverse proxy. This pins the guard durably so a refactor can't silently drop it."""
    import types

    from sigil.cli import cmd_serve_customer
    for bad in ("0.0.0.0", "::", "8.8.8.8"):
        args = types.SimpleNamespace(host=bad, port=0, allow_host=[], allow_origin=[])
        try:
            cmd_serve_customer(args)
        except SystemExit as e:
            assert e.code == 2, (bad, e.code)
        else:
            raise AssertionError(f"serve-customer did NOT fail closed on {bad!r}")


def test_build_customer_server_is_a_keyless_edge_with_the_distinct_cookie(tmp_path):
    """The edge is wired keyless: it carries the edge→provisioner hop secret + a loopback provisioner base
    and its OWN session cookie name (distinct from the operator plane). No owner key is ever loaded here."""
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="hk-123",
                                provision_base="http://127.0.0.1:9999/", sessions_dir=str(tmp_path / "s"))
    try:
        assert srv.hop_key == "hk-123"
        assert srv.provision_base == "http://127.0.0.1:9999"      # trailing slash normalized away
        assert srv.sessions is not None                           # its OWN ledger (not the operator's)
        assert CUSTOMER_COOKIE == "vigil_customer_session"        # distinct from operator `sigil_session`
        # KEYLESS BY CONSTRUCTION — stronger than a name scan (red-pen LOW): the custui module must not
        # import or reference the owner signing key / identity vault AT ALL. Its ONLY credential is the
        # edge→provisioner HMAC hop key; to hold an owner key it would have to pull in one of these owner-key
        # entrypoints, so forbid them in the module source. (assert_no_offense blocks the offense plane;
        # this guards the sovereign OWNER KEY specifically, which must live only in the provisioner.)
        import inspect

        from sigil.ui import custui as _custui
        src = inspect.getsource(_custui)
        for forbidden in ("ensure_owner_keypair", "owner_vault", "OWNER_PRIV", "owner_privkey",
                          "owner_sign", "sign_policy", "SpineStore", "Ed25519Priv", "private_key"):
            assert forbidden not in src, f"custui references {forbidden!r} — the edge must hold NO owner key"
        # and the live object carries the hop key as its only secret — no attribute hints at a signing key.
        assert srv.hop_key and not any(
            k for k in vars(srv) if "owner" in k.lower() or "sign" in k.lower() or "privkey" in k.lower())
    finally:
        srv.server_close()


def test_launch_requires_session(tmp_path, monkeypatch):
    """Both launch edge actions refuse before the hop when there is no customer session — the edge never
    reaches the owner-signed provisioner for an anonymous caller (mirrors the target/member guards)."""
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        c, r = _post(_opener(), ep, "/api/customer/launch/reserve", {"host": "acme.example"})
        assert c == 401, (c, r)
        c, r = _post(_opener(), ep, "/api/customer/launch/cancel", {"lease": {}})
        assert c == 401, (c, r)
        c, r = _post(_opener(), ep, "/api/customer/launch/start", {"lease": {}})
        assert c == 401, (c, r)                                   # K3 start is session-gated before the hop too
    finally:
        sov.shutdown(); edge.shutdown()


def test_launch_reserve_billing_admin_denied_then_body_org_ignored(tmp_path, monkeypatch):
    """Billing != testing AND tenant isolation at the launch edge (Slice G). A billing-only org_admin is
    DENIED at reserve — credits/role never authorize a test. Once promoted to operator, membership passes and
    the next conjunct (ownership proof) fails NAMING the org: assert it is the SESSION org, never the
    body-supplied `org_EVIL`, proving the edge drops the body org before it can reach the owner-signed gate."""
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "launch@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        u, oid = conf["username"], conf["org_id"]
        # default signup role is org_admin (billing) — it may NOT launch assessments (billing != testing)
        c, r = _post(op, ep, "/api/customer/launch/reserve", {"host": "acme.example"})
        assert c == 403, (c, r)
        # the owner promotes the member to operator (carries run_engagement) — an owner act on the sovereign store
        OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 1e6)
        # membership now passes; the ownership-proof conjunct fails and names the org. A BOGUS body org_id is
        # IGNORED — the reserve runs against the SESSION's org, so the refusal names it and never the body org.
        c, r = _post(op, ep, "/api/customer/launch/reserve", {"host": "acme.example", "org_id": "org_EVIL"})
        assert c == 403, (c, r)
        assert oid in r["error"] and "org_EVIL" not in r["error"], r   # session org authoritative; body ignored
    finally:
        sov.shutdown(); edge.shutdown()


def test_launch_cancel_relays_and_is_tenant_bound(tmp_path, monkeypatch):
    """The cancel/settle RELAY works end-to-end over the edge (a lease for the SESSION's OWN org cancels and
    refunds the full reserved amount through edge→hop→provisioner→gate), and it is TENANT-BOUND: a lease
    minted for a DIFFERENT org is refused even when a valid customer presents it (``expect_org_id`` == the
    session org), so one tenant can never release/settle another tenant's owner-signed reservation."""
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        # customer A, promoted to operator so launch_cancel's admit_customer(run_engagement) gate passes
        a = _opener()
        ta = _post(a, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        ca = _post(a, ep, "/api/customer/signup/confirm",
                   {"token": ta, "password": "customer-pw-1", "org_name": "Acme"})[1]
        OrgRegistry(sov.store()).grant_membership(ca["org_id"], ca["username"], "operator",
                                                  issued_at=time.time() + 1e6)
        # a second tenant B (distinct real org id)
        b = _opener()
        tb = _post(b, ep, "/api/customer/signup/request", {"email": "b@beta.com"})[1]["dev_token"]
        cb = _post(b, ep, "/api/customer/signup/confirm",
                   {"token": tb, "password": "customer-pw-2", "org_name": "Beta"})[1]
        assert ca["org_id"] != cb["org_id"]
        # A cancels A's OWN lease → the edge relays it, the gate verifies it owner-signed and refunds in full
        lease_a = _owner_lease(ca["org_id"], "acme.example", units=5, nonce="edge-a-1")
        c, r = _post(a, ep, "/api/customer/launch/cancel", {"lease": lease_a})
        assert c == 200 and r["refunded"] == 5, (c, r)             # positive relay: cancel + refund over the edge
        # A presents B's lease → refused by the tenant binding (expect_org_id == A's session org)
        lease_b = _owner_lease(cb["org_id"], "beta.example", units=5, nonce="edge-b-1")
        c, r = _post(a, ep, "/api/customer/launch/cancel", {"lease": lease_b})
        assert c == 403 and "different org" in r["error"], (c, r)  # cannot settle another tenant's reservation
    finally:
        sov.shutdown(); edge.shutdown()


def test_serve_customer_cli_unions_allowlist_flags_and_env(monkeypatch):
    """`cmd_serve_customer` must feed the edge's anti-DNS-rebind allowlist the de-duped UNION of the
    repeatable --allow-host/--allow-origin flags and the $VIGIL_CUSTOMER_ALLOWED_* env vars — this is the
    sole gate that lets the edge accept the proxy's forwarded Host/Origin, so pin it (red-pen LOW)."""
    import types

    from sigil import cli
    captured = {}
    monkeypatch.setattr("sigil.ui.custui.serve_customer", lambda **kw: captured.update(kw))
    monkeypatch.setenv("VIGIL_CUSTOMER_ALLOWED_HOSTS", "app.example.com, app.example.com, env.example")
    monkeypatch.setenv("VIGIL_CUSTOMER_ALLOWED_ORIGINS", "https://app.example.com")
    args = types.SimpleNamespace(host="127.0.0.1", port=0,
                                 allow_host=["flag.example.com", "app.example.com"],
                                 allow_origin=["https://flag.example.com"])
    cli.cmd_serve_customer(args)
    # flags first, then env; de-duped, order-preserving (the _multi contract shared with cmd_serve).
    assert captured["extra_hosts"] == ("flag.example.com", "app.example.com", "env.example")
    assert captured["extra_origins"] == ("https://flag.example.com", "https://app.example.com")
    assert captured["host"] == "127.0.0.1"


# ---- Slice I backend: customer-plane READS over the edge (admit_customer-gated, session-org-scoped) ----
def test_customer_reads_billing_and_invoices_and_billing_not_testing(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid = conf["org_id"]
        # the signup default role (org_admin) CAN read its own billing + invoices (view_billing/view_invoices)
        c, ov = _get(op, ep, "/api/customer/billing")
        assert c == 200 and ov["org_id"] == oid, (c, ov)
        c, inv = _get(op, ep, "/api/customer/invoices")
        assert c == 200 and inv["org_id"] == oid and inv["count"] == 0, (c, inv)
        # BILLING != TESTING: the billing org_admin may NOT read assessment RESULTS (view_assessments is
        # operator-only) — denied through the edge.
        assert _get(op, ep, "/api/customer/assessments")[0] == 403
        assert _get(op, ep, "/api/customer/assessments/findings")[0] == 403
    finally:
        sov.shutdown(); edge.shutdown()


def test_operator_member_reads_assessments_over_the_edge(tmp_path, monkeypatch):
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid, u = conf["org_id"], conf["username"]
        OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 1e6)   # +view_assessments
        c, summ = _get(op, ep, "/api/customer/assessments")
        assert c == 200 and summ["org_id"] == oid, (c, summ)
        c, f = _get(op, ep, "/api/customer/assessments/findings")
        assert c == 200 and f["org_id"] == oid and f["count"] == 0, (c, f)
    finally:
        sov.shutdown(); edge.shutdown()


def test_customer_assets_read_over_the_edge_and_billing_not_testing(tmp_path, monkeypatch):
    """SS-4: the /api/customer/assets 'Domains' read is wired on the edge, relays to assets_overview, and is
    operator-gated — a signup-default BILLING org_admin is denied (billing != testing); an operator member
    reads their own (empty) tenant-scoped asset list."""
    from sigil.governor.orgs import OrgRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        oid, u = conf["org_id"], conf["username"]
        assert _get(op, ep, "/api/customer/assets")[0] == 403          # billing org_admin: no view_assessments
        OrgRegistry(sov.store()).grant_membership(oid, u, "operator", issued_at=time.time() + 1e6)
        c, assets = _get(op, ep, "/api/customer/assets")
        assert c == 200 and assets == {"assets": []}, (c, assets)      # operator: tenant-scoped, empty for now
    finally:
        sov.shutdown(); edge.shutdown()


def test_customer_reads_require_a_session(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        for path in ("/api/customer/billing", "/api/customer/invoices", "/api/customer/assessments",
                     "/api/customer/assessments/findings"):
            assert _get(_opener(), ep, path)[0] == 401, path    # no session cookie -> refused before the hop
    finally:
        sov.shutdown(); edge.shutdown()


# ---- cross-tenant isolation MERGE-GATE (governance R3): two orgs, one edge ----------------------------
def test_cross_tenant_isolation_two_customer_orgs(tmp_path, monkeypatch):
    """Two customer orgs on one edge: org A's authenticated session sees ONLY org A across every read and
    CANNOT reach org B's data by ANY edge path — there is no client-supplied org selector; the edge scopes
    every read to the SESSION org (admit_customer, no global leg). Org B's own session sees B's seeded
    credits (positive control). This pins the 'IDOR-safe by construction' guarantee as an explicit two-org
    gate, the governance-review requirement before any paying customer."""
    from sigil.governor.wallet import WalletRegistry
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        # org A (founderA is org_admin of A)
        opA = _opener()
        tA = _post(opA, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        orgA = _post(opA, ep, "/api/customer/signup/confirm",
                     {"token": tA, "password": "customer-pw-A1", "org_name": "Acme A"})[1]["org_id"]
        # org B (founderB is org_admin of B), SEEDED (owner path) with credits B must keep private
        opB = _opener()
        tB = _post(opB, ep, "/api/customer/signup/request", {"email": "b@beta.com"})[1]["dev_token"]
        orgB = _post(opB, ep, "/api/customer/signup/confirm",
                     {"token": tB, "password": "customer-pw-B1", "org_name": "Beta B"})[1]["org_id"]
        assert orgA and orgB and orgA != orgB
        WalletRegistry(sov.store()).grant(orgB, 1000, "topup", entry_id="seed-b", issued_at=time.time())

        # A's session sees A (same trial baseline as B, but NOT B's +1000 seed)
        cA, bA = _get(opA, ep, "/api/customer/billing")
        assert cA == 200 and bA["org_id"] == orgA, (cA, bA)
        assert _get(opA, ep, "/api/customer/whoami")[1]["org_id"] == orgA
        # B's own session sees B — and exactly 1000 MORE than A (same trial, plus B's private seed)
        cB, bB = _get(opB, ep, "/api/customer/billing")
        assert cB == 200 and bB["org_id"] == orgB, (cB, bB)
        assert bB["credits"]["available"] == bA["credits"]["available"] + 1000, (bA, bB)
        # IDOR attempt: A names org B via the query -> IGNORED (path-matched read; org from the session only)
        cQ, bQ = _get(opA, ep, f"/api/customer/billing?org_id={orgB}")
        assert cQ == 200 and bQ["org_id"] == orgA, (cQ, bQ)
        assert bQ["credits"]["available"] == bA["credits"]["available"]      # still A's balance, never B's
        # every other read is session-scoped to A too (never B)
        for path in ("/api/customer/invoices", "/api/customer/assessments"):
            c, r = _get(opA, ep, path)
            assert c in (200, 403) and (c == 403 or r.get("org_id") == orgA), (path, c, r)
    finally:
        sov.shutdown(); edge.shutdown()


# ---- Slice I: the keyless edge serves its own hash-routed customer SPA (static, strict-CSP) ----------
def test_customer_spa_shell_and_assets_served_with_strict_csp(tmp_path):
    # static GETs need no provisioner — build a bare edge (any provision_base; it is never called here)
    edge, ep = _edge("http://127.0.0.1:1", str(tmp_path / "s"))
    try:
        code, hdr, body = _get_raw(ep, "/")                      # the SPA shell at the mount root
        assert code == 200 and "text/html" in hdr.get("Content-Type", ""), (code, hdr)
        assert b'<div id="app"' in body and b"app.js" in body    # it IS the app shell
        # strict CSP + nosniff on the SPA response; NO inline-script allowance; NO token/secret in the page
        csp = hdr.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp and "'unsafe-inline'" not in csp, csp
        assert hdr.get("X-Content-Type-Options") == "nosniff"
        assert b"__VIGIL_TOKEN__" not in body and b"data-token" not in body
        # every vendored asset serves with the right content-type (relative refs resolve against the mount)
        for asset, ctype in (("/app.js", "javascript"), ("/ui.js", "javascript"),
                             ("/tokens.css", "text/css"), ("/components.css", "text/css"), ("/app.css", "text/css")):
            c, h2, b2 = _get_raw(ep, asset)
            assert c == 200 and ctype in h2.get("Content-Type", "") and b2, (asset, c, h2.get("Content-Type"))
    finally:
        edge.shutdown()


def test_customer_spa_traversal_refused_and_unknown_api_does_not_leak_the_shell(tmp_path):
    edge, ep = _edge("http://127.0.0.1:1", str(tmp_path / "s"))
    try:
        # URL-encoded ..-traversal (bypasses client-side normalization) must never escape customer_app/
        for p in ("/%2e%2e/custui.py", "/%2e%2e/%2e%2e/config.py", "/sub/%2e%2e/%2e%2e/%2e%2e/custui.py"):
            c, _, _ = _get_raw(ep, p)
            assert c == 404, (p, c)
        # an unknown /api/* route 404s as JSON and must NOT fall through to the SPA shell (no HTML leak)
        c, hdr, body = _get_raw(ep, "/api/customer/nope")
        assert c == 404 and b'<div id="app"' not in body, (c, body[:80])
        # and a real API GET still answers JSON (not the shell): whoami with no cookie -> {authenticated:false}
        c2, h2, b2 = _get_raw(ep, "/api/customer/whoami")
        assert c2 == 200 and "application/json" in h2.get("Content-Type", "") and b'"authenticated"' in b2
    finally:
        edge.shutdown()


# ======================================================================================================
# E2b — the customer Google-OIDC round trip over the edge (edge 302 → fake IdP → callback → hop → _mint)
# ======================================================================================================
_GOOGLE_ISS = "https://accounts.google.com"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class _MiniIdP:
    """A loopback fake Google: one RS256 key, its JWKS, and an id_token minter. Injected into the SOVEREIGN
    provisioner (customer_oidc_http_post / _jwks_fetcher) so the edge round-trip touches NO network."""

    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "mini-kid"
        self.next_id_token = None

    def _jwk(self):
        n = self._key.public_key().public_numbers()
        return {"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                "n": _b64u(n.n.to_bytes((n.n.bit_length() + 7) // 8, "big")),
                "e": _b64u(n.e.to_bytes((n.e.bit_length() + 7) // 8, "big"))}

    def http_post(self, _url, _form):          # the mock token endpoint
        return {"id_token": self.next_id_token, "token_type": "Bearer"}

    def jwks_fetcher(self, _url):              # the mock JWKS endpoint
        return {"keys": [self._jwk()]}

    def mint(self, *, nonce, sub="g-sub-1", email="g@gmail.com", email_verified=True):
        now = int(time.time())
        claims = {"iss": _GOOGLE_ISS, "aud": "client-123", "sub": sub, "exp": now + 300, "iat": now,
                  "nonce": nonce, "email": email, "email_verified": email_verified}
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        h, p = _b64u(json.dumps(header).encode()), _b64u(json.dumps(claims).encode())
        sig = self._key.sign(f"{h}.{p}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64u(sig)}"


def _stack_oidc(tmp_path, monkeypatch, idp, *, enabled=True):
    """A sovereign cockpit with customer-OIDC enabled + a fake IdP injected, plus the custui edge over the hop."""
    from sigil import config
    monkeypatch.setenv("VIGIL_PROVISION_HOP_KEY", HOP)
    if enabled:
        monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_CLIENT_ID", "client-123")
    monkeypatch.setenv("VIGIL_CUSTOMER_OIDC_REDIRECT_URI", "http://127.0.0.1/api/customer/oidc/callback")
    for attr in ("EMAIL_TOKENS_DIR", "LOGIN_RATELIMIT_DIR", "SIGNUP_CAP_DIR", "MEMBER_RATELIMIT_DIR"):
        monkeypatch.setattr(config, attr, tmp_path / attr.lower())
    path = tempfile.mktemp(suffix=".jsonl")
    SpineStore(path).append(kind="message", source="x", actor="user", payload={"text": "hi"})
    ensure_owner_keypair()
    sov = build_server(token=TOKEN, port=0, spine_path=path,
                       customer_oidc_http_post=idp.http_post, customer_oidc_jwks_fetcher=idp.jwks_fetcher)
    threading.Thread(target=sov.serve_forever, daemon=True).start()
    time.sleep(0.05)
    sport = sov.server_address[1]
    edge, eport = _edge(f"http://127.0.0.1:{sport}", str(tmp_path / "custsessions"))
    return sov, edge, eport, sport


def _edge_raw(port, path, *, cookie=None):
    """A no-redirect GET to the edge (http.client never follows 302) → (status, headers, body)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Host": f"127.0.0.1:{port}"}
    if cookie:
        h["Cookie"] = cookie
    conn.request("GET", path, headers=h)
    r = conn.getresponse()
    body = r.read()
    out = (r.status, dict(r.getheaders()), body)
    conn.close()
    return out


def _oidc_login(ep):
    """GET the edge /oidc/login (no redirect-follow); capture state+nonce from the authorize URL + the sid cookie."""
    st, hdr, _ = _edge_raw(ep, "/api/customer/oidc/login")
    assert st == 302, (st, hdr)
    loc = hdr.get("Location")
    params = parse_qs(urlparse(loc).query)
    sid = http.cookies.SimpleCookie(hdr.get("Set-Cookie"))["vigil_customer_oidc_sid"].value
    return params["state"][0], params["nonce"][0], sid, loc


def test_oidc_login_302s_to_the_idp_and_sets_the_lax_sid_cookie(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, _MiniIdP())
    try:
        st, hdr, _ = _edge_raw(ep, "/api/customer/oidc/login")
        assert st == 302
        loc = hdr.get("Location")
        assert loc.startswith("https://accounts.google.com/o/oauth2/v2/auth?")   # the pinned authorize endpoint
        q = parse_qs(urlparse(loc).query)
        assert q["client_id"] == ["client-123"] and q["code_challenge_method"] == ["S256"]
        assert q["response_type"] == ["code"] and q["state"] and q["nonce"] and q["code_challenge"]
        setck = hdr.get("Set-Cookie")
        assert "vigil_customer_oidc_sid=" in setck and "HttpOnly" in setck and "SameSite=Lax" in setck
        assert "Path=/api/customer/oidc" in setck                 # path-scoped to the OIDC routes only
    finally:
        sov.shutdown(); edge.shutdown()


def test_oidc_routes_are_404_when_disabled(tmp_path, monkeypatch):
    # with the toggle OFF the edge's OIDC routes are absent (byte-identical to a build without customer OIDC)
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, _MiniIdP(), enabled=False)
    try:
        monkeypatch.delenv("VIGIL_CUSTOMER_OIDC_ENABLED", raising=False)
        assert _edge_raw(ep, "/api/customer/oidc/login")[0] == 404
        assert _edge_raw(ep, "/api/customer/oidc/callback?code=x&state=y")[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()


def test_oidc_full_round_trip_mints_a_customer_session_never_an_operator(tmp_path, monkeypatch):
    idp = _MiniIdP()
    sov, edge, ep, sp = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        state, nonce, sid, _ = _oidc_login(ep)
        idp.next_id_token = idp.mint(nonce=nonce, sub="g-sub-1", email="founder@gmail.com")
        st, hdr, _ = _edge_raw(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}",
                               cookie=f"vigil_customer_oidc_sid={sid}")
        assert st == 302 and hdr.get("Location") == "/", (st, hdr)   # success → into the SPA
        setck = hdr.get("Set-Cookie") or ""
        assert f"{CUSTOMER_COOKIE}=" in setck, setck                  # a CUSTOMER session cookie was minted
        session = http.cookies.SimpleCookie(setck)[CUSTOMER_COOKIE].value
        # the minted session authenticates the customer on the edge, bound to the auto-provisioned org
        c, who = _get(_opener(), ep, "/api/customer/whoami", cookie=f"{CUSTOMER_COOKIE}={session}")
        assert who["authenticated"] is True and who["username"].startswith("cust_") and who["org_id"]
        # ISOLATION: that customer session presented to the operator cockpit as sigil_session → NOT an operator
        plain = urllib.request.build_opener()
        _, op_who = _get(plain, sp, "/api/whoami", cookie=f"sigil_session={session}")
        assert op_who.get("authenticated") in (False, None), op_who
    finally:
        sov.shutdown(); edge.shutdown()


def test_oidc_callback_wrong_browser_sid_is_refused(tmp_path, monkeypatch):
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        state, nonce, _sid, _ = _oidc_login(ep)
        idp.next_id_token = idp.mint(nonce=nonce)
        # a DIFFERENT browser's sid (login-CSRF / injected auth response) must not satisfy the state binding
        st, hdr, body = _edge_raw(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}",
                                  cookie="vigil_customer_oidc_sid=some-other-browser-sid")
        assert st == 401 and CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or ""), (st, hdr)
        assert b"not bound to this browser" in body
    finally:
        sov.shutdown(); edge.shutdown()


def test_oidc_callback_replayed_state_is_refused(tmp_path, monkeypatch):
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        state, nonce, sid, _ = _oidc_login(ep)
        idp.next_id_token = idp.mint(nonce=nonce)
        first = _edge_raw(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}",
                          cookie=f"vigil_customer_oidc_sid={sid}")
        assert first[0] == 302                                       # the first callback succeeds
        idp.next_id_token = idp.mint(nonce=nonce)                    # re-mint; the state is the single-use guard
        replay = _edge_raw(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}",
                           cookie=f"vigil_customer_oidc_sid={sid}")
        assert replay[0] == 401 and b"already-used oidc state" in replay[2]   # single-use state spent
    finally:
        sov.shutdown(); edge.shutdown()


def test_oidc_callback_email_unverified_lands_signed_out(tmp_path, monkeypatch):
    # an id_token whose email_verified is false → the provisioner refuses → the edge redirects to the
    # signed-out state (no customer session minted), never an auto-provisioned account.
    idp = _MiniIdP()
    sov, edge, ep, _ = _stack_oidc(tmp_path, monkeypatch, idp)
    try:
        state, nonce, sid, _ = _oidc_login(ep)
        idp.next_id_token = idp.mint(nonce=nonce, email_verified=False)
        st, hdr, _ = _edge_raw(ep, f"/api/customer/oidc/callback?code=auth-1&state={state}",
                               cookie=f"vigil_customer_oidc_sid={sid}")
        assert st == 302 and hdr.get("Location") == "/#oidc=err"     # failure → signed-out landing
        assert CUSTOMER_COOKIE not in (hdr.get("Set-Cookie") or "")  # NO session minted
    finally:
        sov.shutdown(); edge.shutdown()


# ======================================================================================================
# E3b-1 — customer TOTP MFA over the edge (enroll → verify a fresh code; session-bound; account-level)
# ======================================================================================================
def _stack_vault(tmp_path, monkeypatch):
    """A provisioned (fake-TPM) owner vault + the sovereign/edge stack — so the provisioner can SEAL the TOTP
    secret. The vault is provisioned BEFORE the stack so the owner key is sealed from the start.

    A stale sealed `spine.dek` in SIGIL_HOME (sealed under a PRIOR run's now-gone fake-TPM KEK) would fail to
    open under our fresh KEK, so we drop it first — the spine here is a brand-new tempfile, so there is no
    sealed data to lose; a fresh DEK is regenerated + sealed under our KEK. Order-independent + CI-clean."""
    from sigil import config
    from sigil.platform import vault as vaultmod
    (config.SIGIL_HOME / "spine" / "keys" / "spine.dek").unlink(missing_ok=True)
    vaultmod.reset_owner_vault_for_test()
    v = vaultmod.Vault(tmp_path / "ownervault", make_fake_tpm())
    v.provision()
    monkeypatch.setattr(vaultmod, "_owner_vault", v)
    return _stack(tmp_path, monkeypatch)


def test_mfa_totp_enroll_and_verify_over_the_edge(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "mfa@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm",
              {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        # enroll a TOTP factor — the edge relays to the provisioner, which seals the secret under the vault
        c, r = _post(op, ep, "/api/customer/mfa/totp/enroll", {})
        assert c == 200 and r["ok"] and r["provisioning_uri"].startswith("otpauth://totp/") and r["secret"], (c, r)
        # verify a fresh code for that secret (the step-up / second-factor proof primitive)
        code = _totp.code_now(r["secret"], at=time.time())
        c, r2 = _post(op, ep, "/api/customer/mfa/verify", {"code": code})
        assert c == 200 and r2["ok"], (c, r2)
        # the SAME code replayed is refused (the per-(username, step) replay ledger)
        c, r3 = _post(op, ep, "/api/customer/mfa/verify", {"code": code})
        assert c == 403, (c, r3)
    finally:
        sov.shutdown(); edge.shutdown()


def test_mfa_requires_a_session(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        assert _post(_opener(), ep, "/api/customer/mfa/totp/enroll", {})[0] == 401
        assert _post(_opener(), ep, "/api/customer/mfa/verify", {"code": "123456"})[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


# ======================================================================================================
# E3b-2 — customer passkey (WebAuthn) over the edge: enroll (session) + a full login that mints a session
# ======================================================================================================
from test_customer_passkey import ORIGIN as PK_ORIGIN  # noqa: E402
from test_customer_passkey import RP as PK_RP  # noqa: E402
from test_customer_passkey import SoftAuthenticator  # noqa: E402


def _stack_passkey(tmp_path, monkeypatch, *, enabled=True):
    if enabled:
        monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", "1")
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_RP_ID", PK_RP)
    monkeypatch.setenv("VIGIL_CUSTOMER_PASSKEY_ORIGINS", PK_ORIGIN)
    return _stack(tmp_path, monkeypatch)


def test_passkey_enroll_then_login_mints_a_customer_session(tmp_path, monkeypatch):
    sov, edge, ep, sp = _stack_passkey(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "pk@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm",
              {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        auth = SoftAuthenticator()
        cid = "cred-edge-abc123"
        # ENROLL: challenge -> register -> verify (session-bound)
        ch = _post(op, ep, "/api/customer/passkey/enroll/challenge", {})[1]["challenge"]
        reg = auth.register(ch)
        c, r = _post(op, ep, "/api/customer/passkey/enroll/verify",
                     {"credential_id": cid, "public_key_spki_b64": reg["public_key_spki_b64"],
                      "cose_alg": reg["cose_alg"], "uv": False, "client_data_json": reg["client_data_json"],
                      "challenge": ch})
        assert c == 200 and r["ok"] and r["credential_id"] == cid, (c, r)
        # a FRESH browser (no session) logs in with the passkey
        op2 = _opener()
        lch = _post(op2, ep, "/api/customer/passkey/login/challenge", {})[1]["challenge"]
        a = auth.assert_(lch, count=7)
        c, r = _post(op2, ep, "/api/customer/passkey/login/verify",
                     {"credential_id": cid, "authenticator_data": a["authenticator_data"],
                      "client_data_json": a["client_data_json"], "signature": a["signature"], "challenge": lch})
        assert c == 200 and r["username"].startswith("cust_") and r.get("active_org"), (c, r)
        # the login minted a working CUSTOMER session
        c, who = _get(op2, ep, "/api/customer/whoami")
        assert who["authenticated"] is True and who["username"] == r["username"]
        # ISOLATION: that customer session is NOT an operator on the cockpit
        jar = op2.handlers[[type(h).__name__ for h in op2.handlers].index("HTTPCookieProcessor")].cookiejar
        sid = next(ck.value for ck in jar if ck.name == CUSTOMER_COOKIE)
        _, op_who = _get(urllib.request.build_opener(), sp, "/api/whoami", cookie=f"sigil_session={sid}")
        assert op_who.get("authenticated") in (False, None), op_who
    finally:
        sov.shutdown(); edge.shutdown()


def test_passkey_login_challenge_is_single_use(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack_passkey(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "pk2@acme.com"})[1]["dev_token"]
        _post(op, ep, "/api/customer/signup/confirm",
              {"token": t, "password": "customer-pw-1", "org_name": "Acme"})
        auth = SoftAuthenticator()
        cid = "cred-su-1"
        ch = _post(op, ep, "/api/customer/passkey/enroll/challenge", {})[1]["challenge"]
        reg = auth.register(ch)
        _post(op, ep, "/api/customer/passkey/enroll/verify",
              {"credential_id": cid, "public_key_spki_b64": reg["public_key_spki_b64"],
               "cose_alg": reg["cose_alg"], "uv": False, "client_data_json": reg["client_data_json"],
               "challenge": ch})
        op2 = _opener()
        lch = _post(op2, ep, "/api/customer/passkey/login/challenge", {})[1]["challenge"]
        a = auth.assert_(lch, count=3)
        payload = {"credential_id": cid, "authenticator_data": a["authenticator_data"],
                   "client_data_json": a["client_data_json"], "signature": a["signature"], "challenge": lch}
        assert _post(op2, ep, "/api/customer/passkey/login/verify", payload)[0] == 200    # first use wins
        assert _post(op2, ep, "/api/customer/passkey/login/verify", payload)[0] == 401    # replayed challenge spent
    finally:
        sov.shutdown(); edge.shutdown()


def test_passkey_routes_404_when_disabled_and_enroll_requires_session(tmp_path, monkeypatch):
    sov, edge, ep, _ = _stack_passkey(tmp_path, monkeypatch, enabled=False)
    try:
        monkeypatch.delenv("VIGIL_CUSTOMER_PASSKEY_ENABLED", raising=False)
        assert _post(_opener(), ep, "/api/customer/passkey/login/challenge", {})[0] == 404
        assert _post(_opener(), ep, "/api/customer/passkey/enroll/challenge", {})[0] == 404
    finally:
        sov.shutdown(); edge.shutdown()
    sov, edge, ep, _ = _stack_passkey(tmp_path, monkeypatch)       # enabled, but no session for enroll
    try:
        assert _post(_opener(), ep, "/api/customer/passkey/enroll/challenge", {})[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


# ======================================================================================================
# E3c — step-up MFA over the edge: a sensitive op is gated until a fresh factor is proven (flag ON)
# ======================================================================================================
def test_stepup_gates_a_sensitive_op_until_a_fresh_factor(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", "1")       # enforcement ON for this test
    sov, edge, ep, _ = _stack_vault(tmp_path, monkeypatch)         # provisioned vault for the TOTP seal
    try:
        admin = _opener()
        ta = _post(admin, ep, "/api/customer/signup/request", {"email": "admin@acme.com"})[1]["dev_token"]
        _post(admin, ep, "/api/customer/signup/confirm",
              {"token": ta, "password": "customer-pw-1", "org_name": "Acme"})
        mate = _opener()
        tm = _post(mate, ep, "/api/customer/signup/request", {"email": "mate@acme.com"})[1]["dev_token"]
        m = _post(mate, ep, "/api/customer/signup/confirm",
                  {"token": tm, "password": "customer-pw-2", "org_name": "Mate"})[1]
        # with step-up ON and no fresh factor, the admin's member/grant is REFUSED with step_up_required
        c, r = _post(admin, ep, "/api/customer/member/grant",
                     {"member_username": m["username"], "role": "analyst"})
        assert c == 401 and r.get("step_up_required") is True, (c, r)
        # enroll TOTP + step up — the edge stamps mfa_at onto the admin's live session
        enr = _post(admin, ep, "/api/customer/mfa/totp/enroll", {})[1]
        code = _totp.code_now(enr["secret"], at=time.time())
        assert _post(admin, ep, "/api/customer/mfa/verify", {"code": code})[0] == 200
        # now the SAME grant proceeds (the session carries a fresh mfa_at within the window)
        c, r = _post(admin, ep, "/api/customer/member/grant",
                     {"member_username": m["username"], "role": "analyst"})
        assert c == 200 and r["role"] == "analyst", (c, r)
    finally:
        sov.shutdown(); edge.shutdown()


def test_stepup_off_by_default_sensitive_op_unchanged(tmp_path, monkeypatch):
    # default (flag OFF): a sensitive op proceeds with NO step-up — byte-identical to pre-E3c.
    monkeypatch.delenv("VIGIL_CUSTOMER_STEPUP_REQUIRED", raising=False)
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        admin = _opener()
        ta = _post(admin, ep, "/api/customer/signup/request", {"email": "a@acme.com"})[1]["dev_token"]
        _post(admin, ep, "/api/customer/signup/confirm",
              {"token": ta, "password": "customer-pw-1", "org_name": "Acme"})
        mate = _opener()
        tm = _post(mate, ep, "/api/customer/signup/request", {"email": "b@acme.com"})[1]["dev_token"]
        m = _post(mate, ep, "/api/customer/signup/confirm",
                  {"token": tm, "password": "customer-pw-2", "org_name": "Mate"})[1]
        c, r = _post(admin, ep, "/api/customer/member/grant",
                     {"member_username": m["username"], "role": "analyst"})
        assert c == 200 and r["role"] == "analyst", (c, r)         # no step-up needed when the flag is off
    finally:
        sov.shutdown(); edge.shutdown()


def test_notifications_route_requires_a_session(tmp_path, monkeypatch):
    # the notification centre read is session-gated at the edge: no customer cookie -> 401, never an anon leak.
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        assert _get(_opener(), ep, "/api/customer/notifications")[0] == 401
    finally:
        sov.shutdown(); edge.shutdown()


def test_notifications_end_to_end_shape_scoped_to_session_org(tmp_path, monkeypatch):
    # a signed-in customer reaches notifications over the edge->hop->dispatch->provisioner path and gets a
    # well-formed, session-org-scoped payload (NOT 404/500). A fresh trial org_admin (credits present, no
    # subscription, no view_assessments) has nothing to nag about -> an empty-but-valid centre.
    sov, edge, ep, _ = _stack(tmp_path, monkeypatch)
    try:
        op = _opener()
        t = _post(op, ep, "/api/customer/signup/request", {"email": "n@acme.com"})[1]["dev_token"]
        conf = _post(op, ep, "/api/customer/signup/confirm",
                     {"token": t, "password": "customer-pw-1", "org_name": "Acme"})[1]
        org = conf["org_id"]
        code, body = _get(op, ep, "/api/customer/notifications")
        assert code == 200, (code, body)
        assert body["org_id"] == org                               # scoped to the SERVER-side session org
        assert isinstance(body["notifications"], list) and body["count"] == 0
    finally:
        sov.shutdown(); edge.shutdown()
