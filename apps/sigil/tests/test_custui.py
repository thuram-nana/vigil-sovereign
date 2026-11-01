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
    monkeypatch.setenv("VIGIL_PROVISION_DEV_TOKENS", "1")   # dev-token exposure is now off-by-default (CO13)
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
