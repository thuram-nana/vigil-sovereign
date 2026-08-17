"""Claim 6 — per-user AUTHENTICATION at the `vigil up` reverse-proxy boundary (acceptance gate).

The proxy DELEGATES bearer verification to the sovereign plane's token-optional ``/api/whoami``. A fake
stands in for it here, resolving the SAME ``{authenticated, username, role, permissions}`` shape the real
cockpit returns — that producer-side contract is pinned by
``apps/sigil/tests/test_rbac_server.py::test_whoami_owner_and_anonymous`` (and ``_principal_json`` in
``sigil/ui/server.py``). This suite proves, at the proxy, that auth is FAIL-CLOSED:

  * a valid per-user bearer authenticates as THAT principal; a viewer is denied an offense mutation
    (the ``run_engagement`` floor) while an operator/owner is allowed;
  * an unknown/blank bearer → 401, and the backend is NEVER reached (no unauthenticated fall-through, never
    acting as owner);
  * the offense CONSOLE credential is SUBSTITUTED onto the offense hop — the browser's own bearer never
    reaches the backend — and the RESOLVED identity is stamped (a client-supplied ``X-VIGIL-Role`` is
    stripped, so a spoof cannot escalate);
  * the login bootstrap (``/sovereign/api/whoami``, ``/sovereign/api/login``) is reachable WITHOUT auth;
  * the served ``index.html`` embeds NO owner token;
  * FATAL-2: exercising the auth path co-loads no sovereign (``sigil``/``apps.sigil``) module in this
    offense interpreter.

Pure-stdlib (no framework/strix/sigil), so it runs on the offense path:
    PYTHONPATH=integration:engine/crucible:gateway pytest integration/tests/test_uiproxy_peruser_auth.py -q
"""
from __future__ import annotations

import http.client
import http.server
import json
import socket
import sys
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from vigil_integration import uiproxy

# ---- test principals the fake sovereign whoami resolves -------------------------------------------
OWNER_TOKEN = "owner-boot-tok-AAAAAAAAAAAAAAAA"    # the offense console credential AND the owner's login
OP_BEARER = "op-bearer-BBBBBBBBBBBBBBBBBBBB"        # operator: has run_engagement, NOT manage_users
VIEWER_BEARER = "viewer-bearer-CCCCCCCCCCCCCCCC"    # viewer: read only
_OWNER_PERMS = ["read", "queue_proposal", "run_engagement", "approve_a2", "toggle_guard",
                "config_nonsecret", "approve_a3", "kill_release", "promote", "secrets",
                "offense_authority", "manage_users", "toggle_protected_guard"]
_OP_PERMS = ["read", "queue_proposal", "run_engagement", "approve_a2", "toggle_guard", "config_nonsecret"]
# Mirrors sigil/ui/server.py::_principal_json — the exact contract uiproxy._whoami parses.
_WHOAMI = {
    OWNER_TOKEN: {"authenticated": True, "username": "owner", "role": "owner", "permissions": _OWNER_PERMS},
    OP_BEARER: {"authenticated": True, "username": "op", "role": "operator", "permissions": _OP_PERMS},
    VIEWER_BEARER: {"authenticated": True, "username": "vv", "role": "viewer", "permissions": ["read"]},
}


# ---- an upstream that RECORDS what it received (so we can prove what the proxy did / did not forward) --
class _AuthHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _do(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        srv = self.server
        parts = urlsplit(self.path)
        srv.records.append({  # type: ignore[attr-defined]
            "path": self.path,
            "method": self.command,
            "token": self.headers.get("X-SIGIL-Token", ""),
            "vigil_role": self.headers.get("X-VIGIL-Role", ""),
            "vigil_role_us": self.headers.get("X_VIGIL_Role", ""),   # underscore variant (advisory)
            "vigil_principal": self.headers.get("X-VIGIL-Principal", ""),
            "body": body.decode("utf-8", "replace"),
        })
        # A backend's OWN static index (console `__CONSOLE_TOKEN__` / cockpit `__SIGIL_TOKEN__`) embeds the
        # owner token and is served token-free. Model that faithfully so the proxy's hop-only-credential
        # redaction is exercised: `/` and `/index.html` return HTML carrying the owner token verbatim.
        if parts.path in ("/", "/index.html"):
            html = f'<!doctype html><body data-token="{OWNER_TOKEN}">console-index</body>'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if parts.path == "/api/whoami" and getattr(srv, "tag", "") == "cockpit":
            tok = self.headers.get("X-SIGIL-Token") or (parse_qs(parts.query).get("token") or [""])[0]
            payload = _WHOAMI.get(tok, {"authenticated": False})
        else:
            payload = {"ok": True, "tag": getattr(srv, "tag", ""), "path": self.path}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _do
    do_POST = _do
    do_PUT = _do
    do_PATCH = _do
    do_DELETE = _do


class _Srv(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start(tag: str):
    s = _Srv(("127.0.0.1", 0), _AuthHandler)
    s.tag = tag              # type: ignore[attr-defined]
    s.records = []           # type: ignore[attr-defined]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, s.server_address[1]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def proxy(tmp_path, monkeypatch):
    cockpit, sov_port = _start("cockpit")
    console, con_port = _start("console")
    api, api_port = _start("api")
    monkeypatch.setattr(uiproxy, "SOVEREIGN_PORT", sov_port)
    monkeypatch.setattr(uiproxy, "CONSOLE_PORT", con_port)
    monkeypatch.setattr(uiproxy, "API_PORT", api_port)

    src = tmp_path / "src"
    src.mkdir()
    (src / "tokens.css").write_text(":root{--a:1}", encoding="utf-8")
    (src / "components.css").write_text(".btn{color:red}", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(f"/*{j}*/", encoding="utf-8")
    (src / "index.html").write_text('<body data-token="__VIGIL_TOKEN__">x</body>', encoding="utf-8")
    serve = tmp_path / "serve"
    uiproxy.assemble_serve_dir(src, serve, token=OWNER_TOKEN)

    port = _free_port()
    # the proxy holds OWNER_TOKEN as the offense CONSOLE credential it substitutes after per-user auth.
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve, token=OWNER_TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield {"base": f"http://127.0.0.1:{port}", "port": port,
               "cockpit": cockpit, "console": console, "api": api}
    finally:
        httpd.shutdown(); httpd.server_close()
        for s in (cockpit, console, api):
            s.shutdown(); s.server_close()


def _req(port: int, method: str, path: str, *, headers=None, body: bytes | None = None):
    """A raw http.client request so we control every header (Host, X-SIGIL-Token, X-VIGIL-*)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        conn.close()


def _tok(token: str, extra=None):
    h = {"X-SIGIL-Token": token} if token else {}
    if extra:
        h.update(extra)
    return h


# ==================================================================================================
# 1) a valid per-user bearer authenticates as THAT principal; the console credential is SUBSTITUTED
# ==================================================================================================
def test_operator_bearer_reaches_offense_with_substituted_credential_and_stamped_identity(proxy):
    port, console = proxy["port"], proxy["console"]
    st, _ = _req(port, "GET", "/offense/api/status", headers=_tok(OP_BEARER))
    assert st == 200
    assert len(console.records) == 1, "an authenticated read must reach the offense console"
    rec = console.records[0]
    # the browser's OWN bearer (OP_BEARER) never reaches the backend — the proxy substitutes the console
    # credential (OWNER_TOKEN) — and the RESOLVED identity is stamped for attribution.
    assert rec["token"] == OWNER_TOKEN, "proxy must present the offense console credential, not the user's bearer"
    assert rec["token"] != OP_BEARER
    assert rec["vigil_role"] == "operator"
    assert rec["vigil_principal"] == "op"


def test_owner_bearer_is_owner(proxy):
    port, console = proxy["port"], proxy["console"]
    st, _ = _req(port, "GET", "/offense/api/status", headers=_tok(OWNER_TOKEN))
    assert st == 200
    assert console.records[0]["vigil_role"] == "owner"


# ==================================================================================================
# 2) role floor — a viewer may READ offense but NOT drive an offense mutation (run_engagement)
# ==================================================================================================
def test_viewer_can_read_offense(proxy):
    port, console = proxy["port"], proxy["console"]
    st, _ = _req(port, "GET", "/offense/api/status", headers=_tok(VIEWER_BEARER))
    assert st == 200 and len(console.records) == 1


def test_viewer_cannot_run_an_offense_mutation_and_it_is_never_forwarded(proxy):
    port, api = proxy["port"], proxy["api"]
    st, body = _req(port, "POST", "/offense/api/v1/tool/invoke", headers=_tok(VIEWER_BEARER), body=b"{}")
    assert st == 403, body
    assert api.records == [], "a floored offense mutation must NEVER reach the backend"


def test_operator_can_run_an_offense_mutation(proxy):
    port, api = proxy["port"], proxy["api"]
    st, _ = _req(port, "POST", "/offense/api/v1/tool/invoke", headers=_tok(OP_BEARER), body=b'{"x":1}')
    assert st == 200
    assert len(api.records) == 1 and api.records[0]["token"] == OWNER_TOKEN
    assert api.records[0]["vigil_role"] == "operator"


# ==================================================================================================
# 3) fail-closed — an unknown / blank bearer is 401 and NEVER forwarded (never acts as owner)
# ==================================================================================================
def test_unknown_bearer_is_401_and_offense_backend_never_reached(proxy):
    port, console, api = proxy["port"], proxy["console"], proxy["api"]
    st, _ = _req(port, "GET", "/offense/api/status", headers=_tok("totally-unknown-bearer-zzzz"))
    assert st == 401
    assert console.records == [] and api.records == [], "an unauthenticated request must not fall through"


def test_unknown_bearer_on_sovereign_is_401_and_not_forwarded(proxy):
    port, cockpit = proxy["port"], proxy["cockpit"]
    st, _ = _req(port, "GET", "/sovereign/api/snapshot", headers=_tok("totally-unknown-bearer-zzzz"))
    assert st == 401
    # the proxy DID probe whoami, but the sovereign /api/snapshot forward must NOT have happened.
    assert not any(r["path"].startswith("/api/snapshot") for r in cockpit.records)


def test_blank_bearer_is_401_without_even_probing_whoami(proxy):
    port, cockpit, console = proxy["port"], proxy["cockpit"], proxy["console"]
    st, _ = _req(port, "GET", "/offense/api/status", headers={})  # no token at all
    assert st == 401
    assert cockpit.records == [], "a blank bearer short-circuits — no whoami round-trip"
    assert console.records == []


# ==================================================================================================
# 4) anti-spoof — a client-supplied X-VIGIL-* identity header is stripped and cannot escalate
# ==================================================================================================
def test_client_supplied_identity_header_is_stripped(proxy):
    port, console = proxy["port"], proxy["console"]
    # a viewer tries to smuggle X-VIGIL-Role: owner. The proxy strips it and stamps the RESOLVED role.
    st, _ = _req(port, "GET", "/offense/api/status",
                 headers=_tok(VIEWER_BEARER, {"X-VIGIL-Role": "owner", "X-VIGIL-Principal": "root"}))
    assert st == 200
    rec = console.records[0]
    assert rec["vigil_role"] == "viewer", "the proxy must overwrite a spoofed role with the resolved one"
    assert rec["vigil_principal"] == "vv"


def test_spoofed_role_does_not_lift_the_offense_mutation_floor(proxy):
    port, api = proxy["port"], proxy["api"]
    # the floor uses the RESOLVED role, not the header — a viewer's spoofed 'owner' header is ignored.
    st, _ = _req(port, "POST", "/offense/api/v1/tool/invoke",
                 headers=_tok(VIEWER_BEARER, {"X-VIGIL-Role": "owner"}), body=b"{}")
    assert st == 403
    assert api.records == []


# ==================================================================================================
# 5) login bootstrap — whoami / login reach the sovereign plane WITHOUT proxy auth
# ==================================================================================================
def test_login_bootstrap_is_reachable_without_auth(proxy):
    port, cockpit = proxy["port"], proxy["cockpit"]
    # /sovereign/api/whoami with NO token must be FORWARDED (not 401'd) — it is the login-state probe.
    st, body = _req(port, "GET", "/sovereign/api/whoami", headers={})
    assert st == 200 and json.loads(body)["authenticated"] is False
    assert any(r["path"] == "/api/whoami" for r in cockpit.records), "whoami must reach the sovereign plane"
    # /sovereign/api/login with NO token must also be forwarded (verifying the presented token is its job).
    st, _ = _req(port, "POST", "/sovereign/api/login", headers={"Content-Type": "application/json"},
                 body=b'{"token":"x"}')
    assert st == 200
    assert any(r["path"] == "/api/login" for r in cockpit.records)


def test_a_non_bootstrap_sovereign_route_still_requires_auth(proxy):
    port = proxy["port"]
    assert _req(port, "GET", "/sovereign/api/settings", headers={})[0] == 401


# ==================================================================================================
# 6) the served page carries NO owner token — AND no RELAYED backend body leaks the hop credential
#    (RED-PEN BLOCK-1: a backend's own token-embedding index.html served token-free at `/`, relayed to a
#     VIEWER, would otherwise hand the owner token to a non-owner who replays it AS OWNER).
# ==================================================================================================
def test_served_index_embeds_no_owner_token(proxy):
    port = proxy["port"]
    st, body = _req(port, "GET", "/", headers={})   # static is token-free
    assert st == 200
    assert OWNER_TOKEN not in body
    assert 'data-token=""' in body


def test_viewer_cannot_read_owner_token_via_offense_index(proxy):
    """The escalation the red-pen found: the offense console serves its token-embedding index.html at `/`
    token-free. A VIEWER GET /offense/ (a read, floor allows) must NOT receive the owner token — the proxy
    redacts the hop credential out of the relayed body. Covers `/offense/` AND `/offense/index.html`."""
    port = proxy["port"]
    for path in ("/offense/", "/offense/index.html"):
        st, body = _req(port, "GET", path, headers=_tok(VIEWER_BEARER))
        assert st == 200, path
        assert OWNER_TOKEN not in body, f"{path} relayed the owner token to a viewer (escalation)"
        # the value is blanked with an equal-length marker (Content-Length preserved), never the secret.
        assert ("X" * len(OWNER_TOKEN)) in body, f"{path} body should carry the redaction marker"


def test_replaying_the_relayed_offense_index_does_not_resolve_as_owner(proxy):
    """End-to-end closure of the repro: whatever a viewer can scrape off /offense/ must not authenticate as
    owner. The redacted marker is not a valid bearer → the proxy 401s it (never owner)."""
    port = proxy["port"]
    _st, body = _req(port, "GET", "/offense/", headers=_tok(VIEWER_BEARER))
    scraped = body.split('data-token="', 1)[1].split('"', 1)[0]
    assert scraped != OWNER_TOKEN
    # replay whatever was scraped — it must NOT reach any backend (401 at the proxy).
    st, _ = _req(port, "GET", "/offense/api/status", headers=_tok(scraped))
    assert st == 401


def test_no_relayed_offense_body_contains_the_owner_credential(proxy):
    """General invariant (any offense read route, any path): no body relayed to the browser contains the
    hop-only owner credential (self.server.token)."""
    port = proxy["port"]
    for path in ("/offense/", "/offense/index.html", "/offense/api/status", "/offense/z"):
        _st, body = _req(port, "GET", path, headers=_tok(VIEWER_BEARER))
        assert OWNER_TOKEN not in body, f"{path} leaked the owner credential in a relayed body"


def test_cockpit_index_owner_token_is_redacted_on_sovereign_relay(proxy):
    """The SAME leak vector on the sovereign plane: the cockpit's own index (__SIGIL_TOKEN__) is served
    token-free at `/`. A viewer GET /sovereign/ must not receive the owner token either."""
    port = proxy["port"]
    st, body = _req(port, "GET", "/sovereign/", headers=_tok(VIEWER_BEARER))
    assert st == 200
    assert OWNER_TOKEN not in body


def test_underscore_identity_header_variant_is_stripped(proxy):
    """ADVISORY: a client-supplied X-VIGIL-* identity header must be stripped by CLASS — including the
    underscore variant (X_VIGIL_Role) some stacks fold to the header a future offense gate reads. The
    proxy must overwrite it with the resolved identity, never forward the spoof."""
    port, console = proxy["port"], proxy["console"]
    st, _ = _req(port, "GET", "/offense/api/status",
                 headers=_tok(VIEWER_BEARER, {"X_VIGIL_Role": "owner", "X-VIGIL-Role": "owner"}))
    assert st == 200
    rec = console.records[0]
    assert rec["vigil_role"] == "viewer", "hyphen spoof must be overwritten with the resolved role"
    assert rec["vigil_role_us"] == "", "the underscore X_VIGIL_Role variant must be stripped, not forwarded"


# ==================================================================================================
# 7) plane control — the same delegated auth + a run_engagement floor
# ==================================================================================================
def _plane_headers(port, token):
    return _tok(token, {"Host": f"127.0.0.1:{port}", "Origin": f"http://127.0.0.1:{port}",
                        "X-Requested-With": "vigil-ui", "Content-Type": "application/json"})


def test_plane_start_requires_run_engagement(proxy):
    port = proxy["port"]
    # no token → 401
    assert _req(port, "POST", "/__vigil/plane/offense/start",
                headers=_plane_headers(port, ""), body=b"{}")[0] == 401
    # viewer → 403 (run_engagement floor), BEFORE any plane action
    assert _req(port, "POST", "/__vigil/plane/offense/start",
                headers=_plane_headers(port, VIEWER_BEARER), body=b"{}")[0] == 403
    # operator passes the floor; this fixture proxy has no plane_control → an honest 503 (not a 401/403)
    assert _req(port, "POST", "/__vigil/plane/offense/start",
                headers=_plane_headers(port, OP_BEARER), body=b"{}")[0] == 503


def test_plane_status_needs_only_authentication(proxy):
    port = proxy["port"]
    assert _req(port, "GET", "/__vigil/plane/status", headers=_plane_headers(port, ""))[0] == 401
    assert _req(port, "GET", "/__vigil/plane/status", headers=_plane_headers(port, VIEWER_BEARER))[0] == 200


# ==================================================================================================
# 8) FATAL-2 — exercising the proxy auth path co-loads NO sovereign module in this interpreter
# ==================================================================================================
def test_fatal2_auth_path_loads_no_sovereign_module(proxy):
    port = proxy["port"]
    # drive the whole auth path (owner, operator, viewer, unknown, bootstrap).
    for tok in (OWNER_TOKEN, OP_BEARER, VIEWER_BEARER, "unknown-xyz"):
        _req(port, "GET", "/offense/api/status", headers=_tok(tok))
    _req(port, "GET", "/sovereign/api/whoami", headers={})
    bad = [m for m in sys.modules
           if m == "sigil" or m.startswith("sigil.") or m.startswith("apps.sigil")
           or m == "framework" or m.startswith("framework.")]
    assert bad == [], f"offense interpreter must not co-load a sovereign module (FATAL-2): {bad}"
