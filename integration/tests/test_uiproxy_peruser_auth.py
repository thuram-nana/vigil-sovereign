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
import ast
import gzip
import os
import pathlib
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

import pytest

from vigil_integration import uiproxy

# repo root (…/integration/tests/this_file → parents[2]) — for the SSE-emitter source guard.
_REPO = pathlib.Path(__file__).resolve().parents[2]

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
            "accept_encoding": self.headers.get("Accept-Encoding", ""),   # what the hop offered the backend
            "vigil_role": self.headers.get("X-VIGIL-Role", ""),
            "vigil_role_us": self.headers.get("X_VIGIL_Role", ""),   # underscore variant (advisory)
            "vigil_principal": self.headers.get("X-VIGIL-Principal", ""),
            "vigil_role_sig": self.headers.get("X-VIGIL-Role-Sig", ""),   # S1 hop assertion
            "vigil_role_ts": self.headers.get("X-VIGIL-Role-Ts", ""),
            "body": body.decode("utf-8", "replace"),
        })
        # A backend's OWN static index (console `__CONSOLE_TOKEN__` / cockpit `__SIGIL_TOKEN__`) embeds the
        # owner token and is served token-free. Model that faithfully so the proxy's hop-only-credential
        # redaction is exercised: `/` and `/index.html` return HTML carrying the owner token verbatim.
        # `srv.compress` models a backend/middleware's content-encoding behaviour (BLOCK-A):
        #   None     → cleartext (default);
        #   "honor"  → gzip IFF the (hop) Accept-Encoding offers gzip — a totally ordinary web server;
        #   "always" → gzip regardless (a backend that IGNORED our forced identity request);
        #   "fake-br"→ Content-Encoding: br over an UNDECODABLE body (proxy must fail closed);
        #   "bomb"   → gzip that ENCODES under the 16 MiB read cap but DECODES past the 64 MiB cap (a
        #              ~1000:1 deflate bomb — the proxy must fail closed WITHOUT materialising it).
        if parts.path in ("/", "/index.html"):
            html = f'<!doctype html><body data-token="{OWNER_TOKEN}">console-index</body>'.encode()
            mode = getattr(srv, "compress", None)
            enc = ""
            if mode == "always":
                html, enc = gzip.compress(html), "gzip"
            elif mode == "honor" and "gzip" in self.headers.get("Accept-Encoding", ""):
                html, enc = gzip.compress(html), "gzip"
            elif mode == "fake-br":
                enc = "br"       # claim brotli but send bytes the proxy cannot decode → fail closed
            elif mode == "bomb":
                # token-bearing HTML + 80 MiB of zeros → gzips to ~80 KiB (well under the 16 MiB encoded
                # read cap) but inflates to > the 64 MiB decoded cap. A one-shot decompress would OOM the
                # proxy; the streaming bound must catch it mid-inflate and 502.
                html, enc = gzip.compress(html + b"\x00" * (80 * 1024 * 1024)), "gzip"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if enc:
                self.send_header("Content-Encoding", enc)
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


def _req_raw(port: int, method: str, path: str, headers=None):
    """Like _req but returns (status, Content-Encoding, RAW body bytes) — http.client does NOT auto-decode,
    so this sees exactly what the browser would receive on the wire."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=6)
    try:
        conn.request(method, path, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.getheader("Content-Encoding"), r.read()
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
# 6b) CONTENT-ENCODING must not smuggle the hop credential past the literal-byte redactor (RED-PEN
#     BLOCK-A). A compressed body has no literal token bytes to scan; a naive relay would forward it
#     `Content-Encoding: gzip` and the browser would decompress → owner token. Two layers close it:
#       Fix 1 — the hop forces `Accept-Encoding: identity` so a backend we control never compresses;
#       Fix 2 — a body that arrives compressed anyway is DECODED before scanning, or FAILS CLOSED.
# ==================================================================================================
def test_hop_forces_identity_so_a_gzip_honoring_backend_serves_cleartext(proxy):
    """Fix 1: the proxy forces `Accept-Encoding: identity` on the backend hop. A viewer offering gzip must
    NOT make the backend compress — so the redactor scans cleartext and the owner token never reaches the
    browser. Mutation-sensitive: reverting the identity-forcing makes the backend record 'gzip...' here."""
    port, console = proxy["port"], proxy["console"]
    console.compress = "honor"       # a normal web server: gzips IFF the request offers gzip
    st, body = _req(port, "GET", "/offense/",
                    headers=_tok(VIEWER_BEARER, {"Accept-Encoding": "gzip, deflate, br"}))
    assert st == 200
    idx = next(r for r in console.records if r["path"] in ("/", "/index.html"))
    assert idx["accept_encoding"] == "identity", "the hop must force identity, never forward the client's gzip"
    assert OWNER_TOKEN not in body, "cleartext body must be redacted"
    assert ("X" * len(OWNER_TOKEN)) in body


def test_backend_that_ignores_identity_and_gzips_is_decoded_then_redacted(proxy):
    """Fix 2 (defense-in-depth): a backend that compresses ANYWAY (ignored our identity request) is DECODED
    before scanning — the proxy relays cleartext with the token redacted and NO Content-Encoding, so the
    browser never recovers the owner token. Mutation-sensitive: without the decode step the compressed
    token-bearing body would pass straight through and gunzip back to the owner token."""
    port, console = proxy["port"], proxy["console"]
    console.compress = "always"      # ignores Accept-Encoding; always gzips
    st, ce, raw = _req_raw(port, "GET", "/offense/", _tok(VIEWER_BEARER))
    assert st == 200
    assert not ce, "the proxy must not relay a Content-Encoding it had to decode away"
    assert OWNER_TOKEN.encode() not in raw, "decoded, relayed body must have the token redacted"
    assert (b"X" * len(OWNER_TOKEN)) in raw, "the redaction marker must be present in the decoded cleartext"
    # belt-and-braces: even trying to gunzip whatever came back must not yield the token.
    try:
        assert OWNER_TOKEN.encode() not in gzip.decompress(raw)
    except (OSError, EOFError, gzip.BadGzipFile):
        pass                         # not gzip (it is cleartext) — expected


def test_undecodable_content_encoding_fails_closed(proxy):
    """Fix 2 fail-closed: a Content-Encoding the proxy cannot decode (brotli/zstd/unknown) on a token-bearing
    body must be REFUSED (502), never relayed un-scanned."""
    port, console = proxy["port"], proxy["console"]
    console.compress = "fake-br"     # Content-Encoding: br over bytes the proxy cannot decode
    st, _ce, raw = _req_raw(port, "GET", "/offense/", _tok(VIEWER_BEARER))
    assert st == 502, "an un-scannable encoding must fail closed, not relay the body"
    assert OWNER_TOKEN.encode() not in raw


def test_decompression_bomb_fails_closed_without_materialising(proxy):
    """RED-PEN re-check BLOCK-1: the decoded cap must be enforced DURING streaming inflate, not by a post-hoc
    `len(decompress(raw)) > cap` check that first materialises the whole body. A body that encodes under the
    16 MiB read cap but inflates past the 64 MiB decoded cap (a ~1000:1 gzip bomb) must FAIL CLOSED (502) and
    relay no token bytes. Mutation-sensitive: reverting `_decode_and_redact` to a one-shot
    `gzip.decompress(raw)` would materialise the full 80 MiB (OOM/observably huge) instead of stopping at the
    1 MiB-stepped budget. The cap constants are referenced so this path has real coverage."""
    from vigil_integration import uiproxy
    assert uiproxy._REDACT_MAX_ENCODED == 16 * 1024 * 1024
    assert uiproxy._REDACT_MAX_DECODED == 64 * 1024 * 1024
    port, console = proxy["port"], proxy["console"]
    console.compress = "bomb"        # < encoded cap, > decoded cap
    st, _ce, raw = _req_raw(port, "GET", "/offense/", _tok(VIEWER_BEARER))
    assert st == 502, "a decompression bomb must fail closed mid-inflate, not be relayed (or OOM the proxy)"
    assert OWNER_TOKEN.encode() not in raw
    assert len(raw) < 64 * 1024 * 1024, "the 502 body must be the small error string, never the inflated bomb"


def test_gzip_bypass_repro_is_closed_end_to_end(proxy):
    """The red-pen repro (rp2/repro_gzip.py) in one assertion: a viewer offering gzip against a gzip-honoring
    token-embedding backend cannot recover the owner token from what the browser ultimately receives."""
    port, console = proxy["port"], proxy["console"]
    console.compress = "honor"
    _st, ce, raw = _req_raw(port, "GET", "/offense/", _tok(VIEWER_BEARER, {"Accept-Encoding": "gzip"}))
    recovered = gzip.decompress(raw) if ce == "gzip" else raw
    assert OWNER_TOKEN.encode() not in recovered


# ==================================================================================================
# 6c) SSE is EXEMPT from redaction (it is streamed as-is to preserve incremental delivery). That
#     exemption rests on: no viewer-reachable SSE stream emits self.server.token. Pin it so it can't
#     silently rot — the real emitters (offense _sse/_sse_blackboard, cockpit _sse/_hud) must not
#     reference the session token.
# ==================================================================================================
_SSE_EMITTERS = [
    ("apps/sigil/sigil/ui/server.py", ["_sse", "_hud"]),
    ("engine/crucible/framework/v2/console/server.py", ["_sse", "_sse_blackboard"]),
]


def _func_segments(rel_path: str, name: str):
    src = (_REPO / rel_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    return [ast.get_source_segment(src, n) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]


def test_sse_emitters_never_reference_the_session_token():
    """Negative control for the SSE redaction exemption: the streams a viewer can reach must not emit the
    session token, so streaming them un-redacted is safe. If a future change makes an SSE emitter reference
    self.server.token (or the token-embedding placeholders), this fails — the exemption cannot rot silently."""
    for rel, names in _SSE_EMITTERS:
        for name in names:
            segs = _func_segments(rel, name)
            assert segs, f"{rel}::{name} not found — did an SSE emitter move? update the exemption pin"
            for seg in segs:
                assert "self.server.token" not in seg, (
                    f"{rel}::{name} references self.server.token — the SSE redaction exemption assumes SSE "
                    f"never carries the session token; this reference would break that invariant")
                assert "__SIGIL_TOKEN__" not in seg and "__CONSOLE_TOKEN__" not in seg, (
                    f"{rel}::{name} references a token-embedding placeholder")


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
def test_fatal2_auth_path_loads_no_sovereign_module():
    """FATAL-2: importing the proxy (and touching its pure auth-path helpers) must co-load NO sovereign
    (`sigil.*`) nor offense-framework (`framework.*`) module. Checked in a CLEAN SUBPROCESS: this test file
    is pure stdlib, but it shares a pytest process with sibling suites that LEGITIMATELY import `sigil`/
    `framework`, so a `sys.modules` check in-process would see THEIR imports, not ours. The subprocess imports
    only `vigil_integration.uiproxy` and exercises the network-free auth-path helpers, then asserts its own
    `sys.modules` carries no plane module. (uiproxy's static import purity is separately pinned by
    `test_control_plane_boundary.test_uiproxy_is_pure_stdlib`; cross-plane calls go over loopback HTTP, never
    an import.)"""
    check = (
        "import sys\n"
        "from vigil_integration import uiproxy as u\n"
        # touch the pure (no-network) helpers the auth path uses — none may transitively pull a plane module
        "u._is_vigil_identity_header('x-vigil-role')\n"
        "u._inflate_bounded(b'', 'br', 1)\n"
        "bad=[m for m in sys.modules if m=='sigil' or m.startswith(('sigil.','apps.sigil','framework.'))"
        " or m=='framework']\n"
        "sys.stdout.write(';'.join(sorted(bad)))\n"
        "sys.exit(1 if bad else 0)\n"
    )
    r = subprocess.run([sys.executable, "-c", check], capture_output=True, text=True, env=os.environ.copy())
    assert r.returncode == 0, (
        f"offense interpreter co-loaded a sovereign/framework module (FATAL-2): "
        f"[{r.stdout.strip()}] stderr=[{r.stderr.strip()}]")


# ==================================================================================================
# S1 — the proxy stamps an UNFORGEABLE hop assertion the console can verify. This pins the proxy→console
# HMAC CONTRACT: the exact field order/format the proxy signs must be the one the console verifies. The
# console-side acceptance of this same formula is pinned in
# framework/v2/console/tests/test_offense_rbac.py; together they close the loop.
# ==================================================================================================
_HOP_KEY = "proxy-hop-secret-abcdefghij0123456789"


@pytest.fixture()
def proxy_hop(tmp_path, monkeypatch):
    """A proxy built WITH a hop key (what `vigil up` does), so it stamps X-VIGIL-Role-Sig/-Ts."""
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
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve, token=OWNER_TOKEN, hop_key=_HOP_KEY)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield {"port": port, "console": console}
    finally:
        httpd.shutdown(); httpd.server_close()
        for s in (cockpit, console, api):
            s.shutdown(); s.server_close()


def test_proxy_stamps_a_verifiable_hop_signature_over_the_documented_fields(proxy_hop):
    import base64 as _b64
    import hashlib as _hl
    import hmac as _hm

    port, console = proxy_hop["port"], proxy_hop["console"]
    # an authenticated operator POST to an offense route → the proxy forwards it, substitutes the console
    # credential, and stamps the hop-signed role.
    st, _ = _req(port, "POST", "/offense/api/launch/assessment",
                 headers=_tok(OP_BEARER, {"X-Requested-With": "vigil-ui"}), body=b"{}")
    assert st in (200, 404, 500), f"an authorized operator POST must reach the backend, got {st}"
    rec = console.records[-1]
    assert rec["vigil_role"] == "operator" and rec["vigil_principal"] == "op"
    sig, ts = rec["vigil_role_sig"], rec["vigil_role_ts"]
    assert sig and ts, "the proxy (given a hop key) must stamp X-VIGIL-Role-Sig and -Ts"
    # recompute the HMAC over EXACTLY the documented fields (principal\nrole\nmethod\npath\nts). The path is
    # the CONSOLE-side path (mount prefix stripped) — the same string the console verifies against.
    msg = f"op\noperator\nPOST\n/api/launch/assessment\n{ts}".encode("utf-8")
    expected = _b64.b64encode(_hm.new(_HOP_KEY.encode(), msg, _hl.sha256).digest()).decode("ascii")
    assert _hm.compare_digest(expected, sig), "proxy signed a different field set than documented"


def test_proxy_without_hop_key_stamps_no_signature(proxy):
    # backward-compat / fail-closed: the default fixture builds the proxy with NO hop key → it stamps the
    # role for attribution but NO signature, so a console with no hop key trusts no stamped role.
    port, console = proxy["port"], proxy["console"]
    _req(port, "POST", "/offense/api/launch/assessment",
         headers=_tok(OP_BEARER, {"X-Requested-With": "vigil-ui"}), body=b"{}")
    rec = console.records[-1]
    assert rec["vigil_role"] == "operator"
    assert rec["vigil_role_sig"] == "" and rec["vigil_role_ts"] == ""
