"""The `vigil up` self-contained reverse proxy — routing, static bundle, never-public, and live SSE.

Pure-stdlib (no framework/strix/sigil), so it runs on the sovereign path:
    PYTHONPATH=integration:gateway pytest integration/tests/test_uiproxy.py -q

It stands up three trivial upstreams that ECHO the path they receive (standing in for the sovereign
cockpit 8733, the offense api 8799, the offense console 8787), points the real proxy at them, and
proves:

  * ``/sovereign/x``            → upstream-A (cockpit) sees ``/x``            (mount prefix stripped)
  * ``/offense/api/v1/y``       → upstream-C (api)     sees ``/api/v1/y``     (api /api/v1 sub-prefix)
  * ``/offense/api/status``     → upstream-B (console) sees ``/api/status``   (read plane on the console)
  * ``/offense/z``              → upstream-B (console) sees ``/z``
  * ``/`` and ``/style.css``    → the assembled bundle, served by the proxy itself
  * a public / 0.0.0.0 bind is REFUSED (never-public)
  * a ``text/event-stream`` upstream STREAMS through incrementally (not buffered): events emitted with
    delays are read one-at-a-time on the client before the stream ends.
"""
from __future__ import annotations

import http.client
import http.server
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlsplit

import pytest

from vigil_integration import uiproxy


# ---- Claim 6 per-user auth: test principals the fake sovereign whoami resolves ---------------------
# The proxy delegates verification to the sovereign `/api/whoami`; the "cockpit" echo upstream below
# stands in for it, resolving these bearers to principals (owner token → owner; per-user bearers → their
# role). An unknown bearer → {authenticated:false} → the proxy 401s.
OWNER_TOKEN = "owner-boot-tok-AAAAAAAAAAAAAAAA"      # the offense console credential + the owner login
OP_BEARER = "op-bearer-BBBBBBBBBBBBBBBBBBBB"          # operator (has run_engagement)
VIEWER_BEARER = "viewer-bearer-CCCCCCCCCCCCCCCC"      # viewer (read only)
_OWNER_PERMS = ["read", "queue_proposal", "run_engagement", "approve_a2", "toggle_guard",
                "config_nonsecret", "approve_a3", "kill_release", "promote", "secrets",
                "offense_authority", "manage_users", "toggle_protected_guard"]
_OP_PERMS = ["read", "queue_proposal", "run_engagement", "approve_a2", "toggle_guard", "config_nonsecret"]
_WHOAMI_PRINCIPALS = {
    OWNER_TOKEN: {"authenticated": True, "username": "owner", "role": "owner", "permissions": _OWNER_PERMS},
    OP_BEARER: {"authenticated": True, "username": "op", "role": "operator", "permissions": _OP_PERMS},
    VIEWER_BEARER: {"authenticated": True, "username": "vv", "role": "viewer", "permissions": ["read"]},
}


# ---- a trivial echo/SSE upstream ------------------------------------------------------------------
class _EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output quiet
        pass

    def _echo(self):
        # The "cockpit" upstream stands in for the sovereign plane's token-optional /api/whoami: resolve the
        # presented bearer to a principal (the proxy calls this to authenticate every forwarded request).
        if urlsplit(self.path).path == "/api/whoami" and getattr(self.server, "tag", "") == "cockpit":
            q = parse_qs(urlsplit(self.path).query)
            tok = self.headers.get("X-SIGIL-Token") or (q.get("token") or [""])[0]
            raw = json.dumps(_WHOAMI_PRINCIPALS.get(tok, {"authenticated": False})).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        # /sse streams events with real gaps so a buffering proxy would be caught out.
        if self.path.startswith("/sse"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(4):
                self.wfile.write(f"data: tick-{i}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.25)
            return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        # echo the exact path the upstream saw + the method + the forwarded Host, so the test can
        # assert the prefix-stripping and header faithfulness.
        payload = (f"UP={self.server.tag}\nPATH={self.path}\nMETHOD={self.command}\n"
                   f"HOST={self.headers.get('Host', '')}\nBODY={body.decode('utf-8', 'replace')}\n")
        raw = payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _echo
    do_POST = _echo


class _EchoServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_echo(tag: str) -> tuple[_EchoServer, int]:
    srv = _EchoServer(("127.0.0.1", 0), _EchoHandler)
    srv.tag = tag  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def proxy(tmp_path, monkeypatch):
    """A live proxy in front of three echo upstreams, with an assembled bundle serve dir."""
    a, sov_port = _start_echo("cockpit")
    b, con_port = _start_echo("console")
    c, api_port = _start_echo("api")
    # repoint the proxy's fixed backend ports at our ephemeral upstreams.
    monkeypatch.setattr(uiproxy, "SOVEREIGN_PORT", sov_port)
    monkeypatch.setattr(uiproxy, "CONSOLE_PORT", con_port)
    monkeypatch.setattr(uiproxy, "API_PORT", api_port)

    # assemble a serve dir from a minimal source bundle (placeholders present, to prove substitution).
    src = tmp_path / "src"
    src.mkdir()
    (src / "tokens.css").write_text(":root{--a:1}", encoding="utf-8")
    (src / "components.css").write_text(".btn{color:red}", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(f"/*{j}*/", encoding="utf-8")
    (src / "index.html").write_text(
        '<body data-token="__VIGIL_TOKEN__" data-sovereign="__VIGIL_SOVEREIGN__" '
        'data-offense="__VIGIL_OFFENSE__"></body>', encoding="utf-8")
    serve = tmp_path / "serve"
    uiproxy.assemble_serve_dir(src, serve, token="TESTTOKEN")

    port = _free_port()
    # Claim 6: build the proxy WITH the offense console credential (= OWNER_TOKEN) it substitutes on an
    # authenticated offense forward. Per-user auth is delegated to the cockpit upstream's /api/whoami above.
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve, token=OWNER_TOKEN)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, serve
    finally:
        httpd.shutdown()
        httpd.server_close()
        for s in (a, b, c):
            s.shutdown()
            s.server_close()


def _get(url: str, token: str = OWNER_TOKEN) -> tuple[int, str]:
    req = urllib.request.Request(url)
    if token:
        req.add_header("X-SIGIL-Token", token)   # Claim 6: every forwarded route is per-user authenticated
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.read().decode("utf-8", "replace")


def _post(url: str, body: bytes, token: str = OWNER_TOKEN) -> str:
    req = urllib.request.Request(url, method="POST", data=body)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-SIGIL-Token", token)
    with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
        return r.read().decode("utf-8", "replace")


# ==================================================================================================
# routing
# ==================================================================================================
def test_sovereign_prefix_stripped_to_cockpit(proxy):
    base, _serve = proxy
    _st, body = _get(base + "/sovereign/x")
    assert "UP=cockpit" in body
    assert "PATH=/x" in body


def test_sovereign_query_and_root_preserved(proxy):
    base, _serve = proxy
    _st, body = _get(base + "/sovereign/api/snapshot?run=1")
    assert "UP=cockpit" in body
    assert "PATH=/api/snapshot?run=1" in body
    _st2, root = _get(base + "/sovereign")
    assert "UP=cockpit" in root and "PATH=/" in root


def test_offense_api_v1_goes_to_the_api(proxy):
    base, _serve = proxy
    body = _post(base + "/offense/api/v1/tool/invoke", b'{"x":1}')
    assert "UP=api" in body
    assert "PATH=/api/v1/tool/invoke" in body
    assert 'BODY={"x":1}' in body           # request body forwarded faithfully
    assert "METHOD=POST" in body


def test_offense_read_plane_goes_to_the_console(proxy):
    base, _serve = proxy
    # the P1 UI's actual read calls (/offense/api/status, /offense/api/tools) must reach the CONSOLE.
    for path, expect in (("/offense/api/status", "/api/status"),
                         ("/offense/api/tools", "/api/tools"),
                         ("/offense/api/events", "/api/events"),
                         ("/offense/z", "/z")):
        _st, body = _get(base + path)
        assert "UP=console" in body, f"{path} must route to the console"
        assert f"PATH={expect}" in body


def test_forwarded_host_is_unchanged(proxy):
    base, _serve = proxy
    # the proxy forwards the client's Host to the upstream (its anti-rebind allowlist matches on it).
    _st, body = _get(base + "/offense/api/status")
    assert "HOST=127.0.0.1:" in body


# ==================================================================================================
# static bundle served by the proxy itself
# ==================================================================================================
def test_root_serves_the_assembled_index_with_substituted_placeholders(proxy):
    base, _serve = proxy
    st, body = _get(base + "/")
    assert st == 200
    # Claim 6: the owner token is NOT embedded — the served page carries no credential. The placeholder is
    # emptied (data-token=""), so the SPA's login gate is the entry and each user carries their own bearer.
    assert 'data-token=""' in body
    assert "TESTTOKEN" not in body
    assert 'data-sovereign="/sovereign"' in body
    assert 'data-offense="/offense"' in body
    assert "__VIGIL_TOKEN__" not in body


def test_style_css_is_the_concatenated_bundle(proxy):
    base, _serve = proxy
    st, body = _get(base + "/style.css")
    assert st == 200
    assert "--a:1" in body and ".btn{color:red}" in body   # tokens.css + components.css


def test_static_has_strict_csp(proxy):
    base, _serve = proxy
    with urllib.request.urlopen(base + "/", timeout=5) as r:  # noqa: S310
        assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


# ==================================================================================================
# deploy hygiene: a per-build cache-buster + revalidating static, so a redeploy is never masked by a
# warm browser cache (the "I updated the UI but still see the old one" gap).
# ==================================================================================================
def _assemble_build(tmp_path, tag, *, app_js="/*app.js*/", index=None):
    src = tmp_path / ("src-" + tag)
    src.mkdir()
    (src / "tokens.css").write_text(":root{--a:1}", encoding="utf-8")
    (src / "components.css").write_text(".btn{color:red}", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(app_js if j == "app.js" else f"/*{j}*/", encoding="utf-8")
    (src / "index.html").write_text(
        index if index is not None else "<body></body>", encoding="utf-8")
    serve = tmp_path / ("serve-" + tag)
    uiproxy.assemble_serve_dir(src, serve, token="T")
    return serve


def test_assemble_stamps_a_build_id_and_versions_the_bundle(tmp_path):
    """A per-deploy build id is written to `.build-id` and substituted into index.html — both the body
    `data-build` (so the running page knows its own build) and the `?v=<build>` cache-buster on the
    asset URLs (so a redeploy changes the URL and a warm cache cannot serve a stale bundle)."""
    serve = _assemble_build(
        tmp_path, "stamp",
        index='<body data-build="__VIGIL_BUILD__"><script src="app.js?v=__VIGIL_BUILD__"></script></body>')
    build = (serve / ".build-id").read_text(encoding="utf-8").strip()
    assert len(build) == 12 and all(c in "0123456789abcdef" for c in build)
    html = (serve / "index.html").read_text(encoding="utf-8")
    assert "__VIGIL_BUILD__" not in html
    assert f'data-build="{build}"' in html
    assert f"app.js?v={build}" in html


def test_build_id_is_deterministic_and_sensitive_to_bundle_changes(tmp_path):
    """Same bytes → same id (a no-op redeploy does not needlessly bust the cache); a changed bundle →
    a new id (the changed code IS picked up)."""
    a1 = (_assemble_build(tmp_path, "a", app_js="/*v1*/") / ".build-id").read_text(encoding="utf-8")
    a2 = (_assemble_build(tmp_path, "b", app_js="/*v1*/") / ".build-id").read_text(encoding="utf-8")
    b1 = (_assemble_build(tmp_path, "c", app_js="/*v2 CHANGED*/") / ".build-id").read_text(encoding="utf-8")
    assert a1 == a2          # deterministic
    assert a1 != b1          # sensitive — a code change mints a new build id


def test_static_assets_revalidate_with_etag_and_304(proxy):
    """Every static asset carries an ETag + `Cache-Control: no-cache`, so the browser MUST revalidate
    it — and a matching `If-None-Match` returns a bodyless 304. That is what makes a redeploy visible
    without a hard reload, cheaply."""
    import http.client
    hostname, port = base_hostport(proxy[0])
    conn = http.client.HTTPConnection(hostname, port, timeout=5)
    conn.request("GET", "/style.css")
    r = conn.getresponse(); r.read()
    etag = r.getheader("ETag")
    assert etag and etag.startswith('"')
    assert "no-cache" in (r.getheader("Cache-Control") or "")
    conn.close()
    # a fresh connection (static responses close the socket) with the SAME ETag → 304, no body
    conn2 = http.client.HTTPConnection(hostname, port, timeout=5)
    conn2.request("GET", "/style.css", headers={"If-None-Match": etag})
    r2 = conn2.getresponse(); body2 = r2.read()
    assert r2.status == 304
    assert body2 == b""
    assert r2.getheader("ETag") == etag
    conn2.close()


def base_hostport(base: str):
    host = base.replace("http://", "").replace("https://", "")
    hostname, port = host.split(":")
    return hostname, int(port)


def test_unknown_static_path_is_404_not_proxied(proxy):
    base, _serve = proxy
    try:
        _get(base + "/nope.js")
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        assert e.code == 404


def test_path_traversal_is_refused(proxy):
    base, _serve = proxy
    # a raw request line so urllib does not normalize the ../ away before it reaches the proxy.
    host = base.removeprefix("http://")
    conn = http.client.HTTPConnection(host, timeout=5)
    conn.request("GET", "/../../etc/passwd")
    resp = conn.getresponse()
    resp.read()
    conn.close()
    assert resp.status == 404


# ==================================================================================================
# never-public
# ==================================================================================================
def test_public_bind_is_refused(tmp_path):
    serve = tmp_path / "serve"
    serve.mkdir()
    for bad in ("0.0.0.0", "8.8.8.8", "::"):
        with pytest.raises(ValueError):
            uiproxy.make_proxy_server(bad, 8770, serve)


def test_child_env_never_leaks_owner_signing_key(monkeypatch):
    # A4: a VIGIL_DESTRUCTION_OWNER_KEY exported in the PARENT `vigil up` env must NEVER be inherited by a
    # spawned child. The sovereign settings-plane allowlist only governs settings INJECTED afterward, not the
    # ambient env `_child_env` starts from, so the key is hard-excluded at the source.
    monkeypatch.setenv("VIGIL_DESTRUCTION_OWNER_KEY", "ed25519-owner-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-legit-offense-key")
    env = uiproxy._child_env()
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in env
    assert env.get("ANTHROPIC_API_KEY") == "sk-legit-offense-key"   # a legitimate key is not over-stripped


# ==================================================================================================
# SSE — the response must stream through live, not be buffered
# ==================================================================================================
def test_sse_streams_incrementally(proxy):
    base, _serve = proxy
    # the console upstream's /sse emits 4 events at 0.25s intervals. Read them one at a time and
    # assert the FIRST event arrives well before the LAST — proof the proxy is not buffering the body.
    conn = http.client.HTTPConnection(base.removeprefix("http://"), timeout=10)
    conn.request("GET", "/offense/sse", headers={"X-SIGIL-Token": OWNER_TOKEN})   # per-user authenticated
    resp = conn.getresponse()
    assert resp.getheader("Content-Type", "").startswith("text/event-stream")

    events: list[tuple[float, str]] = []
    start = time.monotonic()
    buf = b""
    while len(events) < 4:
        chunk = resp.read1(4096)
        if not chunk:
            break
        buf += chunk
        while b"\n\n" in buf:
            frame, buf = buf.split(b"\n\n", 1)
            if frame.strip():
                events.append((time.monotonic() - start, frame.decode("utf-8", "replace")))
    conn.close()

    assert len(events) == 4, f"expected 4 streamed events, got {events}"
    assert "tick-0" in events[0][1] and "tick-3" in events[3][1]
    # the last event must arrive materially later than the first — if the proxy had buffered the whole
    # body, all four would land at ~the same instant. Require a real spread across the 0.75s of gaps.
    assert events[3][0] - events[0][0] > 0.4, f"stream looks buffered: arrival times {[t for t, _ in events]}"


# ==================================================================================================
# serve-dir assembly (unit)
# ==================================================================================================
def test_assemble_serve_dir_contents(tmp_path):
    src = tmp_path / "s"
    src.mkdir()
    (src / "tokens.css").write_text("T", encoding="utf-8")
    (src / "components.css").write_text("C", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(j, encoding="utf-8")
    (src / "manifest.json").write_text("{}", encoding="utf-8")
    (src / "index.html").write_text("__VIGIL_TOKEN__|__VIGIL_SOVEREIGN__|__VIGIL_OFFENSE__",
                                    encoding="utf-8")
    out = tmp_path / "o"
    uiproxy.assemble_serve_dir(src, out, token="TK")
    assert (out / "style.css").read_text(encoding="utf-8") == "T\nC"
    for j in uiproxy.BUNDLE_JS:
        assert (out / j).read_text(encoding="utf-8") == j
    assert (out / "manifest.json").exists()
    # Claim 6: __VIGIL_TOKEN__ is emptied (no credential in the page); the mount bases still substitute.
    assert (out / "index.html").read_text(encoding="utf-8") == "|/sovereign|/offense"
    assert "TK" not in (out / "index.html").read_text(encoding="utf-8")


def test_serve_dir_index_are_owner_only_and_carry_no_token(tmp_path):
    # BLOCK-2 posture kept as defense-in-depth: the runtime serve dir is 0700 and index.html 0600 (runtime
    # state, owner-only). Claim 6 additionally requires the owner token is NOT embedded — the served page
    # carries no credential, so a teammate given the URL still cannot read the owner token off the page.
    import stat
    src = tmp_path / "s"
    src.mkdir()
    (src / "tokens.css").write_text("T", encoding="utf-8")
    (src / "components.css").write_text("C", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(j, encoding="utf-8")
    (src / "index.html").write_text('data-token="__VIGIL_TOKEN__"', encoding="utf-8")
    out = tmp_path / "o"
    uiproxy.assemble_serve_dir(src, out, token="SECRET-TK")
    assert stat.S_IMODE(out.stat().st_mode) == 0o700, "serve dir must be owner-only"
    assert stat.S_IMODE((out / "index.html").stat().st_mode) == 0o600, "index must be owner-only"
    assert not (out / "index.html").stat().st_mode & (stat.S_IRGRP | stat.S_IROTH)
    # the owner token must never appear in the served page (Claim 6)
    assert "SECRET-TK" not in (out / "index.html").read_text(encoding="utf-8")
    assert 'data-token=""' in (out / "index.html").read_text(encoding="utf-8")


def test_static_response_closes_the_connection(proxy):
    # BLOCK-1 fix: a static response MUST send `Connection: close` and close the socket, so a request
    # body left un-consumed can never be re-parsed as a pipelined (smuggled) request.
    base, _serve = proxy
    conn = http.client.HTTPConnection(base.removeprefix("http://"), timeout=5)
    conn.request("GET", "/")
    resp = conn.getresponse()
    resp.read()
    assert resp.status == 200
    assert (resp.getheader("Connection") or "").lower() == "close"
    conn.close()


def test_run_up_refuses_domain_without_api_key(tmp_path, monkeypatch):
    # R2 fix (fail-closed): --domain is internet-fronted; refuse if CRUCIBLE_API_KEY is unset (would
    # expose the gated offense api unauthenticated), unless --insecure-no-api-key is given.
    monkeypatch.delenv("CRUCIBLE_API_KEY", raising=False)
    rc = uiproxy.run_up(host="127.0.0.1", port=0, domain="vigil.example.com",
                        base_dir=str(tmp_path), no_browser=True)
    assert rc == 2, "must refuse --domain without CRUCIBLE_API_KEY"


# ---- P4: the cross-plane LLM-env bridge (sovereign → keyless offense children) ---------------------
import stat as _stat         # noqa: E402
import sys as _sys           # noqa: E402


def _fake_sigil(tmp_path, body: str):
    """Write a tiny executable standing in for the sovereign `sigil` console-script."""
    p = tmp_path / "fake-sigil"
    p.write_text("#!/usr/bin/env python3\nimport sys\n" + body, encoding="utf-8")
    p.chmod(p.stat().st_mode | _stat.S_IEXEC | _stat.S_IRWXU)
    return p


def test_resolve_offense_llm_env_parses_json(tmp_path):
    sig = _fake_sigil(tmp_path, "print('{\"CRUCIBLE_ANTHROPIC_MODEL\": \"claude-opus-5\", "
                                "\"ANTHROPIC_API_KEY\": \"sk-SECRET\"}')\n")
    env = uiproxy._resolve_offense_llm_env(sig)
    assert env == {"CRUCIBLE_ANTHROPIC_MODEL": "claude-opus-5", "ANTHROPIC_API_KEY": "sk-SECRET"}


def test_resolve_offense_llm_env_failsoft(tmp_path):
    # non-existent bin, non-JSON output, non-zero exit → {} (offense simply runs keyless)
    assert uiproxy._resolve_offense_llm_env(tmp_path / "nope") == {}
    assert uiproxy._resolve_offense_llm_env(_fake_sigil(tmp_path, "print('not json')\n")) == {}
    assert uiproxy._resolve_offense_llm_env(_fake_sigil(tmp_path, "sys.exit(3)\n")) == {}
    # a JSON non-object, and non-string/empty values, are all rejected → {}
    assert uiproxy._resolve_offense_llm_env(_fake_sigil(tmp_path, "print('[1,2,3]')\n")) == {}
    # OBS-2 hardening: the CONSUMER key-allowlists too. A non-allowlisted key, an int, and an empty
    # value are all dropped; only allowlisted non-empty str→str survives.
    filtered = uiproxy._resolve_offense_llm_env(_fake_sigil(
        tmp_path, "print('{\"EVIL\": \"x\", \"CRUCIBLE_ANTHROPIC_MODEL\": 5, "
                  "\"SIGIL_LLM_MODEL\": \"\", \"CRUCIBLE_LLM_BACKEND\": \"claude-code\"}')\n"))
    assert filtered == {"CRUCIBLE_LLM_BACKEND": "claude-code"}    # EVIL dropped, int dropped, empty dropped


def test_resolve_offense_llm_env_never_writes_a_file(tmp_path, monkeypatch):
    # the secret is captured on a PRIVATE pipe, not the teed backend logs — resolving must create no files
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    sig = _fake_sigil(tmp_path, "print('{\"ANTHROPIC_API_KEY\": \"sk-SECRET\"}')\n")
    env = uiproxy._resolve_offense_llm_env(sig)
    assert env.get("ANTHROPIC_API_KEY") == "sk-SECRET"
    assert list(workdir.iterdir()) == []     # no stray file holding the captured secret


def test_spawn_injects_extra_env(tmp_path, monkeypatch):
    # deterministic regardless of an ambient ANTHROPIC_API_KEY in the runner's environment: the child
    # inherits the parent env, so a real key present in the session would otherwise make "K=none" flap.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    log = tmp_path / "child.log"
    argv = [_sys.executable, "-c",
            "import os;print('M='+os.environ.get('CRUCIBLE_ANTHROPIC_MODEL','none')+"
            "';K='+os.environ.get('ANTHROPIC_API_KEY','none'))"]
    proc = uiproxy._spawn(argv, log, extra_env={"CRUCIBLE_ANTHROPIC_MODEL": "claude-opus-5"})
    proc.wait(timeout=10)
    out = log.read_text(encoding="utf-8")
    assert "M=claude-opus-5" in out            # injected var reached the child
    assert "K=none" in out                     # a var we did NOT inject is absent (no accidental leak)


def test_console_vigil_bin_is_the_offense_sibling(tmp_path):
    # A0: the console child must get an absolute VIGIL_BIN (the offense-venv `vigil`, sibling of `crucible`)
    # so a graph-backed engage never silently falls back to the non-graph engine when `vigil` isn't on PATH.
    binroot = tmp_path / ".venv-offense" / "bin"
    binroot.mkdir(parents=True)
    crucible = binroot / "crucible"
    crucible.write_text("#!/bin/sh\n", encoding="utf-8")
    # no `vigil` sibling yet → None (never point the child at a bad path; it keeps its PATH fallback)
    assert uiproxy._console_vigil_bin(crucible) is None
    vigil = binroot / "vigil"
    vigil.write_text("#!/bin/sh\n", encoding="utf-8")
    assert uiproxy._console_vigil_bin(crucible) == str(vigil)    # resolves to the sibling, absolute


# =============== crash-hardening of `vigil up` (B1/B2/B4/B6) — helper coverage ===============

def test_port_free_detects_a_busy_port():
    # B1 preflight: a bound (listening) port reads as NOT free; an unbound one reads free.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    busy_port = s.getsockname()[1]
    try:
        assert uiproxy._port_free("127.0.0.1", busy_port) is False
    finally:
        s.close()
    # a now-free ephemeral port (grab one, release it)
    f = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    f.bind(("127.0.0.1", 0)); free_port = f.getsockname()[1]; f.close()
    assert uiproxy._port_free("127.0.0.1", free_port) is True


def test_wait_listening_true_when_up_false_when_dead():
    # B4 readiness probe.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert uiproxy._wait_listening("127.0.0.1", port, time.monotonic() + 2.0) is True
    finally:
        srv.close()
    # nothing is listening now → the probe returns False by its (short) deadline
    assert uiproxy._wait_listening("127.0.0.1", port, time.monotonic() + 0.4) is False


def test_child_env_is_unbuffered():
    # B2: every child inherits PYTHONUNBUFFERED so the cockpit's token line flushes (no 120s hang).
    assert uiproxy._child_env().get("PYTHONUNBUFFERED") == "1"


def test_cockpit_timeout_tolerates_bad_and_degenerate_values(monkeypatch):
    # B6/B6-4: a bad OR degenerate-but-float-valid VIGIL_UP_COCKPIT_TIMEOUT must fall back to 120 — never
    # raise (import-time), never hang forever (inf/1e999), never abort instantly (nan / <=0).
    for bad in ("not-a-number", "inf", "1e999", "1e300", "-inf", "nan", "0", "-5", "1e-9", "0.5", "99999"):
        monkeypatch.setenv("VIGIL_UP_COCKPIT_TIMEOUT", bad)
        assert uiproxy._cockpit_timeout() == 120.0, bad
    monkeypatch.setenv("VIGIL_UP_COCKPIT_TIMEOUT", "45")
    assert uiproxy._cockpit_timeout() == 45.0
    monkeypatch.delenv("VIGIL_UP_COCKPIT_TIMEOUT", raising=False)
    assert uiproxy._cockpit_timeout() == 120.0


def test_await_token_signature_is_lazy():
    # B6 root cause: the timeout default must be None (parsed in-body), never an env read at def-time.
    import inspect
    assert inspect.signature(uiproxy._await_token).parameters["timeout"].default is None


def test_port_free_uses_reuseaddr_like_the_real_bind():
    # B1-1: the preflight must mirror the proxy's allow_reuse_address, or a quick restart whose port is in
    # TIME_WAIT is falsely refused. Guard the implementation + a behavioural TIME_WAIT check.
    import inspect
    assert "SO_REUSEADDR" in inspect.getsource(uiproxy._port_free)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close(); cli.close(); srv.close()          # server-side close first → (127.0.0.1, port) TIME_WAIT
    assert uiproxy._port_free("127.0.0.1", port) is True   # REUSEADDR → still bindable, matching the proxy


def test_spawn_tracked_cleans_up_on_spawn_failure(monkeypatch):
    # B?-2: a failed spawn must clean up EVERYTHING already started and signal abort — never orphan.
    procs = [("already-running", object())]
    cleaned = {"called": False}

    def _boom(*a, **k):
        raise OSError(24, "EMFILE")                 # too many open files / fork pressure
    monkeypatch.setattr(uiproxy, "_spawn", _boom)
    aborted = uiproxy._spawn_tracked(procs, "offense-console", ["x"], object(),
                                     lambda: cleaned.__setitem__("called", True))
    assert aborted is True                          # caller returns 1 (a clean abort)
    assert cleaned["called"] is True                # the running backends were cleaned up
    assert len(procs) == 1                          # the failed spawn was not appended

    # success path: appended, returns False, no (further) cleanup
    monkeypatch.setattr(uiproxy, "_spawn", lambda *a, **k: "PROC")
    ok = uiproxy._spawn_tracked(procs, "offense-api", ["y"], object(), lambda: None)
    assert ok is False and procs[-1] == ("offense-api", "PROC")


def test_plane_control_stop_offense_already_stopped_when_nothing_listens():
    """Nothing listening on either backend port → an immediate, idempotent `already_stopped`, and the
    on_stopped callback is never invoked (there is nothing to terminate)."""
    port = _free_port()
    called = []
    specs = [("offense-console", ["a"], "log", {}, "127.0.0.1", port),
             ("offense-api", ["b"], "log", {}, "127.0.0.1", port)]
    pc = uiproxy.PlaneControl(specs, on_stopped=lambda names: called.append(names))
    res = pc.stop_offense()
    assert res["result"] == "already_stopped"
    assert res["ok"] is True
    assert called == []


def test_plane_control_stop_offense_uses_on_stopped_for_boot_children():
    """The common case: the console + api were spawned at boot (not through this object), so stop asks
    its on_stopped callback to terminate + un-track them — passing ONLY the two offense names — and then
    reports a measured `stopped` once their ports read free. A second stop is idempotent."""
    s1 = socket.socket(); s1.bind(("127.0.0.1", 0)); s1.listen()
    s2 = socket.socket(); s2.bind(("127.0.0.1", 0)); s2.listen()
    p1 = s1.getsockname()[1]
    p2 = s2.getsockname()[1]
    asked = []

    def _on_stopped(names):
        asked.extend(names)
        s1.close(); s2.close()            # the boot path kills the children → ports freed
    specs = [("offense-console", ["a"], "log", {}, "127.0.0.1", p1),
             ("offense-api", ["b"], "log", {}, "127.0.0.1", p2)]
    pc = uiproxy.PlaneControl(specs, on_stopped=_on_stopped)
    try:
        res = pc.stop_offense()
    finally:
        for s in (s1, s2):
            try:
                s.close()
            except OSError:
                pass
    assert set(asked) == {"offense-console", "offense-api"}
    assert res["result"] == "stopped"
    assert res["status"]["running"] is False
    # idempotent: nothing listening now → already_stopped, callback not invoked again
    asked.clear()
    res2 = pc.stop_offense()
    assert res2["result"] == "already_stopped"
    assert asked == []


def test_plane_control_stop_offense_terminates_a_child_it_started(monkeypatch):
    """A backend the proxy itself started (a Popen in `_children`) is terminated on stop; the port then
    reads free and the result is a clean `stopped`."""
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen()
    port = sock.getsockname()[1]
    killed = []

    def _fake_terminate(pid, **_kw):
        killed.append(pid)
        sock.close()                      # the child dying frees its listening port
        return True
    monkeypatch.setattr(uiproxy, "_terminate", _fake_terminate)

    class _FakeProc:
        pid = 4242

        def poll(self):
            return None                   # alive
    specs = [("offense-console", ["x"], "log", {}, "127.0.0.1", port)]
    pc = uiproxy.PlaneControl(specs)
    pc._children["offense-console"] = _FakeProc()
    try:
        res = pc.stop_offense()
    finally:
        try:
            sock.close()
        except OSError:
            pass
    assert 4242 in killed
    assert res["result"] == "stopped"
    assert res["status"]["running"] is False


def test_plane_control_stop_offense_reports_failure_if_a_backend_will_not_die(monkeypatch):
    """A kill that did not take (the backend keeps listening) must surface as an honest `failed` that
    NAMES the surviving backend — never a false clean stop."""
    monkeypatch.setattr(uiproxy.time, "sleep", lambda *_a: None)   # skip the settle wait; fail fast
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen()
    port = sock.getsockname()[1]
    specs = [("offense-console", ["x"], "log", {}, "127.0.0.1", port)]
    pc = uiproxy.PlaneControl(specs, on_stopped=lambda names: None)   # does NOT free the port
    try:
        res = pc.stop_offense()
    finally:
        sock.close()
    assert res["ok"] is False
    assert res["result"] == "failed"
    assert "offense-console" in res["error"]


def test_plane_control_stop_offense_keeps_a_child_it_could_not_kill(monkeypatch):
    """A UI-started child that survives the kill (poll stays None — a D-state child) must KEEP its Popen
    handle so a retry can still re-target it, symmetric with _unadopt. Dropping it would strand the plane
    (the operator would have to fall back to `vigil down`)."""
    monkeypatch.setattr(uiproxy.time, "sleep", lambda *_a: None)   # skip the settle wait; fail fast
    monkeypatch.setattr(uiproxy, "_terminate", lambda pid, **_k: False)   # the kill does not take
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen()
    port = sock.getsockname()[1]

    class _Stubborn:
        pid = 5252

        def poll(self):
            return None                   # never dies
    specs = [("offense-console", ["x"], "log", {}, "127.0.0.1", port)]
    pc = uiproxy.PlaneControl(specs)
    pc._children["offense-console"] = _Stubborn()
    try:
        res = pc.stop_offense()
    finally:
        sock.close()
    assert res["result"] == "failed"
    assert "offense-console" in pc._children   # handle KEPT so a retry can re-target the survivor


def test_new_plane_routes_are_guarded_like_start(proxy):
    """/offense/stop (POST) and /offense/version (GET) run the SAME guard chain as /offense/start: this
    fixture's proxy has no session token, so every plane route fails closed with a 4xx BEFORE the route
    body runs — proving the guard is not bypassed for the routes this slice added."""
    base, _serve = proxy
    for method, path in [("POST", "/__vigil/plane/offense/stop"),
                         ("GET", "/__vigil/plane/version")]:
        req = urllib.request.Request(base + path, method=method,
                                     data=(b"{}" if method == "POST" else None))
        try:
            urllib.request.urlopen(req, timeout=5)  # noqa: S310 (loopback test)
            raise AssertionError(f"{method} {path} should have been refused (no token)")
        except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
            assert e.code in (401, 403), f"{method} {path} → {e.code} (expected a fail-closed refusal)"
