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
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from vigil_integration import uiproxy


# ---- a trivial echo/SSE upstream ------------------------------------------------------------------
class _EchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep test output quiet
        pass

    def _echo(self):
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
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve)
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


def _get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 (loopback test)
        return r.status, r.read().decode("utf-8", "replace")


def _post(url: str, body: bytes) -> str:
    req = urllib.request.Request(url, method="POST", data=body)
    req.add_header("Content-Type", "application/json")
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
    assert 'data-token="TESTTOKEN"' in body
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


# ==================================================================================================
# SSE — the response must stream through live, not be buffered
# ==================================================================================================
def test_sse_streams_incrementally(proxy):
    base, _serve = proxy
    # the console upstream's /sse emits 4 events at 0.25s intervals. Read them one at a time and
    # assert the FIRST event arrives well before the LAST — proof the proxy is not buffering the body.
    conn = http.client.HTTPConnection(base.removeprefix("http://"), timeout=10)
    conn.request("GET", "/offense/sse")
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
    assert (out / "index.html").read_text(encoding="utf-8") == "TK|/sovereign|/offense"


def test_serve_dir_and_token_index_are_owner_only(tmp_path):
    # BLOCK-2 fix: index.html embeds the sovereign session TOKEN, so the runtime serve dir must be 0700
    # and the token-bearing index.html 0600 — never world-readable on a multi-user host.
    import stat
    src = tmp_path / "s"
    src.mkdir()
    (src / "tokens.css").write_text("T", encoding="utf-8")
    (src / "components.css").write_text("C", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(j, encoding="utf-8")
    (src / "index.html").write_text("__VIGIL_TOKEN__", encoding="utf-8")
    out = tmp_path / "o"
    uiproxy.assemble_serve_dir(src, out, token="SECRET-TK")
    assert stat.S_IMODE(out.stat().st_mode) == 0o700, "serve dir must be owner-only"
    assert stat.S_IMODE((out / "index.html").stat().st_mode) == 0o600, "token index must be owner-only"
    # the token must NOT be world/group readable anywhere in the tree
    assert not (out / "index.html").stat().st_mode & (stat.S_IRGRP | stat.S_IROTH)


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
