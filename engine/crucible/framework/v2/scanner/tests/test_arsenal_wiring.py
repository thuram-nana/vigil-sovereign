"""
Wave 4 — the advanced web arsenal wired into WebScanCampaign behind `enable_arsenal`.

Two properties matter and are tested here:

  * DEFAULT-SAFE / gate-neutral — with the flag OFF (the default) the scan is
    unchanged: the arsenal lead lists stay empty and no arsenal-only bug class ever
    reaches active_findings. This is what keeps `make gate` byte-identical.
  * ADDITIVE + GATED + ORACLE-ANCHORED — with the flag ON the modules run: content /
    JS discovery surface LEADS (never confirmed), request smuggling and CSWSH confirm
    through their oracles (with a re-verifiable certificate), a benign server yields no
    smuggling false positive, and the raw-socket modules refuse an unauthorized host
    (fail-closed).

All traffic is loopback. The smuggling and WS servers are raw-socket fixtures (the
same shapes scanner.smuggling / scanner.websocket are unit-tested against).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.campaign import WebScanCampaign

_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _dummy_send(req):
    """A send that must never be reached by the raw-socket arsenal (which speaks
    bytes directly). The crawl/discovery paths that DO use it are not exercised in
    the raw-socket unit tests."""
    return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}


# ---------------------------------------------------------------------------
# an HTTP fixture with hidden paths + a JS bundle carrying a secret and a ws:// ref
# ---------------------------------------------------------------------------


class _DiscoveryApp(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            body = (
                b'<html><a href="/search?q=hi">search</a>'
                b'<script>var k="' + _AWS_KEY.encode() + b'";'
                b'var s=new WebSocket("ws://127.0.0.1/live");</script></html>'
            )
            status = 200
        elif path == "/search":
            q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html>echo:{q}</html>".encode()
            status = 200
        elif path in ("/.env", "/admin"):
            body = b"SECRET=1"
            status = 200
        else:
            body = b"not found"
            status = 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _http_server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


# ---------------------------------------------------------------------------
# a raw server that hangs on the smuggling probe signature (a desync)
# ---------------------------------------------------------------------------


class _HangingRawServer(threading.Thread):
    def __init__(self, delay: float) -> None:
        super().__init__(daemon=True)
        self.delay = delay
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(1.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            with contextlib.suppress(socket.timeout):
                data += conn.recv(4096)
        low = data.lower()
        if self.delay and b"transfer-encoding: chunked" in low and b"content-length" in low:
            time.sleep(self.delay)  # simulate the back-end hanging on a chunk that never comes
        with contextlib.suppress(OSError):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol")
        conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _hanging_server(delay: float) -> Iterator[int]:
    srv = _HangingRawServer(delay)
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# a raw WS server that accepts ANY origin (vulnerable to CSWSH)
# ---------------------------------------------------------------------------

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _AnyOriginWSServer(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        key = ""
        for line in data.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                if k.decode().strip().lower() == "sec-websocket-key":
                    key = v.decode().strip()
        accept = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
        with contextlib.suppress(OSError):
            conn.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n")
        with contextlib.suppress(OSError):
            conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _ws_server() -> Iterator[int]:
    srv = _AnyOriginWSServer()
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# default-safe: the flag OFF leaves the scan unchanged
# ---------------------------------------------------------------------------


def test_arsenal_off_is_the_default_and_surfaces_nothing() -> None:
    from framework.v2.scanner.cli import loopback_send

    with _http_server(_DiscoveryApp) as base:
        off = WebScanCampaign(loopback_send, max_pages=10, enable_oob=False).run(base + "/")
    # the new lead lists are empty and no arsenal-only class leaked into findings
    assert off.discovered_paths == []
    assert off.js_secrets == []
    assert off.arsenal_leads == []
    assert all(f.bug_class not in {"request_smuggling", "cross_site_websocket_hijacking",
                                   "request_race"} for f in off.active_findings)


def test_arsenal_on_surfaces_discovery_and_js_leads_only() -> None:
    from framework.v2.scanner.cli import loopback_send

    with _http_server(_DiscoveryApp) as base:
        on = WebScanCampaign(
            loopback_send, max_pages=10, enable_oob=False, enable_arsenal=True,
        ).run(base + "/")
    # content discovery reached the hidden paths (gated via the injected send)
    found = {p.path for p in on.discovered_paths}
    assert "/.env" in found and "/admin" in found, found
    # JS mining pulled the planted AWS key out of the bundle
    assert any(s.value == _AWS_KEY for s in on.js_secrets), on.js_secrets
    # the mined ws:// endpoint surfaced as a lead
    assert any("ws://127.0.0.1/live" in lead for lead in on.arsenal_leads), on.arsenal_leads
    # leads are NEVER confirmed findings — prove-don't-guess stays intact
    assert all(f.bug_class not in {"js_secret", "content_discovery"} for f in on.active_findings)


def test_arsenal_on_no_smuggling_false_positive_on_a_benign_server() -> None:
    from framework.v2.scanner.cli import loopback_send

    # a normal HTTP app never hangs on a smuggling probe, so the latency oracle
    # must not fire — no request_smuggling finding (the negative control).
    with _http_server(_DiscoveryApp) as base:
        on = WebScanCampaign(
            loopback_send, max_pages=10, enable_oob=False, enable_arsenal=True,
        ).run(base + "/")
    assert not any(f.bug_class == "request_smuggling" for f in on.active_findings)


# ---------------------------------------------------------------------------
# fail-closed host gating for the raw-socket arsenal
# ---------------------------------------------------------------------------


def test_arsenal_host_gate_is_fail_closed() -> None:
    # no authz gate (loopback `scan`): only loopback hosts are allowed
    loopback_only = WebScanCampaign(_dummy_send, enable_arsenal=True)
    assert loopback_only._arsenal_host_allowed("http://127.0.0.1:9/x") is True
    assert loopback_only._arsenal_host_allowed("http://10.0.0.5/x") is False
    assert loopback_only._arsenal_host_allowed("http://example.com/x") is False

    # an authz gate that DENIES refuses even a loopback host
    deny = WebScanCampaign(_dummy_send, enable_arsenal=True, arsenal_authz=lambda url: False)
    assert deny._arsenal_host_allowed("http://127.0.0.1:9/x") is False

    # a gate that ALLOWS lets a remote in-scope host through
    allow = WebScanCampaign(_dummy_send, enable_arsenal=True,
                            arsenal_authz=lambda url: "in-scope" in url)
    assert allow._arsenal_host_allowed("http://in-scope.test/x") is True
    assert allow._arsenal_host_allowed("http://off-scope.test/x") is False

    # a gate that RAISES fails closed (never assume authorized)
    def _boom(url: str) -> bool:
        raise RuntimeError("gate error")

    err = WebScanCampaign(_dummy_send, enable_arsenal=True, arsenal_authz=_boom)
    assert err._arsenal_host_allowed("http://127.0.0.1:9/x") is False


def test_smuggling_gate_blocks_probe_on_unauthorized_host() -> None:
    # even with a hanging desync server, a DENY gate means the probe never runs and
    # no finding is produced — the raw socket is never opened for an unauthorized host.
    with _hanging_server(delay=2.0) as port:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True, arsenal_authz=lambda url: False)
        findings, leads = camp._smuggling_findings([("127.0.0.1", port, f"http://127.0.0.1:{port}/")])
    assert findings == [] and leads == []


# ---------------------------------------------------------------------------
# positive, oracle-confirmed arsenal findings (with a re-verifiable certificate)
# ---------------------------------------------------------------------------


def test_smuggling_desync_confirmed_through_the_arsenal() -> None:
    with _hanging_server(delay=2.0) as port:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)  # loopback → allowed
        findings, _leads = camp._smuggling_findings([("127.0.0.1", port, f"http://127.0.0.1:{port}/")])
    assert findings, "a hanging desync server should confirm at least one smuggling technique"
    f = findings[0]
    assert f.bug_class == "request_smuggling"
    assert f.confirmed_by  # an oracle kind carried the confirmation
    assert f.oracle_context is not None  # a retained, re-verifiable certificate
    assert f.confidence > 0.0


def test_cswsh_confirmed_through_the_arsenal() -> None:
    with _ws_server() as port:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)  # loopback → allowed
        findings = camp._cswsh_findings([f"ws://127.0.0.1:{port}/live"])
    assert findings, "an any-origin WS server should confirm CSWSH"
    f = findings[0]
    assert f.bug_class == "cross_site_websocket_hijacking"
    assert f.oracle_context is not None


def test_cswsh_gate_blocks_probe_on_unauthorized_host() -> None:
    with _ws_server() as port:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True, arsenal_authz=lambda url: False)
        findings = camp._cswsh_findings([f"ws://127.0.0.1:{port}/live"])
    assert findings == []


def test_ws_candidates_are_scoped_to_the_seed_host() -> None:
    camp = WebScanCampaign(_dummy_send, enable_arsenal=True)

    class _P:
        def __init__(self, url: str, body: str) -> None:
            self.url = url
            self.body = body

    class _Crawl:
        pages = [_P("http://127.0.0.1:8000/",
                    'x=new WebSocket("ws://127.0.0.1:8000/a");y="wss://evil.example/b"')]

    cands = camp._ws_candidates("http://127.0.0.1:8000/", _Crawl(), [])
    assert "ws://127.0.0.1:8000/a" in cands
    assert all("evil.example" not in c for c in cands)  # off-host ws refs are dropped


# ---------------------------------------------------------------------------
# the destructive race engine is NEVER auto-run
# ---------------------------------------------------------------------------


def test_race_engine_does_not_run_without_explicit_targets() -> None:
    # enable_arsenal alone must not fire the destructive race engine.
    camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
    assert camp.arsenal_race_targets == ()
    assert camp._race_findings("http://127.0.0.1:8000/") == []
