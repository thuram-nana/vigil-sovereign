"""
AEGIS Gateway hardening — regression tests for the defects the adversarial review found and I fixed.
Each test pins a concrete failing input the review proved, so the fix cannot silently regress:

  * forward-SSRF via a request-target that does not start with '/' (`@evil.com/x`),
  * an oversized request body -> honest 413 + close (never a truncated/desynced forward),
  * a malformed request-target -> 502, never a connection-drop crash,
  * error-based-SQLi false positive (benign apostrophe + an UNRELATED db-error string in the response),
  * reflected-XSS false positive (a marker that only coincides with the site's OWN script; the
    reflection itself was HTML-encoded).
"""

from __future__ import annotations

import http.server
import socket
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import AegisGatewayHandler, GatewaySettings, serve_gateway
from framework.v2.aegis.inspect import inspect_response
from framework.v2.aegis.models import AegisConfig


# --------------------------------------------------------------------------- forward-SSRF (unit)

def test_forward_url_forces_leading_slash_defeating_at_host_ssrf():
    from urllib.parse import urlsplit
    st = GatewaySettings("http://127.0.0.1:8000/app", AegisConfig(deployment_secret="k"))
    stub = type("S", (), {"settings": st, "path": ""})()
    fwd = AegisGatewayHandler._forward_url.__get__(stub)
    # each hostile target would, without the leading-'/' force, splice as an authority and re-home the
    # forward to evil.com; after the fix the host stays the upstream and evil.com is inert path text.
    for hostile in ("@evil.com/steal", "//evil.com/x", "\\\\evil.com/x", "@127.0.0.1:9/x"):
        url = fwd(hostile)
        parsed = urlsplit(url)
        assert (parsed.hostname, parsed.port) == ("127.0.0.1", 8000), f"SSRF: {hostile!r} -> {url!r}"


def test_forward_url_survives_a_malformed_target():
    st = GatewaySettings("http://127.0.0.1:8000", AegisConfig(deployment_secret="k"))
    stub = type("S", (), {"settings": st, "path": ""})()
    fwd = AegisGatewayHandler._forward_url.__get__(stub)
    assert fwd("http://[").startswith("http://127.0.0.1:8000/")   # no crash, falls back to '/'


# --------------------------------------------------------------------------- raw-socket end-to-end

class _Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = f"UP {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET


@pytest.fixture()
def upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Echo)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _raw(port: int, request_line_and_headers: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request_line_and_headers)
        s.settimeout(5)
        chunks = []
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        except socket.timeout:
            pass
        return b"".join(chunks)


def test_oversized_body_gets_413_not_a_truncated_forward(upstream):
    gw, port = serve_gateway(f"http://127.0.0.1:{upstream}",
                             config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0), None
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        # Content-Length over the 10 MiB cap; we never send the body -> the gateway must 413 + close.
        resp = _raw(port, b"POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 11000000\r\n\r\n")
        assert b"413" in resp.split(b"\r\n", 1)[0]
    finally:
        gw.shutdown()


def test_chunked_body_is_refused_411_not_dropped_and_desynced(upstream):
    """A chunked (Transfer-Encoding) request body this handler cannot buffer must be refused with
    411 + Connection: close — never read-as-empty (which would drop the body and desync keep-alive)."""
    gw = serve_gateway(f"http://127.0.0.1:{upstream}",
                       config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        resp = _raw(port, b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                          b"5\r\nhello\r\n0\r\n\r\n")
        first = resp.split(b"\r\n", 1)[0]
        assert b"411" in first and b"close" in resp.lower()
    finally:
        gw.shutdown()


def test_malformed_target_yields_a_response_not_a_dropped_connection(upstream):
    gw = serve_gateway(f"http://127.0.0.1:{upstream}",
                       config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        resp = _raw(port, b"GET http://[ HTTP/1.1\r\nHost: x\r\n\r\n")
        assert resp, "malformed target dropped the connection with no response (fail-closed crash)"
        assert resp.split(b" ", 2)[1] in (b"502", b"400", b"200")   # an honest status, not a reset
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- F-01: ambient env isolation

def test_ambient_proxy_and_ca_env_do_not_divert_the_forward(upstream, monkeypatch):
    """Audit F-01 regression: the forward must IGNORE the ambient environment — ALL_PROXY/HTTP(S)_PROXY
    (which would re-route the httpx forward through an attacker/monitor) and SSL_CERT_FILE/SSL_CERT_DIR
    (which would swap the TLS trust store). With those set to bogus values a benign request must STILL
    reach the real local upstream DIRECTLY (the gateway builds its client with trust_env=False). Before the
    fix, httpx honoured ALL_PROXY and dialed the dead proxy port, so the forward failed (502) instead of
    reaching the upstream."""
    # Clear any ambient NO_PROXY first: httpx (0.28) has no built-in localhost bypass, but an ambient
    # NO_PROXY=127.0.0.1 would bypass the proxy even under trust_env=True and make this test VACUOUS. With
    # NO_PROXY cleared, ALL_PROXY applies to the loopback forward, so the OLD (trust_env=True) code dials the
    # dead proxy and 502s — proving the fix is what keeps the forward direct.
    for var in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(var, raising=False)
    for var in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:1")           # a dead port: any diversion here fails the forward
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent/ca.pem")
    monkeypatch.setenv("SSL_CERT_DIR", "/nonexistent/ca.d")
    gw = serve_gateway(f"http://127.0.0.1:{upstream}",
                       config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        resp = _raw(port, b"GET /alive HTTP/1.1\r\nHost: x\r\n\r\n")
        first = resp.split(b"\r\n", 1)[0]
        body = resp.split(b"\r\n\r\n", 1)[-1]
        assert b"200" in first, f"the forward did not reach the local upstream (ambient proxy diverted it?): {first!r}"
        assert b"UP /alive" in body, "the real upstream body did not come back — the ambient env diverted the forward"
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- A11: XFF + response bound

class _XffEcho(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        xff = self.headers.get("X-Forwarded-For", "<none>")
        n = sum(1 for k in self.headers.keys() if k.lower() == "x-forwarded-for")
        body = f"XFF={xff} N={n}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def xff_upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _XffEcho)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def test_a11_client_supplied_xff_is_stripped_gateway_sets_its_own(xff_upstream):
    # A11: a forged client X-Forwarded-For must NOT survive; the gateway strips it and sets its OWN (the real
    # client IP), so exactly ONE XFF (the true one) reaches the upstream — no identity-spoofing ambiguity.
    gw = serve_gateway(f"http://127.0.0.1:{xff_upstream}",
                       config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        resp = _raw(port, b"GET /x HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n")
        body = resp.split(b"\r\n\r\n", 1)[-1]
        assert b"9.9.9.9" not in body, "a forged client X-Forwarded-For must be stripped"
        assert b"XFF=127.0.0.1" in body and b"N=1" in body   # exactly one XFF, the gateway's own
    finally:
        gw.shutdown()


def test_a11_oversized_upstream_response_is_refused_not_silently_truncated(upstream, monkeypatch):
    # A11: an upstream response larger than the relay bound must be REFUSED (502), never silently truncated
    # with a rewritten Content-Length (which would corrupt the body while claiming success).
    from framework.v2.aegis import gateway as gw_mod
    monkeypatch.setattr(gw_mod, "_MAX_RESPONSE_BYTES", 8)   # tiny cap; the _Echo body is longer
    gw = serve_gateway(f"http://127.0.0.1:{upstream}",
                       config=AegisConfig(deployment_secret="k"), host="127.0.0.1", port=0)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        resp = _raw(port, b"GET /averylongpathwellover8bytes HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"502" in resp.split(b"\r\n", 1)[0], f"oversized response must 502, got {resp[:40]!r}"
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- response-side FP fixes

def test_error_sqli_is_off_the_inline_block_path():
    """Error-based SQLi is deliberately NOT confirmed inline (no control/baseline response, so a DB
    error cannot be proven caused by the payload). Neither a benign apostrophe near an unrelated error
    NOR a payload-provoked error is blocked — both are forwarded (roadmap: differential/OOB)."""
    benign = ("<html><body>results for O'Brien</body>" + ("x" * 2000)
              + "<pre>java.sql.SQLException: connection timeout</pre></html>")
    assert inspect_response("/search?q=O%27Brien", [], None, benign, enforce=True) is None
    # a page that reflects a *searched* DB-error string must also not self-trigger a block
    searched = "<html>No results for: You have an error in your SQL syntax near '1'</html>"
    q = "/search?q=" + "You%20have%20an%20error%20in%20your%20SQL%20syntax%20near%20%271%27"
    assert inspect_response(q, [], None, searched, enforce=True) is None


def test_reflected_xss_does_not_fire_when_marker_only_matches_the_sites_own_script():
    """The reflection was HTML-ENCODED (safe), but the extracted marker 'update' also appears in the
    site's OWN legit <script>. Must NOT block — only a VERBATIM reflection counts."""
    resp = ("<html><body>your pref: onselect&#61;update</body>"
            "<script>function update(){return true;}</script></html>")
    v = inspect_response("/prefs?pref=onselect%3Dupdate", [], None, resp, enforce=True)
    assert v is None, "reflected-XSS false-positive fired on the site's own script / encoded reflection"


def test_reflected_xss_still_fires_on_a_verbatim_unencoded_reflection():
    resp = "<html><body>results for <script>alert(1)</script></body></html>"
    v = inspect_response("/s?q=%3Cscript%3Ealert(1)%3C/script%3E", [], None, resp, enforce=True)
    assert v is not None and v.attack_class == "xss"
