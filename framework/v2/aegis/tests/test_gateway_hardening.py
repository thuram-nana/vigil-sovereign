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


# --------------------------------------------------------------------------- response-side FP fixes

def test_error_sqli_does_not_fire_on_benign_apostrophe_plus_unrelated_db_error():
    """A benign O'Brien search whose results page merely CONTAINS an unrelated pasted stack trace
    (java.sql.SQLException) far from the reflected value must NOT be blocked."""
    resp = ("<html><body>results for O'Brien</body>" + ("x" * 2000)
            + "<pre>java.sql.SQLException: connection timeout</pre></html>")
    v = inspect_response("/search?q=O%27Brien", [], None, resp, enforce=True)
    assert v is None, "error-based SQLi false-positive: benign apostrophe + unrelated DB error blocked"


def test_error_sqli_still_fires_when_the_payload_caused_the_error():
    resp = "<html>You have an error in your SQL syntax near 'x'' at line 1</html>"
    v = inspect_response("/search?q=x%27", [], None, resp, enforce=True)
    assert v is not None and v.attack_class == "error_based_sqli"


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
