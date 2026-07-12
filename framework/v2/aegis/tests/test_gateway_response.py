"""
AEGIS Gateway G4 — response-side proxy-and-confirm.

Most web-attack proofs are only visible in the app's OWN answer, so the gateway forwards the request,
holds the response, runs the RESPONSE-SIDE effect oracles over it, and withholds it only on a
CONFIRMED verdict. The properties that matter:

  * reflected XSS is BLOCKED only when the payload's executable token reaches an EXECUTABLE context —
    an HTML-ENCODED reflection (the app did the right thing) is NOT blocked (near-zero FP),
  * error-based SQLi is BLOCKED only when the app leaks a datastore error LINKED to a quote-bearing
    request value,
  * every response-side block carries a certificate that re-runs offline,
  * benign responses (and non-executable reflections like `<b>`) are relayed untouched.

The upstream below is deliberately vulnerable (reflects unencoded, leaks SQL errors) — a stand-in for
the operator's own app so the end-to-end proxy-and-confirm path is exercised over real sockets.
"""

from __future__ import annotations

import html as _html
import http.server
import socketserver
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.models import AegisConfig, Verdict


class _VulnUpstream(http.server.BaseHTTPRequestHandler):
    """q reflects into HTML (unencoded, or encoded when ?enc=1); a quote leaks a SQL error."""

    def log_message(self, *_a):
        return

    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query, keep_blank_values=True)
        q = (qs.get("q") or [""])[0]
        if "'" in q:
            body = f"<html>You have an error in your SQL syntax near '{q}'</html>".encode()
        elif "enc" in qs:
            body = f"<html><body>results for {_html.escape(q)}</body></html>".encode()
        else:
            body = f"<html><body>results for {q}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


@pytest.fixture()
def vuln_upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _VulnUpstream)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def _gateway(upstream_port: int, *, mode: str, sink: list | None = None):
    gw = serve_gateway(f"http://127.0.0.1:{upstream_port}",
                       config=AegisConfig(deployment_secret="k", mode=mode),
                       host="127.0.0.1", port=0,
                       on_verdict=(sink.append if sink is not None else None))
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    return gw, gw.server_address[1]


def _hit(port: int, query: str):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/s?{query}", timeout=5)


_Q = urllib.parse.quote


def test_reflected_xss_script_is_blocked_with_certificate(vuln_upstream):
    sink: list[Verdict] = []
    gw, port = _gateway(vuln_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _hit(port, "q=" + _Q("<script>alert(1)</script>"))
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "xss"
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "xss")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_reflected_xss_event_handler_is_blocked(vuln_upstream):
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _hit(port, "q=" + _Q("<img src=x onerror=alert(9)>"))
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "xss"
    finally:
        gw.shutdown()


def test_html_encoded_reflection_is_NOT_blocked(vuln_upstream):
    """The app HTML-encoded the reflection (did the right thing) — the token is inert, so the gateway
    must NOT block. This is the near-zero-FP guarantee that separates a provable firewall from a WAF."""
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        body = _hit(port, "q=" + _Q("<script>alert(1)</script>") + "&enc=1").read().decode()
        assert "results for" in body   # relayed, not blocked
    finally:
        gw.shutdown()


def test_error_based_sqli_is_not_blocked_inline_without_a_control(vuln_upstream):
    """Error-based SQLi is DELIBERATELY off the inline block path: without a control/baseline response
    a datastore error cannot be PROVEN caused by the payload (the adversarial review showed every
    proximity heuristic still false-positives on Q&A/paste/log-viewer pages). So even a payload that
    provokes a DB error is forwarded, not blocked (roadmap: a differential/OOB confirmation)."""
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        body = _hit(port, "q=" + _Q("x'")).read().decode()
        assert "error in your SQL syntax" in body   # the app's error is relayed, not blocked
    finally:
        gw.shutdown()


def test_benign_and_non_executable_reflections_are_relayed(vuln_upstream):
    gw, port = _gateway(vuln_upstream, mode="enforce")
    try:
        assert "results for laptop" in _hit(port, "q=laptop").read().decode()
        # a reflected <b> is not executable -> not blocked
        assert "results for" in _hit(port, "q=" + _Q("<b>bold</b>")).read().decode()
    finally:
        gw.shutdown()


def test_observe_mode_forwards_the_vulnerable_response_but_emits_the_verdict(vuln_upstream):
    sink: list[Verdict] = []
    gw, port = _gateway(vuln_upstream, mode="observe", sink=sink)
    try:
        body = _hit(port, "q=" + _Q("<script>alert(1)</script>")).read().decode()
        assert "<script>alert(1)</script>" in body   # observe never blocks — forwarded as-is
        assert any(v.decision == "confirmed" and v.attack_class == "xss" for v in sink)
    finally:
        gw.shutdown()
