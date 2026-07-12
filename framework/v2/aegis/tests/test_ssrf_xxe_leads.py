"""
AEGIS — SSRF / XXE emitted as LEADS, never blocks (the honest first slice).

SSRF and XXE are confirmed by an OUT-OF-BAND callback (the app dereferencing an attacker-controlled
resource), which a single inline request/response cannot prove near-zero-FP. So AEGIS emits them as
LEAD verdicts: belief-raising + logged, carrying NO certificate and action=observe — the gateway
forwards the request untouched. These tests pin that contract:

  * an SSRF probe (internal / cloud-metadata host, or file://) -> a LEAD "ssrf", NOT a block,
  * an XXE payload (DOCTYPE declaring a SYSTEM/PUBLIC entity) -> a LEAD "xxe", NOT a block,
  * a CONFIRMED block still takes priority over a lead in the same request,
  * a benign external URL / benign XML does not even raise a lead,
  * end-to-end: the gateway relays an SSRF probe in ENFORCE mode (a lead never blocks).
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.parse
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.inspect import inspect_request
from framework.v2.aegis.models import AegisConfig, Verdict

_JSON = [("Content-Type", "application/json")]
_XML = [("Content-Type", "application/xml")]


def _req(path, *, headers=None, body=None):
    return inspect_request("GET", path, headers or [], body, enforce=True)


# --------------------------------------------------------------------------- SSRF leads

@pytest.mark.parametrize("value", [
    "http://169.254.169.254/latest/meta-data/",         # AWS metadata
    "http://metadata.google.internal/computeMetadata/",  # GCP metadata
    "http://127.0.0.1:8080/admin",                        # loopback
    "https://10.0.0.5/internal",                           # RFC1918
    "http://192.168.1.1/",                                 # RFC1918
    "file:///etc/passwd",                                 # dangerous scheme
    "gopher://127.0.0.1:6379/_INFO",                       # dangerous scheme
])
def test_ssrf_probe_is_a_lead_not_a_block(value):
    v = _req("/fetch?url=" + urllib.parse.quote(value, safe=""))
    assert v is not None
    assert v.decision == "lead" and v.attack_class == "ssrf"
    assert v.certificate is None and v.action == "observe"


@pytest.mark.parametrize("value", [
    "https://api.stripe.com/v1/charges",     # legitimate external API
    "https://cdn.example.com/logo.png",      # external asset
    "https://github.com/org/repo",           # external
    "just some search text",                 # not a URL at all
    "8.8.8.8",                               # public IP, not URL-shaped
])
def test_benign_url_does_not_raise_an_ssrf_lead(value):
    v = _req("/fetch?url=" + urllib.parse.quote(value, safe=""))
    assert v is None, f"benign value falsely raised a lead: {value!r} -> {v}"


# --------------------------------------------------------------------------- XXE leads

def test_xxe_external_entity_is_a_lead_not_a_block():
    body = ('<?xml version="1.0"?>'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
            '<foo>&xxe;</foo>')
    v = _req("/upload", headers=_XML, body=body)
    assert v is not None
    assert v.decision == "lead" and v.attack_class == "xxe"
    assert v.certificate is None and v.action == "observe"


def test_xxe_public_entity_is_a_lead():
    body = ('<!DOCTYPE r [ <!ENTITY e PUBLIC "-//x//y" "http://evil/x.dtd"> ]><r>&e;</r>')
    v = _req("/upload", headers=_XML, body=body)
    assert v is not None and v.attack_class == "xxe" and v.decision == "lead"


def test_benign_xml_without_external_entity_is_not_a_lead():
    for body in (
        '<?xml version="1.0"?><note><to>bob</to><body>hi</body></note>',
        '<!DOCTYPE html><html><body>ordinary doctype, no entity</body></html>',
        '<config><entry name="timeout">30</entry></config>',
    ):
        assert _req("/upload", headers=_XML, body=body) is None, body


# --------------------------------------------------------------------------- priority + end-to-end

def test_confirmed_block_takes_priority_over_a_lead_in_the_same_request():
    # a value that is BOTH an SSRF-ish loopback URL AND a proven SQL breakout -> the CONFIRMED block
    # must win (a lead never masks a proof).
    path = "/x?q=" + urllib.parse.quote("http://127.0.0.1/' OR '1'='1", safe="")
    v = _req(path)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "sqli_attempt"
    assert v.certificate is not None and v.certificate.reverify() is True


class _Echo(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        return

    def do_GET(self):
        body = b"UP"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


def test_gateway_relays_an_ssrf_probe_in_enforce_mode_and_emits_the_lead(upstream):
    sink: list[Verdict] = []
    gw = serve_gateway(f"http://127.0.0.1:{upstream}",
                       config=AegisConfig(deployment_secret="k", mode="enforce"),
                       host="127.0.0.1", port=0, on_verdict=sink.append)
    threading.Thread(target=gw.serve_forever, daemon=True).start()
    port = gw.server_address[1]
    try:
        url = f"http://127.0.0.1:{port}/fetch?url=" + urllib.parse.quote(
            "http://169.254.169.254/latest/meta-data/", safe="")
        body = urllib.request.urlopen(url, timeout=5).read()
        assert body == b"UP"   # a lead NEVER blocks — forwarded
        assert any(v.decision == "lead" and v.attack_class == "ssrf" for v in sink)
    finally:
        gw.shutdown()
