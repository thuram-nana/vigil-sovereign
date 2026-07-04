"""
OOB producer end to end — a BLIND vulnerability confirmed by an out-of-band
callback, not by anything in the response.

A real SSRF target fetches an attacker-supplied URL server-side. The OOB check
mints a loopback correlation URL, injects it, and the target's server-side fetch
lands on the receiver — the deterministic proof. This activates the blind classes
(SSRF/XXE/RCE/deserialization) the oracle layer routed but could never fire live.

Three guarantees are pinned: the blind SSRF is confirmed; a target that does NOT
fetch confirms nothing; and with no receiver the blind check is skipped (never
guessed).
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.checks import SSRF_OOB
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind
from framework.v2.verify.oob import OOBReceiver


class _SSRFTarget(BaseHTTPRequestHandler):
    """Vulnerable: it fetches the `url` parameter server-side (the SSRF). Any
    loopback callback injected there is dereferenced by the SERVER."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        url = params.get("url", [""])[0]
        if url.startswith("http://127.0.0.1"):
            with contextlib.suppress(Exception):
                urllib.request.urlopen(url, timeout=2).read()  # the server-side fetch
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SafeTarget(BaseHTTPRequestHandler):
    """Reads `url` but never fetches it — no out-of-band interaction happens."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
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


def _send(req: HttpRequest) -> dict:
    r = urllib.request.Request(req.url, method=req.method, headers=dict(req.headers))
    if req.body is not None:
        r.data = req.body.encode("utf-8")
    with urllib.request.urlopen(r, timeout=5) as resp:  # noqa: S310 (loopback only)
        return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}


def test_blind_ssrf_confirmed_by_oob_callback() -> None:
    with _server(_SSRFTarget) as base, OOBReceiver() as oob:
        req = HttpRequest(method="GET", url=f"{base}/fetch?url=http://example.internal")
        engine = AuditEngine(_send, oob=oob)
        findings = engine.audit(req, checks=(SSRF_OOB,), insertion_kinds=(InsertionKind.QUERY_VALUE,))

        ssrf = [f for f in findings if f.bug_class == "ssrf"]
        assert ssrf, "blind SSRF was not confirmed by an out-of-band callback"
        assert ssrf[0].confirmed_by == "oob_callback"
        assert ssrf[0].param == "url"
        assert 0.0 < ssrf[0].confidence <= 1.0


def test_no_callback_no_confirmation() -> None:
    with _server(_SafeTarget) as base, OOBReceiver() as oob:
        req = HttpRequest(method="GET", url=f"{base}/fetch?url=http://example.internal")
        engine = AuditEngine(_send, oob=oob)
        # a short deadline keeps the negative control fast — no hit will ever land
        fast = SSRF_OOB.__class__(id="ssrf-oob", bug_class="ssrf", poll_deadline=0.3)
        findings = engine.audit(req, checks=(fast,), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert findings == [], "a target that makes no callback must not be confirmed"


def test_oob_check_skipped_without_a_receiver() -> None:
    with _server(_SSRFTarget) as base:
        req = HttpRequest(method="GET", url=f"{base}/fetch?url=http://example.internal")
        engine = AuditEngine(_send)  # no oob receiver
        findings = engine.audit(req, checks=(SSRF_OOB,), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert findings == [], "blind check must be skipped, not guessed, without a receiver"


class _SSRFSite(BaseHTTPRequestHandler):
    """An index that links to a server-side-fetch endpoint — so a full crawl
    reaches the SSRF and the campaign's own receiver confirms it blind."""

    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        sp = urllib.parse.urlsplit(self.path)
        if sp.path == "/fetch":
            url = urllib.parse.parse_qs(sp.query).get("url", [""])[0]
            if url.startswith("http://127.0.0.1"):
                with contextlib.suppress(Exception):
                    urllib.request.urlopen(url, timeout=2).read()
            body = b"fetched"
        else:
            body = b'<html><body><a href="/fetch?url=http://example.internal">f</a></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_campaign_confirms_blind_ssrf_end_to_end() -> None:
    from framework.v2.scanner import WebScanCampaign

    with _server(_SSRFSite) as base:
        report = WebScanCampaign(
            _send, checks=(SSRF_OOB,),
            insertion_kinds=(InsertionKind.QUERY_VALUE,), enable_oob=True,
        ).run(base + "/")
        ssrf = [f for f in report.active_findings if f.bug_class == "ssrf"]
        assert ssrf, "the campaign did not confirm the blind SSRF it crawled to"
        assert ssrf[0].confirmed_by == "oob_callback" and ssrf[0].param == "url"
