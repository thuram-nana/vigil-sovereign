"""
Open-redirect producer — confirmed only when the app actually redirects to the
attacker's canary host, not when it merely reflects the parameter safely.
"""

from __future__ import annotations

import contextlib
import http.client
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.checks import OpenRedirectCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind

_CANARY_HOST = "crucible-redirect-canary.test"


def _make(vulnerable: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            nxt = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("next", [""])[0]
            if vulnerable:
                # open redirect: sends the user wherever `next` says
                self.send_response(302)
                self.send_header("Location", nxt)
            else:
                # safe: only ever redirects to a local path, param echoed inside OWN host
                self.send_response(302)
                self.send_header("Location", f"/home?from={urllib.parse.quote(nxt, safe='')}")
            self.send_header("Content-Length", "0")
            self.end_headers()

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(vulnerable: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(vulnerable))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "127.0.0.1", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _non_following_send(host: str, port: int):
    """A send that does NOT follow redirects, exposing the Location header — as
    the production executor does (follow_redirects=False)."""
    def send(req: HttpRequest) -> dict:
        path = req.url.split(f"{host}:{port}", 1)[1] if f"{host}:{port}" in req.url else req.url
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(req.method, path, headers=dict(req.headers))
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "replace")
            return {"status": resp.status, "headers": resp.getheaders(), "body": body}
        finally:
            conn.close()
    return send


def test_open_redirect_confirmed_on_vulnerable_app() -> None:
    with _server(vulnerable=True) as (host, port):
        req = HttpRequest(method="GET", url=f"http://{host}:{port}/go?next=/seed")
        findings = AuditEngine(_non_following_send(host, port)).audit(
            req, checks=(OpenRedirectCheck(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        redir = [f for f in findings if f.bug_class == "open_redirect"]
        assert redir, "open redirect to the canary host was not confirmed"
        assert redir[0].confirmed_by == "achieved_state" and redir[0].param == "next"


def test_safe_redirect_not_confirmed() -> None:
    with _server(vulnerable=False) as (host, port):
        req = HttpRequest(method="GET", url=f"http://{host}:{port}/go?next=/seed")
        findings = AuditEngine(_non_following_send(host, port)).audit(
            req, checks=(OpenRedirectCheck(),), insertion_kinds=(InsertionKind.QUERY_VALUE,))
        assert findings == [], "an app that only redirects to its own host must not be flagged"
