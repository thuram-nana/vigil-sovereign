"""
Request-level checks — CORS-active and host-header injection, confirmed only on
the dangerous behavior, run once per request via the engine's request_checks.
"""

from __future__ import annotations

import contextlib
import http.client
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner.checks import CorsActiveCheck, HostHeaderCheck
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest


def _make(kind: str, vulnerable: bool) -> type[BaseHTTPRequestHandler]:
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            return

        def do_GET(self) -> None:  # noqa: N802
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            extra: list[tuple[str, str]] = []
            body = b"ok"
            if kind == "cors":
                if vulnerable and origin:
                    extra = [("Access-Control-Allow-Origin", origin),
                             ("Access-Control-Allow-Credentials", "true")]  # reflects any origin
                elif origin:
                    extra = [("Access-Control-Allow-Origin", "https://trusted.example")]  # fixed, safe
            elif kind == "host":
                if vulnerable:
                    body = f'<a href="https://{host}/reset?t=abc">reset</a>'.encode()  # uses Host in a link
                else:
                    body = b'<a href="/reset?t=abc">reset</a>'  # relative, host-independent
            self.send_response(200)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return _H


class _Srv(ThreadingHTTPServer):
    daemon_threads = True


@contextlib.contextmanager
def _server(kind: str, vulnerable: bool) -> Iterator[tuple[str, int]]:
    srv = _Srv(("127.0.0.1", 0), _make(kind, vulnerable))
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield "127.0.0.1", srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send(host: str, port: int):
    def send(req: HttpRequest) -> dict:
        path = urllib.parse.urlsplit(req.url).path or "/"
        if urllib.parse.urlsplit(req.url).query:
            path += "?" + urllib.parse.urlsplit(req.url).query
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            conn.request(req.method, path, headers=dict(req.headers))
            resp = conn.getresponse()
            return {"status": resp.status, "headers": resp.getheaders(),
                    "body": resp.read().decode("utf-8", "replace")}
        finally:
            conn.close()
    return send


def test_cors_active_confirmed_and_safe() -> None:
    with _server("cors", vulnerable=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/api")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(CorsActiveCheck(),))
        assert [x for x in f if x.bug_class == "cors"], "CORS reflect-with-credentials not confirmed"
        assert f[0].confirmed_by == "achieved_state"

    with _server("cors", vulnerable=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/api")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(CorsActiveCheck(),))
        assert f == [], "a fixed trusted-origin CORS policy must not be flagged"


def test_host_header_injection_confirmed_and_safe() -> None:
    with _server("host", vulnerable=True) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/reset")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(HostHeaderCheck(),))
        assert [x for x in f if x.bug_class == "host_header_injection"], "host-header injection not confirmed"

    with _server("host", vulnerable=False) as (h, p):
        req = HttpRequest(method="GET", url=f"http://{h}:{p}/reset")
        f = AuditEngine(_send(h, p)).audit(req, checks=(), request_checks=(HostHeaderCheck(),))
        assert f == [], "an app using relative links must not be flagged for host-header injection"
