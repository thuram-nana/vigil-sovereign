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


def test_emitted_url_hosts_counts_emission_not_inert_echo() -> None:
    """The hostile Host counts only when it is the AUTHORITY of a URL the app EMITS (href/src/action, or a
    meta/JS redirect) — a URL a victim's browser would use. A plain-text ECHO of the reconstructed URL back
    to the requester (a 404 message, a <pre> sample, a comment, a JSON error string) is NOT exploitable and
    must NOT count (re-red-pen BLOCK-D). Matching is on the WHOLE authority, so a subdomain reflection does
    not collide with the evil host."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts

    evil = HostHeaderCheck().evil_host
    # EMISSIONS — a link / resource / form target / redirect the app builds from the Host: all must be found
    assert evil in hosts(f'<a href="https://{evil}/reset?t=1">reset</a>')
    assert evil in hosts(f'<a href="//{evil}/reset">reset</a>')          # scheme-relative
    assert evil in hosts(f'<img src="https://{evil}/logo.png">')
    assert evil in hosts(f'<form action="https://{evil}/submit">')
    assert evil in hosts(f'<meta http-equiv="refresh" content="0;url=https://{evil}/x">')  # redirect emission
    assert evil in hosts(f'<meta property="og:url" content="https://{evil}/">')   # canonical URL metadata
    assert evil in hosts(f'<link rel="canonical" href="https://{evil}/">')        # canonical link (href)
    # NON-EMISSIONS — inert echoes shown only to the requester, or not the evil authority at all
    assert evil not in hosts(f'<meta name="description" content="visit https://{evil} today">')  # prose, not URL meta
    # the property name must match the WHOLE allow-listed value: `:alt` sub-properties are TEXT, not URLs,
    # and a name that merely CONTAINS an og token is not og metadata (substring matching would false-FACT)
    assert evil not in hosts(f'<meta name="twitter:image:alt" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="og:image:alt" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="not-og:url" content="https://{evil}/x">')
    assert evil not in hosts(f'<meta name="x og:url y" content="https://{evil}/x">')
    # ... while every genuinely URL-valued og/twitter property is still counted
    for prop in ("og:url", "og:image", "og:image:secure_url", "twitter:url", "twitter:image:src"):
        assert evil in hosts(f'<meta property="{prop}" content="https://{evil}/x">'), prop


def test_emitted_url_hosts_ignores_inert_markup_contexts() -> None:
    """Markup a browser never PARSES emits nothing: an HTML comment, or the raw-text contents of
    script/style/textarea. An app echoing attacker text that merely LOOKS like a link into one of those must
    not mint a FACT. `<pre>` is deliberately NOT inert — tags inside it are live, clickable links."""
    from framework.v2.scanner.checks import _emitted_url_hosts as hosts

    evil = HostHeaderCheck().evil_host
    # INERT — never parsed as markup, so nothing is emitted
    assert evil not in hosts(f'<!-- <a href="https://{evil}/">x</a> -->')
    assert evil not in hosts(f"""<script>var t = "<a href='https://{evil}/'>";</script>""")
    assert evil not in hosts(f'<!-- <meta property="og:url" content="https://{evil}/"> -->')
    for el in ("style", "textarea", "title", "xmp", "noscript", "noembed", "noframes", "template", "iframe"):
        assert evil not in hosts(f'<{el}><a href="https://{evil}/">x</a></{el}>'), el
    assert evil not in hosts(f'<plaintext><a href="https://{evil}/">x</a>')   # no end tag: literal to EOF
    assert evil not in hosts(f'<template><meta property="og:url" content="https://{evil}/"></template>')
    # LIVE — <pre>/<code> contents ARE parsed, so a link inside them is a real emission
    assert evil in hosts(f'<pre><a href="https://{evil}/">x</a></pre>')
    assert evil in hosts(f'<a href="https://{evil}/reset">reset</a>')
    # ... and an inert element's OPENING TAG still emits: <script src>/<iframe src> load attacker content,
    # the canonical high-severity host-header sink. Masking the whole element dropped this real finding.
    assert evil in hosts(f'<script src="https://{evil}/evil.js"></script>')
    assert evil in hosts(f'<iframe src="https://{evil}/x"></iframe>')
    assert evil in hosts(f'<link rel="stylesheet" href="https://{evil}/x.css">')
    assert evil not in hosts(f'Cannot GET http://{evil}/foo')                    # 404 text echo (BLOCK-D)
    assert evil not in hosts(f'<pre>curl http://{evil}/api</pre>')               # code sample
    assert evil not in hosts(f'<!-- built from host: //{evil}/ -->')            # HTML comment
    assert evil not in hosts(f'{{"error": "unknown path http://{evil}/x"}}')     # JSON error echo
    assert evil not in hosts(f'<img src="https://{evil}.cdn.example.com/l.png">')  # subdomain prefix
    assert evil not in hosts(f"<p>Host: {evil}</p>")                             # bare plain-text echo
    assert evil not in hosts(f'<a href="https://app.example/go?to=//{evil}">x</a>')  # evil in path/query
    assert hosts('<a href="/reset">reset</a>') == []                            # relative link only
