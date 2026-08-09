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


_CANARY_URL = f"https://{_CANARY_HOST}/pwned"


def test_markup_redirect_hosts_extracts_only_real_navigation_targets() -> None:
    """Re-red-pen BLOCK-C: `content=` must be anchored to a real ATTRIBUTE boundary. A plain `\\b` is NOT
    enough (`-` is a non-word char, so `\\bcontent` matches inside `data-content=`), which let a benign
    own-host redirect mint a signed false FACT. Every real sink must still be extracted."""
    from framework.v2.scanner.checks import _markup_redirect_hosts as hosts

    # TRUE POSITIVES — real navigation targets must still be found
    assert _CANARY_HOST in hosts(f'<meta http-equiv="refresh" content="0; url={_CANARY_URL}">')
    assert _CANARY_HOST in hosts(f'<meta HTTP-EQUIV = "Refresh" content = "5; URL={_CANARY_URL}">')
    assert _CANARY_HOST in hosts(f"<meta http-equiv='refresh' content='0;url={_CANARY_URL}'>")
    assert _CANARY_HOST in hosts(f'<script>location.href="{_CANARY_URL}"</script>')
    assert _CANARY_HOST in hosts(f'<script>location.assign("{_CANARY_URL}")</script>')
    assert _CANARY_HOST in hosts(f'<script>window.location="{_CANARY_URL}"</script>')
    # `.` is deliberately allowed before `location` so real sinks like top/parent/self still match
    assert _CANARY_HOST in hosts(f'<script>top.location.href="{_CANARY_URL}"</script>')

    # NEGATIVES — none of these is a navigation target; none may contribute a host
    assert _CANARY_HOST not in hosts(   # BLOCK-C: a *content-named attribute is not `content`
        f'<meta http-equiv="refresh" data-content="0;url={_CANARY_URL}" content="0;url=/home">')
    assert _CANARY_HOST not in hosts(   # reflected next to an unrelated charset meta (BLOCK-1)
        f'<meta http-equiv="Content-Type" content="text/html"><p>next: {_CANARY_URL}</p>')
    assert _CANARY_HOST not in hosts(f'<script>var back="{_CANARY_URL}"</script>')   # a string, not a sink
    assert _CANARY_HOST not in hosts(   # the canary is a query param of an OWN-host redirect
        f'<meta http-equiv="refresh" content="0;url=/go?returnurl={_CANARY_URL}">')
    assert hosts(f'<!-- {_CANARY_URL} -->') == []
    # commented-out markup never navigates — a meta-refresh or JS sink inside an HTML comment emits nothing
    assert _CANARY_HOST not in hosts(
        f'<!-- <meta http-equiv="refresh" content="0;url={_CANARY_URL}"> -->')
    assert _CANARY_HOST not in hosts(f'<!-- location.href="{_CANARY_URL}" -->')
    # ... but a JS sink in a real <script> is still a true positive (script is NOT stripped for redirects)
    assert _CANARY_HOST in hosts(f'<script>location.href="{_CANARY_URL}"</script>')


def test_markup_redirect_hosts_ignores_inert_elements_and_reads_inner_quoted_content() -> None:
    """Convergence red-pen: a meta-refresh / JS sink inside an escapable- or raw-text element (textarea,
    title, xmp, plaintext, noscript, template, iframe) renders LITERALLY and never navigates, so it must not
    count — while `<script>` content still does (JS sinks live there). And a `content` value delimited by one
    quote may legitimately contain the other (`content="0; url='...'"`), which browsers honour."""
    from framework.v2.scanner.checks import _markup_redirect_hosts as hosts

    for el in ("textarea", "title", "xmp", "noscript", "template", "iframe"):
        assert _CANARY_HOST not in hosts(
            f'<{el}><meta http-equiv="refresh" content="0;url={_CANARY_URL}"></{el}>'), el
    assert _CANARY_HOST not in hosts(f'<plaintext><meta http-equiv="refresh" content="0;url={_CANARY_URL}">')
    # ... while the real sinks still fire
    assert _CANARY_HOST in hosts(f'<script>location.href="{_CANARY_URL}"</script>')
    assert _CANARY_HOST in hosts(f"""<meta http-equiv="refresh" content="0; url='{_CANARY_URL}'">""")
    assert _CANARY_HOST in hosts(f'<meta http-equiv="refresh" content="0; url={_CANARY_URL}">')


def test_markup_redirect_hosts_is_bounded_on_a_hostile_body() -> None:
    """Re-red-pen BLOCK-B: the markup parse must stay ~linear on a hostile, unterminated-<meta> body — a
    target-controlled response must not be able to make it super-linear (availability). 1.2MB of '<meta '
    (no '>') used to be quadratic (~minutes); it must now complete quickly and return no hosts."""
    import time as _time

    from framework.v2.scanner.checks import _emitted_url_hosts, _markup_redirect_hosts

    # Every shape that has been super-linear at some point in this parser's history. An unterminated
    # comment/script used to backtrack quadratically (minutes at the cap); a `<meta`-run used to re-scan the
    # 4096 bound at each start. All must now complete well inside the bound and find no navigation target.
    for label, body in (
        ("unterminated meta", "<meta " * 200_000),
        ("unterminated comment", "<!--" * 128_000),
        ("unterminated script", "<script>" * 64_000),
        ("unterminated href", '<a href="' * 56_000),
        ("angle-bracket spam", '<meta<a href="' * 36_000),
    ):
        t0 = _time.perf_counter()
        assert _markup_redirect_hosts(body) == [], label
        assert _emitted_url_hosts(body) == [], label
        dt = _time.perf_counter() - t0
        assert dt < 3.0, f"{label}: markup parse must stay bounded (was {dt:.2f}s) — super-linear regression"
