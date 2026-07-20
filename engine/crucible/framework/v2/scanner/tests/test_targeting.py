"""
Surface-driven check selection — the right checks for the right insertion point,
with a fall-back that never silently drops coverage, and a real efficiency win.
"""

from __future__ import annotations

import contextlib
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

from framework.v2.scanner import (
    AuditEngine,
    DEFAULT_CHECKS,
    HttpRequest,
    InsertionKind,
    RequestTemplate,
    likely_classes,
    select_checks,
)


def _point(name: str):
    t = RequestTemplate(HttpRequest(url=f"https://t/x?{name}=v"))
    return next(p for p in t.insertion_points(kinds=[InsertionKind.QUERY_VALUE]) if p.name == name)


def test_param_name_maps_to_likely_classes() -> None:
    assert "ssrf" in likely_classes("url") and "open_redirect" in likely_classes("url")
    assert "open_redirect" in likely_classes("redirect")
    assert "path_traversal" in likely_classes("filename")
    assert "idor" in likely_classes("user_id") and "boolean_sqli" in likely_classes("user_id")
    assert "boolean_sqli" in likely_classes("search") and "xss" in likely_classes("search")
    assert likely_classes("nonsense_param") == []


def test_select_checks_prioritises_by_point() -> None:
    url_checks = {c.bug_class for c in select_checks(_point("url"), DEFAULT_CHECKS)}
    assert "ssrf" in url_checks
    assert "boolean_sqli" not in url_checks  # a url param is not SQL-first

    id_checks = {c.bug_class for c in select_checks(_point("id"), DEFAULT_CHECKS)}
    assert "boolean_sqli" in id_checks
    assert "ssrf" not in id_checks


def test_unhinted_point_falls_back_to_full_set() -> None:
    selected = select_checks(_point("weird"), DEFAULT_CHECKS)
    assert {c.bug_class for c in selected} == {c.bug_class for c in DEFAULT_CHECKS}, \
        "an unhinted point must keep full coverage, not be skipped"


# --- efficiency: targeting sends fewer requests but still finds the bug --------


class _SqliOnId(BaseHTTPRequestHandler):
    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        p = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        i = p.get("id", [""])[0]
        rows = "\n".join(f"r{n}" for n in range(9)) if ("'1'='1" in i or "1=1" in i) else "none"
        body = f"id[{i}]:{rows}".encode()  # note: does NOT reflect other params richly
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server() -> Iterator[str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _SqliOnId)
    srv.daemon_threads = True
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(timeout=5)


def _send_counting(base_send):
    calls = {"n": 0}

    def send(req):
        calls["n"] += 1
        return base_send(req)
    return send, calls


def _raw(req: HttpRequest) -> dict:
    with urllib.request.urlopen(  # noqa: S310 (loopback)
        urllib.request.Request(req.url, method=req.method), timeout=5
    ) as resp:
        return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}


def test_targeting_cuts_requests_but_keeps_the_finding() -> None:
    with _server() as base:
        req = HttpRequest(method="GET", url=f"{base}/q?id=1")

        # untargeted: every check runs on the id point
        s_all, all_calls = _send_counting(_raw)
        found_all = AuditEngine(s_all).audit(req, insertion_kinds=(InsertionKind.QUERY_VALUE,))

        # targeted: id -> {idor, boolean_sqli} only
        s_tg, tg_calls = _send_counting(_raw)
        found_tg = AuditEngine(s_tg).audit(
            req, insertion_kinds=(InsertionKind.QUERY_VALUE,), selector=select_checks)

        assert any(f.bug_class == "boolean_sqli" for f in found_tg), "targeting lost the SQLi"
        assert tg_calls["n"] < all_calls["n"], "targeting did not reduce request volume"
