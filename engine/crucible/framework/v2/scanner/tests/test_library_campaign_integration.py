"""
M1 gate — data-driven, fingerprint-scoped coverage running in a real scan.

A library-driven campaign fingerprints the target from the crawl, selects the
declarative checks whose applicability predicate matches the detected stack,
compiles them to oracle-anchored checks, and runs them. A WordPress target runs
the WP-gated check; a plain target does not — coverage is now data + fingerprint,
and precision is unaffected because the oracle still adjudicates.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.library import load_library, select_entries


class _WpApp(BaseHTTPRequestHandler):
    """A WordPress-fingerprinted, boolean-SQLi-vulnerable fixture."""

    server_header = "nginx"
    powered_by = "PHP/8.1"

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/":
            body = (b'<meta name="generator" content="WordPress 6.4">'
                    b'<a href="/search?q=hi">search</a> /wp-content/themes/x')
        elif parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            dump = "".join(f"row{i}\n" for i in range(40)) if ("'1'='1" in q or "1=1" in q) else ""
            body = f"echo:{q}\n{dump}".encode()
        else:
            body = b"not found"
        self.send_response(200)
        self.send_header("Server", self.server_header)
        self.send_header("X-Powered-By", self.powered_by)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _PlainApp(_WpApp):
    """Same bug surface but a non-WordPress, non-PHP stack (no WP/PHP tells)."""

    server_header = "nginx"
    powered_by = "nginx"  # no PHP banner

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/":
            body = b'<html><a href="/search?q=hi">search</a></html>'  # no WP generator
        elif parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            dump = "".join(f"row{i}\n" for i in range(40)) if ("'1'='1" in q or "1=1" in q) else ""
            body = f"echo:{q}\n{dump}".encode()
        else:
            body = b"not found"
        self.send_response(200)
        self.send_header("Server", self.server_header)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def _server(handler) -> Iterator[str]:
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


def test_wordpress_target_fingerprints_and_runs_gated_library_checks() -> None:
    with _server(_WpApp) as base:
        report = WebScanCampaign(
            loopback_send, max_pages=5, enable_oob=False, use_library=True,
        ).run(base + "/")
        # the stack was detected...
        assert report.fingerprint is not None
        toks = report.fingerprint.tokens
        assert "wordpress" in toks and "php" in toks
        # ...and exactly the library entries applicable to this stack were run
        expected = len(select_entries(load_library(), toks))
        assert report.library_checks_run == expected
        # the WP/PHP-gated entries are included for this target
        wp_gated = {e.id for e in load_library() if e.applies({"wordpress", "php", "cms"})} \
            - {e.id for e in load_library() if e.applies(set())}
        assert wp_gated, "fixture must exercise at least one framework-gated entry"
        # coverage produced confirmed findings, precision intact (oracle-anchored)
        assert report.active_findings


def test_plain_target_does_not_run_framework_gated_checks() -> None:
    with _server(_PlainApp) as base:
        report = WebScanCampaign(
            loopback_send, max_pages=5, enable_oob=False, use_library=True,
        ).run(base + "/")
        assert report.fingerprint is not None
        toks = report.fingerprint.tokens
        assert "wordpress" not in toks and "php" not in toks
        # only the entries applicable to this (non-WP/PHP) stack ran...
        entries = load_library()
        assert report.library_checks_run == len(select_entries(entries, toks))
        # ...and strictly fewer than for a WordPress+PHP stack (the gated ones excluded)
        assert report.library_checks_run < len(select_entries(entries, {"wordpress", "php", "cms", "nginx", "server"}))


def test_library_off_by_default_leaves_the_report_fingerprint_free() -> None:
    with _server(_PlainApp) as base:
        report = WebScanCampaign(loopback_send, max_pages=5, enable_oob=False).run(base + "/")
        assert report.fingerprint is None and report.library_checks_run == 0
