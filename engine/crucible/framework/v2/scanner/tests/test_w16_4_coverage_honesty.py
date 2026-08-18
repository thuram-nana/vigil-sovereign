"""
W16-4 — the run tells the truth about its OWN check-corpus coverage.

The default scan/engage exercises only the built-in seed roster (``DEFAULT_CHECKS``,
11 point checks); the far larger declarative library (``scanner.library``, ~172 checks
across 23 bug classes) runs ONLY under ``--library`` (``use_library=True``), and the
TIMING oracle fires only there. Before this slice a run said NOTHING about that gap — a
claim-honesty hole where a default scan could be mistaken for comprehensive.

These tests prove the disclosure is present and HONEST, at every surface:
  * the ``ScanReport.coverage()`` object, over REAL campaigns (default vs --library);
  * the machine JSON report (``build_report`` ``coverage`` block) + the HTML note;
  * the operator-facing text line (``coverage_line``).

``library_available`` is asserted against the registry (``library_stats``), never a
hardcoded constant, so the test tracks the corpus as it grows/shrinks. ``full_coverage``
is true ONLY when the library actually contributed checks (``library_run > 0``).
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from framework.v2.scanner.campaign import WebScanCampaign
from framework.v2.scanner.checks import DEFAULT_CHECKS
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.library import library_stats, load_library, select_entries
from framework.v2.scanner.report import build_report, coverage_line, to_html


class _WpApp(BaseHTTPRequestHandler):
    """A WordPress/PHP-fingerprinted fixture with a search param — enough surface for
    the crawl + a fingerprint that selects real library entries under --library."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        if parts.path == "/":
            body = (b'<meta name="generator" content="WordPress 6.4">'
                    b'<a href="/search?q=hi">search</a> /wp-content/themes/x')
        elif parts.path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            body = f"echo:{q}".encode()
        else:
            body = b"not found"
        self.send_response(200)
        self.send_header("Server", "nginx")
        self.send_header("X-Powered-By", "PHP/8.1")
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


def _run(base: str, *, use_library: bool):
    return WebScanCampaign(
        loopback_send, max_pages=5, enable_oob=False, use_library=use_library,
    ).run(base + "/")


# --------------------------------------------------------------------------- #
# 1. the coverage OBJECT over REAL campaigns
# --------------------------------------------------------------------------- #


def test_default_scan_records_partial_coverage() -> None:
    """A DEFAULT run: only the built-in seed roster ran; the library did NOT."""
    available, _classes = library_stats()
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)

    # the built-in seed roster ran, and it is the DEFAULT_CHECKS count (11), derived
    # from the roster length — not hardcoded into the report.
    assert report.built_in_checks_run == len(DEFAULT_CHECKS) == 11
    assert report.library_checks_run == 0

    cov = report.coverage()
    assert cov == {
        "built_in_run": 11,
        "library_available": available,   # from the registry, not a literal
        "library_run": 0,
        "full_coverage": False,           # the library did NOT run
    }
    assert cov["library_available"] > cov["built_in_run"], (
        "the library must dwarf the seed set — otherwise the disclosure is pointless"
    )


def test_library_scan_records_full_coverage() -> None:
    """A --library run over a fingerprintable target: the library actually contributed
    checks, so coverage is full and library_run > 0."""
    with _server(_WpApp) as base:
        report = _run(base, use_library=True)
        # sanity: the fixture fingerprinted and selected a non-empty applicable subset
        assert report.fingerprint is not None
        expected = len(select_entries(load_library(), report.fingerprint.tokens))

    assert report.built_in_checks_run == 11
    assert report.library_checks_run == expected > 0
    cov = report.coverage()
    assert cov["library_run"] > 0
    assert cov["full_coverage"] is True


# --------------------------------------------------------------------------- #
# 2. the machine JSON report + HTML note carry the SAME truth
# --------------------------------------------------------------------------- #


def test_json_report_carries_coverage_object() -> None:
    available, _classes = library_stats()
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)
    doc = build_report(report)
    # the disclosure is present in the machine report and matches the object
    assert "coverage" in doc, "the JSON report must carry the coverage disclosure"
    assert doc["coverage"] == {
        "built_in_run": 11,
        "library_available": available,
        "library_run": 0,
        "full_coverage": False,
    }
    # and it survives a JSON round-trip (a real CI consumer reads bytes, not a dict)
    round_trip = json.loads(json.dumps(doc))
    assert round_trip["coverage"]["full_coverage"] is False


def test_html_report_shows_coverage_note() -> None:
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)
    html_out = to_html(report)
    assert "scanner.library" in html_out
    assert "--library" in html_out
    assert "NOT run" in html_out


# --------------------------------------------------------------------------- #
# 3. the operator-facing TEXT line
# --------------------------------------------------------------------------- #


def test_coverage_line_default_discloses_the_gap() -> None:
    available, classes = library_stats()
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)
    line = coverage_line(report)
    assert "11 built-in" in line
    assert "DEFAULT_CHECKS" in line
    assert f"{available} checks" in line          # real, registry-derived size
    assert f"{classes} classes" in line
    assert "--library" in line                    # tells the operator how to get full coverage
    assert "TIMING oracle" in line


def test_coverage_line_library_says_full_corpus() -> None:
    with _server(_WpApp) as base:
        report = _run(base, use_library=True)
    line = coverage_line(report)
    assert "full corpus" in line
    assert "NOT run" not in line
