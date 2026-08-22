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


# --------------------------------------------------------------------------- #
# 4. the BOUNDED verdict — a default-run CLEAN is not a corpus-wide negative
#    (W16-4 second slice, issue #509). A default run commits only the built-in
#    seed roster; for every library-only bug class it committed NO check, so its
#    per-class verdict is "inconclusive", never "clean". A target that IS
#    vulnerable to such a class is therefore never reported CLEAN by a default run.
# --------------------------------------------------------------------------- #

import re  # noqa: E402
from pathlib import Path  # noqa: E402

from framework.v2.scanner.campaign import ScanReport, _corpus_bug_classes  # noqa: E402
from framework.v2.scanner.engine import AuditFinding  # noqa: E402
from framework.v2.scanner.library import split_checks  # noqa: E402


def _library_only_point_classes() -> set[str]:
    """The point-check bug classes the shipped library covers but the built-in seed
    roster does NOT — derived from the registry, never hardcoded."""
    point_lib, _request = split_checks(load_library())
    return {c.bug_class for c in point_lib} - {c.bug_class for c in DEFAULT_CHECKS}


def test_default_run_reports_library_only_class_inconclusive_not_clean() -> None:
    """AC negative control: a target vulnerable to a library-only class (NoSQL injection)
    is NOT reported CLEAN by a default run — its per-class verdict is `inconclusive`,
    because the default roster committed no nosqli check at all."""
    with _server(_WpApp) as base:
        default = _run(base, use_library=False)
        lib = _run(base, use_library=True)

    # nosqli is genuinely in the corpus and library-only.
    assert "nosqli" in _corpus_bug_classes()
    assert "nosqli" in _library_only_point_classes()

    # DEFAULT run: nosqli was never adjudicated -> inconclusive, never clean/finding.
    assert default.verdict_by_class()["nosqli"] == "inconclusive"
    # --library run over the SAME fixture DOES adjudicate nosqli (the WP echo endpoint is
    # in fact nosqli-vulnerable, so it lands as a finding) — proving the default run's
    # "inconclusive" was a real coverage gap the operator would otherwise read as safe.
    assert lib.verdict_by_class()["nosqli"] != "inconclusive"


def test_default_run_clean_is_not_corpus_wide() -> None:
    """A default run leaves EVERY library-only point class inconclusive, so a CLEAN from it
    is explicitly NOT corpus-wide. The exercised + inconclusive sets partition the corpus."""
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)

    cb = report.coverage_bounds()
    corpus = _corpus_bug_classes()
    assert cb["corpus_classes"] == len(corpus)
    # partition: exercised + inconclusive cover the corpus with no overlap
    assert set(cb["classes_exercised"]).isdisjoint(cb["classes_inconclusive"])
    assert len(cb["classes_exercised"]) + len(cb["classes_inconclusive"]) == cb["corpus_classes"]
    # a default run cannot claim a corpus-wide clean
    assert cb["clean_is_corpus_wide"] is False
    # and precisely the library-only point classes are the inconclusive set
    assert set(cb["classes_inconclusive"]) == _library_only_point_classes()
    for c in ("nosqli", "ldap_injection", "xpath_injection", "el_injection"):
        assert report.verdict_by_class()[c] == "inconclusive"


def test_library_run_shrinks_the_inconclusive_set() -> None:
    """--library over a fingerprintable target exercises the library-only classes, so the
    inconclusive set becomes a STRICT subset of the default run's."""
    with _server(_WpApp) as base:
        default = _run(base, use_library=False)
        lib = _run(base, use_library=True)

    d_inc = set(default.coverage_bounds()["classes_inconclusive"])
    l_inc = set(lib.coverage_bounds()["classes_inconclusive"])
    assert l_inc < d_inc, "the library must adjudicate classes the default run could not"
    for c in ("nosqli", "ldap_injection", "xpath_injection"):
        assert default.verdict_by_class()[c] == "inconclusive"
        assert lib.verdict_by_class()[c] != "inconclusive"


def test_verdict_gate_is_not_a_noop_flips_with_the_committed_roster() -> None:
    """No-op-gate control (deterministic): the per-class verdict is driven by what the run
    actually committed, not hardcoded. A class in the committed roster is `clean` (a bounded
    negative); the SAME class absent is `inconclusive`; a confirmed finding of it is `finding`."""
    assert {"nosqli", "boolean_sqli"} <= _corpus_bug_classes()

    # default-shaped roster: boolean_sqli exercised, nosqli not
    default = ScanReport(target="http://127.0.0.1/", committed_check_classes=["boolean_sqli"])
    v = default.verdict_by_class()
    assert v["boolean_sqli"] == "clean"        # exercised, no finding -> bounded negative
    assert v["nosqli"] == "inconclusive"       # not exercised -> a CLEAN cannot be claimed

    # add nosqli to the committed roster -> it FLIPS to clean (the gate is real, not a no-op)
    withlib = ScanReport(target="http://127.0.0.1/",
                         committed_check_classes=["boolean_sqli", "nosqli"])
    assert withlib.verdict_by_class()["nosqli"] == "clean"

    # a confirmed nosqli finding -> "finding" (the finding branch, over a real AuditFinding)
    found = ScanReport(
        target="http://127.0.0.1/", committed_check_classes=["nosqli"],
        active_findings=[AuditFinding(
            check_id="nosqli-op", bug_class="nosqli", insertion_point="query:q",
            param="q", confidence=0.99, confirmed_by="differential")],
    )
    assert found.verdict_by_class()["nosqli"] == "finding"


def test_json_report_carries_bounded_verdict() -> None:
    """The machine report carries the per-class verdict + the bounded-verdict summary, and
    they survive a JSON round-trip. The pre-existing `coverage` object is UNCHANGED (4 keys)."""
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)
    doc = build_report(report)

    assert "verdict_by_class" in doc
    assert "coverage_verdict" in doc
    assert doc["verdict_by_class"]["nosqli"] == "inconclusive"
    assert doc["coverage_verdict"]["clean_is_corpus_wide"] is False
    assert "nosqli" in doc["coverage_verdict"]["classes_inconclusive"]

    # the original coverage disclosure is untouched — additive change, no consumer breaks
    assert set(doc["coverage"]) == {"built_in_run", "library_available", "library_run", "full_coverage"}

    round_trip = json.loads(json.dumps(doc))
    assert round_trip["coverage_verdict"]["clean_is_corpus_wide"] is False
    assert round_trip["verdict_by_class"]["nosqli"] == "inconclusive"


def test_coverage_line_states_bounded_verdict() -> None:
    """The operator-facing text line states the bounded verdict: a default CLEAN is NOT
    corpus-wide and names the inconclusive count; a --library run says a CLEAN IS corpus-wide."""
    with _server(_WpApp) as base:
        default = _run(base, use_library=False)
        lib = _run(base, use_library=True)

    d_line = coverage_line(default)
    d_bounds = default.coverage_bounds()
    assert "VERDICT BOUNDED" in d_line
    assert "NOT corpus-wide" in d_line
    assert "INCONCLUSIVE" in d_line
    assert (f"adjudicated {len(d_bounds['classes_exercised'])}/"
            f"{d_bounds['corpus_classes']} point-check bug classes") in d_line

    l_line = coverage_line(lib)
    assert "a CLEAN is corpus-wide" in l_line
    assert "NOT corpus-wide" not in l_line


def test_html_report_shows_bounded_verdict() -> None:
    with _server(_WpApp) as base:
        report = _run(base, use_library=False)
    html_out = to_html(report)
    assert "VERDICT BOUNDED" in html_out
    assert "INCONCLUSIVE" in html_out
    assert "NOT corpus-wide" in html_out


# --------------------------------------------------------------------------- #
# 5. doc-truth: the decision record (docs/decisions) is TRUE of the code.
# --------------------------------------------------------------------------- #


def _find_adr() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        cand = parent / "docs" / "decisions" / "W16-4-default-check-corpus.md"
        if cand.exists():
            return cand
    raise AssertionError("W16-4 decision record not found walking up from the test file")


def test_adr_pins_the_default_check_corpus() -> None:
    """The W16-4 decision record's stated corpus numbers MATCH the code at runtime — a
    doc-truth guard so the record cannot silently drift from the shipped rosters. Stands in
    for the [W0-3] #398 claims-registry registration (not yet landed), per the W5-1 precedent."""
    adr = _find_adr().read_text(encoding="utf-8")
    # flatten markdown soft-wrapping so an assertion is not brittle to where a line breaks
    flat = re.sub(r"\s+", " ", adr)

    # DEFAULT_CHECKS: 11 point checks across 10 bug classes
    default_classes = len({c.bug_class for c in DEFAULT_CHECKS})
    assert f"{len(DEFAULT_CHECKS)} point checks" in flat
    assert f"{default_classes} bug classes" in flat

    # the shipped library size, derived from the registry
    available, classes = library_stats()
    assert f"{available} entries across {classes} bug classes" in flat

    # the point-check corpus size the disclosure bounds a CLEAN against
    corpus = len(_corpus_bug_classes())
    assert f"{corpus} distinct point-check classes" in flat

    # every library-only point class the record names is genuinely library-only in the code
    library_only = _library_only_point_classes()
    for c in ("nosqli", "ldap_injection", "xpath_injection", "el_injection", "rce", "lfi"):
        assert c in library_only
        assert f"`{c}`" in adr, f"{c} not documented in the ADR"

    # the record must state the core claim
    assert "clean_is_corpus_wide" in adr
    assert "#509" in adr
