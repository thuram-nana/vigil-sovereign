"""Audit-A soundness regressions for ``scanner.campaign`` — F2 / F3 / F7 (+ R3).

Every test here FAILS on 838e0b42. Each one pins a MEASURED defect, not a style rule:

  * F2 — ``verdict_by_class`` / ``coverage_bounds`` rolled up the bare SET of probed bug
    classes, discarding the per-probe verdict ``engine.probe_verdict`` computed. A class
    whose every probe came back ``inconclusive`` (payload sent, no oracle had a channel)
    was reported ``clean``, and a run that adjudicated NOTHING could report
    ``clean_is_corpus_wide``. Measured on a WAF-fronted static target: eight classes, all
    ``{'inconclusive': 3..6}``, all reported clean.
  * F3 — ``_smuggling_findings`` minted a High ``request_smuggling`` FACT from a LATENCY
    differential over two LITERAL placeholder bodies. ``latency`` weighs exactly 0.7 and
    ``HIGH_CONFIDENCE`` is 0.7, so a timing delta alone landed on the confirm boundary
    with NO target bytes in the certificate. Measured against a single-socket origin with
    NO proxy that merely honours RFC 7230 §3.3.3: three High FACTs at conf 0.700.
  * B1 (the audit-A RED-PEN on the F3 fix) — the canary DIFFERENTIAL that replaced the
    latency mint is ALSO not a CWE-444 fact: it is observed on the ONE connection VIGIL
    itself pipelined the smuggled prefix onto, so it measures one parser, not two parsers
    disagreeing. A benign single origin with no proxy (TE over CL per RFC 9112 §6.1,
    keep-alive pipelining, a stock path-echoing 404) minted High/0.95, and two ORDINARY
    pipelined requests with no framing conflict produce the identical canary echo.
    ``request_smuggling`` is LEAD-only; the cross-connection FACT is named blocking_work.
  * B2 — the raw response reader mis-framed a 1xx interim, an under-declared
    Content-Length and a chunked trailer block, each of which turns a benign echo of the
    FIRST request into the reply to VIGIL's SECOND. See ``test_rawhttp_reader``.
  * B3 — the CSWSH predicate matched ``"http/1.1 101"`` and the accept key ANYWHERE in the
    retained block: a server answering 403 whose headers echo those strings was reported
    hijackable (BASE 0 findings -> HEAD 1). It is anchored to the STATUS LINE now.
  * B4 — ``_arsenal_finding`` discarded the producer's title/severity and the report
    re-labelled every entry "<bug_class> confirmed at <param>", so an explicitly
    UNCONFIRMED Medium LEAD rendered as a confirmed High.
  * F7 — the CSWSH certificate was ``from_state({"cross_origin_ws_accepted": True},
    {"cross_origin_ws_accepted": True})``: BOTH sides literals, so it re-confirmed forever
    regardless of the target, the fix state, or whether the endpoint ever existed.
  * R3 — ``request_race`` minted from ``result.successes``, a producer-computed scalar
    over the DEFAULT any-2xx rule, which ``BUG_CLASS_ORACLES``' own row calls a LEAD.

All traffic is loopback.
"""

from __future__ import annotations

import contextlib
import json
import re
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import unquote_plus, urlsplit

import pytest

from framework.v2.eval.benchmark_app import (
    serve_smuggling_benign, serve_smuggling_desync, serve_smuggling_reflect_error,
)
from framework.v2.scanner.campaign import ScanReport, WebScanCampaign, _corpus_bug_classes
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.engine import AuditFinding, ProbeRecord
from framework.v2.scanner.report import build_report
from framework.v2.verify.reverify import reverify_context


def _dummy_send(req):
    return {"status": 0, "body": "", "headers": [], "latency_ms": 0.0}


def _probe(bug_class: str, *, verdict: str, point: str = "query:q") -> ProbeRecord:
    """One EXERCISED probe record carrying the verdict the engine adjudicated."""
    return ProbeRecord(
        endpoint="http://127.0.0.1/search", method="GET", insertion_point=point,
        param="q", check_id=f"{bug_class}-op", bug_class=bug_class, verdict=verdict)


# ===========================================================================
# F2 — a class whose every probe was INCONCLUSIVE is not CLEAN
# ===========================================================================

# The eight classes the audit measured as all-inconclusive-yet-"clean" on a WAF-fronted
# static target. Named here so the regression pins the measured case, not a generic one.
_MEASURED_ALL_INCONCLUSIVE = (
    "blind_xxe", "command_injection", "deserialization", "error_based_sqli",
    "path_traversal", "ssrf", "ssti", "xss",
)


def test_f2_all_inconclusive_class_is_inconclusive_not_clean() -> None:
    """The measured case, deterministically: several probes of a class ran, EVERY one came
    back ``inconclusive``, no finding. ``probe_verdict``'s rule is absolute — "only
    non-conclusive non-signals -> inconclusive ... NEVER clean" — so the class verdict must
    be ``inconclusive`` too. On 838e0b42 every one of these read ``clean``."""
    probes = [_probe(c, verdict="inconclusive", point=f"query:p{i}")
              for c in _MEASURED_ALL_INCONCLUSIVE for i in range(3)]
    report = ScanReport(target="http://127.0.0.1/", exercised_probes=probes)

    verdicts = report.verdict_by_class()
    for c in _MEASURED_ALL_INCONCLUSIVE:
        assert verdicts[c] == "inconclusive", f"{c} was all-inconclusive but read {verdicts[c]!r}"

    bounds = report.coverage_bounds()
    for c in _MEASURED_ALL_INCONCLUSIVE:
        assert c not in bounds["classes_exercised"]
        assert c in bounds["classes_inconclusive"]
    # the partition invariant still holds
    assert set(bounds["classes_exercised"]).isdisjoint(bounds["classes_inconclusive"])
    assert len(bounds["classes_exercised"]) + len(bounds["classes_inconclusive"]) == bounds["corpus_classes"]


def test_f2_one_conclusive_probe_still_earns_clean() -> None:
    """Positive control — the gate is not a blanket demotion. A class with at least ONE
    ``clean`` probe (an oracle proved it had a channel and rendered a decisive negative)
    is still a bounded CLEAN, even alongside inconclusive siblings; a ``finding`` probe
    still wins."""
    report = ScanReport(target="http://127.0.0.1/", exercised_probes=[
        _probe("boolean_sqli", verdict="inconclusive", point="query:a"),
        _probe("boolean_sqli", verdict="clean", point="query:b"),
        _probe("xss", verdict="clean", point="query:c"),
        _probe("xss", verdict="finding", point="query:d"),
    ])
    verdicts = report.verdict_by_class()
    assert verdicts["boolean_sqli"] == "clean"
    assert verdicts["xss"] == "finding"
    assert "boolean_sqli" in report.coverage_bounds()["classes_exercised"]


def test_f2_corpus_wide_clean_is_unreachable_without_an_adjudication() -> None:
    """The sharp end of the defect: a run that probed EVERY corpus class but adjudicated
    NONE of them could declare ``clean_is_corpus_wide`` — a corpus-wide negative over a run
    that proved nothing. On 838e0b42 this is True; it must be False."""
    corpus = sorted(_corpus_bug_classes())
    nothing_adjudicated = ScanReport(
        target="http://127.0.0.1/",
        exercised_probes=[_probe(c, verdict="inconclusive") for c in corpus])

    bounds = nothing_adjudicated.coverage_bounds()
    assert bounds["clean_is_corpus_wide"] is False
    assert bounds["classes_exercised"] == []
    assert sorted(bounds["classes_inconclusive"]) == corpus
    assert set(nothing_adjudicated.verdict_by_class().values()) == {"inconclusive"}

    # ... and the positive control: the SAME corpus, actually adjudicated, still is.
    all_adjudicated = ScanReport(
        target="http://127.0.0.1/",
        exercised_probes=[_probe(c, verdict="clean") for c in corpus])
    assert all_adjudicated.coverage_bounds()["clean_is_corpus_wide"] is True


class _WafStaticApp(BaseHTTPRequestHandler):
    """The audit's fixture shape: a completely STATIC page with NO database and NO
    injection surface at all (the query string is never parsed or interpolated), fronted
    by a CRS-942130-style SQL-tautology deny rule. The ONLY input-dependent behaviour is
    the WAF's block page — so no oracle has a channel and every probe is inconclusive."""

    protocol_version = "HTTP/1.1"
    _TAUT = re.compile(r"(?i)(\b(or|and)\b\s*['\"]?\s*\d+\s*['\"]?\s*=\s*['\"]?\s*\d+|"
                       r"['\"]\s*(or|and)\s*['\"]?\s*['\"]?\s*\w+\s*['\"]?\s*=)")
    _PAGE = (b"<!doctype html><html><head><title>Acme Corp</title></head><body>"
             b"<h1>Welcome to Acme</h1><p>We sell widgets.</p>"
             b"<form action='/search' method='get'><input name='q'></form></body></html>")
    _BLOCK = (b"<!doctype html><html><head><title>403 Forbidden</title></head><body>"
              b"<h1>Request blocked</h1><p>rule 942130: SQL tautology detected</p></body></html>")

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        raw = unquote_plus(urlsplit(self.path).query or "")
        body, status = (self._BLOCK, 403) if self._TAUT.search(raw) else (self._PAGE, 200)
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


@contextlib.contextmanager
def _http_server(handler) -> Iterator[str]:
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


def test_f2_waf_static_target_does_not_report_a_false_clean() -> None:
    """End to end over the audit's WAF-fronted static fixture: a class must not be
    reported ``clean`` unless a probe of it actually returned the ``clean`` verdict.

    The assertion is guarded against vacuity — the run MUST contain at least one class
    whose every probe was inconclusive, otherwise the fixture stopped exercising the
    defect and the test says so instead of passing quietly."""
    with _http_server(_WafStaticApp) as base:
        report = WebScanCampaign(loopback_send, max_pages=5, enable_oob=False).run(base + "/")

    by_class: dict[str, set[str]] = {}
    for p in report.exercised_probes:
        by_class.setdefault(p.bug_class, set()).add(p.verdict)
    all_inconclusive = {c for c, v in by_class.items() if v == {"inconclusive"}}
    assert all_inconclusive, (
        "fixture no longer produces an all-inconclusive class — the F2 regression would be vacuous")

    verdicts = report.verdict_by_class()
    for c in sorted(all_inconclusive):
        assert verdicts[c] == "inconclusive", (
            f"{c}: every probe was inconclusive ({sorted(by_class[c])}) yet the run reported "
            f"{verdicts[c]!r} — a FALSE CLEAN on the default path")

    # and the same truth reaches the machine report the json/sarif/html consumers read
    doc = build_report(report)
    for c in sorted(all_inconclusive):
        assert doc["verdict_by_class"][c] == "inconclusive"
        assert c in doc["coverage_verdict"]["classes_inconclusive"]
    assert doc["coverage_verdict"]["clean_is_corpus_wide"] is False
    json.loads(json.dumps(doc))   # still serialises


# ===========================================================================
# F3 + B1 — request_smuggling is a LEAD on every campaign path
# ===========================================================================
#
# F3 deleted the LATENCY mint. B1 (the audit-A red-pen) then falsified the canary
# DIFFERENTIAL that replaced it: it is observed on the ONE connection VIGIL itself
# pipelined the smuggled prefix onto, so it measures ONE parser ("does this origin honour
# TE over CL and pipeline the remainder"), not two parsers disagreeing across a trust
# boundary, which is what CWE-444 is. The three origins below are the measurement:
#
#   _Rfc7230Origin        — single hop, TE over CL, PIPELINES, but does NOT echo the path.
#                           No canary comes back at all.
#   _StockEchoOrigin      — the same, plus a STOCK path-echoing 404 (the Apache httpd /
#                           Express / Tomcat default). The full differential holds against
#                           a server where a desync is not even possible.
#   _InterimContinueOrigin— the shipped reflect-error red-pen twin PLUS one unsolicited
#                           `100 Continue`, which used to defeat the reader's framing.
#
# Every one of them must produce a LEAD and never a finding, and each test asserts
# POSITIVELY that the producer ran, captured the differential, and refused to mint.


class _LoopingOrigin(threading.Thread):
    """Base for the single-hop negative controls: accept, serve requests IN A LOOP on the
    same connection, and honour Transfer-Encoding over Content-Length."""

    #: subclasses answer a request path with a full response
    def respond(self, path: str) -> bytes:                # pragma: no cover - overridden
        raise NotImplementedError

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def page(body: bytes, status: bytes = b"200 OK") -> bytes:
        return (b"HTTP/1.1 " + status + b"\r\nContent-Type: text/html\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + body)

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            f = conn.makefile("rb")
            # THE LOOP. The pre-B1 fixture handled exactly ONE request and closed, so it
            # never reached the keep-alive pipelining path — which is the path that fires.
            for _ in range(8):
                request_line = f.readline()
                if not request_line:
                    return
                path = (request_line.decode("latin-1", "replace").split(" ") + ["", ""])[1]
                headers: dict[bytes, bytes] = {}
                while True:
                    ln = f.readline()
                    if not ln or ln in (b"\r\n", b"\n"):
                        break
                    if b":" in ln:
                        k, v = ln.split(b":", 1)
                        headers[k.strip().lower()] = v.strip()
                self.before_body(conn, headers)
                if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                    while True:                       # TE wins, CL ignored (RFC 9112 6.1)
                        sz = f.readline()
                        if not sz:
                            return
                        try:
                            n = int(sz.strip().split(b";")[0], 16)
                        except ValueError:
                            return
                        if n == 0:
                            f.readline()
                            break
                        f.read(n)
                        f.readline()
                elif b"content-length" in headers:
                    f.read(int(headers[b"content-length"]))
                conn.sendall(self.respond(path))
        except Exception:      # noqa: BLE001 — a fixture, not a product path
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def before_body(self, conn: socket.socket, headers: "dict[bytes, bytes]") -> None:
        return None

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


class _Rfc7230Origin(_LoopingOrigin):
    """A SINGLE ORIGIN — no front-end, no proxy, no CDN, so NO desync is even possible —
    that honours RFC 9112 §6.1 / RFC 7230 §3.3.3 rule 3: when Transfer-Encoding is present,
    Content-Length is IGNORED and the body is read as chunked to the terminating zero-chunk.
    It then serves the NEXT pipelined request on the same connection, like any keep-alive
    server. One socket, one parser, nothing for two parsers to disagree about — yet it HANGS
    on the CL+TE probes, which is why timing is a LEAD and not a proof.

    (The pre-B1 version of this fixture claimed nginx / Go net/http / Node / Tomcat behave
    this way. They do not: those servers REJECT a request carrying both Content-Length and
    Transfer-Encoding outright, which is the RFC's recommended handling. The servers that
    behave like this fixture are precisely the lax ones that FIRE under pipelining — which
    is the point. It also handled exactly ONE request and closed, so it never reached the
    pipelining path at all.)

    It returns a FIXED page, so no canary is ever echoed: this is the control that isolates
    the path echo as the thing that makes the differential hold."""

    def respond(self, path: str) -> bytes:
        return self.page(b"<html><body><h1>Hello world</h1></body></html>")


class _StockEchoOrigin(_LoopingOrigin):
    """The same benign single hop, with the STOCK 404 page every mainstream server ships —
    Apache httpd's "The requested URL <path> was not found on this server", Express's
    "Cannot GET <path>", Tomcat's "The requested resource [<path>] is not available". They
    all ECHO THE REQUESTED PATH, which is all it takes: VIGIL's smuggled prefix is a GET to
    ``/vigil-reflect?c=<canary>``, so the pipelined 404 for it carries the canary."""

    def respond(self, path: str) -> bytes:
        if path.startswith("/vigil-start") or path.startswith("/vigil-follow"):
            return self.page(b"ok")
        return self.page(
            b"<!DOCTYPE HTML><html><head><title>404 Not Found</title></head><body>"
            b"<h1>Not Found</h1><p>The requested URL " + path.encode("latin-1", "replace")
            + b" was not found on this server.</p></body></html>", status=b"404 Not Found")


class _InterimContinueOrigin(_LoopingOrigin):
    """The shipped red-pen twin (``serve_smuggling_reflect_error``: a 400 whose page echoes
    the offending request, canary and all) PLUS one unsolicited ``HTTP/1.1 100 Continue``
    for any bodied request — which servers and load balancers really do send.

    The 1xx is the B2 defect: the reader returned the interim as a COMPLETE response, so the
    FINAL 400 (carrying the echoed canary) became "response 2" and the documented defence
    ("that echo lives in the FIRST response") collapsed. A 1xx is INTERIM (RFC 9112 §15)."""

    def before_body(self, conn: socket.socket, headers: "dict[bytes, bytes]") -> None:
        if b"content-length" in headers or b"transfer-encoding" in headers:
            with contextlib.suppress(OSError):
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    def _serve(self, conn: socket.socket) -> None:
        # This origin rejects the ambiguous framing outright (the SAFE behaviour) with a 400
        # that echoes the request, so it cannot use the base loop's TE-over-CL body handling.
        try:
            conn.settimeout(2.0)
            f = conn.makefile("rb")
            for _ in range(8):
                request_line = f.readline()
                if not request_line:
                    return
                path = (request_line.decode("latin-1", "replace").split(" ") + ["", ""])[1]
                head = bytearray(request_line)
                headers: dict[bytes, bytes] = {}
                while True:
                    ln = f.readline()
                    if not ln or ln in (b"\r\n", b"\n"):
                        break
                    head.extend(ln)
                    if b":" in ln:
                        k, v = ln.split(b":", 1)
                        headers[k.strip().lower()] = v.strip()
                self.before_body(conn, headers)
                conflict = (b"transfer-encoding" in headers and b"content-length" in headers)
                if conflict:
                    rest = f.read1(65536) if hasattr(f, "read1") else b""
                    conn.sendall(self.page(b"Malformed request rejected:\n" + bytes(head)
                                           + b"\r\n" + rest, status=b"400 Bad Request"))
                    continue
                if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                    while True:
                        sz = f.readline()
                        if not sz:
                            return
                        try:
                            n = int(sz.strip().split(b";")[0], 16)
                        except ValueError:
                            return
                        if n == 0:
                            f.readline()
                            break
                        f.read(n)
                        f.readline()
                elif b"content-length" in headers:
                    f.read(int(headers[b"content-length"]))
                conn.sendall(self.respond(path))
        except Exception:      # noqa: BLE001 — a fixture
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def respond(self, path: str) -> bytes:
        return self.page(b"ok")


@contextlib.contextmanager
def _origin(cls) -> Iterator[int]:
    srv = cls()
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


def _smuggling_run(port: int) -> "tuple[list[str], list]":
    camp = WebScanCampaign(_dummy_send, enable_arsenal=True)   # loopback -> allowed
    return camp._smuggling_leads([("127.0.0.1", port, f"http://127.0.0.1:{port}/")])


def _assert_no_smuggling_fact(port: int) -> list[str]:
    """Every smuggling negative control asserts the SAME positive facts: the producer really
    ran (a probe record exists for the class), it really adjudicated the differential, the
    lead says UNCONFIRMED in so many words, and NOTHING was minted anywhere. Asserting only
    "no finding appeared" would pass if the probe never ran at all."""
    leads, probes = _smuggling_run(port)
    assert probes, "the desync producer did not run at all — the control would be vacuous"
    assert {p.bug_class for p in probes} == {"request_smuggling"}
    assert all(p.verdict == "inconclusive" for p in probes), [p.verdict for p in probes]
    smug = [ln for ln in leads if ln.startswith("smuggling ")]
    assert smug, f"the producer ran but reported nothing: {leads}"
    # the class never reaches active_findings through the arsenal pass
    assert not hasattr(WebScanCampaign, "_smuggling_findings"), (
        "the FACT-minting smuggling path must be gone")
    return smug


def test_f3_rfc7230_compliant_origin_mints_no_smuggling_fact() -> None:
    """The measured false positive: a conformant single-socket origin with no proxy at all,
    now ACTUALLY LOOPING so it reaches the keep-alive pipelining path. It HANGS on the CL+TE
    probes (waiting for a chunk that never comes), so the old latency mint produced High
    ``request_smuggling`` FACTs at conf 0.700 where a desync is not even possible."""
    with _origin(_Rfc7230Origin) as port:
        smug = _assert_no_smuggling_fact(port)
    assert any("UNCONFIRMED" in ln or "not adjudicable" in ln or "NOT echoed" in ln
               for ln in smug), smug


def test_b1_stock_404_pipelining_origin_mints_no_smuggling_fact() -> None:
    """THE B1 FALSE POSITIVE. One benign origin, no proxy, no second parser: TE preferred
    over CL (RFC 9112 §6.1 permits it), keep-alive pipelining, and the stock path-echoing
    404 that Apache httpd, Express and Tomcat all ship. On ff0c90db this minted
    ``severity High, confidence 0.95, confirmed_by differential_response`` and its
    certificate re-verified ``ok``.

    The full differential DOES hold here — that is the point. It must be reported as a LEAD
    that names why, not as a CWE-444 fact."""
    with _origin(_StockEchoOrigin) as port:
        leads, probes = _smuggling_run(port)
    assert probes and all(p.verdict == "inconclusive" for p in probes)
    echoed = [ln for ln in leads if "canary was echoed" in ln]
    assert echoed, (
        "the differential did NOT hold against the stock-404 pipelining origin — the B1 "
        f"regression test has gone vacuous and would pass for the wrong reason: {leads}")
    for ln in echoed:
        assert "UNCONFIRMED LEAD" in ln and "NOT a CWE-444 fact" in ln, ln
        assert "blocking_work" in ln, ln


def test_b1_plain_pipelining_reproduces_the_whole_differential() -> None:
    """THE DECISIVE MEASUREMENT. Against that same origin, TWO ORDINARY PIPELINED REQUESTS
    with NO framing conflict anywhere produce the IDENTICAL canary echo. So the differential
    cannot be attributed to a framing disagreement between two parsers: it detects "does
    this origin honour keep-alive pipelining and echo the path", which one parser does on
    its own. This is the test that makes the demotion a measurement rather than an opinion."""
    canary = "crsmugdeadbeefcafe0011223344"
    with _origin(_StockEchoOrigin) as port:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.settimeout(3)
        try:
            s.sendall(
                (f"GET /vigil-start HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n"
                 f"GET /vigil-reflect?c={canary} HTTP/1.1\r\nHost: h\r\n"
                 f"Connection: close\r\n\r\n").encode())
            data = b""
            while len(data) < 65536:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            with contextlib.suppress(OSError):
                s.close()
    assert canary in data.decode("latin-1", "replace"), (
        "plain pipelining did not echo the canary — the control is vacuous")
    assert data.count(b"HTTP/1.1 ") >= 2, data[:200]


def test_b2_interim_continue_origin_mints_no_smuggling_fact() -> None:
    """The B2 end-to-end: the shipped reflect-error red-pen twin plus ONE unsolicited
    ``100 Continue``. Before the shared reader treated a 1xx as INTERIM, the final 400 —
    which echoes the offending request, canary and all — was attributed to VIGIL's follow-up
    on BOTH techniques, defeating the documented "that echo lives in the FIRST response"
    defence."""
    with _origin(_InterimContinueOrigin) as port:
        leads, probes = _smuggling_run(port)
    assert probes, "the desync producer did not run"
    assert not any("canary was echoed" in ln for ln in leads), (
        "the 100-Continue origin still produces a canary-echo differential — the interim "
        f"response is being mis-framed as the reply to VIGIL's second request: {leads}")


def _port_of(url: str) -> int:
    return urlsplit(url).port or 80


def test_f3_canary_echo_desync_is_a_lead_not_a_fact() -> None:
    """The shipped POSITIVE fixture. It is a single ``ThreadingTCPServer`` with no front-end,
    so it has the SAME single-hop shape as the benign origin above and the oracle cannot
    distinguish them — which is exactly why this must be a LEAD too. The producer must still
    capture the whole differential (the machinery is kept, not deleted); only the CLAIM is
    demoted."""
    with serve_smuggling_desync() as origin:
        leads, probes = _smuggling_run(_port_of(origin))

    assert probes and {p.bug_class for p in probes} == {"request_smuggling"}
    echoed = [ln for ln in leads if "canary was echoed" in ln]
    assert echoed, f"the canary machinery must still capture the differential: {leads}"
    for ln in echoed:
        assert "UNCONFIRMED LEAD" in ln and "NOT a CWE-444 fact" in ln, ln


def test_f3_safe_twins_do_not_fire() -> None:
    """Negative controls from the shipped corpus: a back-end that REJECTS the ambiguous
    framing, and the red-pen twin whose 400 page ECHOES the offending request (canary and
    all) while answering the well-formed control cleanly. Neither may produce an echo
    differential at all."""
    for serve in (serve_smuggling_benign, serve_smuggling_reflect_error):
        with serve() as origin:
            leads, probes = _smuggling_run(_port_of(origin))
        assert probes, f"{serve.__name__}: the producer did not run"
        assert not any("canary was echoed" in ln for ln in leads), (
            f"{serve.__name__} produced a canary-echo differential: {leads}")


def test_n3_a_probed_smuggling_class_reaches_the_coverage_evidence() -> None:
    """N3 — a probed class must reach ``exercised_probes`` so the W16-4 coverage machinery
    can see it was probed. It is recorded ``inconclusive``, never ``clean``, even for the
    oracle's step-4 CONCLUSIVE negative: the evidence branch declares ``clean_capable:
    false`` and bounds a non-firing to the probed technique/origin, so a class-wide CLEAN
    from two cleartext techniques on one origin would be the F2 false-CLEAN reintroduced."""
    with _origin(_Rfc7230Origin) as port:
        _leads, probes = _smuggling_run(port)
    report = ScanReport(target="http://127.0.0.1/", exercised_probes=probes)
    assert report.verdict_by_class()["request_smuggling"] == "inconclusive"
    assert "request_smuggling" not in report._adjudicated_classes()[0]

# ===========================================================================
# F7 — a certificate must contain target-derived bytes and must be falsifiable
# ===========================================================================

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _AnyOriginWSServer(threading.Thread):
    """A WS endpoint that accepts ANY Origin — vulnerable to CSWSH."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        import base64
        import hashlib
        conn.settimeout(2.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        key = ""
        for line in data.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                if k.decode().strip().lower() == "sec-websocket-key":
                    key = v.decode().strip()
        accept = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
        with contextlib.suppress(OSError):
            # B3 (audit-A red-pen BLOCK-3): the 101 header block AND a WebSocket DATA FRAME
            # go out in ONE sendall, so a single ``recv`` really does deliver both. Without
            # this the fixture sent nothing after CRLFCRLF, ``_header_block`` was a no-op on
            # every byte pattern it ever saw, and the test asserting the block is bounded
            # passed identically with the trimming removed (measured: 0 tests killed).
            # ``0x81 0x0a`` is a final text frame with a 10-byte payload, "fake-frame".
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept.encode()
                         + b"\r\n\r\n" + b"\x81\x0afake-frame")
        with contextlib.suppress(OSError):
            conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _ws_server() -> Iterator[int]:
    srv = _AnyOriginWSServer()
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


def test_f7_cswsh_certificate_carries_raw_bytes_and_fails_on_tamper() -> None:
    """On 838e0b42 the retained certificate was
    ``{"expected_state": {"cross_origin_ws_accepted": true},
       "observed_state": {"cross_origin_ws_accepted": true}}`` — two literals, so
    ``achieved_state_oracle(True, True)`` re-confirmed FOREVER: no target bytes to tamper,
    nothing that could ever fail. The certificate must now carry the two handshakes' raw
    request/response blocks, and altering ANY of them must break the re-verification."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    with _ws_server() as port:
        ws_url = f"ws://127.0.0.1:{port}/live"
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
        findings = camp._cswsh_findings([ws_url])

    assert findings, "an any-origin WS server should still be reported"
    ctx = findings[0].oracle_context
    assert ctx is not None

    evidence = ctx["observed_evidence"]
    # RAW target bytes — the server's own 101 status line and Sec-WebSocket-Accept value
    assert "101 Switching Protocols" in evidence["evil_response"]
    assert evidence["evil_accept_key"] and evidence["evil_accept_key"] in evidence["evil_response"]
    assert "101 Switching Protocols" in evidence["trusted_response"]
    assert "Origin: https://crucible-evil-origin.test" in evidence["evil_request"]
    # ... and NOT the old producer-computed boolean
    assert "cross_origin_ws_accepted" not in json.dumps(ctx)

    assert reverify_context(ctx, bug_class="cross_site_websocket_hijacking").ok

    for field, replacement in (
        ("evil_response", "HTTP/1.1 403 Forbidden\r\n\r\n"),      # the endpoint refused the foreign origin
        ("trusted_response", "HTTP/1.1 404 Not Found\r\n\r\n"),   # the endpoint does not exist
    ):
        tampered = json.loads(json.dumps(ctx))
        tampered["observed_evidence"][field] = replacement
        assert not reverify_context(tampered, bug_class="cross_site_websocket_hijacking").ok, (
            f"editing {field} out of the certificate must break the re-verification")



class _Echo403WSServer(threading.Thread):
    """B3's negative control: a server that REFUSES the foreign Origin with
    ``HTTP/1.1 403 Forbidden`` — but whose response HEADERS contain the substring
    ``HTTP/1.1 101 Switching Protocols`` and the correctly computed
    ``Sec-WebSocket-Accept`` value (a diagnostic "here is the upgrade I would have sent"
    header; echoing the rejected exchange back is an ordinary thing for a gateway to do).

    Measured on ff0c90db: BASE 838e0b42 = 0 findings, HEAD = 1 ``cross_site_websocket_
    hijacking`` at conf 0.9. The predicate matched ``"http/1.1 101"`` and the accept key
    ANYWHERE in the retained block instead of on the STATUS LINE, and the retained block was
    whatever ``recv`` delivered. A refusing server must never be reported as hijackable."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.foreign_seen = 0
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        import base64
        import hashlib
        conn.settimeout(2.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        key = origin = ""
        for line in data.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                name = k.decode("latin-1", "replace").strip().lower()
                if name == "sec-websocket-key":
                    key = v.decode("latin-1", "replace").strip()
                elif name == "origin":
                    origin = v.decode("latin-1", "replace").strip()
        accept = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
        if "crucible-evil-origin" in origin:
            self.foreign_seen += 1
            body = b"cross-origin upgrade refused"
            with contextlib.suppress(OSError):
                conn.sendall(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"X-Rejected-Upgrade: HTTP/1.1 101 Switching Protocols\r\n"
                    b"X-Would-Have-Been-Accept: " + accept.encode() + b"\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        else:
            with contextlib.suppress(OSError):
                conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                             b"Connection: Upgrade\r\nSec-WebSocket-Accept: "
                             + accept.encode() + b"\r\n\r\n")
        with contextlib.suppress(OSError):
            conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


def test_b3_a_403_that_echoes_the_101_status_line_is_not_a_cswsh() -> None:
    """The F7 regression this slice introduced, pinned. Asserts POSITIVELY that the probe
    really ran against the refusing endpoint (the server counts the foreign handshake it
    rejected) and that the producer's own status-line-anchored verdict says NOT accepted —
    not merely that no finding appeared."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    srv = _Echo403WSServer()
    srv.start()
    try:
        ws_url = f"ws://127.0.0.1:{srv.port}/live"
        from framework.v2.scanner.websocket import CswshCheck, handshake
        _conn, evil_hs = handshake(ws_url, origin="https://crucible-evil-origin.test")
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
        findings = camp._cswsh_findings([ws_url])
        confirmed, ctx = CswshCheck(url=ws_url).probe_with_context()
    finally:
        srv.stop()

    # the probe really happened and the server really refused the foreign origin
    assert srv.foreign_seen >= 2, srv.foreign_seen
    assert evil_hs.status == 403 and evil_hs.status_line.startswith("HTTP/1.1 403")
    # ... and the RAW bytes really do carry both decoys, so the control is not vacuous
    assert "HTTP/1.1 101 Switching Protocols" in evil_hs.response
    assert evil_hs.accept_key and evil_hs.accept_key in evil_hs.response
    # the producer's own anchored verdict, which the predicate used to throw away
    assert evil_hs.accepted is False
    # nothing is reported, and the refusal still carries a re-verifiable certificate
    assert findings == [], findings
    assert confirmed is None
    assert not reverify_context(ctx.model_dump(mode="json"),
                                bug_class="cross_site_websocket_hijacking").ok


def test_b3_retained_response_is_bounded_to_the_header_block() -> None:
    """``_read_headers`` returns whatever ``recv`` delivered, so body/frame bytes could ride
    into the block the predicate searches. What is RETAINED must be the headers only.

    Audit-A red-pen BLOCK-3: this control used to be VACUOUS. ``_AnyOriginWSServer`` never
    sent anything after CRLFCRLF, so ``count("\r\n\r\n") == 1`` and ``endswith`` held with
    ``_header_block`` reduced to ``return resp`` — 0 tests killed. The fixture now writes the
    101 headers AND a WebSocket text frame in a SINGLE ``sendall``, so one ``recv`` delivers
    both and the trimming is the only thing that keeps the frame out of the retained block."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    with _ws_server() as port:
        from framework.v2.scanner.websocket import handshake
        _conn, hs = handshake(f"ws://127.0.0.1:{port}/live", origin="http://x.test")
    assert hs.response.endswith("\r\n\r\n"), repr(hs.response[-16:])
    assert hs.response.count("\r\n\r\n") == 1
    assert hs.status_line == "HTTP/1.1 101 Switching Protocols"
    # the load-bearing clause: the frame that arrived in the SAME read must NOT be retained
    assert "fake-frame" not in hs.response, repr(hs.response[-32:])


def test_b4_an_unconfirmed_lead_is_never_rendered_as_confirmed() -> None:
    """B4 — the campaign supplies NO victim cookies, so ``CswshCheck`` takes its explicitly
    UNCONFIRMED Medium branch ("… possible CSWSH — UNCONFIRMED", "an authenticated hijack is
    NOT proven"). ``_arsenal_finding`` used to DISCARD that title and severity and
    ``build_report`` re-labelled the entry ``"cross_site_websocket_hijacking confirmed at
    ws://…"`` at the class's table severity — so the hedge was cosmetic and this slice's own
    F3/R3 demotions would have rendered the same way."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    with _ws_server() as port:
        ws_url = f"ws://127.0.0.1:{port}/live"
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
        findings = camp._cswsh_findings([ws_url])

    assert findings, "an any-origin WS server must still be reported"
    f = findings[0]
    # the producer's own claim survives the adapter
    assert "UNCONFIRMED" in f.title and f.severity == "Medium", (f.title, f.severity)

    doc = build_report(ScanReport(target=ws_url, active_findings=findings))
    entry = next(x for x in doc["findings"] if x["bug_class"] == "cross_site_websocket_hijacking")
    assert "UNCONFIRMED" in entry["title"], entry["title"]
    assert "confirmed at" not in entry["title"], entry["title"]
    assert entry["severity"] == "Medium", entry
    assert doc["summary"]["by_severity"].get("High", 0) == 0, doc["summary"]


def test_b4_arsenal_leads_reach_the_rendered_document() -> None:
    """A demotion that the document never prints is indistinguishable, to the operator, from
    a class that was never probed. The LEAD channel must be exported."""
    report = ScanReport(target="http://127.0.0.1/",
                        arsenal_leads=["smuggling CL.TE @ http://127.0.0.1/: … UNCONFIRMED LEAD"])
    doc = build_report(report)
    assert doc["arsenal_leads"] == report.arsenal_leads
    assert doc["findings"] == []
    json.loads(json.dumps(doc))

class _GraphQLApp(BaseHTTPRequestHandler):
    """A GraphQL endpoint with introspection ENABLED and field suggestions ON."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        query = self.rfile.read(n).decode("utf-8", "replace")
        if "__schema" in query:
            body = json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                                                     "types": [{"name": "User"}]}}}).encode()
        else:
            body = json.dumps({"errors": [{"message": 'Cannot query field "x". Did you mean "xy"?'}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_f7_graphql_certificates_carry_raw_bytes_and_fail_on_tamper() -> None:
    """The milder F7 instances: the introspection / suggestions checks passed
    ``{"introspection_enabled": True}`` vs a Python bool THEY had computed, so the oracle
    re-asserted the check's own verdict over a certificate with no target bytes."""
    from framework.v2.scanner.graphql import GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
    from framework.v2.scanner.insertion import HttpRequest, RequestTemplate
    from framework.v2.verify.confirmation import confirm_finding

    with _http_server(_GraphQLApp) as base:
        tmpl = RequestTemplate(HttpRequest(method="POST", url=base + "/graphql"))
        intro = GraphQLIntrospectionCheck().probe(tmpl, loopback_send)
        sugg = GraphQLSuggestionsCheck().probe(tmpl, loopback_send)

    for ctx, bug_class, marker in (
        (intro, "graphql_introspection", '"__schema":'),
        (sugg, "graphql_suggestions", "Did you mean"),
    ):
        assert ctx is not None
        doc = ctx.model_dump(mode="json")
        assert "response_body" in doc["observed_evidence"]
        assert marker in doc["observed_evidence"]["response_body"]
        assert confirm_finding({"bug_class": bug_class, "title": bug_class,
                                "severity": "Medium", "surface": "x", "summary": "x"}, ctx) is not None
        assert reverify_context(doc, bug_class=bug_class).ok

        tampered = json.loads(json.dumps(doc))
        tampered["observed_evidence"]["response_body"] = '{"errors":[{"message":"not allowed"}]}'
        assert not reverify_context(tampered, bug_class=bug_class).ok


# ===========================================================================
# R3 — request_race over a bare any-2xx count is a LEAD, never a FACT
# ===========================================================================


class _AlwaysOkApp(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = do_POST


def test_r3_race_over_run_is_a_lead_not_a_fact() -> None:
    """An endpoint that 200s every request in the burst over-runs any limit under the
    DEFAULT any-2xx success rule, and the campaign has no owner-signed workflow spec and no
    SEMANTIC success predicate. ``BUG_CLASS_ORACLES``' own ``request_race`` row calls that
    a LEAD; on 838e0b42 it minted a High FACT from ``result.successes``."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    with _http_server(_AlwaysOkApp) as base:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True,
                               arsenal_race_targets=(("/buy", 1),))
        leads = camp._race_leads(base + "/")

    assert not hasattr(camp, "_race_findings"), "the FACT-minting race path must be gone"
    assert any("UNCONFIRMED LEAD" in ln for ln in leads), leads
    assert all(isinstance(ln, str) for ln in leads)


# ===========================================================================================
# BLOCK-1 / BLOCK-2 — GraphQL introspection: a POPULATED schema, or nothing
# ===========================================================================================

#: Bodies that disclose ZERO schema. Each one was MEASURED to mint a signed
#: ``ACHIEVED_STATE`` FACT at conf 0.9 that re-verified offline against the substring-only
#: form of the check — on a check that is in ``DEFAULT_REQUEST_CHECKS``, i.e. on every scan.
_NO_SCHEMA_BODIES: "dict[str, str]" = {
    # the field-auth denial that preserves the __schema SHAPE; `[]` IS an open bracket, which
    # is what defeated the "a real object or list" clause
    "field_auth_denial": '{"data": {"__schema": {"queryType": null, "types": []}}, '
                         '"errors": [{"message": "Introspection is disabled on this endpoint."}]}',
    "empty_query_type": '{"data":{"__schema":{"queryType":{},"types":null}}}',
    "empty_types_list": '{"data":{"__schema":{"types":[]}}}',
    "null_data_with_errors": '{"data":null,"errors":[{"message":"GraphQL introspection is not '
                             'allowed by Apollo Server, but the query contained __schema"}]}',
    "apollo_introspection_disabled": '{"errors":[{"message":"GraphQL introspection is not allowed '
                                     'by Apollo Server, but the query contained __schema or '
                                     '__type. To enable introspection, pass introspection: true"}]}',
    # residual 3, same root cause: a NON-JSON page that merely QUOTES a sample response
    "waf_page_quoting_a_sample": '<html><body><h1>Request blocked</h1><p>Your request resembled '
                                 'an introspection query such as {"data":{"__schema":'
                                 '{"queryType":{"name":"Query"},"types":[{"name":"User"}]}}} '
                                 'and was refused by the WAF.</p></body></html>',
}

#: The positive control: a real, populated schema. If THIS stops firing the check is dead and
#: every negative control above is vacuous.
_POPULATED_SCHEMA = json.dumps(
    {"data": {"__schema": {"queryType": {"name": "Query"},
                           "types": [{"name": "User"}, {"name": "Query"}]}}})


def _introspection_ctx(body: str):
    """Run the shipped check against a canned response body and return its context."""
    from framework.v2.scanner.graphql import GraphQLIntrospectionCheck
    from framework.v2.scanner.insertion import HttpRequest, RequestTemplate

    def _send(_req: object) -> dict:
        return {"status": 200, "headers": [("Content-Type", "application/json")], "body": body}

    tmpl = RequestTemplate(HttpRequest(method="POST", url="http://127.0.0.1:1/graphql"))
    return GraphQLIntrospectionCheck().probe(tmpl, _send)


@pytest.mark.parametrize("name", sorted(_NO_SCHEMA_BODIES))
def test_block1_a_body_that_discloses_no_schema_is_never_introspection_enabled(name: str) -> None:
    """BLOCK-1 (CRITICAL). ``GraphQLIntrospectionCheck`` is in ``DEFAULT_REQUEST_CHECKS``
    (``campaign.py``), so it runs on EVERY scan. Three unrelated substring matches over the
    whole body confirmed "introspection enabled" against endpoints that disclosed nothing at
    all — including one whose only body is an explicit "Introspection is disabled" denial.

    The decision is now a full JSON parse plus a POPULATED-``data.__schema`` test. Each body
    below is asserted POSITIVELY: the probe still ran and still retained the target's raw
    bytes (so this is a refusal, not a missing check), the oracle did not fire, and the
    retained certificate does NOT re-verify."""
    from framework.v2.verify.confirmation import confirm_finding

    body = _NO_SCHEMA_BODIES[name]
    ctx = _introspection_ctx(body)
    assert ctx is not None, "the probe must still produce a certificate for the refusal"
    doc = ctx.model_dump(mode="json")
    # the raw target bytes really were retained — the control is not passing because the
    # check silently stopped looking at the response
    assert doc["observed_evidence"]["response_body"] == body
    assert doc["observed_evidence"]["disclosed_schema_name"] == "", doc["observed_evidence"]
    assert confirm_finding({"bug_class": "graphql_introspection"}, ctx) is None
    assert not reverify_context(doc, bug_class="graphql_introspection").ok


def test_block1_a_populated_schema_still_confirms_and_re_verifies() -> None:
    """The positive control the six negatives are only meaningful against."""
    from framework.v2.verify.confirmation import confirm_finding

    ctx = _introspection_ctx(_POPULATED_SCHEMA)
    assert ctx is not None
    doc = ctx.model_dump(mode="json")
    assert doc["observed_evidence"]["disclosed_schema_name"] == "Query"
    confirmed = confirm_finding({"bug_class": "graphql_introspection"}, ctx)
    assert confirmed is not None and confirmed.confidence >= 0.7
    assert reverify_context(doc, bug_class="graphql_introspection").ok
    # and the name the oracle is anchored on really is pinned to the retained bytes
    tampered = json.loads(json.dumps(doc))
    tampered["observed_evidence"]["response_body"] = '{"data":{"__schema":{"types":[]}}}'
    assert not reverify_context(tampered, bug_class="graphql_introspection").ok


class _IntrospectionDisabledApp(BaseHTTPRequestHandler):
    """A LIVE loopback GraphQL endpoint whose ONLY body is the field-auth denial — the exact
    origin the red-pen measured the false FACT against, end to end."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = _NO_SCHEMA_BODIES["field_auth_denial"].encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_block1_end_to_end_against_a_live_introspection_disabled_origin() -> None:
    """The red-pen's own measurement, as a regression test: a real socket, the real gated
    ``loopback_send``, the real check — and no FACT."""
    from framework.v2.scanner.graphql import GraphQLIntrospectionCheck
    from framework.v2.scanner.insertion import HttpRequest, RequestTemplate
    from framework.v2.verify.confirmation import confirm_finding

    with _http_server(_IntrospectionDisabledApp) as base:
        tmpl = RequestTemplate(HttpRequest(method="POST", url=base + "/graphql"))
        ctx = GraphQLIntrospectionCheck().probe(tmpl, loopback_send)

    assert ctx is not None
    assert "Introspection is disabled" in ctx.model_dump(mode="json")["observed_evidence"]["response_body"]
    assert confirm_finding({"bug_class": "graphql_introspection"}, ctx) is None
    assert not reverify_context(ctx.model_dump(mode="json"), bug_class="graphql_introspection").ok


# ===========================================================================================
# BLOCK-4 — the two producer-side guards that killed zero tests
# ===========================================================================================

def test_block4_adjudicable_refuses_a_leg_that_read_no_real_status() -> None:
    """``DesyncProbe.adjudicable`` ships a nine-line docstring calling itself "the
    producer-side belt-and-braces, because the differential must never be computed over
    bytes that are not a response" — and ``return True`` killed ZERO tests.

    The shape it guards is the one the pre-fix reader produced: ``channel=True`` with
    ``status=None``, from surplus bytes (a benign echo of VIGIL's FIRST request, canary and
    all) that were never a response. The shared reader now refuses that shape at the
    transport, so this guard can only be pinned at the model — which is precisely what
    "belt-and-braces" means, and precisely why it needs its own control."""
    from framework.v2.scanner.smuggling import DesyncLeg, DesyncProbe

    canary = "crsmug" + "00112233445566778899aa"
    echoed = f"rejected: GET /vigil-reflect?c={canary}"

    # POSITIVE control — two real responses, canary only on the conflict leg
    good = DesyncProbe(technique="CL.TE", canary=canary,
                       conflict=DesyncLeg(channel=True, status=200, body=echoed),
                       control=DesyncLeg(channel=True, status=200, body="ok"))
    assert good.adjudicable is True
    assert good.canary_echo_differential is True

    # NEGATIVE control — the conflict leg's "response" has no status line at all
    statusless = DesyncProbe(technique="CL.TE", canary=canary,
                             conflict=DesyncLeg(channel=True, status=None, body=echoed),
                             control=DesyncLeg(channel=True, status=200, body="ok"))
    assert statusless.adjudicable is False, (
        "a blob with no status line is not a response — the differential must not be "
        "computed over it")
    assert statusless.canary_echo_differential is False

    # and the same on the CONTROL leg, so the guard is not one-sided
    control_statusless = DesyncProbe(technique="TE.CL", canary=canary,
                                     conflict=DesyncLeg(channel=True, status=200, body=echoed),
                                     control=DesyncLeg(channel=True, status=None, body="ok"))
    assert control_statusless.adjudicable is False
    assert control_statusless.canary_echo_differential is False


class _ReasonPhraseDecoyWSServer(threading.Thread):
    """B3's REACHABLE decoy: the endpoint REFUSES the foreign Origin, but says so in a
    verbose reason phrase that itself contains ``HTTP/1.1 101 Switching Protocols`` — and it
    echoes back the very ``Sec-WebSocket-Accept`` value VIGIL computed for this handshake.

    ``_status_of`` reads the status line's own token and gets 403, so the producer refuses.
    The PREDICATE, however, only asks whether "http/1.1 101" appears INSIDE the status line —
    and here it does. So this is the shape where the producer-side refusal is the only thing
    standing between a 403 and a conf-0.9 CSWSH finding."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self) -> None:
        self.sock.settimeout(0.3)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        import base64
        import hashlib
        conn.settimeout(2.0)
        data = b""
        with contextlib.suppress(OSError, socket.timeout):
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        key = ""
        for line in data.split(b"\r\n")[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                if k.decode().strip().lower() == "sec-websocket-key":
                    key = v.decode().strip()
        accept = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
        with contextlib.suppress(OSError):
            conn.sendall(
                b"HTTP/1.1 403 Forbidden - expected HTTP/1.1 101 Switching Protocols\r\n"
                b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
                b"Content-Length: 0\r\n\r\n")
        with contextlib.suppress(OSError):
            conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


def test_block4_cswsh_producer_refusal_is_load_bearing() -> None:
    """B3's producer-side refusal (``if not (legit_hs.accepted and evil_hs.accepted)``) is a
    named deliverable and killed ZERO tests. Against ``_Echo403WSServer`` it is genuinely
    redundant with the status-line clause; this origin is the case where it is NOT.

    Everything the predicate checks holds here — the status line CONTAINS "http/1.1 101", the
    status line is contained in the retained block, and the retained block carries VIGIL's own
    accept key — yet the endpoint answered 403 and refused the handshake. Only the producer's
    ``_status_of``-anchored verdict separates the two."""
    # Drives a REAL CSWSH/race socket through the WS1.1b floor (websocket.handshake / race.raw_race),
    # which imports vigil_gateway.denylist and fail-closes without it. SKIP in the gateway-less CRUCIBLE-core
    # job, RUN in the offense leg that ships gateway — as verify/tests/test_egress_pin.py does.
    pytest.importorskip("vigil_gateway")
    from framework.v2.scanner.websocket import CswshCheck, handshake
    from framework.v2.verify.oracles import predicate_oracle

    srv = _ReasonPhraseDecoyWSServer()
    srv.start()
    try:
        ws_url = f"ws://127.0.0.1:{srv.port}/live"
        _conn, hs = handshake(ws_url, origin="https://crucible-evil-origin.test")
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
        findings = camp._cswsh_findings([ws_url])
        confirmed, ctx = CswshCheck(url=ws_url).probe_with_context()
    finally:
        srv.stop()

    # the decoy really is a REFUSAL that the predicate's clauses cannot tell from an accept
    assert hs.status == 403 and hs.accepted is False, (hs.status, hs.accepted)
    assert "http/1.1 101" in hs.status_line.lower(), hs.status_line
    assert hs.status_line in hs.response and hs.accept_key and hs.accept_key in hs.response
    # ... so the predicate ALONE, over those very bytes, WOULD have fired
    would_fire = predicate_oracle(
        {"trusted_request": "Origin: http://127.0.0.1", "trusted_origin_header": "Origin: http://127.0.0.1",
         "trusted_response": hs.response, "trusted_status_line": hs.status_line,
         "trusted_accept_key": hs.accept_key,
         "evil_request": "Origin: https://crucible-evil-origin.test",
         "evil_origin_header": "Origin: https://crucible-evil-origin.test",
         "evil_response": hs.response, "evil_status_line": hs.status_line,
         "evil_accept_key": hs.accept_key},
        {"all": [
            {"icontains": [{"var": "trusted_request"}, {"var": "trusted_origin_header"}]},
            {"icontains": [{"var": "trusted_status_line"}, "http/1.1 101"]},
            {"contains": [{"var": "trusted_response"}, {"var": "trusted_status_line"}]},
            {"contains": [{"var": "trusted_response"}, {"var": "trusted_accept_key"}]},
            {"icontains": [{"var": "evil_request"}, {"var": "evil_origin_header"}]},
            {"icontains": [{"var": "evil_status_line"}, "http/1.1 101"]},
            {"contains": [{"var": "evil_response"}, {"var": "evil_status_line"}]},
            {"contains": [{"var": "evil_response"}, {"var": "evil_accept_key"}]},
        ]})
    assert would_fire.fired is True, (
        "this control has gone vacuous: the predicate no longer accepts the decoy, so the "
        "producer refusal it exists to pin is redundant again")
    # ... and the PRODUCER refuses anyway, so nothing is reported and nothing re-verifies
    assert findings == [], findings
    assert confirmed is None
    assert not reverify_context(ctx.model_dump(mode="json"),
                                bug_class="cross_site_websocket_hijacking").ok


# ===========================================================================================
# BLOCK-5 — a demotion must not be a disappearance on ANY render path
# ===========================================================================================

def _demoted_report() -> ScanReport:
    """A report in exactly the shape a real ``_StockEchoOrigin`` scan produces: the class was
    PROBED (two probe records, verdict inconclusive), nothing was confirmed, and the finding
    lives only in the LEAD channel."""
    lead = (
        "smuggling CL.TE @ http://127.0.0.1:9/: the unique per-probe canary was echoed in "
        "VIGIL's OWN second response on the CONFLICT connection and is ABSENT from the "
        "identical well-formed control — an UNCONFIRMED LEAD, NOT a CWE-444 fact. Proving "
        "CWE-444 needs the corruption observed on a connection VIGIL did NOT pipeline the "
        "prefix onto, which requires explicit operator authorisation (blocking_work on "
        "request_smuggling.differential_desync)")
    probes = [
        ProbeRecord(endpoint="http://127.0.0.1:9/", method="POST",
                    insertion_point=f"request:{t}", param=t,
                    check_id=f"smuggling-{t}", bug_class="request_smuggling",
                    verdict="inconclusive")
        for t in ("CL.TE", "TE.CL")
    ]
    return ScanReport(target="http://127.0.0.1:9/", arsenal_leads=[lead],
                      exercised_probes=probes)


def test_block5_a_demoted_lead_reaches_sarif_html_and_the_coverage_verdict() -> None:
    """B4 wired the LEAD channel into ONE render path. Measured against ``_StockEchoOrigin``,
    ``to_sarif`` produced 0 results, ``to_html`` never mentioned the class, and
    ``coverage_verdict`` listed it in neither half — so an operator who renders HTML or SARIF
    saw NOTHING: not the lead, not the blocking work, not even that the class was probed.
    A false FACT converted into a silent gap is not a fix."""
    from framework.v2.scanner.report import coverage_line, to_html, to_sarif

    report = _demoted_report()
    lead = report.arsenal_leads[0]

    # 1. the machine JSON (already wired by B4) still carries it
    doc = build_report(report)
    assert doc["arsenal_leads"] == [lead]

    # 2. the coverage verdict now NAMES the probed-but-lead-only class
    cvd = doc["coverage_verdict"]
    assert cvd["classes_probed_outside_corpus"] == ["request_smuggling"], cvd
    assert "request_smuggling" not in cvd["classes_exercised"]
    assert "request_smuggling" not in cvd["classes_inconclusive"]
    assert "request_smuggling" in coverage_line(report)

    # 3. SARIF — a result exists, it is a NOTE (never a finding level), and it carries the
    #    producer's verbatim text including the blocking work
    sarif = json.loads(to_sarif(report))
    results = sarif["runs"][0]["results"]
    lead_results = [r for r in results if r["ruleId"] == "arsenal-lead"]
    assert len(lead_results) == 1, results
    r = lead_results[0]
    assert r["level"] == "note", r
    assert r["message"]["text"] == f"UNCONFIRMED LEAD (not a finding): {lead}"
    assert "blocking_work on request_smuggling.differential_desync" in r["message"]["text"]
    assert r["properties"]["kind"] == "lead" and r["properties"]["reVerifiable"] is False
    assert [x["level"] for x in results] == ["note"], "a lead must never be warning/error"
    assert any(rule["id"] == "arsenal-lead" for rule in sarif["runs"][0]["tool"]["driver"]["rules"])

    # 4. HTML — the human document says the class was probed, shows the lead, and frames it
    html_doc = to_html(report)
    assert "Unconfirmed leads (probed, NOT findings)" in html_doc
    assert "request_smuggling" in html_doc
    assert "blocking_work on request_smuggling.differential_desync" in html_doc
    assert "UNCONFIRMED LEAD" in html_doc
    assert "PROBED outside the point-check corpus, LEAD-only" in html_doc
    # ... and it is NOT counted as a finding anywhere
    assert "<h2>Findings</h2><p>No findings.</p>" in html_doc
    assert doc["summary"]["by_severity"] == {}


def test_block5_a_lead_free_report_renders_exactly_as_before() -> None:
    """The negative control for the above: with no leads, no lead section, no lead result,
    no extra coverage key — the byte-identity the BLOCK-6 measurement depends on."""
    from framework.v2.scanner.report import to_html, to_sarif

    report = ScanReport(target="http://127.0.0.1:9/")
    doc = build_report(report)
    assert doc["arsenal_leads"] == []
    assert "classes_probed_outside_corpus" not in doc["coverage_verdict"]
    assert json.loads(to_sarif(report))["runs"][0]["results"] == []
    assert "Unconfirmed leads" not in to_html(report)


def test_block6_a_producer_claim_that_was_never_made_is_not_serialized() -> None:
    """BLOCK-6. ``AuditFinding.title``/``severity`` (added by B4) made every finding row in
    ``--reverifiable-out`` gain ``"title": "", "severity": ""`` — a MOVED re-verification
    input, measured sha256 3b0c2d1e… -> bcc93b41…. The same precedent as ``cli.py:203-207``
    applies: a field the producer never set is not serialized at all. A producer that DID
    hedge still carries its hedge."""
    plain = AuditFinding(check_id="boolean-sqli", bug_class="boolean_sqli",
                         insertion_point="query:id", param="id", confidence=0.95,
                         confirmed_by="BOOLEAN_INFERENCE")
    hedged = AuditFinding(check_id="cswsh", bug_class="cross_site_websocket_hijacking",
                          insertion_point="request:ws", param="ws", confidence=0.9,
                          confirmed_by="ACHIEVED_STATE",
                          title="Cross-origin WS handshake accepted — UNCONFIRMED",
                          severity="Medium")
    assert "title" not in json.loads(plain.model_dump_json())
    assert "severity" not in json.loads(plain.model_dump_json())
    assert json.loads(hedged.model_dump_json())["title"].endswith("UNCONFIRMED")
    assert json.loads(hedged.model_dump_json())["severity"] == "Medium"
    # round-trips: an absent claim loads back as the empty default
    assert AuditFinding.model_validate(json.loads(plain.model_dump_json())).title == ""
    # and the whole-report dump the CLI writes is free of the empty keys
    dumped = ScanReport(target="http://x/", active_findings=[plain]).model_dump_json(
        indent=2, exclude={"exercised_probes": {"__all__": {"evidence"}}})
    assert '"title"' not in dumped and '"severity"' not in dumped


def test_block5_the_spine_mirror_does_not_relabel_a_hedged_lead_confirmed() -> None:
    """The third surface B4 missed: ``engage._spine_finding_payload`` hardcoded
    ``"title": f"{bug_class} confirmed at {param}"`` and ``"severity": "High"``, so the
    CSWSH no-cookies branch's explicit "… UNCONFIRMED" Medium was written onto the
    IMMUTABLE event spine as a confirmed High — the same relabelling B4 retired in
    ``build_report``, on the one stream that cannot be re-rendered."""
    from framework.v2.engage import _spine_finding_payload

    hedged = AuditFinding(
        check_id="cswsh", bug_class="cross_site_websocket_hijacking",
        insertion_point="request:ws", param="ws://127.0.0.1/live", confidence=0.9,
        confirmed_by="ACHIEVED_STATE",
        title="Cross-origin WebSocket handshake accepted — possible CSWSH — UNCONFIRMED",
        severity="Medium")
    out = _spine_finding_payload(hedged, None)
    assert "UNCONFIRMED" in out["title"], out["title"]
    assert "confirmed at" not in out["title"], out["title"]
    assert out["severity"] == "Medium", out
    assert out["verified_by_oracle"] is False and out["critique_status"] == "llm_advisory"

    # the built-in point checks set neither field, so their mirror is unchanged
    plain = AuditFinding(check_id="boolean-sqli", bug_class="boolean_sqli",
                         insertion_point="query:id", param="id", confidence=0.95,
                         confirmed_by="BOOLEAN_INFERENCE")
    assert _spine_finding_payload(plain, None)["title"] == "boolean_sqli confirmed at id"
    assert _spine_finding_payload(plain, None)["severity"] == "High"


if __name__ == "__main__":       # pragma: no cover - manual measurement helper
    sys.exit("run under pytest")
