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
            conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept.encode() + b"\r\n\r\n")
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
    into the block the predicate searches. What is RETAINED must be the headers only."""
    with _ws_server() as port:
        from framework.v2.scanner.websocket import handshake
        _conn, hs = handshake(f"ws://127.0.0.1:{port}/live", origin="http://x.test")
    assert hs.response.endswith("\r\n\r\n"), repr(hs.response[-16:])
    assert hs.response.count("\r\n\r\n") == 1
    assert hs.status_line == "HTTP/1.1 101 Switching Protocols"


def test_b4_an_unconfirmed_lead_is_never_rendered_as_confirmed() -> None:
    """B4 — the campaign supplies NO victim cookies, so ``CswshCheck`` takes its explicitly
    UNCONFIRMED Medium branch ("… possible CSWSH — UNCONFIRMED", "an authenticated hijack is
    NOT proven"). ``_arsenal_finding`` used to DISCARD that title and severity and
    ``build_report`` re-labelled the entry ``"cross_site_websocket_hijacking confirmed at
    ws://…"`` at the class's table severity — so the hedge was cosmetic and this slice's own
    F3/R3 demotions would have rendered the same way."""
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
    with _http_server(_AlwaysOkApp) as base:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True,
                               arsenal_race_targets=(("/buy", 1),))
        leads = camp._race_leads(base + "/")

    assert not hasattr(camp, "_race_findings"), "the FACT-minting race path must be gone"
    assert any("UNCONFIRMED LEAD" in ln for ln in leads), leads
    assert all(isinstance(ln, str) for ln in leads)


if __name__ == "__main__":       # pragma: no cover - manual measurement helper
    sys.exit("run under pytest")
