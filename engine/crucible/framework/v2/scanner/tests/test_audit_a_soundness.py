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
# F3 — request_smuggling is minted from the canary differential, never latency
# ===========================================================================


class _Rfc7230Origin(threading.Thread):
    """A SINGLE ORIGIN — no front-end, no proxy, no CDN, so NO desync is even possible —
    that honours RFC 7230 §3.3.3 rule 3: when Transfer-Encoding is present, Content-Length
    is IGNORED and the body is read as chunked to the terminating zero-chunk. That is what
    nginx, Go net/http, Node and Tomcat all do. One socket, one parser, nothing for two
    parsers to disagree about — yet it HANGS on the CL+TE probes, which is exactly why
    timing is a LEAD and not a proof."""

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
    def _serve(conn: socket.socket) -> None:
        page = b"<html><body><h1>Hello world</h1></body></html>"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Content-Length: " + str(len(page)).encode() + b"\r\n\r\n" + page)
        try:
            conn.settimeout(8.0)
            f = conn.makefile("rb")
            if not f.readline():
                return
            headers: dict[bytes, bytes] = {}
            while True:
                ln = f.readline()
                if not ln or ln in (b"\r\n", b"\n"):
                    break
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    headers[k.strip().lower()] = v.strip()
            if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                while True:                       # TE wins, CL ignored
                    sz = f.readline()
                    if not sz:
                        return                    # peer went away mid-body
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
            conn.sendall(resp)
        except Exception:      # noqa: BLE001 — a fixture, not a product path
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def stop(self) -> None:
        self._stop = True
        with contextlib.suppress(OSError):
            self.sock.close()


@contextlib.contextmanager
def _rfc7230_origin() -> Iterator[int]:
    srv = _Rfc7230Origin()
    srv.start()
    try:
        yield srv.port
    finally:
        srv.stop()


def test_f3_rfc7230_compliant_origin_mints_no_smuggling_fact() -> None:
    """The measured false positive: a conformant single-socket origin with no proxy at all.
    It HANGS on the CL+TE probes (it is waiting for a chunk that never comes), so the old
    latency mint produced High ``request_smuggling`` FACTs at conf 0.700 against a target
    where a desync is not even possible. A LEAD is fine; a FACT is not."""
    with _rfc7230_origin() as port:
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)   # loopback -> allowed
        findings, leads = camp._smuggling_findings(
            [("127.0.0.1", port, f"http://127.0.0.1:{port}/")])

    assert [f for f in findings if f.bug_class == "request_smuggling"] == [], (
        "a conformant RFC 7230 origin with no proxy minted a request_smuggling FACT")
    assert findings == []
    # the honest timing signal is preserved, as a LEAD that says so
    assert any("UNCONFIRMED timing LEAD" in ln or "not adjudicable" in ln for ln in leads), leads


def _port_of(url: str) -> int:
    return urlsplit(url).port or 80


def test_f3_genuine_canary_echo_desync_still_confirms() -> None:
    """The positive control: a back-end that REALLY desyncs (it honours chunked on a CL.TE
    conflict, leaving the smuggled prefix on the socket) must still mint a High FACT — and
    the certificate must carry the raw second-request bodies, re-verify offline, and FAIL
    when a retained byte is altered."""
    with serve_smuggling_desync() as origin:
        port = _port_of(origin)
        camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
        findings, _leads = camp._smuggling_findings([("127.0.0.1", port, f"http://127.0.0.1:{port}/")])

    assert findings, "a genuinely desyncing back-end must still confirm"
    f = findings[0]
    assert f.bug_class == "request_smuggling"
    assert f.confidence >= 0.9      # the canary oracle's confidence, not the 0.700 latency boundary

    ctx = f.oracle_context
    assert ctx is not None
    rec = ctx["smuggling_desync"]
    # RAW target bytes, not a placeholder and not a latency
    assert rec["canary"] and rec["canary"] in rec["conflict"]["body"]
    assert rec["canary"] not in rec["control"]["body"]
    assert "latency" not in json.dumps(ctx)

    assert reverify_context(ctx, bug_class="request_smuggling").ok

    tampered = json.loads(json.dumps(ctx))
    tampered["smuggling_desync"]["conflict"]["body"] = "reflected c=not-the-canary"
    assert not reverify_context(tampered, bug_class="request_smuggling").ok, (
        "an altered conflict-leg body must break the re-verification")


def test_f3_safe_twins_do_not_fire() -> None:
    """Negative controls from the shipped corpus: a back-end that REJECTS the ambiguous
    framing, and the red-pen twin whose 400 page ECHOES the offending request (canary and
    all) while answering the well-formed control cleanly. Neither may mint."""
    for serve in (serve_smuggling_benign, serve_smuggling_reflect_error):
        with serve() as origin:
            port = _port_of(origin)
            camp = WebScanCampaign(_dummy_send, enable_arsenal=True)
            findings, _leads = camp._smuggling_findings(
                [("127.0.0.1", port, f"http://127.0.0.1:{port}/")])
        assert findings == [], f"{serve.__name__} produced a smuggling finding"


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
