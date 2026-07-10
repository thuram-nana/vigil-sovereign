"""
Wave-4b — closing the verifier<->library coverage gap.

The deterministic verifier (``verify.verifier.BUG_CLASS_ORACLES``) routes ~40 bug
classes, but the data-driven check library only PROBED for ~16 of them: the engine
could PROVE classes it never PROBED. These ``w4b-*`` library entries add
data-driven coverage for routed-but-uncovered classes, each via an oracle whose
kind the entry's check shape produces:

  * time_based / time_based_command_injection  -> TIMING (and OOB for cmdi)
  * ldap_injection / xpath_injection            -> ERROR_SIGNATURE (quote-free breakers)
  * el_injection                                -> EVALUATION
  * security_misconfiguration / sensitive_exposure -> ACHIEVED_STATE (known-path signature)
  * xxe (in-band file read)                     -> SIDE_EFFECT

Prove-don't-guess: every test drives a REAL synthetic target to a CONFIRMED
finding through the same ``OracleVerifier`` the engine uses — and drives a benign
(or merely reflecting) twin to NO confirmation, so none of these checks can
false-positive. The gate stays byte-identical because none of these fire on the
benchmark corpus (timing is filtered out of the benchmark; OOB has no receiver;
the signature paths 404; the error/eval/content payloads never match a benchmark
response).
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.checks import (
    ContentSignatureCheck,
    ErrorSignatureCheck,
    EvaluationCheck,
    OOBCheck,
    PathProbeCheck,
    TimingCheck,
)
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import compile_entry, load_library
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oob import OOBReceiver
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    normalize_bug_class,
)

W4B_PREFIX = "w4b-"

# The library oracle kind -> the OracleKind context that kind's compiled check
# produces (the oracle that must be in the bug_class's routed set for the entry
# to confirm end to end).
_KIND_PRODUCES = {
    "differential": OracleKind.DIFFERENTIAL_RESPONSE,
    "reflection": OracleKind.SIDE_EFFECT,
    "oob": OracleKind.OOB_CALLBACK,
    "timing": OracleKind.TIMING,
    "evaluation": OracleKind.EVALUATION,
    "error_signature": OracleKind.ERROR_SIGNATURE,
    "signature": OracleKind.ACHIEVED_STATE,
    "content": OracleKind.SIDE_EFFECT,
}


# ---------------------------------------------------------------------------
# fixtures: load the w4b subset from the shipped library dir
# ---------------------------------------------------------------------------


def _all() -> list:
    return load_library()


def _w4b() -> list:
    return [e for e in _all() if e.id.startswith(W4B_PREFIX)]


def _by_id(entry_id: str):
    return next(e for e in _w4b() if e.id == entry_id)


# ---------------------------------------------------------------------------
# load + shape: the subset validates, is rich, unique, and routes correctly
# ---------------------------------------------------------------------------


def test_w4b_entries_load_unique_and_prefixed() -> None:
    w4b = _w4b()
    assert len(w4b) == 8, f"expected 8 w4b entries, got {len(w4b)}"
    ids = [e.id for e in w4b]
    assert all(i.startswith(W4B_PREFIX) for i in ids)
    assert len(ids) == len(set(ids)), "duplicate w4b ids"
    # globally unique against the rest of the shipped library, too
    all_ids = [e.id for e in _all()]
    assert len(all_ids) == len(set(all_ids)), "w4b ids collide with existing entries"


def test_w4b_entries_are_rich() -> None:
    for e in _w4b():
        assert e.title
        assert e.severity in {"Critical", "High", "Medium", "Low", "Info"}
        assert any(r.startswith("CWE-") for r in e.references), f"{e.id} lacks a CWE id"
        assert e.remediation, f"{e.id} carries no remediation text"


def test_w4b_covers_the_intended_uncovered_classes() -> None:
    # the exact routed-but-previously-uncovered canonical classes this wave closes
    got = {normalize_bug_class(e.bug_class) for e in _w4b()}
    assert got == {
        "time_based",
        "time_based_command_injection",
        "ldap_injection",
        "xpath_injection",
        "el_injection",
        "sensitive_exposure",
        "xxe",
    }


def test_every_w4b_entry_routes_to_a_compatible_oracle() -> None:
    # prove-don't-guess wiring: each entry's bug_class routes to an oracle set that
    # INCLUDES the oracle its compiled check produces — otherwise the check could
    # never be confirmed (or, worse, be treated as proof without an oracle).
    for e in _w4b():
        norm = normalize_bug_class(e.bug_class)
        routed = BUG_CLASS_ORACLES.get(norm)
        assert routed is not None, f"{e.id}: {norm!r} is not routed by the verifier"
        produced = _KIND_PRODUCES[e.oracle.kind]
        assert produced in routed, (
            f"{e.id}: kind {e.oracle.kind!r} produces {produced.value} but "
            f"{norm!r} only routes to {[k.value for k in routed]}"
        )


def test_no_w4b_entry_uses_the_reflection_oracle() -> None:
    # regression guard aligned with the library's precision fix: a reflected canary
    # proves only echo (an XSS signal), never SSTI/traversal/injection. No w4b entry
    # may reintroduce a reflection-oracle check for a non-XSS class.
    offenders = [e.id for e in _w4b() if e.oracle.kind == "reflection"]
    assert offenders == []


# ---------------------------------------------------------------------------
# shared HTTP harness
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
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


def _q_point(base: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/probe?q=seed"))
    point = next(
        p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"
    )
    return tpl, point


def _confirm_point(check, tpl, point):
    ctx = check.probe(tpl, point, loopback_send)
    return confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )


# ---------------------------------------------------------------------------
# error-signature: LDAP + XPath injection (quote-free breakers)
# ---------------------------------------------------------------------------


class _InjErrorApp(BaseHTTPRequestHandler):
    """Vulnerable: a malformed directory/parser query surfaces a distinctive
    backend error. XPath metachars ('[', ']') provoke an XPathException; an
    unbalanced LDAP filter ('(', ')') provokes an LDAPException. A benign term
    hits neither branch and returns an ordinary page (the control)."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("q", [""])[0]
        if "[" in q or "]" in q:
            body = b"net.sf.saxon.trans.XPathException: Unexpected token ']' in path expression"
        elif ")(" in q or "(|" in q:
            body = b"javax.naming.directory.InvalidSearchFilterException: invalid filter"
        else:
            body = b"<html><body>results for your query</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _NoErrorApp(BaseHTTPRequestHandler):
    """The safe twin: every input yields the same ordinary page — no backend error
    ever surfaces, so the error-signature oracle has nothing attributable to fire on."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"<html><body>results for your query</body></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize(
    "entry_id,engine_expected",
    [("w4b-ldapi-filter-paren", "ldap"), ("w4b-xpathi-numeric-break", "xpath")],
)
def test_error_signature_entries_confirm_on_backend_error(entry_id, engine_expected) -> None:
    check = compile_entry(_by_id(entry_id))
    assert isinstance(check, ErrorSignatureCheck)
    with _server(_InjErrorApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm_point(check, tpl, point)
    assert confirmed is not None, f"{entry_id} did not confirm on a real backend error"
    assert confirmed.confirmed_by == OracleKind.ERROR_SIGNATURE
    assert confirmed.confidence >= 0.7 and confirmed.signals


@pytest.mark.parametrize("entry_id", ["w4b-ldapi-filter-paren", "w4b-xpathi-numeric-break"])
def test_error_signature_entries_do_not_fire_without_an_error(entry_id) -> None:
    check = compile_entry(_by_id(entry_id))
    with _server(_NoErrorApp) as base:
        tpl, point = _q_point(base)
        assert _confirm_point(check, tpl, point) is None


# ---------------------------------------------------------------------------
# evaluation: expression-language injection
# ---------------------------------------------------------------------------


class _ElEvalApp(BaseHTTPRequestHandler):
    """Vulnerable: the server EVALUATES an injected EL arithmetic and renders only
    the product (the raw '#{...}' does not survive) — the evaluation signature."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("q", [""])[0]
        m = re.fullmatch(r"#\{(\d+)\*(\d+)\}", q)
        if m:
            body = f"<p>{int(m.group(1)) * int(m.group(2))}</p>".encode()
        else:
            body = b"<p>welcome</p>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ElReflectApp(BaseHTTPRequestHandler):
    """The safe twin (precision guard): the value is REFLECTED verbatim, never
    evaluated — so the raw '#{...}' survives and the evaluation oracle refuses it.
    A reflecting endpoint is XSS-shaped, not EL injection."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("q", [""])[0]
        body = f"<p>you searched for: {q}</p>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_el_injection_confirms_only_when_server_evaluates() -> None:
    check = compile_entry(_by_id("w4b-el-injection-spel"))
    assert isinstance(check, EvaluationCheck)
    with _server(_ElEvalApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm_point(check, tpl, point)
    assert confirmed is not None, "EL injection was not confirmed on an evaluating server"
    assert confirmed.confirmed_by == OracleKind.EVALUATION


def test_el_injection_does_not_fire_on_a_reflecting_endpoint() -> None:
    check = compile_entry(_by_id("w4b-el-injection-spel"))
    with _server(_ElReflectApp) as base:
        tpl, point = _q_point(base)
        assert _confirm_point(check, tpl, point) is None, "reflection must not read as EL injection"


# ---------------------------------------------------------------------------
# content: in-band XXE file read
# ---------------------------------------------------------------------------


class _XxeVulnApp(BaseHTTPRequestHandler):
    """Vulnerable: resolves an external entity and returns the target file's
    content — the distinctive '/etc/passwd' signature proves the READ."""

    def log_message(self, *a: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace")
        if "SYSTEM" in body and "file:" in body:
            out = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        else:
            out = b"<ok/>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class _XxeSafeApp(BaseHTTPRequestHandler):
    """The safe twin: DTDs/entities are disabled — the request body is echoed but
    the entity is never resolved, so no file content ever appears."""

    def log_message(self, *a: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)  # echoed inertly; entity NOT resolved
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _body_point(base: str):
    req = HttpRequest(
        method="POST", url=f"{base}/xml", body="<r>seed</r>",
        headers=[("Content-Type", "application/xml")],
    )
    tpl = RequestTemplate(req)
    point = next(p for p in tpl.insertion_points(kinds=(InsertionKind.BODY_WHOLE,)))
    return tpl, point


def test_xxe_content_entry_confirms_on_file_read() -> None:
    check = compile_entry(_by_id("w4b-xxe-inband-passwd"))
    assert isinstance(check, ContentSignatureCheck)
    with _server(_XxeVulnApp) as base:
        tpl, point = _body_point(base)
        confirmed = _confirm_point(check, tpl, point)
    assert confirmed is not None, "in-band XXE file read was not confirmed"
    assert confirmed.confirmed_by == OracleKind.SIDE_EFFECT


def test_xxe_content_entry_does_not_fire_when_entities_disabled() -> None:
    check = compile_entry(_by_id("w4b-xxe-inband-passwd"))
    with _server(_XxeSafeApp) as base:
        tpl, point = _body_point(base)
        assert _confirm_point(check, tpl, point) is None


# ---------------------------------------------------------------------------
# signature (request-level): security misconfiguration + sensitive exposure
# ---------------------------------------------------------------------------


class _ExposedApp(BaseHTTPRequestHandler):
    """Vulnerable: serves the sensitive paths with their distinctive signatures."""

    _PATHS = {
        "/server-status": (
            "<html><head><title>Apache Status</title></head><body>"
            "<h1>Apache Server Status for localhost</h1></body></html>"
        ),
        "/.aws/credentials": (
            "[default]\naws_access_key_id=AKIAEXAMPLE\n"
            "aws_secret_access_key=wJalrXUtnFEMIexampleKEY\n"
        ),
    }

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import urlsplit

        path = urlsplit(self.path).path
        if path in self._PATHS:
            body = self._PATHS[path].encode()
            status = 200
        else:
            body = b"not found"
            status = 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _HardenedApp(BaseHTTPRequestHandler):
    """The safe twin: the sensitive endpoints are absent (404) OR access-denied
    (200 without the signature) — either way the predicate oracle does not fire."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import urlsplit

        path = urlsplit(self.path).path
        if path == "/server-status":
            body, status = b"<h1>403 Forbidden</h1>", 200  # 200 but NO signature
        else:
            body, status = b"not found", 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _confirm_request(check, base):
    tpl = RequestTemplate(HttpRequest(method="GET", url=base + "/"))
    ctx = check.probe(tpl, loopback_send)
    if ctx is None:
        return None
    return confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )


@pytest.mark.parametrize(
    "entry_id", ["w4b-sensitive-aws-credentials"]
)
def test_signature_entries_confirm_on_real_exposure(entry_id) -> None:
    check = compile_entry(_by_id(entry_id))
    assert isinstance(check, PathProbeCheck)
    with _server(_ExposedApp) as base:
        confirmed = _confirm_request(check, base)
    assert confirmed is not None, f"{entry_id} did not confirm on a real exposure"
    assert confirmed.confirmed_by == OracleKind.ACHIEVED_STATE


@pytest.mark.parametrize(
    "entry_id", ["w4b-sensitive-aws-credentials"]
)
def test_signature_entries_do_not_fire_when_hardened(entry_id) -> None:
    check = compile_entry(_by_id(entry_id))
    with _server(_HardenedApp) as base:
        assert _confirm_request(check, base) is None


# ---------------------------------------------------------------------------
# timing: time-based blind (generic) + time-based command injection
# ---------------------------------------------------------------------------


class _SleepApp(BaseHTTPRequestHandler):
    """Vulnerable: an injected delay clause ('sleep'/'SLEEP(') actually delays the
    response; a benign value returns immediately — a real, dose-shaped latency shift."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True).get("q", [""])[0]
        low = q.lower()
        if "sleep(" in low or "sleep " in low or "; sleep" in low:
            time.sleep(0.25)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _NoSleepApp(BaseHTTPRequestHandler):
    """The safe twin: input never induces a delay, so no timing signal exists."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.parametrize(
    "entry_id", ["w4b-timeblind-generic", "w4b-time-cmdi-sleep"]
)
def test_timing_entries_ship_a_real_delay_probe(entry_id) -> None:
    # the shipped entry probes with a genuine 5s delay (injected_ms=5000) so the
    # timing oracle has a large, unambiguous effect-size floor on a real target.
    check = compile_entry(_by_id(entry_id))
    assert isinstance(check, TimingCheck)
    assert check.injected_ms == 5000.0
    assert check.bug_class == normalize_bug_class(_by_id(entry_id).bug_class)


@pytest.mark.parametrize(
    "entry_id", ["w4b-timeblind-generic", "w4b-time-cmdi-sleep"]
)
def test_timing_entries_confirm_on_a_delaying_endpoint(entry_id) -> None:
    # Drive the SAME TimingCheck->timing_oracle path the shipped entry uses, but
    # with a scaled-down delay/samples so the test stays fast: a statistically
    # significant, effect-floor-clearing latency shift confirms; a flat endpoint
    # does not.
    entry = _by_id(entry_id)
    fast = TimingCheck(
        id=entry.id, bug_class=entry.bug_class,
        benign=entry.oracle.benign, sleep_payload=entry.oracle.sleep_payload,
        injected_ms=200.0, samples=8,
    )
    with _server(_SleepApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm_point(fast, tpl, point)
    assert confirmed is not None, f"{entry_id} did not confirm a real latency shift"
    assert confirmed.confirmed_by == OracleKind.TIMING

    with _server(_NoSleepApp) as base:
        tpl, point = _q_point(base)
        assert _confirm_point(fast, tpl, point) is None, "a flat endpoint must not confirm"


# ---------------------------------------------------------------------------
# oob: time-based command injection confirmed by an out-of-band callback
# ---------------------------------------------------------------------------


_LOOPBACK_CB = re.compile(r"http://127\.0\.0\.1:\d+/[0-9a-fA-F]{16,}")


class _CmdiOobTarget(BaseHTTPRequestHandler):
    """Vulnerable: the injected '; curl <callback> ;' executes and fetches the
    loopback callback server-side — the blind command's out-of-band interaction."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        raw = urllib.parse.unquote(self.path)
        m = _LOOPBACK_CB.search(raw)
        if m:
            with contextlib.suppress(Exception):
                urllib.request.urlopen(m.group(0), timeout=2).read()
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CmdiSafeTarget(BaseHTTPRequestHandler):
    """The safe twin: the command never executes, so nothing hits the receiver."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _send(req: HttpRequest) -> dict:
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def test_time_cmdi_oob_entry_confirmed_by_callback() -> None:
    check = compile_entry(_by_id("w4b-time-cmdi-oob-curl"))
    assert isinstance(check, OOBCheck)
    assert getattr(check, "wants_oob", False) is True
    with _server(_CmdiOobTarget) as base, OOBReceiver() as oob:
        tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/run?cmd=x"))
        point = next(
            p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "cmd"
        )
        ctx = check.probe(tpl, point, _send, oob)
    confirmed = confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )
    assert confirmed is not None, "blind cmdi was not confirmed by an out-of-band callback"
    assert confirmed.confirmed_by == OracleKind.OOB_CALLBACK


def test_time_cmdi_oob_entry_no_callback_no_confirmation() -> None:
    check = OOBCheck(
        id="w4b-time-cmdi-oob-curl", bug_class="time_based_command_injection",
        payload_template=_by_id("w4b-time-cmdi-oob-curl").oracle.payload_template,
        poll_deadline=0.3,
    )
    with _server(_CmdiSafeTarget) as base, OOBReceiver() as oob:
        tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/run?cmd=x"))
        point = next(
            p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "cmd"
        )
        ctx = check.probe(tpl, point, _send, oob)
    assert confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    ) is None
