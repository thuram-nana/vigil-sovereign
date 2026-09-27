"""
ATTRIBUTION is what separates a FACT from a coincidence — regressions for two measured
default-path false-FACT defects (audit C), both at rate 1.0 against targets with no bug at all.

F1 — ``boolean_sqli`` on a target with NO DATABASE.
    ``DifferentialCheck`` (first entry of ``DEFAULT_CHECKS``) sent one benign string and one
    tautology string and let ``differential_response_oracle`` judge ``{status,length,lexical}``.
    ANY dimension differing fires, so the loudest trigger was a DEFENCE: a STATIC page behind a
    ModSecurity-CRS-942130 tautology rule (200 -> 403) and an app doing TEXTBOOK STRICT INPUT
    VALIDATION (400 on a quote) both minted High ``boolean_sqli`` FACTs that the offline
    re-verifier re-confirmed. There is no attribution step in a bare differential: its control is a
    DIFFERENT STRING, not a same-shape negative, so nothing separates "the injected boolean changed
    the query" from "the app treated two strings differently". The fix removes DIFFERENTIAL_RESPONSE
    from every truth-value-attribution row (``verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES``);
    the SOUND path — ``BooleanInferenceCheck`` + ``boolean_inference_oracle``, which partitions
    responses BY TRUTH VALUE over shape-varied clauses — still confirms a genuine boolean channel.

F5 — ``path_traversal`` from a bare substring with NO CONTROL.
    ``ContentSignatureCheck`` sent ONE request and confirmed on pure substring presence of
    ``root:x:0:0:`` at 0.90. An ordinary security KNOWLEDGE-BASE site (a static dict of articles,
    ZERO file I/O) whose path-traversal article legitimately contains
    ``root:x:0:0:root:/root:/bin/bash`` minted four High FACTs. The control existed only in ONE
    CONSUMER while the ``path_traversal.file_signature`` evidence branch advertised it and named the
    CHECK as its implementation ref. The guard now lives in the check and is retained in the
    evidence, so ``side_effect_oracle`` re-derives the refusal offline too.

Every server here is a BENIGN loopback target: no database, no file I/O, no injection surface —
except ``_GenuineBooleanSqli`` (a real sqlite3 query, string-concatenated) and ``_FileRead``, the
positive controls that must still confirm.
"""

from __future__ import annotations

import contextlib
import html
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, unquote_plus, urlsplit

import pytest

from framework.v2.scanner.checks import (
    BOOLEAN_SQLI,
    BOOLEAN_SQLI_SPRT,
    DEFAULT_CHECKS,
    PATH_TRAVERSAL,
    BooleanInferenceCheck,
    ContentSignatureCheck,
    DifferentialCheck,
    boolean_clause_families,
)
from framework.v2.scanner.cli import loopback_send
from framework.v2.scanner.engine import AuditEngine
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.oracles import side_effect_oracle
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    DIFFERENTIAL_LEAD_ONLY_CLASSES,
    OracleVerifier,
    oracle_confirms_class,
)

# --------------------------------------------------------------------------------------------
# Loopback fixtures
# --------------------------------------------------------------------------------------------

_PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash\n"
_SIGNATURE = "root:x:0:0:"


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        return

    def _reply(self, status: int, body: bytes, ctype: str = "text/html") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# CRS-942130-shaped SQL tautology rule — the most widely deployed WAF rule family.
_TAUTOLOGY_RULE = re.compile(
    r"(?i)(\b(or|and)\b\s*['\"]?\s*\d+\s*['\"]?\s*=\s*['\"]?\s*\d+|"
    r"['\"]\s*(or|and)\s*['\"]?\s*['\"]?\s*\w+\s*['\"]?\s*=)")

_STATIC_PAGE = (b"<!doctype html><html><head><title>Acme Corp</title></head><body>"
                b"<h1>Welcome to Acme</h1><p>We sell widgets. Our widgets are the best widgets."
                b"</p><form action='/search' method='get'><input name='q'></form>"
                b"<footer>(c) Acme Corp</footer></body></html>")
_BLOCK_PAGE = (b"<!doctype html><html><head><title>403 Forbidden</title></head><body>"
               b"<h1>Request blocked</h1><p>Your request was blocked by the web application "
               b"firewall (rule 942130: SQL tautology detected).</p></body></html>")


class _WafStatic(_Base):
    """BENIGN: a byte-constant STATIC page with NO DATABASE, behind a CRS-942130 tautology deny
    rule. The query string is never parsed, never interpolated. The ONLY input-dependent behaviour
    in the whole server is the WAF's 403 block page — i.e. the DEFENCE."""

    def do_GET(self) -> None:  # noqa: N802
        raw = unquote_plus(urlsplit(self.path).query or "")
        if _TAUTOLOGY_RULE.search(raw):
            self._reply(403, _BLOCK_PAGE)
            return
        self._reply(200, _STATIC_PAGE)


class _StrictValidation(_Base):
    """BENIGN: an ordinary app doing TEXTBOOK STRICT INPUT VALIDATION. No database. ``q`` must match
    ``[A-Za-z0-9 _-]{0,64}``; anything else gets a 400. Rejecting a quote is CORRECT behaviour."""

    _OK = re.compile(r"^[A-Za-z0-9 _-]{0,64}$")

    def do_GET(self) -> None:  # noqa: N802
        q = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        if not self._OK.match(q):
            self._reply(400, b"<!doctype html><html><body><h1>400 Bad Request</h1><p>The search "
                             b"term contains characters that are not allowed.</p></body></html>")
            return
        self._reply(200, ("<!doctype html><html><body><h1>Catalogue</h1><p>Showing items for "
                          "&quot;%s&quot;.</p><ul><li>Widget</li></ul></body></html>"
                          % html.escape(q)).encode())


class _BenignEcho(_Base):
    """BENIGN: an echo/search page with NO database that HTML-escapes the term and always answers
    200. The bare differential never fired here — the audit measured this direction as already
    correct, so it is pinned: the fix must not be a threshold nudge that also silences it."""

    def do_GET(self) -> None:  # noqa: N802
        q = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        self._reply(200, ("<!doctype html><html><body><h1>Search</h1><p>You searched for "
                          "&quot;%s&quot;.</p></body></html>" % html.escape(q)).encode())


class _GenuineBooleanSqli(_Base):
    """VULNERABLE (the F1 positive control): a REAL sqlite3 query built by string concatenation, so
    the response is a genuine FUNCTION OF THE INJECTED BOOLEAN'S TRUTH VALUE for every clause shape
    a real SQL engine understands — not a regex stand-in for one."""

    def do_GET(self) -> None:  # noqa: N802
        q = (parse_qs(urlsplit(self.path).query).get("q") or [""])[0]
        con = sqlite3.connect(":memory:")
        con.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
        con.executemany("INSERT INTO users VALUES (?,?,?)",
                        [(1, "alice", "user"), (2, "bob", "admin"), (3, "carol", "user")])
        try:  # the planted bug: user input concatenated into the WHERE clause
            rows = con.execute("SELECT id, name, role FROM users WHERE name = '" + q + "'").fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            con.close()
        body = ("<h2>User lookup</h2><ul>%s</ul>"
                % "".join(f"<li>id={r[0]} name={r[1]} role={r[2]}</li>" for r in rows)
                if rows else "<h2>User lookup</h2><p>No results found.</p>")
        self._reply(200, body.encode())


_KB_ARTICLES = {
    "path-traversal": ("Path traversal 101",
                       "A successful traversal of /etc/passwd returns lines like "
                       + _PASSWD_LINE.strip() + " . Mitigate by canonicalising paths."),
    "xss": ("Cross-site scripting", "Encode on output, contextually."),
}


class _KnowledgeBase(_Base):
    """BENIGN: an ordinary security KNOWLEDGE-BASE site. A static dict of articles rendered as
    HTML-escaped text. NO database, NO file reads, NO templating. Its only 'sin' is that a security
    KB legitimately CONTAINS the string ``root:x:0:0:root:/root:/bin/bash`` — in its article about
    path traversal. The page is the same for every input, so a benign control carries it too."""

    def do_GET(self) -> None:  # noqa: N802
        body = ("<!doctype html><html><head><title>Security KB</title></head><body>"
                + "".join("<article><h2>%s</h2><p>%s</p></article>" % (html.escape(t), html.escape(b))
                          for t, b in _KB_ARTICLES.values())
                + "</body></html>")
        self._reply(200, body.encode())


class _FileRead(_Base):
    """VULNERABLE (the F5 positive control): a REAL traversal. A benign name returns an ordinary
    document; a traversal returns the FILE CONTENT and never reflects the raw path."""

    def do_GET(self) -> None:  # noqa: N802
        name = (parse_qs(urlsplit(self.path).query).get("name") or [""])[0]
        if "etc/passwd" in name:
            self._reply(200, _PASSWD_LINE.encode(), ctype="text/plain")
            return
        self._reply(200, b"<p>ordinary document</p>")


@contextlib.contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
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


_MIN_CLAUSES = 7   # the shipped K_T / K_F per truth value


def _assert_detector_really_ran(finding) -> None:
    """A confirm is only meaningful if the SOUND detector actually produced the evidence. Assert
    POSITIVELY, from the finding's own retained certificate, that it did: non-empty SPRT rounds,
    each carrying the full K_T always-TRUE and K_F always-FALSE clause sets AND their
    byte-identical determinism repeats, the determinism pre-gate samples, and only then the
    verdict. Without this a test could pass because some OTHER oracle fired, or because the rounds
    were empty and the oracle refused for the wrong reason."""
    ctx = finding.oracle_context
    assert isinstance(ctx, dict), "no retained certificate"
    rounds = ctx.get("probe_rounds")
    assert rounds, "the SPRT detector produced NO rounds — it did not run"
    for i, rnd in enumerate(rounds):
        for key in ("trues", "falses", "true_repeats", "false_repeats"):
            assert len(rnd.get(key) or []) >= _MIN_CLAUSES, (
                f"round {i} carries {len(rnd.get(key) or [])} {key}, expected >= {_MIN_CLAUSES}")
    assert len(ctx.get("false_baseline_samples") or []) >= 6, (
        "the determinism PRE-GATE samples are missing — a boolean confirm requires proving the "
        "page is deterministic to identical input first")
    assert ctx.get("baseline") is None and ctx.get("mutated") is None, (
        "a boolean FACT must not rest on a bare benign-vs-payload differential")
    assert finding.confirmed_by == OracleKind.BOOLEAN_INFERENCE.value


def _audit(url: str, checks: tuple) -> list:
    """Run the REAL default audit engine — the same path a `framework.v2 scan` takes — and return
    the oracle-CONFIRMED findings. Nothing is stubbed: a finding here is a minted FACT."""
    engine = AuditEngine(loopback_send)
    return engine.audit(HttpRequest(method="GET", url=url), checks=checks,
                        insertion_kinds=(InsertionKind.QUERY_VALUE,))


# --------------------------------------------------------------------------------------------
# F1 — a bare differential can never mint a truth-value-attribution FACT
# --------------------------------------------------------------------------------------------


def test_waf_blocked_static_page_mints_no_boolean_sqli_fact() -> None:
    """A static page with NO DATABASE behind a CRS-942130 rule minted a High `boolean_sqli` FACT at
    confidence 0.95 (`confirmed_by: differential_response`). The defence was the trigger."""
    with _serve(_WafStatic) as base:
        findings = _audit(f"{base}/search?q=hello", (BOOLEAN_SQLI,))
    assert findings == [], (
        "a bare differential minted a boolean_sqli FACT on a STATIC page with no database — the "
        f"only input-dependent behaviour is the WAF block page: {[f.rationale for f in findings]}")


def test_strict_input_validation_mints_no_boolean_sqli_fact() -> None:
    """An app doing textbook strict input validation (400 on a quote) minted a High `boolean_sqli`
    FACT at 0.87 on 3/3 runs. Rejecting the payload must never look like executing it."""
    with _serve(_StrictValidation) as base:
        findings = _audit(f"{base}/search?q=hello", (BOOLEAN_SQLI,))
    assert findings == [], (
        "a bare differential minted a boolean_sqli FACT on an app whose only reaction to the "
        f"payload is a 400 validation error: {[f.rationale for f in findings]}")


def test_benign_echo_without_a_status_change_still_does_not_fire() -> None:
    """The direction that was ALREADY correct on the base commit, pinned so the fix is not mistaken
    for a threshold nudge: a benign echo with no status change never fired, and still does not."""
    with _serve(_BenignEcho) as base:
        findings = _audit(f"{base}/search?q=hello", (BOOLEAN_SQLI,))
    assert findings == []


def test_genuine_boolean_channel_still_confirms_via_boolean_inference() -> None:
    """The recall side: a REAL sqlite3-backed boolean channel must still mint a FACT — and via
    BOOLEAN_INFERENCE (truth-value attribution), never via a differential."""
    verifier = OracleVerifier()
    with _serve(_GenuineBooleanSqli) as base:
        tmpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/users?q=guest"))
        (point,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                    if p.name == "q"]
        trues, falses = boolean_clause_families()[0]
        ctx = BooleanInferenceCheck(id="b", bug_class="boolean_sqli",
                                    true_clauses=trues, false_clauses=falses,
                                    n_max=8).probe(tmpl, point, loopback_send)
    assert ctx is not None
    confirmed = confirm_finding(
        finding={"bug_class": "boolean_sqli", "title": "t", "severity": "High",
                 "surface": "s", "summary": "x"},
        context=ctx, verifier=verifier)
    assert confirmed is not None, "the sound SPRT path lost a genuine boolean channel"
    assert confirmed.confirmed_by is OracleKind.BOOLEAN_INFERENCE


@pytest.mark.parametrize("bug_class", sorted(DIFFERENTIAL_LEAD_ONLY_CLASSES))
def test_differential_response_cannot_confirm_a_truth_value_class(bug_class: str) -> None:
    """The authority itself: DIFFERENTIAL_RESPONSE is not an acceptable confirmer for any
    truth-value-attribution class, so a relabelled or hand-crafted differential context cannot
    ride into a FACT either."""
    assert OracleKind.DIFFERENTIAL_RESPONSE not in BUG_CLASS_ORACLES[bug_class]
    assert not oracle_confirms_class("differential_response", bug_class)
    # a maximally-separated differential (status + length + lexical) still must not confirm
    ctx = FindingContext.from_http_responses(
        {"status": 200, "body": "a" * 400}, {"status": 403, "body": "blocked by the firewall"},
        bug_class=bug_class, discriminator={"dimensions": ["status", "length", "lexical"]})
    assert OracleVerifier().confirm(ctx.to_verifier_context()).confirmed is False


# --------------------------------------------------------------------------------------------
# F5 — a known-content signature needs a benign control before it is a file read
# --------------------------------------------------------------------------------------------


def test_knowledge_base_page_mints_no_path_traversal_fact() -> None:
    """A documentation site that PRINTS `root:x:0:0:` — zero file I/O — minted four High
    `path_traversal` FACTs at 0.90 from a bare substring with no baseline at all."""
    with _serve(_KnowledgeBase) as base:
        findings = _audit(f"{base}/kb?topic=xss", (PATH_TRAVERSAL,))
    assert findings == [], (
        "a bare substring minted a path_traversal FACT against a static KB page that merely "
        f"documents the signature: {[f.rationale for f in findings]}")


def test_genuine_traversal_read_still_confirms() -> None:
    """The recall side: a real file read (signature present under the payload, ABSENT from the
    benign control) must still mint a FACT."""
    with _serve(_FileRead) as base:
        findings = _audit(f"{base}/file?name=manual.txt", (PATH_TRAVERSAL,))
    assert [f.bug_class for f in findings] == ["path_traversal"]
    assert findings[0].confirmed_by == OracleKind.SIDE_EFFECT.value


def test_content_signature_check_refuses_when_the_control_is_unreadable() -> None:
    """FAIL-CLOSED: no observable control means no attribution, so no FACT — even though the
    payload response carries the signature."""
    check = ContentSignatureCheck(id="t", bug_class="path_traversal",
                                  payload="../../../../etc/passwd", signature=_SIGNATURE)

    def send(request: HttpRequest) -> dict:
        if check.control_value in request.url:
            raise OSError("control request failed")
        return {"status": 200, "body": _PASSWD_LINE}

    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://127.0.0.1:1/f?name=x"))
    (point,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                if p.name == "name"]
    assert check.probe(tmpl, point, send) is None


def test_side_effect_oracle_refuses_a_marker_already_in_the_control() -> None:
    """The offline half: the refusal is re-derived by the pure oracle over the RETAINED control, so
    re-verification of such a certificate cannot re-confirm it."""
    sink = f"<p>traversal returns lines like {_PASSWD_LINE}</p>"
    assert side_effect_oracle(_SIGNATURE, sink).fired is True            # no control -> unchanged
    assert side_effect_oracle(_SIGNATURE, sink, sink).fired is False     # control carries it -> refuse
    assert side_effect_oracle(_SIGNATURE, sink, "<p>ordinary document</p>").fired is True


def test_control_costs_a_request_only_when_the_signature_is_present() -> None:
    """Budget discipline: the attribution control is sent ONLY on a probe that would otherwise
    fire, so a non-firing surface costs exactly what it always did (one request)."""
    sent: list[str] = []

    def counting_send(request: HttpRequest) -> dict:
        sent.append(request.url)
        return {"status": 200, "body": "<p>nothing to see</p>"}

    tmpl = RequestTemplate(HttpRequest(method="GET", url="http://127.0.0.1:1/f?name=x"))
    (point,) = [p for p in tmpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,))
                if p.name == "name"]
    ctx = PATH_TRAVERSAL.probe(tmpl, point, counting_send)
    assert len(sent) == 1
    # the non-firing probe is still RETAINED as coverage (an exercised, oracle-cleared surface)
    assert ctx is not None and ctx.observed_sink is not None


# --------------------------------------------------------------------------------------------
# The PRODUCER half: demoting the differential without wiring the sound detector into the default
# roster would have been a pure capability removal on the path an operator actually runs.
# --------------------------------------------------------------------------------------------


def test_default_checks_carry_a_sound_boolean_producer_and_no_lead_only_differential() -> None:
    """DEFAULT_CHECKS must contain a producer whose evidence the class's oracle can act on. A
    DifferentialCheck for a lead-only class produces a context NOTHING can confirm, so it is dead
    traffic; a BooleanInferenceCheck for boolean_sqli is the producer BOOLEAN_INFERENCE needs."""
    sprt = [c for c in DEFAULT_CHECKS
            if isinstance(c, BooleanInferenceCheck) and c.bug_class == "boolean_sqli"]
    assert sprt, "DEFAULT_CHECKS has no sound producer for boolean_sqli"
    assert len(sprt[0].true_clauses) >= _MIN_CLAUSES
    assert len(sprt[0].false_clauses) >= _MIN_CLAUSES
    assert not set(sprt[0].true_clauses) & set(sprt[0].false_clauses)
    dead = [c for c in DEFAULT_CHECKS
            if isinstance(c, DifferentialCheck) and c.bug_class in DIFFERENTIAL_LEAD_ONLY_CLASSES]
    assert dead == [], f"dead differential(s) left in the default roster: {[c.id for c in dead]}"


def test_default_roster_confirms_a_genuine_boolean_channel() -> None:
    """The recall the demotion would otherwise have cost: a REAL sqlite3-backed boolean channel is
    confirmed by the DEFAULT roster, via BOOLEAN_INFERENCE, with the detector proven to have run."""
    with _serve(_GenuineBooleanSqli) as base:
        findings = _audit(f"{base}/users?q=guest", DEFAULT_CHECKS)
    boolean = [f for f in findings if f.bug_class == "boolean_sqli"]
    assert boolean, "the default roster lost the TRUE positive along with the false one"
    _assert_detector_really_ran(boolean[0])


def test_default_roster_mints_no_boolean_fact_on_the_waf_static_page() -> None:
    """The soundness side, through the WHOLE default roster rather than the boolean check alone."""
    with _serve(_WafStatic) as base:
        findings = _audit(f"{base}/search?q=hello", DEFAULT_CHECKS)
    assert [f for f in findings if f.bug_class == "boolean_sqli"] == []


def test_default_roster_mints_no_boolean_fact_on_strict_input_validation() -> None:
    with _serve(_StrictValidation) as base:
        findings = _audit(f"{base}/search?q=hello", DEFAULT_CHECKS)
    assert [f for f in findings if f.bug_class == "boolean_sqli"] == []
