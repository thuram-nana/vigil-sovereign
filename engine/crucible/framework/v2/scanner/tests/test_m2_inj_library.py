"""
Milestone-2 module B — injection-variant breadth for the declarative check
library (NoSQL / LDAP / XPath / auth-bypass differentials + blind cmdi / SSRF /
OOB-SQLi / blind-XXE / JNDI out-of-band callbacks).

These entries are DATA (``library_entries/m2_inj_*.json``). This suite proves the
whole path for every ``m2-inj-*`` entry: it loads and validates under the shared
schema, compiles to the correct concrete ``Check`` shape, and — crucially — its
``bug_class`` ROUTES to an oracle in ``verifier.BUG_CLASS_ORACLES`` whose kind the
compiled check can actually produce (differential entries -> DIFFERENTIAL_RESPONSE,
oob entries -> OOB_CALLBACK). An entry that routed nowhere, or to an oracle it can
never feed, would be a dud that can never confirm; the routing tests forbid that.

A representative NoSQL / LDAP / XPath differential is driven end-to-end against a
real loopback fixture that diverges on the injection and NOT on a safe twin,
through the same oracle authority the engine uses (``confirm_finding`` +
``OracleVerifier``) — never the check's own opinion. The OOB entries assert the
compiled ``OOBCheck`` shape and that the ``{callback}`` template renders a real
callback URL (a full callback confirmation needs a live ``OOBReceiver``, out of
scope for a hermetic unit test).
"""

from __future__ import annotations

import contextlib
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from framework.v2.scanner.checks import Check, DifferentialCheck, OOBCheck
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import (
    LibraryEntry,
    compile_entry,
    load_library,
)
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind
from framework.v2.verify.verifier import (
    BUG_CLASS_ORACLES,
    OracleVerifier,
    normalize_bug_class,
)

M2_PREFIX = "m2-inj-"


# ---------------------------------------------------------------------------
# fixtures: the m2-inj-* subset loaded from the shipped library directory
# ---------------------------------------------------------------------------


def _all_entries() -> list[LibraryEntry]:
    return load_library()


def _m2_entries() -> list[LibraryEntry]:
    return [e for e in _all_entries() if e.id.startswith(M2_PREFIX)]


def _by_id(entry_id: str) -> LibraryEntry:
    return next(e for e in _m2_entries() if e.id == entry_id)


def _prefix(pfx: str) -> list[LibraryEntry]:
    return [e for e in _m2_entries() if e.id.startswith(pfx)]


# ---------------------------------------------------------------------------
# load + validate: whole directory loads, m2-inj ids unique and well-formed
# ---------------------------------------------------------------------------


def test_whole_library_loads_and_includes_m2_inj() -> None:
    entries = _all_entries()
    assert entries, "library failed to load"
    m2 = [e for e in entries if e.id.startswith(M2_PREFIX)]
    assert 20 <= len(m2) <= 30, f"expected ~20-30 m2-inj entries, got {len(m2)}"


def test_m2_inj_ids_unique_and_prefixed() -> None:
    m2 = _m2_entries()
    ids = [e.id for e in m2]
    assert len(ids) == len(set(ids)), "duplicate m2-inj ids"
    assert all(i.startswith(M2_PREFIX) for i in ids)
    # globally unique against the rest of the library, too
    all_ids = [e.id for e in _all_entries()]
    assert len(all_ids) == len(set(all_ids)), "m2-inj ids collide with existing entries"


def test_m2_inj_entries_are_rich() -> None:
    for e in _m2_entries():
        assert e.title, e.id
        assert e.severity in {"Critical", "High", "Medium", "Low", "Info"}, e.id
        assert e.references, f"{e.id} carries no reference"
        assert any(r.startswith("CWE-") for r in e.references), f"{e.id} lacks a CWE id"
        assert e.remediation, f"{e.id} carries no remediation"
        assert e.payload_family, f"{e.id} carries no payload_family"


def test_m2_inj_only_strong_oracle_kinds() -> None:
    # the milestone scope is the STRONG, low-false-positive kinds only
    kinds = {e.oracle.kind for e in _m2_entries()}
    assert kinds <= {"differential", "oob"}, f"unexpected oracle kinds {kinds}"


def test_m2_inj_severity_rules() -> None:
    for e in _m2_entries():
        if e.bug_class in ("command_injection", "deserialization"):
            assert e.severity == "Critical", f"{e.id} cmdi/deser must be Critical"
        else:
            assert e.severity == "High", f"{e.id} should be High"


def test_m2_inj_expected_classes_present() -> None:
    # breadth: every named injection class is represented
    assert len(_prefix("m2-inj-nosql-")) >= 4      # NoSQL operator / JS
    assert len(_prefix("m2-inj-ldap-")) >= 2       # LDAP filter
    assert len(_prefix("m2-inj-xpath-")) >= 2      # XPath
    assert len(_prefix("m2-inj-authbypass-")) >= 2  # auth-bypass differentials
    assert len(_prefix("m2-inj-cmdi-")) >= 6       # blind OS cmdi variants
    assert len(_prefix("m2-inj-ssrf-")) >= 3       # blind SSRF schemes
    assert len(_prefix("m2-inj-sqli-oob-")) >= 3   # OOB SQLi (mssql/mysql/oracle)
    assert len(_prefix("m2-inj-xxe-")) >= 2        # blind XXE entities
    assert len(_prefix("m2-inj-deser-")) >= 2      # JNDI/deserialization


# ---------------------------------------------------------------------------
# compile: each entry becomes the right concrete Check
# ---------------------------------------------------------------------------


def test_every_m2_inj_compiles_to_correct_check_type() -> None:
    for e in _m2_entries():
        check = compile_entry(e)
        assert isinstance(check, Check), e.id
        assert check.id == e.id
        assert check.bug_class == e.bug_class
        if e.oracle.kind == "differential":
            assert isinstance(check, DifferentialCheck), e.id
            assert check.benign and check.probe_payload, e.id
        elif e.oracle.kind == "oob":
            assert isinstance(check, OOBCheck), e.id
            assert getattr(check, "wants_oob", False) is True, e.id
            assert "{callback}" in check.payload_template, e.id


# ---------------------------------------------------------------------------
# routing: EVERY entry's bug_class routes to an oracle that can confirm it.
# This proves no entry is a dud that can never confirm.
# ---------------------------------------------------------------------------


def test_every_m2_inj_bug_class_is_routed() -> None:
    for e in _m2_entries():
        key = normalize_bug_class(e.bug_class)
        assert key in BUG_CLASS_ORACLES, (
            f"{e.id}: bug_class {e.bug_class!r} (norm {key!r}) not in BUG_CLASS_ORACLES "
            f"— would fall back to every oracle and never reliably confirm"
        )


def test_routed_oracle_matches_the_compiled_check_evidence() -> None:
    # the oracle kind the compiled check produces evidence for must be in the
    # routed tuple, else confirmation is structurally impossible
    for e in _m2_entries():
        oracles = BUG_CLASS_ORACLES[normalize_bug_class(e.bug_class)]
        if e.oracle.kind == "differential":
            assert OracleKind.DIFFERENTIAL_RESPONSE in oracles, e.id
        elif e.oracle.kind == "oob":
            assert OracleKind.OOB_CALLBACK in oracles, e.id


def test_verifier_router_agrees() -> None:
    # go through the public router, not just the raw table
    v = OracleVerifier()
    for e in _m2_entries():
        kinds = v.oracles_for(e.bug_class)
        # a routed class returns its specific tuple, never the all-oracles fallback
        assert kinds == BUG_CLASS_ORACLES[normalize_bug_class(e.bug_class)], e.id
        assert len(kinds) >= 1


# ---------------------------------------------------------------------------
# OOB entries: compiled shape + the {callback} template renders a callback URL
# ---------------------------------------------------------------------------


_SAMPLE_CB = "127.0.0.1:59999/crucible-oob-token-abc123"


@pytest.mark.parametrize(
    "entry_id",
    [
        "m2-inj-ssrf-http-scheme",
        "m2-inj-cmdi-subshell-curl",
        "m2-inj-cmdi-backtick-curl",
        "m2-inj-deser-jndi-ldap",           # doubled braces must survive .format
        "m2-inj-sqli-oob-mssql-xpdirtree",  # backslash UNC path must survive
        "m2-inj-xxe-param-entity",
    ],
)
def test_oob_template_renders_callback(entry_id: str) -> None:
    check = compile_entry(_by_id(entry_id))
    assert isinstance(check, OOBCheck)
    assert "{callback}" in check.payload_template
    rendered = check.payload_template.format(callback=_SAMPLE_CB)
    assert _SAMPLE_CB in rendered, f"{entry_id} did not render the callback"
    # after substitution there must be no stray unrendered placeholder
    assert "{callback}" not in rendered


def test_every_oob_entry_renders_without_error() -> None:
    for e in _m2_entries():
        if e.oracle.kind != "oob":
            continue
        rendered = compile_entry(e).payload_template.format(callback=_SAMPLE_CB)
        assert _SAMPLE_CB in rendered, e.id


# ---------------------------------------------------------------------------
# end-to-end confirmation of a representative differential per class against a
# real loopback fixture (vuln diverges on the injection; safe twin does not)
# ---------------------------------------------------------------------------

# The injection markers a deliberately-vulnerable backend would react to. The
# benign control value contains none of them, so it returns the empty page.
_INJECTION_MARKERS = ("'1'=='1", "'1'='1", "(uid=")


class _DivergingApp(BaseHTTPRequestHandler):
    """Vulnerable twin: when the query carries an injection breakout the backend
    'returns every record' (a large body); a benign term returns none. A real
    boolean/logic differential a downstream oracle can confirm."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        hit = any(m in q for m in _INJECTION_MARKERS)
        body = ("record\n" * 40).encode() if hit else b"no results"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _ConstantApp(BaseHTTPRequestHandler):
    """Safe twin: input is bound as a value, so the page never changes."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"constant page, injection bound as value"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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


def _send(req: HttpRequest) -> dict:
    with urllib.request.urlopen(req.url, timeout=10) as r:  # noqa: S310 (loopback)
        return {"status": r.status, "body": r.read().decode("utf-8", "replace")}


def _q_point(base: str):
    tpl = RequestTemplate(HttpRequest(method="GET", url=f"{base}/search?q=x"))
    point = next(
        p for p in tpl.insertion_points(kinds=(InsertionKind.QUERY_VALUE,)) if p.name == "q"
    )
    return tpl, point


def _confirm(check: Check, tpl: RequestTemplate, point) -> object:
    ctx = check.probe(tpl, point, _send)
    return confirm_finding(
        finding={"bug_class": check.bug_class}, context=ctx, verifier=OracleVerifier()
    )


# one representative differential entry per injection class (always-on)
_REPRESENTATIVES = [
    "m2-inj-nosql-js-tautology",
    "m2-inj-ldap-wildcard-or",
    "m2-inj-xpath-tautology",
    "m2-inj-authbypass-or-true",
]


@pytest.mark.parametrize("entry_id", _REPRESENTATIVES)
def test_differential_confirms_on_vuln_and_not_on_safe(entry_id: str) -> None:
    check = compile_entry(_by_id(entry_id))
    assert isinstance(check, DifferentialCheck)

    with _server(_DivergingApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(check, tpl, point)
    assert confirmed is not None, f"{entry_id} did not confirm on the vulnerable fixture"
    assert confirmed.confirmed_by is OracleKind.DIFFERENTIAL_RESPONSE

    with _server(_ConstantApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(check, tpl, point) is None, (
            f"{entry_id} false-positived on the safe twin"
        )


def test_authbypass_marker_reacts_but_benign_does_not() -> None:
    # the auth-bypass representative's probe contains a comment marker; ensure the
    # fixture's marker set covers it so the differential is honest, not accidental
    e = _by_id("m2-inj-authbypass-or-true")
    assert any(m in e.oracle.probe for m in _INJECTION_MARKERS), e.oracle.probe
    assert not any(m in e.oracle.benign for m in _INJECTION_MARKERS), e.oracle.benign
