"""
Module B — the declarative check library loads, validates, gates, compiles, and
confirms end to end.

A check is now DATA: a JSON entry carrying a payload, an oracle contract (which
of the four concrete check shapes runs it), and an applicability predicate. These
tests prove the whole path: every seed entry validates; the predicate grammar
evaluates every node; ``select_entries`` returns only the always-on plus the
matching-fingerprint subset; ``compile_entry`` yields a runnable ``Check`` for
each oracle kind; and a compiled differential/reflection check drives a REAL
loopback fixture to a confirmed finding (and its safe twin to none) through the
same oracle authority the engine uses — never the check's own opinion.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest
from pydantic import ValidationError

from framework.v2.scanner.checks import (
    Check,
    DifferentialCheck,
    MarkerReflectionCheck,
    OOBCheck,
    TimingCheck,
)
from framework.v2.scanner.insertion import HttpRequest, InsertionKind, RequestTemplate
from framework.v2.scanner.library import (
    LIBRARY_DIR,
    LibraryEntry,
    LibraryError,
    OracleSpec,
    compile_entry,
    compile_library,
    evaluate_predicate,
    load_library,
    select_entries,
)
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.verifier import OracleVerifier


# ---------------------------------------------------------------------------
# loading + schema validation of the shipped seed entries
# ---------------------------------------------------------------------------


def _seed() -> list[LibraryEntry]:
    return load_library()


def test_default_directory_exists_and_holds_json() -> None:
    assert LIBRARY_DIR.is_dir()
    assert list(LIBRARY_DIR.glob("*.json")), "no seed entries shipped"


def test_all_seed_entries_load_and_validate() -> None:
    entries = _seed()
    # every *.json parsed and validated into a LibraryEntry
    assert len(entries) == len(list(LIBRARY_DIR.glob("*.json")))
    assert entries, "expected shipped seed entries"
    assert all(isinstance(e, LibraryEntry) for e in entries)
    # sorted by id, deterministically, and ids are unique
    ids = [e.id for e in entries]
    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))
    # a second load is identical (deterministic)
    assert [e.id for e in _seed()] == ids


def test_seed_entries_are_rich() -> None:
    for e in _seed():
        assert e.title
        assert e.severity in {"Critical", "High", "Medium", "Low", "Info"}
        assert e.references, f"{e.id} carries no CWE/CVE/CAPEC reference"
        assert any(r.startswith("CWE-") for r in e.references), f"{e.id} lacks a CWE id"
        assert e.remediation, f"{e.id} carries no remediation text"


def test_seed_covers_all_four_oracle_kinds() -> None:
    # the library covers at least the four foundational check shapes; later
    # milestones add more kinds (e.g. "evaluation" for SSTI), so this is a
    # subset check, not an exact-set one.
    kinds = {e.oracle.kind for e in _seed()}
    assert {"differential", "reflection", "oob", "timing"} <= kinds


def test_seed_has_the_named_minimum_entries() -> None:
    by_id = {e.id: e for e in _seed()}
    # the required coverage across oracle kinds
    assert by_id["boolean-sqli"].oracle.kind == "differential"
    assert by_id["reflected-xss"].oracle.kind == "reflection"
    # SSTI / path-traversal / error-based are confirmed by EVIDENCE, not reflection.
    # The former reflection-gated entries (ssti-reflection / path-traversal /
    # error-based-sqli) were false-positive generators — a reflected canary proves
    # only that input is echoed, never that a template evaluated, a file was read,
    # or a datastore errored — and were removed in favour of these evidence oracles.
    assert by_id["m2-ssti-jinja2"].oracle.kind == "evaluation"
    assert by_id["h1-lfi-etc-passwd"].oracle.kind == "content"
    assert by_id["m2-errsqli-single-quote"].oracle.kind == "error_signature"
    assert by_id["ssrf-oob"].oracle.kind == "oob"
    assert by_id["blind-xxe-oob"].oracle.kind == "oob"
    assert by_id["command-injection-oob"].oracle.kind == "oob"
    assert by_id["time-based-sqli"].oracle.kind == "timing"
    # the two fingerprint-gated exemplars
    assert by_id["wp-author-sqli"].applies_when == {"tech": "wordpress"}
    assert by_id["m2-ssti-smarty"].applies_when == {"category": "php"}


# ---------------------------------------------------------------------------
# predicate grammar — every node type
# ---------------------------------------------------------------------------


def test_predicate_always() -> None:
    assert evaluate_predicate({"always": True}, set()) is True
    assert evaluate_predicate({"always": False}, {"anything"}) is False


def test_predicate_empty_and_none_mean_always() -> None:
    assert evaluate_predicate({}, set()) is True
    assert evaluate_predicate(None, set()) is True


def test_predicate_tech() -> None:
    assert evaluate_predicate({"tech": "wordpress"}, {"wordpress", "cms"}) is True
    assert evaluate_predicate({"tech": "wordpress"}, {"nginx"}) is False
    # case-insensitive, and a namespaced token matches too
    assert evaluate_predicate({"tech": "WordPress"}, {"wordpress"}) is True
    assert evaluate_predicate({"tech": "wordpress"}, {"tech:wordpress"}) is True


def test_predicate_category() -> None:
    assert evaluate_predicate({"category": "php"}, {"php", "apache"}) is True
    assert evaluate_predicate({"category": "php"}, {"python"}) is False
    assert evaluate_predicate({"category": "php"}, {"category:php"}) is True


def test_predicate_any() -> None:
    pred = {"any": [{"tech": "wordpress"}, {"category": "php"}]}
    assert evaluate_predicate(pred, {"php"}) is True
    assert evaluate_predicate(pred, {"wordpress"}) is True
    assert evaluate_predicate(pred, {"nginx"}) is False
    assert evaluate_predicate({"any": []}, {"x"}) is False  # any of nothing


def test_predicate_all() -> None:
    pred = {"all": [{"tech": "wordpress"}, {"category": "php"}]}
    assert evaluate_predicate(pred, {"wordpress", "php"}) is True
    assert evaluate_predicate(pred, {"wordpress"}) is False
    assert evaluate_predicate({"all": []}, set()) is True  # all of nothing (vacuous)


def test_predicate_not() -> None:
    assert evaluate_predicate({"not": {"tech": "nginx"}}, {"apache"}) is True
    assert evaluate_predicate({"not": {"tech": "nginx"}}, {"nginx"}) is False


def test_predicate_nested() -> None:
    pred = {"all": [{"tech": "wordpress"}, {"not": {"category": "php"}}]}
    assert evaluate_predicate(pred, {"wordpress"}) is True
    assert evaluate_predicate(pred, {"wordpress", "php"}) is False


@pytest.mark.parametrize(
    "bad",
    [
        {"unknown_op": "x"},
        {"tech": "a", "category": "b"},   # more than one operator
        {"any": {"tech": "x"}},            # any takes a list
        {"tech": 123},                      # tech takes a string
        {"always": "yes"},                  # always takes a bool
        {"tech": ""},                       # empty token
        "not-a-dict",
    ],
)
def test_predicate_malformed_raises(bad: object) -> None:
    with pytest.raises(LibraryError):
        evaluate_predicate(bad, set())


# ---------------------------------------------------------------------------
# select_entries — fingerprint gating
# ---------------------------------------------------------------------------


def _ids(entries: list[LibraryEntry]) -> set[str]:
    return {e.id for e in entries}


def test_select_entries_wordpress_includes_wp_excludes_php() -> None:
    entries = _seed()
    always_on = _ids([e for e in entries if e.applies(set())])
    assert "wp-author-sqli" not in always_on and "php-lfi" not in always_on

    selected = _ids(select_entries(entries, {"wordpress", "cms"}))
    assert "wp-author-sqli" in selected          # gated WP entry now applies
    assert "php-lfi" not in selected             # php entry still gated out
    assert always_on <= selected                 # every always-on entry included


def test_select_entries_nginx_excludes_both_gated() -> None:
    entries = _seed()
    always_on = _ids([e for e in entries if e.applies(set())])
    selected = _ids(select_entries(entries, {"nginx"}))
    assert "wp-author-sqli" not in selected
    assert "php-lfi" not in selected
    assert selected == always_on                 # only the always-on subset


def test_select_entries_php_includes_php_excludes_wp() -> None:
    selected = _ids(select_entries(_seed(), {"php", "apache"}))
    assert "m2-ssti-smarty" in selected  # php-category-gated (Smarty is a PHP engine)
    assert "wp-author-sqli" not in selected


def test_select_entries_empty_tokens_is_always_on_only() -> None:
    entries = _seed()
    always_on = _ids([e for e in entries if e.applies(set())])
    assert _ids(select_entries(entries, set())) == always_on


# ---------------------------------------------------------------------------
# compile_entry — one runnable Check per oracle kind
# ---------------------------------------------------------------------------


def _entry(entry_id: str) -> LibraryEntry:
    return next(e for e in _seed() if e.id == entry_id)


def test_compile_differential_yields_differential_check() -> None:
    check = compile_entry(_entry("boolean-sqli"))
    assert isinstance(check, DifferentialCheck)
    assert isinstance(check, Check)
    assert check.id == "boolean-sqli"
    assert check.bug_class == "boolean_sqli"


def test_compile_reflection_yields_marker_reflection_check() -> None:
    check = compile_entry(_entry("reflected-xss"))
    assert isinstance(check, MarkerReflectionCheck)
    assert isinstance(check, Check)
    assert "{marker}" in check.payload_template


def test_compile_oob_yields_oob_check() -> None:
    check = compile_entry(_entry("ssrf-oob"))
    assert isinstance(check, OOBCheck)
    assert isinstance(check, Check)
    assert getattr(check, "wants_oob", False) is True
    assert "{callback}" in check.payload_template


def test_compile_timing_yields_timing_check() -> None:
    check = compile_entry(_entry("time-based-sqli"))
    assert isinstance(check, TimingCheck)
    assert isinstance(check, Check)
    assert check.injected_ms == 5000.0
    assert check.benign == "1"


def test_compile_library_compiles_all_entries() -> None:
    from framework.v2.scanner.library import REQUEST_LEVEL_KINDS, split_checks
    entries = _seed()
    # compile_library returns POINT-level checks; request-level entries (e.g.
    # signature framework packs) compile via split_checks instead.
    point_entries = [e for e in entries if e.oracle.kind not in REQUEST_LEVEL_KINDS]
    checks = compile_library(entries)
    assert len(checks) == len(point_entries)
    assert all(isinstance(c, Check) for c in checks)
    # split_checks compiles EVERY entry across the two buckets
    point, request = split_checks(entries)
    assert len(point) + len(request) == len(entries)
    assert {c.id for c in point} | {c.id for c in request} == {e.id for e in entries}


# ---------------------------------------------------------------------------
# end-to-end confirmation against a real loopback fixture (and its safe twin)
# ---------------------------------------------------------------------------


class _SqliVulnApp(BaseHTTPRequestHandler):
    """Boolean-blind SQLi: a tautology dumps the table, a benign term returns none."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = ("row\n" * 40).encode() if "'1'='1" in q else b"no results"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _SqliSafeApp(BaseHTTPRequestHandler):
    """The parameterised twin: a constant page, injection ignored."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"constant page, injection ignored"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _EchoApp(BaseHTTPRequestHandler):
    """Reflects the (decoded) q parameter into the body — a traversal/LFI marker
    that echoes proves the input reached the file/output sink verbatim."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlsplit

        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = f"loaded: {q}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _StripApp(BaseHTTPRequestHandler):
    """The safe twin: never reflects input."""

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"loaded: <sanitized>"
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


def test_compiled_differential_confirms_on_vuln_and_not_on_safe() -> None:
    check = compile_entry(_entry("boolean-sqli"))
    with _server(_SqliVulnApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(check, tpl, point)
    assert confirmed is not None
    assert confirmed.confirmed_by.value == "differential_response"

    with _server(_SqliSafeApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(check, tpl, point) is None


def test_no_reflection_oracle_for_injection_classes() -> None:
    # Regression guard for the false-positive fix. A reflected canary proves only
    # that input is echoed — an XSS signal, and ONLY an XSS signal. It never proves
    # SSTI (needs evaluation), path-traversal/LFI (needs file content), or
    # error-based SQLi (needs a datastore error). Shipping a reflection-oracle entry
    # for any of those classes makes every reflecting endpoint (a search box, an
    # echo, an error page) a false positive — which is exactly what we removed. No
    # shipped entry may reintroduce it.
    offenders = [
        (e.id, e.bug_class)
        for e in _seed()
        if e.oracle.kind == "reflection" and e.bug_class != "xss"
    ]
    assert offenders == [], f"reflection oracle used for non-XSS classes: {offenders}"


def test_reflection_oracle_still_confirms_xss_on_executable_echo() -> None:
    # The reflection oracle remains valid for its ONE legitimate class: reflected
    # XSS still confirms when the canary reaches an executable context, and not when
    # the input is stripped. (The compiled check is a MarkerReflectionCheck; XSS
    # routes to the executable-context reflection oracle, not bare side-effect.)
    check = compile_entry(_entry("reflected-xss"))
    with _server(_EchoApp) as base:
        tpl, point = _q_point(base)
        confirmed = _confirm(check, tpl, point)
    assert confirmed is not None

    with _server(_StripApp) as base:
        tpl, point = _q_point(base)
        assert _confirm(check, tpl, point) is None


# ---------------------------------------------------------------------------
# OracleSpec / LibraryEntry validation (extra="forbid", per-kind requirements)
# ---------------------------------------------------------------------------


def test_oraclespec_differential_requires_benign_and_probe() -> None:
    OracleSpec(kind="differential", benign="a", probe="b")  # ok
    with pytest.raises(ValidationError):
        OracleSpec(kind="differential", benign="a")  # missing probe
    with pytest.raises(ValidationError):
        OracleSpec(kind="differential", probe="b")  # missing benign


def test_oraclespec_reflection_requires_marker_placeholder() -> None:
    OracleSpec(kind="reflection", payload_template="x{marker}y")  # ok
    with pytest.raises(ValidationError):
        OracleSpec(kind="reflection", payload_template="no placeholder")
    with pytest.raises(ValidationError):
        OracleSpec(kind="reflection")  # missing payload_template


def test_oraclespec_oob_requires_callback_placeholder() -> None:
    OracleSpec(kind="oob", payload_template="{callback}")  # ok
    with pytest.raises(ValidationError):
        OracleSpec(kind="oob", payload_template="{marker}")  # wrong placeholder


def test_oraclespec_timing_requires_injected_ms() -> None:
    OracleSpec(kind="timing", benign="1", sleep_payload="SLEEP", injected_ms=500)  # ok
    with pytest.raises(ValidationError):
        OracleSpec(kind="timing", benign="1", sleep_payload="SLEEP")  # no injected_ms
    with pytest.raises(ValidationError):
        OracleSpec(kind="timing", benign="1", sleep_payload="SLEEP", injected_ms=0)  # non-positive


def test_oraclespec_unknown_kind_and_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        OracleSpec(kind="magic", payload_template="{marker}")
    with pytest.raises(ValidationError):
        OracleSpec(kind="reflection", payload_template="{marker}", bogus="x")


def _valid_entry_dict() -> dict:
    return {
        "id": "x", "bug_class": "xss", "title": "t", "severity": "High",
        "oracle": {"kind": "reflection", "payload_template": "{marker}"},
    }


def test_entry_rejects_bad_severity() -> None:
    d = _valid_entry_dict()
    d["severity"] = "Spicy"
    with pytest.raises(ValidationError):
        LibraryEntry.model_validate(d)


def test_entry_rejects_unknown_insertion_kind() -> None:
    d = _valid_entry_dict()
    d["insertion_kinds"] = ["query_value", "not_a_real_kind"]
    with pytest.raises(ValidationError):
        LibraryEntry.model_validate(d)


def test_entry_accepts_insertion_kind_by_name_or_value() -> None:
    d = _valid_entry_dict()
    d["insertion_kinds"] = ["QUERY_VALUE", "body_form_value"]
    e = LibraryEntry.model_validate(d)
    assert e.insertion_kinds == ["query_value", "body_form_value"]


def test_entry_rejects_malformed_applies_when() -> None:
    d = _valid_entry_dict()
    d["applies_when"] = {"nonsense_op": "x"}
    with pytest.raises(ValidationError):
        LibraryEntry.model_validate(d)


def test_entry_rejects_extra_field() -> None:
    d = _valid_entry_dict()
    d["surprise"] = "x"
    with pytest.raises(ValidationError):
        LibraryEntry.model_validate(d)


# ---------------------------------------------------------------------------
# loader error handling — a broken file fails loudly, naming itself
# ---------------------------------------------------------------------------


def test_load_missing_directory_raises() -> None:
    with pytest.raises(LibraryError):
        load_library("/no/such/library/dir")


def test_load_bad_json_raises_naming_the_file(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(LibraryError) as ei:
        load_library(tmp_path)
    assert "broken.json" in str(ei.value)


def test_load_schema_invalid_raises_naming_the_file(tmp_path: Path) -> None:
    # valid JSON, but missing required fields / bad oracle
    (tmp_path / "bad_entry.json").write_text(
        json.dumps({"id": "z", "bug_class": "xss"}), encoding="utf-8"
    )
    with pytest.raises(LibraryError) as ei:
        load_library(tmp_path)
    assert "bad_entry.json" in str(ei.value)


def test_load_duplicate_ids_raises(tmp_path: Path) -> None:
    entry = _valid_entry_dict()
    (tmp_path / "a.json").write_text(json.dumps(entry), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(entry), encoding="utf-8")  # same id
    with pytest.raises(LibraryError) as ei:
        load_library(tmp_path)
    assert "duplicate" in str(ei.value).lower()
