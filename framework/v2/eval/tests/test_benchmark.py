"""
Tests for the CRUCIBLE public benchmark (eval.benchmark_app / benchmark_run /
adapters_ext).

The centrepiece is an end-to-end CRUCIBLE run over the labelled vulnerable app via
``run_benchmark`` (the CRUCIBLE-only path — no incumbent required): it must score
precision 1.0 (zero false positives on the SAFE endpoints) while rediscovering a
solid subset of the planted bugs. The Wapiti and Nikto parsers are proven at the
unit level against captured sample JSON, so parsing is verified without the tools
installed; ``available()`` is asserted to return a bool without throwing.
"""

from __future__ import annotations

import json

import pytest

from ..adapters_ext import (
    AdapterError,
    NiktoAdapter,
    WapitiAdapter,
    parse_nikto,
    parse_wapiti,
)
from ..benchmark_app import benchmark_corpus, serve
from ..benchmark_run import PRECISION_TARGET, BenchmarkCrucibleAdapter, run_benchmark, write_report
from ..validation import score


# ---------------------------------------------------------------------------
# Captured sample outputs (trimmed from real wapiti / nikto runs on this host).
# ---------------------------------------------------------------------------

_WAPITI_SAMPLE = json.dumps({
    "classifications": {},
    "vulnerabilities": {
        "Open Redirect": [
            {"method": "GET", "path": "/redirect", "parameter": "url", "level": 1,
             "info": "Open Redirect via injection in the parameter url", "module": "redirect"},
        ],
        "SQL Injection": [
            {"method": "GET", "path": "/product", "parameter": "id", "level": 3,
             "info": "SQL Injection (DBMS: MySQL) via injection in the parameter id", "module": "sql"},
        ],
        "Cross Site Scripting": [
            {"method": "GET", "path": "/search", "parameter": "q", "level": 2,
             "info": "XSS via injection in the parameter q", "module": "xss"},
        ],
        "Content Security Policy Configuration": [
            {"method": "GET", "path": "/", "parameter": "", "level": 1,
             "info": "CSP is not set", "module": "csp"},
        ],
    },
    "anomalies": {},
    "infos": {"target": "http://127.0.0.1:8099/"},
})

_NIKTO_SAMPLE = json.dumps([
    {
        "host": "127.0.0.1", "ip": "127.0.0.1", "port": "8099",
        "server_banner": "Jetty(9.4.z-SNAPSHOT)",
        "vulnerabilities": [
            {"id": 750004, "method": "GET", "references": "https://docs.spring.io/",
             "msg": "/actuator/env: Spring Boot Actuator endpoint exposed (valid JSON response).",
             "url": "/"},
            {"id": "007226", "method": "GET", "references": "",
             "msg": "/.env: .env file found. The .env file may contain credentials.",
             "url": "/.env"},
            {"id": "999986", "method": "GET", "references": "",
             "msg": "Retrieved access-control-allow-origin header: nikto.example.com.",
             "url": "/"},
            {"id": "013587", "method": "GET", "references": "https://developer.mozilla.org/",
             "msg": "Suggested security header missing: content-security-policy.",
             "url": "/"},
        ],
    },
])


# ---------------------------------------------------------------------------
# Wapiti parser
# ---------------------------------------------------------------------------


def test_parse_wapiti_maps_categories_and_locations():
    findings = parse_wapiti(_WAPITI_SAMPLE)
    assert len(findings) == 4
    assert all(f.tool == "wapiti" and f.confirmed is False for f in findings)

    by_class = {f.bug_class: f for f in findings}
    assert by_class["open_redirect"].location == "/redirect?url"
    assert by_class["sql_injection"].location == "/product?id"
    assert by_class["xss"].location == "/search?q"
    # an unlisted "header hardening" category folds onto a normalized slug
    assert "security_misconfiguration" in by_class
    assert by_class["security_misconfiguration"].location == "/"
    # severity comes from wapiti's numeric level
    assert by_class["sql_injection"].severity == "high"


def test_parse_wapiti_scores_open_redirect_against_manifest():
    """Wapiti's open-redirect detection lines up with the manifest label+location
    (the one bug CRUCIBLE misses), so it earns a true positive on that class."""
    corpus = benchmark_corpus("http://127.0.0.1:8099")
    sb = score(parse_wapiti(_WAPITI_SAMPLE), corpus.expected, tool="wapiti", target=corpus.name)
    assert sb.true_positives >= 1  # at least the open redirect matches


def test_parse_wapiti_malformed_raises():
    with pytest.raises(AdapterError):
        parse_wapiti("not json at all")
    with pytest.raises(AdapterError):
        parse_wapiti(json.dumps({"no_vulnerabilities": True}))


# ---------------------------------------------------------------------------
# Nikto parser
# ---------------------------------------------------------------------------


def test_parse_nikto_classifies_and_locates():
    findings = parse_nikto(_NIKTO_SAMPLE)
    assert len(findings) == 4
    assert all(f.tool == "nikto" and f.confirmed is False for f in findings)

    classes = [f.bug_class for f in findings]
    assert classes.count("exposure") == 2          # actuator + .env
    assert "cors" in classes                        # reflected ACAO header
    assert "security_misconfiguration" in classes   # missing CSP header

    by_class = {f.bug_class: f for f in findings if f.bug_class == "exposure"}
    # locations are lifted from the "/path:" prefix in the message
    locs = {f.location for f in findings if f.bug_class == "exposure"}
    assert "/actuator/env" in locs
    assert "/.env" in locs


def test_parse_nikto_accepts_single_host_object():
    single = json.loads(_NIKTO_SAMPLE)[0]
    findings = parse_nikto(json.dumps(single))
    assert len(findings) == 4


def test_parse_nikto_malformed_raises():
    with pytest.raises(AdapterError):
        parse_nikto("<<not json>>")
    with pytest.raises(AdapterError):
        parse_nikto(json.dumps({"vulnerabilities": {"not": "a list"}}))


# ---------------------------------------------------------------------------
# Adapter availability probes (must return a bool without throwing)
# ---------------------------------------------------------------------------


def test_adapter_availability_probes_return_bool():
    for adapter in (WapitiAdapter(), NiktoAdapter()):
        result = adapter.available()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# End-to-end CRUCIBLE benchmark (no incumbent required)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def crucible_boards():
    """One CRUCIBLE-only benchmark run, shared across the assertions below."""
    return run_benchmark(incumbents=False)


def test_crucible_precision_is_perfect_with_no_false_positives(crucible_boards):
    assert len(crucible_boards) == 1
    board = crucible_boards[0]
    assert board.tool == "crucible"
    # Zero false positives on the SAFE endpoints — the hard requirement.
    assert board.false_positives == 0
    # precision == 1.0 (and comfortably above the stated >= 0.98 target).
    assert board.precision == 1.0
    assert board.precision >= PRECISION_TARGET
    # Recall covers a solid subset of the planted bugs.
    assert board.true_positives >= 5


def test_crucible_recovers_the_response_visible_classes():
    """A direct adapter run confirms the mapped classes/locations are the planted
    ones (xss, boolean_sqli, error_based_sqli, cors, and the exposures)."""
    with serve() as base_url:
        corpus = benchmark_corpus(base_url)
        produced = BenchmarkCrucibleAdapter().run(corpus)

    classes = {f.bug_class for f in produced}
    assert {"xss", "boolean_sqli", "error_based_sqli", "cors", "exposure"} <= classes
    # every produced finding is oracle-confirmed
    assert all(f.confirmed for f in produced)
    # and none of them land on a SAFE endpoint
    safe_markers = ("profile", "health", "download")
    assert not any(any(m in f.location for m in safe_markers) for f in produced)


def test_write_report_emits_a_scoreboard_table(crucible_boards, tmp_path):
    out = write_report(crucible_boards, tmp_path / "benchmark-report.md")
    text = out.read_text(encoding="utf-8")
    assert "| tool | tp | fp | fn | precision | recall | f1 |" in text
    assert "crucible" in text
    assert "0.98" in text  # the stated precision target appears in the preamble
