"""
Tests for the comparative validation / benchmark spine (eval.harness M1-C) and
the incumbent adapters (eval.adapters).

The centrepiece is an end-to-end run of the CRUCIBLE adapter against a labelled,
in-process vulnerable fixture — a real ThreadingHTTPServer that reflects a query
param raw (so reflected XSS confirms) and dumps many rows on a SQL tautology (so
boolean SQLi confirms) — scored against a ground-truth manifest. That proves the
whole spine (runner -> normalize -> score) end-to-end against known truth.

The incumbent adapters are proven at the parser level against captured sample
outputs, so parsing is verified without Nuclei/ZAP/sqlmap/Burp installed.
"""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib.parse import parse_qs, urlsplit

from ..adapters import (
    AdapterError,
    BurpAdapter,
    NucleiAdapter,
    SqlmapAdapter,
    ZapAdapter,
    parse_burp,
    parse_nuclei,
    parse_sqlmap,
    parse_zap,
)
from ..validation import (
    CorpusTarget,
    CrucibleAdapter,
    ExpectedFinding,
    HarnessError,
    NormalizedFinding,
    Scoreboard,
    comparative_report,
    render_table,
    score,
)
from ...scanner.insertion import InsertionKind

import pytest


# ---------------------------------------------------------------------------
# A labelled, deliberately-vulnerable in-process fixture (loopback only).
# ---------------------------------------------------------------------------


def _looks_sqli(value: str) -> bool:
    low = value.lower()
    return "'='" in value or " or " in low


class _VulnApp(BaseHTTPRequestHandler):
    """Two planted bugs, each inert to the other's payload class:

      * ``/reflect?q=`` echoes ``q`` UNESCAPED when it carries markup ('<') —
        reflected XSS. The XSS canary reflects; the SQLi/benign probes (no '<')
        hit a constant branch, so nothing else fires here.
      * ``/items?filter=`` returns a large row set on a tautology and a tiny one
        otherwise — a boolean-blind SQLi differential. ``filter`` is never
        reflected, so the XSS check cannot fire here.
    """

    def log_message(self, *args: object) -> None:  # silence the access log
        return

    def _reply(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        sp = urlsplit(self.path)
        params = parse_qs(sp.query, keep_blank_values=True)

        if sp.path == "/reflect":
            q = params.get("q", [""])[0]
            if "<" in q:
                self._reply(200, f"<html><body><div>echo: {q}</div></body></html>")
            else:
                self._reply(200, "<html><body>reflect page</body></html>")
            return

        if sp.path == "/items":
            filt = params.get("filter", [""])[0]
            if _looks_sqli(filt):
                rows = "\n".join(f"row {i}: record #{i}" for i in range(40))
                self._reply(200, f"items:\n{rows}")
            else:
                self._reply(200, "items:\nno results")
            return

        self._reply(200, (
            "<html><body>"
            '<a href="/reflect?q=hi">reflect</a>'
            '<a href="/items?filter=hi">items</a>'
            "</body></html>"
        ))


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


@contextlib.contextmanager
def _serve() -> Iterator[str]:
    srv = _Server(("127.0.0.1", 0), _VulnApp)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _labelled_target(base_url: str) -> CorpusTarget:
    return CorpusTarget(
        name="m1c-fixture",
        base_url=base_url,
        expected=[
            ExpectedFinding(bug_class="xss", location="/reflect?q"),
            ExpectedFinding(bug_class="boolean_sqli", location="/items?filter"),
        ],
        notes="Reflected XSS on q; boolean-blind SQLi on filter.",
    )


# ---------------------------------------------------------------------------
# End-to-end: CRUCIBLE adapter against ground truth.
# ---------------------------------------------------------------------------


def test_crucible_adapter_scores_perfect_against_ground_truth() -> None:
    with _serve() as base:
        target = _labelled_target(base)
        adapter = CrucibleAdapter(
            max_pages=5,
            enable_oob=False,  # keep it fast; blind classes not under test
            insertion_kinds=(InsertionKind.QUERY_VALUE,),
        )
        produced = adapter.run(target)
        board = score(produced, target.expected, tool=adapter.name, target=target.name)

    # every produced finding is oracle-confirmed
    assert produced, "CRUCIBLE confirmed nothing against the vulnerable fixture"
    assert all(f.confirmed for f in produced)
    assert {f.bug_class for f in produced} >= {"xss", "boolean_sqli"}

    # the whole spine lines up with ground truth: both bugs, no false positives
    assert board.true_positives >= 2
    assert board.false_positives == 0
    assert board.false_negatives == 0
    assert board.precision == 1.0
    assert board.recall == 1.0


def test_crucible_adapter_refuses_non_loopback() -> None:
    adapter = CrucibleAdapter()
    target = CorpusTarget(name="remote", base_url="http://example.com/", expected=[])
    with pytest.raises(Exception) as excinfo:
        adapter.run(target)
    assert "loopback" in str(excinfo.value).lower()


# ---------------------------------------------------------------------------
# score(): perfect / false-positive / false-negative, and param-only match.
# ---------------------------------------------------------------------------


def _nf(bug_class: str, location: str, tool: str = "t") -> NormalizedFinding:
    return NormalizedFinding(tool=tool, bug_class=bug_class, location=location)


def test_score_perfect_match() -> None:
    expected = [
        ExpectedFinding(bug_class="xss", location="/a?q"),
        ExpectedFinding(bug_class="sqli", location="/b?id"),
    ]
    produced = [_nf("xss", "/a?q"), _nf("sqli", "/b?id")]
    s = score(produced, expected, tool="t", target="T")
    assert (s.true_positives, s.false_positives, s.false_negatives) == (2, 0, 0)
    assert s.precision == 1.0 and s.recall == 1.0 and s.f1 == 1.0


def test_score_spurious_finding_lowers_precision() -> None:
    expected = [ExpectedFinding(bug_class="xss", location="/a?q")]
    produced = [_nf("xss", "/a?q"), _nf("xss", "/z?other")]  # second is spurious
    s = score(produced, expected, tool="t", target="T")
    assert s.true_positives == 1
    assert s.false_positives == 1
    assert s.precision == 0.5
    assert s.recall == 1.0


def test_score_missed_expected_lowers_recall() -> None:
    expected = [
        ExpectedFinding(bug_class="xss", location="/a?q"),
        ExpectedFinding(bug_class="idor", location="/b?id"),
    ]
    produced = [_nf("xss", "/a?q")]  # idor missed
    s = score(produced, expected, tool="t", target="T")
    assert s.true_positives == 1
    assert s.false_negatives == 1
    assert s.recall == 0.5
    assert s.precision == 1.0


def test_score_bug_class_must_match() -> None:
    expected = [ExpectedFinding(bug_class="xss", location="/a?q")]
    s = score([_nf("sqli", "/a?q")], expected, tool="t", target="T")
    assert s.true_positives == 0
    assert s.false_positives == 1
    assert s.false_negatives == 1


def test_score_param_only_location_matches_path_param() -> None:
    # CRUCIBLE reports a bare param name; it must still line up with a path+param
    # ground-truth label on the shared parameter.
    expected = [ExpectedFinding(bug_class="xss", location="/reflect?q")]
    produced = [NormalizedFinding(tool="crucible", bug_class="xss", location="q", confirmed=True)]
    s = score(produced, expected, tool="crucible", target="T")
    assert s.true_positives == 1
    assert s.false_positives == 0


def test_score_deduplicates_produced_by_key() -> None:
    expected = [ExpectedFinding(bug_class="xss", location="/a?q")]
    produced = [_nf("xss", "/a?q"), _nf("XSS", "/a/?q")]  # same identity, reported twice
    s = score(produced, expected, tool="t", target="T")
    assert s.true_positives == 1
    assert s.false_positives == 0


def test_scoreboard_guards_divide_by_zero() -> None:
    s = Scoreboard(tool="t", target="T", true_positives=0, false_positives=0, false_negatives=0)
    assert s.precision == 0.0 and s.recall == 0.0 and s.f1 == 0.0


# ---------------------------------------------------------------------------
# comparative_report / render_table with stub adapters.
# ---------------------------------------------------------------------------


class _StubAdapter:
    def __init__(self, name: str, findings: list[NormalizedFinding], *, available: bool = True) -> None:
        self.name = name
        self._findings = findings
        self._available = available

    def available(self) -> bool:
        return self._available

    def run(self, target: CorpusTarget) -> list[NormalizedFinding]:
        return self._findings


def test_comparative_report_skips_unavailable_and_scores_available() -> None:
    target = CorpusTarget(
        name="T",
        base_url="http://127.0.0.1/",
        expected=[ExpectedFinding(bug_class="xss", location="/a?q")],
    )
    good = _StubAdapter("good", [_nf("xss", "/a?q", tool="good")])
    absent = _StubAdapter("absent", [_nf("xss", "/a?q", tool="absent")], available=False)

    boards = comparative_report(target, [good, absent])
    assert [b.tool for b in boards] == ["good"]
    assert boards[0].precision == 1.0 and boards[0].recall == 1.0


def test_render_table_has_header_and_rows() -> None:
    boards = [
        Scoreboard(tool="crucible", target="T", true_positives=2, false_positives=0, false_negatives=0),
        Scoreboard(tool="nuclei", target="T", true_positives=1, false_positives=3, false_negatives=1),
    ]
    table = render_table(boards)
    assert "tool" in table and "precision" in table and "recall" in table and "f1" in table
    assert "crucible" in table and "nuclei" in table
    # header + separator + two data rows
    assert len(table.splitlines()) == 4


# ---------------------------------------------------------------------------
# Corpus load: JSON round-trip and directory load.
# ---------------------------------------------------------------------------


def test_corpus_target_json_round_trips(tmp_path) -> None:
    target = CorpusTarget(
        name="rt",
        base_url="http://127.0.0.1:8080/",
        expected=[
            ExpectedFinding(bug_class="xss", location="/reflect?q"),
            ExpectedFinding(bug_class="boolean_sqli", location="/items?filter"),
        ],
        notes="round trip",
    )
    path = tmp_path / "rt.json"
    path.write_text(target.model_dump_json(), encoding="utf-8")

    loaded = CorpusTarget.from_json(path)
    assert loaded == target

    corpus = CorpusTarget.load_corpus(tmp_path)
    assert corpus == [target]


def test_corpus_target_from_json_rejects_malformed(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(HarnessError):
        CorpusTarget.from_json(path)


# ---------------------------------------------------------------------------
# Incumbent adapter parsers — captured sample outputs (tools NOT installed).
# ---------------------------------------------------------------------------

_NUCLEI_SAMPLE = "\n".join([
    json.dumps({
        "template-id": "reflected-xss",
        "info": {"name": "Reflected XSS", "severity": "high"},
        "matched-at": "http://127.0.0.1:9/reflect?q=payload",
        "host": "127.0.0.1:9",
    }),
    "",  # blank lines are skipped
    json.dumps({
        "template-id": "sqli-error-based",
        "info": {"name": "Error-based SQLi", "severity": "critical"},
        "matched-at": "http://127.0.0.1:9/items?filter=x",
    }),
])


def test_parse_nuclei_maps_jsonl() -> None:
    findings = parse_nuclei(_NUCLEI_SAMPLE)
    assert len(findings) == 2
    first = findings[0]
    assert first.tool == "nuclei"
    assert first.bug_class == "reflected-xss"
    assert first.location == "http://127.0.0.1:9/reflect?q=payload"
    assert first.severity == "high"
    assert first.confirmed is False
    assert findings[1].bug_class == "sqli-error-based"


def test_parse_nuclei_raises_on_malformed_line() -> None:
    with pytest.raises(AdapterError):
        parse_nuclei('{"template-id": "ok", "matched-at": "x"}\nthis is not json')


def test_nuclei_available_false_when_binary_absent() -> None:
    assert NucleiAdapter(binary="nuclei-not-a-real-binary-xyz").available() is False
    assert isinstance(NucleiAdapter().available(), bool)


_ZAP_SAMPLE = json.dumps({
    "@version": "2.14.0",
    "site": [{
        "@name": "http://127.0.0.1:9",
        "alerts": [{
            "pluginid": "40012",
            "alert": "Cross Site Scripting (Reflected)",
            "riskdesc": "High (Medium)",
            "instances": [
                {"uri": "http://127.0.0.1:9/reflect?q=1", "method": "GET", "param": "q", "evidence": "<script>"},
            ],
        }, {
            "pluginid": "40018",
            "alert": "SQL Injection",
            "riskdesc": "High (Medium)",
            "instances": [
                {"uri": "http://127.0.0.1:9/items", "method": "GET", "param": "filter"},
            ],
        }],
    }],
})


def test_parse_zap_maps_alerts_and_instances() -> None:
    findings = parse_zap(_ZAP_SAMPLE)
    assert len(findings) == 2
    xss = findings[0]
    assert xss.tool == "zap"
    assert xss.bug_class == "cross site scripting (reflected)"
    assert xss.location == "http://127.0.0.1:9/reflect?q=1"
    assert xss.severity == "high"
    assert xss.evidence == "<script>"
    # the instance had no query in the URI, so the param is appended
    assert findings[1].location == "http://127.0.0.1:9/items?filter"


def test_parse_zap_raises_on_missing_site() -> None:
    with pytest.raises(AdapterError):
        parse_zap(json.dumps({"not": "a report"}))


def test_zap_available_false_when_binaries_absent() -> None:
    assert ZapAdapter(binaries=("zap-not-real-xyz",)).available() is False
    assert isinstance(ZapAdapter().available(), bool)


_SQLMAP_SAMPLE = """
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8}
[*] starting @ 12:00:00

[12:00:01] [INFO] testing connection to the target URL
[12:00:02] [INFO] GET parameter 'id' is 'boolean-based blind' injectable
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1

    Type: time-based blind
    Title: MySQL >= 5.0.12 time-based blind
    Payload: id=1 AND SLEEP(5)
---
[12:00:05] [INFO] the back-end DBMS is MySQL
"""


def test_parse_sqlmap_extracts_parameter_and_types() -> None:
    findings = parse_sqlmap(_SQLMAP_SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "sqlmap"
    assert f.bug_class == "sql_injection"
    assert f.location == "id"
    assert f.confirmed is True
    assert "boolean-based blind" in f.evidence and "time-based blind" in f.evidence


def test_parse_sqlmap_empty_on_no_injection() -> None:
    assert parse_sqlmap("[INFO] all tested parameters do not appear to be injectable.") == []


def test_parse_sqlmap_raises_when_identified_but_unparseable() -> None:
    with pytest.raises(AdapterError):
        parse_sqlmap("sqlmap identified the following injection point(s) with a total of 1 requests:\n<garbled>")


def test_sqlmap_available_false_when_binary_absent() -> None:
    assert SqlmapAdapter(binary="sqlmap-not-real-xyz").available() is False
    assert isinstance(SqlmapAdapter().available(), bool)


_BURP_SAMPLE = json.dumps({
    "issues": [
        {
            "name": "Cross-site scripting (reflected)",
            "severity": "high",
            "confidence": "certain",
            "origin": "http://127.0.0.1:9",
            "path": "/reflect?q=1",
            "issueDetail": "The value of the q request parameter is copied into the response.",
        },
        {
            "name": "SQL injection",
            "severity": "high",
            "confidence": "firm",
            "url": "http://127.0.0.1:9/items?filter=1",
        },
    ],
})


def test_parse_burp_maps_issues() -> None:
    findings = parse_burp(_BURP_SAMPLE)
    assert len(findings) == 2
    xss = findings[0]
    assert xss.tool == "burp"
    assert xss.bug_class == "cross-site scripting (reflected)"
    assert xss.location == "http://127.0.0.1:9/reflect?q=1"
    assert xss.severity == "high"
    assert xss.confirmed is True  # confidence == certain
    assert findings[1].location == "http://127.0.0.1:9/items?filter=1"
    assert findings[1].confirmed is False  # confidence == firm


def test_parse_burp_handles_issue_events_shape() -> None:
    payload = json.dumps({
        "issue_events": [
            {"issue": {"name": "Open redirection", "severity": "medium", "url": "http://h/r?u=1"}},
        ],
    })
    findings = parse_burp(payload)
    assert len(findings) == 1
    assert findings[0].bug_class == "open redirection"
    assert findings[0].location == "http://h/r?u=1"


def test_parse_burp_raises_on_malformed_json() -> None:
    with pytest.raises(AdapterError):
        parse_burp("<html>not json</html>")


def test_burp_available_from_env(monkeypatch) -> None:
    monkeypatch.delenv("CRUCIBLE_BURP_URL", raising=False)
    assert BurpAdapter().available() is False
    monkeypatch.setenv("CRUCIBLE_BURP_URL", "http://127.0.0.1:1337/burp")
    assert BurpAdapter().available() is True
    # an explicit empty api_url disables it regardless of env
    assert BurpAdapter(api_url="").available() is False
