"""
Tests for Workstream D.3 — the Nuclei-template -> CRUCIBLE library-entry compiler.

The compiler reads a Nuclei TEMPLATE (the YAML) and compiles a supported subset into a native
LibraryEntry whose match a CRUCIBLE oracle re-verifies. Coverage:

  * a supported GET/word template compiles to a valid `signature` LibraryEntry with the right
    probe_path, signature, severity, bug_class and PROVENANCE (payload_family + nuclei-template ref).
  * end-to-end: the compiled entry -> a runnable check -> the predicate/ACHIEVED-STATE oracle CONFIRMS
    only when the signature actually appears in a real response; a 404 or a signature-less 200 yields
    NO fact (the template's claim is never trusted — prove-don't-guess).
  * templates outside the subset (POST / raw / computed path / regex-only / no matcher / no http block)
    degrade cleanly to supported=False with a reason.
  * determinism, CWE->class hinting, batch/dir compilation, and malformed-YAML handling.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

import pytest

from framework.v2.scanner.insertion import HttpRequest, RequestTemplate
from framework.v2.scanner.library import LibraryEntry, compile_entry
from framework.v2.scanner.nuclei_compile import (
    CompiledTemplate,
    NucleiCompileError,
    compile_nuclei_dir,
    compile_nuclei_template,
    compile_nuclei_templates,
    compiled_entries,
)
from framework.v2.verify.confirmation import confirm_finding
from framework.v2.verify.models import OracleKind

_TEMPLATE = """
id: spring-actuator-env
info:
  name: Spring Boot Actuator env exposure
  severity: high
  classification:
    cwe-id:
      - CWE-200
  reference:
    - https://example.test/actuator
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "propertySources"
      - type: status
        status:
          - 200
"""


def test_supported_template_compiles_to_a_valid_signature_entry() -> None:
    res = compile_nuclei_template(_TEMPLATE)
    assert res.supported and res.entry is not None
    e = res.entry
    assert isinstance(e, LibraryEntry)
    assert e.id == "nuclei-spring-actuator-env"
    assert e.oracle.kind == "signature"
    assert e.oracle.probe_path == "/actuator/env"
    assert e.oracle.signature == "propertySources"
    assert e.oracle.http_method == "GET"
    assert e.severity == "High"
    assert e.bug_class == "sensitive_exposure"        # CWE-200 hint
    # PROVENANCE: the compiled entry traces back to its origin template.
    assert e.payload_family == "nuclei:spring-actuator-env"
    assert "nuclei-template:spring-actuator-env" in e.references
    assert "CWE-200" in e.references
    assert "https://example.test/actuator" in e.references


def _mock_target(*, path: str, signature: str | None, status: int = 200):
    """A send that returns `signature` in the body for `path`, else a 404."""
    def send(req: HttpRequest) -> dict:
        if urlsplit(req.url).path == path:
            body = f'{{"{signature}": [{{"name": "systemProperties"}}]}}' if signature else "{}"
            return {"status": status, "headers": [], "body": body}
        return {"status": 404, "headers": [], "body": "not found"}
    return send


def test_compiled_entry_is_oracle_reverified_only_on_a_real_signature() -> None:
    entry = compile_nuclei_template(_TEMPLATE).entry
    assert entry is not None
    check = compile_entry(entry)   # -> a PathProbeCheck (request-level)
    template = RequestTemplate(HttpRequest(method="GET", url="http://target.test/", headers=[], body=None))

    # vulnerable: the signature really appears -> the ACHIEVED-STATE/predicate oracle re-fires -> FACT.
    ctx = check.probe(template, _mock_target(path="/actuator/env", signature="propertySources"))
    assert ctx is not None
    confirmed = confirm_finding({"bug_class": entry.bug_class, "title": "", "severity": "High"}, ctx)
    assert confirmed is not None and confirmed.confirmed_by == OracleKind.ACHIEVED_STATE

    # the path exists (200) but the signature is ABSENT -> the oracle does NOT fire -> no fact.
    ctx2 = check.probe(template, _mock_target(path="/actuator/env", signature=None))
    assert ctx2 is not None
    assert confirm_finding({"bug_class": entry.bug_class, "title": "", "severity": "High"}, ctx2) is None

    # the path is absent (404) -> the check yields nothing to adjudicate at all.
    assert check.probe(template, _mock_target(path="/nonexistent", signature="propertySources")) is None


def test_compilation_is_deterministic() -> None:
    a = compile_nuclei_template(_TEMPLATE).entry
    b = compile_nuclei_template(_TEMPLATE).entry
    assert a is not None and b is not None
    assert a.model_dump() == b.model_dump()


@pytest.mark.parametrize("yaml_text, needle", [
    # POST is out of the fixed-path GET subset
    ("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: POST\n    path:\n      - '{{BaseURL}}/x'\n    matchers:\n      - type: word\n        words: ['z']\n", "GET"),
    # raw NON-GET request (a scanner mints only over idempotent probes) is still out of subset
    ("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - raw:\n      - 'POST /x HTTP/1.1'\n    matchers:\n      - type: word\n        words: ['z']\n", "get"),
    # computed path (interpolation beyond BaseURL)
    ("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/{{randstr}}/x'\n    matchers:\n      - type: word\n        words: ['z']\n", "interpolation"),
    # only a regex/status matcher, no body word
    ("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n    matchers:\n      - type: regex\n        regex: ['a.*b']\n", "word"),
    # no http block at all
    ("id: t\ninfo:\n  name: n\n  severity: info\ndns:\n  - name: x\n", "http"),
])
def test_unsupported_templates_degrade_cleanly(yaml_text: str, needle: str) -> None:
    res = compile_nuclei_template(yaml_text)
    assert res.supported is False and res.entry is None
    assert needle.lower() in res.reason.lower()


def test_legacy_requests_key_and_word_only_matcher_compile() -> None:
    text = (
        "id: legacy-x\ninfo:\n  name: legacy\n  severity: medium\n"
        "requests:\n  - method: GET\n    path:\n      - '{{BaseURL}}/legacy'\n"
        "    matchers:\n      - type: word\n        part: body\n        words: ['SECRET_TOKEN']\n"
    )
    res = compile_nuclei_template(text)
    assert res.supported and res.entry is not None
    assert res.entry.oracle.probe_path == "/legacy" and res.entry.oracle.signature == "SECRET_TOKEN"
    assert res.entry.severity == "Medium" and res.entry.bug_class == "exposure"   # no CWE -> default


def test_missing_id_or_bad_yaml_raise_and_are_caught_in_a_batch() -> None:
    with pytest.raises(NucleiCompileError):
        compile_nuclei_template("info:\n  name: no id\n")        # missing id
    with pytest.raises(NucleiCompileError):
        compile_nuclei_template("::: not : valid : yaml : [")     # unparseable

    # a batch never sinks on one bad template — it is captured as supported=False.
    batch = compile_nuclei_templates([_TEMPLATE, "info:\n  name: no id\n"])
    assert batch[0].supported is True
    assert batch[1].supported is False and "id" in batch[1].reason.lower()


def test_compile_dir_and_compiled_entries_filter(tmp_path: Path) -> None:
    (tmp_path / "ok.yaml").write_text(_TEMPLATE, encoding="utf-8")
    (tmp_path / "bad.yaml").write_text("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: POST\n    path: ['{{BaseURL}}/x']\n", encoding="utf-8")
    results = compile_nuclei_dir(tmp_path)
    assert len(results) == 2
    entries = compiled_entries(results)
    assert len(entries) == 1 and entries[0].id == "nuclei-spring-actuator-env"
    # the compiled entry validates as a real library entry the engine can run.
    assert isinstance(entries[0], LibraryEntry)


def test_compiled_entry_is_not_written_into_the_shipped_library() -> None:
    # Gate-neutrality guard: the compiler must not touch the shipped library_entries dir.
    from framework.v2.scanner.library import LIBRARY_DIR
    before = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    compile_nuclei_template(_TEMPLATE)
    after = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    assert before == after and not any(n.startswith("nuclei-") for n in after)


# ---------------------------------------------------------------------------
# Wave C slice C2 — the widened matcher subset (status / regex / dsl / multi-request / raw).
# Each new matcher type: a template compiles to a LibraryEntry whose match VIGIL's OWN check
# re-verifies via the predicate oracle; a NON-matching response mints nothing; and a matching
# template ALONE never mints a FACT without the oracle re-firing over a real response.
# ---------------------------------------------------------------------------


def _resp(*, path: str, status: int, body: str):
    """A send that returns (status, body) for `path`, else a 404 — so a probe of the wrong path, or a
    response the predicate does not hold over, yields no fact."""
    def send(req: HttpRequest) -> dict:
        if urlsplit(req.url).path == path:
            return {"status": status, "headers": [], "body": body}
        return {"status": 404, "headers": [], "body": "not found"}
    return send


def _target_template():
    return RequestTemplate(HttpRequest(method="GET", url="http://target.test/", headers=[], body=None))


def _confirm(entry, ctx, severity="Info"):
    if ctx is None:
        return None
    return confirm_finding({"bug_class": entry.bug_class, "title": "", "severity": severity}, ctx)


def test_status_matcher_compiles_and_is_reverified() -> None:
    tmpl = (
        "id: admin-panel-open\ninfo:\n  name: Admin panel exposed\n  severity: medium\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/admin'\n"
        "    matchers:\n      - type: status\n        status:\n          - 200\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.kind == "nuclei_http"
    assert e.oracle.probe_path == "/admin"
    assert e.oracle.match_predicate == {"in": [{"var": "status"}, [200]]}
    assert e.payload_family == "nuclei:admin-panel-open"
    check = compile_entry(e)   # -> a NucleiTemplateCheck (request-level)
    assert type(check).__name__ == "NucleiTemplateCheck"
    tpl = _target_template()
    # status matches -> the predicate/ACHIEVED-STATE oracle re-fires over the REAL status -> fact.
    hit = _confirm(e, check.probe(tpl, _resp(path="/admin", status=200, body="<html>admin</html>")), "Medium")
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE
    # status differs (302) -> the oracle does not fire -> no fact.
    assert _confirm(e, check.probe(tpl, _resp(path="/admin", status=302, body="redirect")), "Medium") is None
    # path absent (probe of /admin returns 404) -> no fact.
    assert _confirm(e, check.probe(tpl, _resp(path="/elsewhere", status=200, body="x")), "Medium") is None


def test_regex_matcher_compiles_to_literal_core_and_reverifies() -> None:
    tmpl = (
        "id: phpsessid-leak\ninfo:\n  name: PHPSESSID exposed\n  severity: low\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/status'\n"
        "    matchers:\n      - type: regex\n        part: body\n"
        "        regex:\n          - 'PHPSESSID=[a-f0-9]{10,}'\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.kind == "nuclei_http"
    # The regex reduces to its distinctive LITERAL CORE — VIGIL re-verifies the literal, not the pattern.
    assert e.oracle.match_predicate == {"contains": [{"var": "body"}, "PHPSESSID="]}
    assert any("literal core" in w for w in res.warnings)
    check = compile_entry(e)
    tpl = _target_template()
    hit = _confirm(e, check.probe(tpl, _resp(path="/status", status=200, body="x PHPSESSID=deadbeef01 y")), "Low")
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE
    # literal core absent -> no fact.
    assert _confirm(e, check.probe(tpl, _resp(path="/status", status=200, body="nothing here")), "Low") is None


def test_regex_without_a_distinctive_literal_core_degrades_cleanly() -> None:
    # A pure character-class pattern has no distinctive literal core -> the term (and template) degrade.
    tmpl = (
        "id: hashy\ninfo:\n  name: n\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
        "    matchers:\n      - type: regex\n        part: body\n        regex:\n          - '[a-f0-9]{32}'\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "literal core" in res.reason.lower() or "re-verifiable" in res.reason.lower()


def test_dsl_matcher_compiles_and_is_reverified() -> None:
    tmpl = (
        "id: dsl-marker\ninfo:\n  name: dsl marker\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
        "    matchers:\n      - type: dsl\n        dsl:\n"
        "          - 'status_code == 200 && contains(body, \"DEBUG_MODE=on\")'\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.kind == "nuclei_http"
    assert e.oracle.match_predicate == {
        "all": [{"eq": [{"var": "status"}, 200]}, {"contains": [{"var": "body"}, "DEBUG_MODE=on"]}]
    }
    check = compile_entry(e)
    tpl = _target_template()
    hit = _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="... DEBUG_MODE=on ...")))
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE
    # right body, wrong status -> AND not satisfied -> no fact.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=500, body="DEBUG_MODE=on"))) is None
    # right status, wrong body -> no fact.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="clean"))) is None


def test_a_matching_template_alone_does_not_mint_a_fact_without_the_oracle() -> None:
    # The whole point of the slice: compiling a template yields a LEAD (a library entry with a check
    # spec + provenance) — NEVER a fact. The external template's verdict is never trusted; a fact
    # exists only after VIGIL's OWN oracle re-fires over a REAL response.
    # A regex+status AND template (a plain body WORD would take the back-compat 'signature' path; here
    # we exercise the widened nuclei_http predicate path explicitly).
    tmpl = (
        "id: trust-nothing\ninfo:\n  name: trust nothing\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
        "    matchers-condition: and\n    matchers:\n"
        "      - type: regex\n        part: body\n        regex:\n          - 'SECRET_MARKER'\n"
        "      - type: status\n        status:\n          - 200\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    # Provenance is retained; the entry is a LEAD, not a confirmed finding.
    assert "nuclei-template:trust-nothing" in e.references
    assert e.oracle.kind == "nuclei_http"
    check = compile_entry(e)
    tpl = _target_template()
    # The template would "match" a 200 body containing SECRET_MARKER — but nothing is minted until the
    # oracle re-fires over a real matching response. Each near-miss mints NOTHING, whatever the template
    # claims.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="no marker"))) is None
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=404, body="SECRET_MARKER"))) is None
    hit = _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="here: SECRET_MARKER")))
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE


def test_multi_request_template_compiles_first_self_contained_reverifiable_request() -> None:
    # req#1 is a POST (out of the idempotent-probe subset); the compiler picks the first self-contained
    # GET probe (req#2). A dependent/POST leg is skipped, never fatal.
    tmpl = (
        "id: multi-probe\ninfo:\n  name: multi\n  severity: low\n"
        "http:\n"
        "  - method: POST\n    path:\n      - '{{BaseURL}}/login'\n"
        "    matchers:\n      - type: word\n        words:\n          - 'ignored'\n"
        "  - method: GET\n    path:\n      - '{{BaseURL}}/debug'\n"
        "    matchers:\n      - type: word\n        part: body\n        words:\n          - 'DEBUG_MODE=on'\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.probe_path == "/debug"
    assert e.oracle.kind == "signature" and e.oracle.signature == "DEBUG_MODE=on"   # plain GET+word leg
    assert any("multi-request" in w for w in res.warnings)


def test_raw_get_request_compiles_carries_headers_and_reverifies() -> None:
    # dict form keeps the raw blob unambiguous. Host is dropped (target netloc wins); interpolation-free
    # headers are carried; the body-word matcher re-verifies via VIGIL's own oracle.
    tmpl = {
        "id": "raw-actuator",
        "info": {"name": "raw actuator", "severity": "high", "classification": {"cwe-id": ["CWE-200"]}},
        "http": [{
            "raw": ["GET /actuator/env HTTP/1.1\nHost: {{Hostname}}\nAccept: application/json\nX-Probe: obsidian\n"],
            "matchers": [{"type": "word", "part": "body", "words": ["propertySources"]}],
        }],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.kind == "nuclei_http"
    assert e.oracle.probe_path == "/actuator/env" and e.oracle.http_method == "GET"
    assert dict(tuple(h) for h in e.oracle.request_headers) == {
        "Accept": "application/json", "X-Probe": "obsidian",
    }
    assert e.oracle.match_predicate == {"icontains": [{"var": "body"}, "propertySources"]}
    assert e.bug_class == "sensitive_exposure"   # CWE-200 hint still applies through the raw path
    check = compile_entry(e)
    hit = _confirm(e, check.probe(_target_template(),
                                  _resp(path="/actuator/env", status=200, body='{"propertySources": []}')), "High")
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE


def test_raw_non_get_request_degrades() -> None:
    tmpl = {
        "id": "raw-post", "info": {"name": "n", "severity": "info"},
        "http": [{"raw": ["POST /x HTTP/1.1\n\nfoo=bar"],
                  "matchers": [{"type": "word", "words": ["z"]}]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "get" in res.reason.lower()


def test_and_condition_degrades_when_a_term_is_not_reverifiable() -> None:
    # AND of a supported body regex and an UNSUPPORTED header regex: dropping the header term would fire
    # MORE broadly than the template, so the whole template degrades (never widen an AND).
    tmpl = {
        "id": "and-degrade", "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "and",
                  "matchers": [
                      {"type": "regex", "part": "body", "regex": ["MARKER_TOKEN_[0-9]+"]},
                      {"type": "regex", "part": "header", "regex": ["X-Thing"]},
                  ]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "and" in res.reason.lower()


def test_or_condition_drops_unsupported_branch_and_stays_a_subset() -> None:
    # OR of a supported status match and an UNSUPPORTED header regex: the header branch is dropped,
    # leaving a STRICTER match (a subset) -> sound. The compiled predicate is just the status clause.
    tmpl = {
        "id": "or-drop", "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "or",
                  "matchers": [
                      {"type": "status", "status": [200]},
                      {"type": "regex", "part": "header", "regex": ["X-Thing"]},
                  ]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    # Only the status clause survives; a single clause needs no all/any wrapper.
    assert res.entry.oracle.match_predicate == {"in": [{"var": "status"}, [200]]}


def test_negative_matcher_never_grounds_a_fact() -> None:
    # A negative (must-NOT-appear) matcher is never a basis for a mint; a template with only one degrades.
    tmpl = {
        "id": "neg", "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "word", "part": "body", "words": ["notpresent"], "negative": True}]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "negative" in " ".join(res.warnings).lower()


def test_widened_compilation_is_deterministic() -> None:
    tmpl = (
        "id: det\ninfo:\n  name: n\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
        "    matchers-condition: or\n    matchers:\n"
        "      - type: status\n        status:\n          - 200\n          - 302\n"
        "      - type: regex\n        part: body\n        regex:\n          - 'X-Marker: [0-9]+'\n"
    )
    a = compile_nuclei_template(tmpl).entry
    b = compile_nuclei_template(tmpl).entry
    assert a is not None and b is not None and a.model_dump() == b.model_dump()
    assert a.oracle.kind == "nuclei_http"
    assert a.oracle.match_predicate == {
        "any": [{"in": [{"var": "status"}, [200, 302]]}, {"contains": [{"var": "body"}, "X-Marker: "]}]
    }


def test_compiled_nuclei_http_entry_is_not_written_into_the_shipped_library() -> None:
    from framework.v2.scanner.library import LIBRARY_DIR
    before = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    compile_nuclei_template(
        "id: x\ninfo:\n  name: n\n  severity: info\nhttp:\n  - method: GET\n    path:\n"
        "      - '{{BaseURL}}/x'\n    matchers:\n      - type: status\n        status:\n          - 200\n"
    )
    after = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    assert before == after and not any(n.startswith("nuclei-") for n in after)
