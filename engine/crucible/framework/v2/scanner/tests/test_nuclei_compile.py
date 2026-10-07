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


def test_status_only_template_is_refused_at_compile() -> None:
    # BLOCK 1 headline: a status-only matcher would fire over ANY live 200 -> a High exposure fact with
    # no re-verification value. It must DEGRADE (no discriminating body observable), never mint.
    tmpl = (
        "id: admin-panel-open\ninfo:\n  name: Admin panel exposed\n  severity: high\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/admin'\n"
        "    matchers:\n      - type: status\n        status:\n          - 200\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "discriminating" in res.reason.lower()


def test_broad_status_set_template_is_refused_at_compile() -> None:
    # A near-tautology status set is the same defect, larger.
    tmpl = {
        "id": "broad-status", "info": {"name": "n", "severity": "high"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "status", "status": [200, 201, 301, 302, 401, 403, 404, 500, 502]}]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None


def test_status_matcher_is_reverified_only_as_a_corroborator_of_a_body_literal() -> None:
    # Status is admissible ONLY AND-combined with a discriminating body literal. A benign SAME-STATUS
    # 200 (no signature) MUST mint nothing — the control that exposes the vacuous-mint defect.
    tmpl = (
        "id: actuator-200\ninfo:\n  name: Actuator env exposed\n  severity: high\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/actuator/env'\n"
        "    matchers-condition: and\n    matchers:\n"
        "      - type: word\n        part: body\n        words:\n          - 'propertySources'\n"
        "      - type: status\n        status:\n          - 200\n"
    )
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    # A single body word takes the back-compat `signature` path; the status is subsumed by
    # PathProbeCheck's own "not a bare 2xx" rule. Either way the mint requires the body signature.
    assert e.oracle.kind == "signature" and e.oracle.signature == "propertySources"
    check = compile_entry(e)
    tpl = _target_template()
    # SAFE CONTROL: a benign homepage with the SAME status 200 but no signature mints NOTHING.
    assert _confirm(e, check.probe(tpl, _resp(path="/actuator/env", status=200,
                                              body="totally benign homepage")), "High") is None
    # the signature actually present -> the oracle re-fires -> fact.
    hit = _confirm(e, check.probe(tpl, _resp(path="/actuator/env", status=200,
                                             body='{"propertySources": []}')), "High")
    assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE


def test_status_and_regex_literal_compiles_and_benign_same_status_mints_nothing() -> None:
    # status AND a regex literal core -> a nuclei_http predicate whose mint REQUIRES the body literal.
    tmpl = {
        "id": "status-and-regex", "info": {"name": "n", "severity": "high"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "and",
                  "matchers": [
                      {"type": "regex", "part": "body", "regex": ["X-Secret-Token: [A-Za-z0-9]{6,}"]},
                      {"type": "status", "status": [200]},
                  ]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    e = res.entry
    assert e.oracle.kind == "nuclei_http"
    assert e.oracle.match_predicate == {
        "all": [{"contains": [{"var": "body"}, "X-Secret-Token: "]}, {"in": [{"var": "status"}, [200]]}]
    }
    check = compile_entry(e)
    assert type(check).__name__ == "NucleiTemplateCheck"
    tpl = _target_template()
    # SAFE CONTROL: benign SAME-STATUS 200 without the literal mints NOTHING.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="totally benign homepage")), "High") is None
    # right literal, wrong status -> AND not satisfied -> nothing.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=500, body="X-Secret-Token: abcdef")), "High") is None
    # Lane S: a third-party template's status+body-literal predicate carries NO positive discriminator
    # (no VIGIL canary, no present/absent differential, no numeric achieved-state — "status==200" is a
    # gate-B corroborator and a body literal is producer-authorable), so the structural grammar REFUSES it.
    # nuclei_http stays a compile-time LEAD (the entry + provenance above), never a runtime FACT.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="X-Secret-Token: abcdef")), "High") is None


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
    # Lane S: a bare body-literal predicate from a third-party template has no positive discriminator, so
    # the grammar REFUSES it — nuclei_http is a compile-time LEAD (entry + provenance), never a FACT.
    assert _confirm(e, check.probe(tpl, _resp(path="/status", status=200, body="x PHPSESSID=deadbeef01 y")), "Low") is None
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
    # Lane S: the DSL compiles to all[eq[status,200], contains[body,literal]] — status==200 is a gate-B
    # protocol-status corroborator (not a discriminator) and the body literal is producer-authorable, so
    # the grammar REFUSES this third-party predicate. nuclei_http is a compile-time LEAD, never a FACT.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="... DEBUG_MODE=on ..."))) is None
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=500, body="DEBUG_MODE=on"))) is None
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
    # Lane S: even a FULL match mints nothing — a third-party template's status+literal predicate has no
    # positive discriminator, so the oracle REFUSES it. The entry remains a compile-time LEAD, never a FACT.
    assert _confirm(e, check.probe(tpl, _resp(path="/x", status=200, body="here: SECRET_MARKER"))) is None


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
    # Lane S: the raw-request template's bare body-literal predicate has no positive discriminator, so the
    # grammar REFUSES it — the compiled entry is a LEAD (headers/path/provenance above), never a FACT.
    assert _confirm(e, check.probe(_target_template(),
                                   _resp(path="/actuator/env", status=200, body='{"propertySources": []}')), "High") is None


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
    # OR of a supported, DISCRIMINATING body-regex branch and an UNSUPPORTED header regex: the header
    # branch is dropped, leaving a STRICTER match (a subset) -> sound. The surviving clause still carries
    # a discriminating body literal, so the mint stays grounded.
    tmpl = {
        "id": "or-drop", "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "or",
                  "matchers": [
                      {"type": "regex", "part": "body", "regex": ["ADMIN_PANEL_[0-9]+"]},
                      {"type": "regex", "part": "header", "regex": ["X-Thing"]},
                  ]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    # Only the body-regex clause survives; a single clause needs no all/any wrapper.
    assert res.entry.oracle.match_predicate == {"contains": [{"var": "body"}, "ADMIN_PANEL_"]}


def test_or_of_status_and_a_body_literal_degrades_status_cannot_fire_alone() -> None:
    # An OR that mixes status with a body literal is NOT discriminating: the status branch fires over any
    # benign 200 on its own. The template must DEGRADE rather than mint (status is only an AND-corroborator).
    tmpl = {
        "id": "or-status-literal", "info": {"name": "x", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "or",
                  "matchers": [
                      {"type": "status", "status": [200]},
                      {"type": "regex", "part": "body", "regex": ["SECRET_[0-9]+"]},
                  ]}],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported is False and res.entry is None
    assert "discriminating" in res.reason.lower()


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
    # status AND a discriminating body regex (an OR of status+literal would degrade — status can't fire
    # alone). The body literal makes the predicate discriminating; status corroborates.
    tmpl = (
        "id: det\ninfo:\n  name: n\n  severity: info\n"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/x'\n"
        "    matchers-condition: and\n    matchers:\n"
        "      - type: status\n        status:\n          - 200\n          - 302\n"
        "      - type: regex\n        part: body\n        regex:\n          - 'X-Marker: [0-9]+'\n"
    )
    a = compile_nuclei_template(tmpl).entry
    b = compile_nuclei_template(tmpl).entry
    assert a is not None and b is not None and a.model_dump() == b.model_dump()
    assert a.oracle.kind == "nuclei_http"
    assert a.oracle.match_predicate == {
        "all": [{"in": [{"var": "status"}, [200, 302]]}, {"contains": [{"var": "body"}, "X-Marker: "]}]
    }


def test_sub_floor_literal_is_refused_at_compile() -> None:
    # BLOCK 1: contains(body,"a") fires on "banana" — a 1-char literal is not a discriminating observable.
    # Both a dsl contains and a short body word must be refused (they carry no distinctive signature).
    dsl = {
        "id": "banana", "info": {"name": "n", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "dsl", "dsl": ['contains(body, "a")']}]}],
    }
    res = compile_nuclei_template(dsl)
    assert res.supported is False and res.entry is None
    assert "discriminating" in res.reason.lower()
    # a short body word is not a distinctive signature either -> degrades (does not mint via any path).
    word = {
        "id": "short-word", "info": {"name": "n", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"],
                  "matchers": [{"type": "word", "part": "body", "words": ["ok"]}]}],
    }
    res2 = compile_nuclei_template(word)
    assert res2.supported is False and res2.entry is None


def test_regex_core_terminates_at_a_max_gt_1_quantifier() -> None:
    # BLOCK 2: a char that may repeat (max>1) must END a run, not extend it. ab{2}cde matches "abbcde",
    # which does NOT contain "abcde"; the core must not be "abcde".
    from framework.v2.scanner.nuclei_compile import _regex_literal_core
    assert _regex_literal_core("ab{2}cde") is None          # runs "ab"(2) / "cde"(3), both < floor
    assert _regex_literal_core("ab{2,5}cde") is None
    assert _regex_literal_core("x{2,}yzw") is None           # "xxyzw" — was wrongly "xyzw" before
    # a clean prefix before a bounded class is still extracted; a clean run after a quantifier survives.
    assert _regex_literal_core("PHPSESSID=[a-f0-9]{10,}") == "PHPSESSID="
    assert _regex_literal_core("x{2,}abcd") == "abcd"
    # sanity: the crafted core is never a substring the pattern can dodge.
    import re as _re
    assert _re.fullmatch("ab{2}cde", "abbcde") and "abcde" not in "abbcde"


def test_raw_method_override_header_is_stripped() -> None:
    # BLOCK 4: a raw template must never smuggle an HTTP method-override onto the idempotent GET probe.
    tmpl = {
        "id": "raw-override", "info": {"name": "n", "severity": "info"},
        "http": [{
            "raw": ["GET /x HTTP/1.1\nHost: {{Hostname}}\nX-HTTP-Method-Override: DELETE\n"
                    "X-Method-Override: PUT\nAccept: application/json\n"],
            "matchers": [{"type": "word", "part": "body", "words": ["propertySources"]}],
        }],
    }
    res = compile_nuclei_template(tmpl)
    assert res.supported and res.entry is not None
    hdr_names = {n.lower() for n, _ in res.entry.oracle.request_headers}
    assert "x-http-method-override" not in hdr_names and "x-method-override" not in hdr_names
    assert dict(tuple(h) for h in res.entry.oracle.request_headers) == {"Accept": "application/json"}


def test_compiled_nuclei_http_entry_is_not_written_into_the_shipped_library() -> None:
    from framework.v2.scanner.library import LIBRARY_DIR
    before = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    # a discriminating status+regex template that DOES compile to a nuclei_http entry.
    compile_nuclei_template({
        "id": "x", "info": {"name": "n", "severity": "info"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/x"], "matchers-condition": "and",
                  "matchers": [{"type": "regex", "part": "body", "regex": ["TOKEN_[0-9]+"]},
                               {"type": "status", "status": [200]}]}],
    })
    after = {p.name for p in Path(LIBRARY_DIR).glob("*.json")}
    assert before == after and not any(n.startswith("nuclei-") for n in after)


# ---------------------------------------------------------------------------
# Wave B, slice B1 — breadth by INGESTION. A request that lists several FIXED probe paths compiles
# to one independent, oracle-re-verified LibraryEntry per path (more LEADs, same oracle, same
# discrimination gate). A compiled entry is a CHECK to run, never a fact: the fact exists only after
# VIGIL's OWN oracle re-fires over a real response — no nuclei byte is ever trusted.
# ---------------------------------------------------------------------------

_MULTI_PATH_TEMPLATE = (
    "id: multi-path-env\ninfo:\n  name: dotenv exposure\n  severity: high\n"
    "http:\n  - method: GET\n    path:\n"
    "      - '{{BaseURL}}/.env'\n      - '{{BaseURL}}/config/.env'\n      - '{{BaseURL}}/app/.env'\n"
    "      - '{{BaseURL}}/.env'\n"                      # a duplicate — must be de-duplicated
    "    matchers:\n      - type: word\n        part: body\n        words:\n          - 'DB_PASSWORD='\n"
)


def test_multi_path_request_compiles_one_entry_per_fixed_path() -> None:
    res = compile_nuclei_template(_MULTI_PATH_TEMPLATE)
    assert res.supported and res.entry is not None
    # back-compat: `.entry` is the first path and keeps the canonical id.
    assert res.entry.id == "nuclei-multi-path-env" and res.entry.oracle.probe_path == "/.env"
    assert res.entries[0] is res.entry
    # one entry per DISTINCT fixed path (the duplicate collapsed), each with a unique id.
    assert [e.oracle.probe_path for e in res.entries] == ["/.env", "/config/.env", "/app/.env"]
    assert len({e.id for e in res.entries}) == len(res.entries)
    # every entry shares the one compiled matcher (same signature), and compiled_entries flattens them.
    assert {e.oracle.signature for e in res.entries} == {"DB_PASSWORD="}
    assert len(compiled_entries([res])) == 3


def test_each_multi_path_entry_is_oracle_reverified_independently_and_mints_no_fact_from_bytes() -> None:
    res = compile_nuclei_template(_MULTI_PATH_TEMPLATE)
    tpl = _target_template()
    for entry in res.entries:
        p = entry.oracle.probe_path
        check = compile_entry(entry)
        # the signature really appears at THIS path -> VIGIL's own oracle re-fires -> a fact.
        hit = _confirm(entry, check.probe(tpl, _resp(path=p, status=200, body="DB_PASSWORD=hunter2")), "High")
        assert hit is not None and hit.confirmed_by == OracleKind.ACHIEVED_STATE, p
        # the path exists but the signature is ABSENT -> oracle does NOT fire -> no fact from the mere path.
        assert _confirm(entry, check.probe(tpl, _resp(path=p, status=200, body="nothing here")), "High") is None, p
        # a match at a DIFFERENT path never fires this entry's check (host/path pinned).
        assert _confirm(entry, check.probe(tpl, _resp(path="/elsewhere", status=200, body="DB_PASSWORD=x"))) is None


def test_ingested_multi_path_entries_carry_only_lead_semantics() -> None:
    """A compiled entry — for EVERY path — is a LibraryEntry (a check definition + provenance), never a
    Finding/fact object. The ingestion widens the set of CHECKS, not the set of facts."""
    res = compile_nuclei_template(_MULTI_PATH_TEMPLATE)
    for entry in res.entries:
        assert isinstance(entry, LibraryEntry)
        assert "nuclei-template:multi-path-env" in entry.references   # provenance retained
        assert entry.payload_family == "nuclei:multi-path-env"
        # the entry is a re-verification spec, not a verdict: it carries an oracle to RUN.
        assert entry.oracle.kind in ("signature", "nuclei_http")
        assert not hasattr(entry, "confirmed_by")


def test_multi_path_widening_is_deterministic() -> None:
    a = compile_nuclei_template(_MULTI_PATH_TEMPLATE)
    b = compile_nuclei_template(_MULTI_PATH_TEMPLATE)
    assert [e.id for e in a.entries] == [e.id for e in b.entries]
    assert [e.oracle.probe_path for e in a.entries] == [e.oracle.probe_path for e in b.entries]


def test_single_path_template_entries_is_just_the_one_entry() -> None:
    """Back-compat: a single-path template compiles to exactly one entry and ``entries == (entry,)``."""
    res = compile_nuclei_template(_TEMPLATE)
    assert res.supported and res.entry is not None
    assert res.entries == (res.entry,)
