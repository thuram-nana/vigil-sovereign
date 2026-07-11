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
    # raw request blob
    ("id: t\ninfo:\n  name: n\n  severity: info\nhttp:\n  - raw:\n      - 'GET /x HTTP/1.1'\n", "raw"),
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
