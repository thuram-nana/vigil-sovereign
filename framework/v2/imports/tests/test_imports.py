"""
imports — external-tool importers (Wave 6).

Pins the load-bearing guarantees:

  * every supported format parses a captured third-party export into leads, and a
    MALFORMED export fails LOUD (never a silent no-op);
  * importing mints GROUNDING_INTEL leads into the world-model — labelled
    ``lead: True, unverified: True``, NEVER a ``FINDING`` node (prove-don't-guess);
  * the importer is DETERMINISTIC + IDEMPOTENT (claim-keyed obs_ids; a re-import does
    not inflate belief or node count);
  * the importer as a gated tool is REFUSED by a tripped kill-switch (fail-closed).
"""

from __future__ import annotations

import json

import pytest

from framework.v2.imports import (
    ImportAdapterError,
    available_formats,
    detect_format,
    import_report,
    parse_export,
)
from framework.v2.imports.tool import ImportFindingsTool
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import GROUNDING_GROUNDED, NodeKind

# --- captured third-party fixtures -----------------------------------------

NUCLEI = (
    '{"template-id":"CVE-2021-44228","matched-at":"http://t.example/api","host":"t.example",'
    '"info":{"name":"Log4j RCE","severity":"critical"}}\n'
    '{"template-id":"tech-detect","matched-at":"http://t.example/","info":{"name":"nginx","severity":"info"}}'
)
ZAP = json.dumps({"site": [{"@name": "http://t.example", "alerts": [
    {"alert": "Cross Site Scripting (Reflected)", "riskdesc": "High (Medium)",
     "instances": [{"uri": "http://t.example/search", "param": "q", "evidence": "<script>"}]},
]}]})
BURP = json.dumps({"issues": [
    {"name": "SQL injection", "severity": "high", "confidence": "certain",
     "url": "http://t.example/item?id=1", "issueDetail": "confirmed"},
]})
SQLMAP = (
    "sqlmap identified the following injection point(s):\n"
    "Parameter: id (GET)\n    Type: boolean-based blind\n    Type: time-based blind\n"
)
GENERIC = json.dumps({"findings": [
    {"bug_class": "idor", "url": "http://t.example/account?id=7", "severity": "high",
     "confirmed": False, "evidence": "swapped id"},
    {"type": "open_redirect", "location": "http://t.example/go", "severity": "medium"},
]})
SARIF = json.dumps({
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [
        {"id": "xss-rule", "properties": {"tags": ["security", "external/cwe/cwe-079"]}},
        {"id": "sqli-rule", "properties": {"cwe": "CWE-89"}},
        {"id": "secret-rule", "properties": {"tags": ["external/cwe/cwe-798"]}}]}},
        "results": [
            {"ruleId": "xss-rule", "level": "error", "message": {"text": "Reflected XSS"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "http://t.example/search"},
                                                 "region": {"startLine": 1}}}]},
            {"ruleId": "sqli-rule", "level": "warning", "message": {"text": "SQLi"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.py"},
                                                 "region": {"startLine": 42}}}]},
            {"ruleId": "passing", "kind": "pass", "message": {"text": "ok"}}]}]})


# --- parsing ----------------------------------------------------------------

@pytest.mark.parametrize("fmt,export,min_n,has_host", [
    ("nuclei", NUCLEI, 2, True), ("zap", ZAP, 1, True), ("burp", BURP, 1, True),
    ("sqlmap", SQLMAP, 1, False), ("generic", GENERIC, 2, True), ("sarif", SARIF, 2, True),
])
def test_each_format_parses(fmt, export, min_n, has_host) -> None:
    findings, tool = parse_export(fmt, export)
    assert len(findings) >= min_n
    assert all(f.bug_class for f in findings)
    # host is derived for the asset-tier observation on URL-bearing exports. sqlmap's
    # stdout carries only the parameter, not the URL, so no host is derivable — that's
    # honest, not a bug.
    if has_host:
        assert any(f.host == "t.example" for f in findings)
    else:
        assert all(not f.host for f in findings)


def test_available_formats_stable() -> None:
    assert available_formats() == ["burp", "generic", "nikto", "nuclei", "sarif", "sqlmap", "wapiti", "zap"]


def test_sarif_cwe_mapping_and_code_locations() -> None:
    findings, tool = parse_export("sarif", SARIF)
    by_class = {f.bug_class: f for f in findings}
    # a URL-located finding tagged CWE-79 maps to the CRUCIBLE `xss` class + a host -> re-verifiable
    assert "xss" in by_class
    assert by_class["xss"].host == "t.example" and by_class["xss"].severity == "High"
    # a file-located SAST finding (CWE-89) maps to `sqli` but has NO host (a code location, aggregation)
    assert "sqli" in by_class and by_class["sqli"].host == "" and "src/db.py" in by_class["sqli"].location
    # the passing result (kind=pass) is skipped
    assert "passing" not in by_class
    # every SARIF finding is tool_confirmed=False (a LEAD — CRUCIBLE re-verifies, never trusts say-so)
    assert all(not f.tool_confirmed for f in findings)


def test_sarif_non_sarif_json_is_loud() -> None:
    with pytest.raises(ImportAdapterError):
        parse_export("sarif", json.dumps({"findings": []}))   # a generic export, not SARIF


def test_unknown_format_is_loud() -> None:
    with pytest.raises(ImportAdapterError, match="unknown import format"):
        parse_export("nessus-xml", "<xml/>")


def test_malformed_export_is_loud() -> None:
    # non-JSON where JSON is promised -> a clean adapter error, never a silent []
    with pytest.raises(ImportAdapterError):
        parse_export("zap", "this is not json")
    with pytest.raises(ImportAdapterError):
        parse_export("generic", "not json at all")


def test_generic_skips_malformed_entries_without_aborting() -> None:
    export = json.dumps({"findings": [
        "not-an-object", {"bug_class": "xss", "url": "http://t.example/x"}]})
    findings, _ = parse_export("generic", export)
    assert len(findings) == 1 and findings[0].bug_class == "xss"


def test_detect_format() -> None:
    assert detect_format(NUCLEI) == "nuclei"
    assert detect_format(ZAP) == "zap"
    assert detect_format(BURP) == "burp"
    assert detect_format(SQLMAP) == "sqlmap"
    assert detect_format(GENERIC) == "generic"
    assert detect_format(SARIF) == "sarif"
    assert detect_format("") is None
    assert detect_format("plain text, no shape") is None


# --- ingest into the world-model: leads, never facts ------------------------

def test_import_mints_grounding_intel_leads_never_facts() -> None:
    world = WorldModel()
    result = import_report("generic", GENERIC, world=world)
    assert result.applied > 0 and result.dropped == 0
    assert len(result.leads) == 2

    # NOTHING became a FINDING node (a FINDING is reserved for oracle-confirmed).
    assert all(n.kind is not NodeKind.FINDING for n in world.all_nodes())
    # every written node/edge is GROUNDING_INTEL — real, collected, but not oracle-proof.
    assert world.node_count > 0
    for n in world.all_nodes():
        assert n.grounding != GROUNDING_GROUNDED
        assert n.provenance.startswith("intel:import:")
    for e in world.all_edges():
        assert e.grounding != GROUNDING_GROUNDED

    # the endpoint leads carry the explicit unverified label.
    endpoints = [n for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT]
    assert endpoints and all(n.attrs.get("lead") is True for n in endpoints)
    assert all(n.attrs.get("unverified") is True for n in endpoints)
    bug_classes = {n.attrs.get("bug_class") for n in endpoints}
    assert {"idor", "open_redirect"} <= bug_classes


def test_import_is_idempotent_and_deterministic() -> None:
    w1 = WorldModel()
    import_report("nuclei", NUCLEI, world=w1)
    n_after_first = w1.node_count
    # re-import the SAME export: claim-keyed obs_ids de-dup -> no new nodes.
    import_report("nuclei", NUCLEI, world=w1)
    assert w1.node_count == n_after_first

    # a fresh world from the same export yields identical node ids (pure of wallclock/rng).
    w2 = WorldModel()
    import_report("nuclei", NUCLEI, world=w2)
    assert {n.id for n in w1.all_nodes()} == {n.id for n in w2.all_nodes()}


def test_tool_confirmed_flag_never_promotes_to_fact() -> None:
    # a source tool that self-confirms (burp confidence=certain) is STILL a lead to us.
    world = WorldModel()
    import_report("burp", BURP, world=world)
    endpoints = [n for n in world.all_nodes() if n.kind is NodeKind.ENDPOINT]
    assert endpoints
    ep = endpoints[0]
    assert ep.attrs.get("tool_confirmed") is True   # the tool's own confidence, recorded
    assert ep.attrs.get("unverified") is True        # ... but a lead to CRUCIBLE
    assert ep.grounding != GROUNDING_GROUNDED


# --- persistence + enumeration ---------------------------------------------

def test_import_persists_and_reads_back(tmp_path) -> None:
    from framework.v2.api import reads
    from framework.v2.intel.store import IntelStore
    from framework.v2.memory.store import Store

    db = tmp_path / "m.db"
    factory = lambda: IntelStore(Store(db))  # noqa: E731

    world = WorldModel()
    import_report("generic", GENERIC, world=world, store=factory(),
                  engagement_slug="demo")

    view = reads.imports("demo", store_factory=factory)
    assert view["count"] >= 2
    assert all(row["unverified"] for row in view["leads"])
    assert {"idor", "open_redirect"} <= {row["bug_class"] for row in view["leads"]}
    # a different engagement sees none of them (scoped by slug).
    assert reads.imports("other", store_factory=factory)["count"] == 0


# --- the importer as a GATED tool ------------------------------------------

def _ctx(slug: str, world=None):
    from framework.v2.agents.tools.base import ToolContext
    return ToolContext(slug=slug, world=world)


def test_import_tool_runs_and_refuses_bad_args() -> None:
    tool = ImportFindingsTool(store_factory=lambda: None)  # hermetic: no persistence
    world = WorldModel()
    res = tool.run({"format": "generic", "report": GENERIC}, _ctx("demo", world))
    assert res.ok and res.output["applied"] > 0

    # a missing/undetectable format is a clean failed result, never a crash.
    bad = tool.run({"report": "still not detectable"}, _ctx("demo"))
    assert not bad.ok and "format" in bad.note
    # a non-dict args is handled.
    assert not tool.run("nope", _ctx("demo")).ok


def test_import_tool_refused_by_tripped_killswitch(tmp_path, monkeypatch) -> None:
    # route the kill-switch file to a tmp path so BOTH the trip and invoke_tool's check
    # read the same file — fully hermetic, no real targets/ write.
    from framework.v2.agents.tools.base import ToolContext
    from framework.v2.agents.tools.invoker import invoke_tool
    from framework.v2.agents.tools.base import ToolRegistry
    from framework.v2.authority.killswitch import KillSwitch
    from framework.v2.common import paths

    ks_file = tmp_path / "demo.killswitch"
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: ks_file)

    reg = ToolRegistry()
    reg.register(ImportFindingsTool(store_factory=lambda: None))

    # not tripped -> the import runs.
    world = WorldModel()
    ok = invoke_tool(reg, "import_findings", {"format": "generic", "report": GENERIC},
                     ToolContext(slug="demo", world=world))
    assert ok.ok and not ok.refused

    # tripped -> the SAME action is REFUSED at the kill-switch gate; nothing runs.
    KillSwitch("demo").trip("halt for test")
    world2 = WorldModel()
    refused = invoke_tool(reg, "import_findings", {"format": "generic", "report": GENERIC},
                          ToolContext(slug="demo", world=world2))
    assert refused.refused and refused.gate == "kill-switch"
    assert world2.node_count == 0  # the importer never touched the world-model
