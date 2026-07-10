"""
Tests for Wave 4a — the Nuclei / ZAP / Burp WEB-SCANNER sensors.

These wrap the tested ``eval.adapters`` parsers as gated CRUCIBLE sensors whose output enters the
world-model as third-party LEADS (``GROUNDING_INTEL``), never facts. The normalize path is PURE
(reuse ``parse_nuclei``/``parse_zap``/``parse_burp`` -> the shared ``web_lead_observations`` minter),
tested offline against captured real-format fixtures; the subprocess/REST paths degrade cleanly when
the tool is absent; the active sensors are Tier-2, so ``run_sensor`` refuses them without
``ACTIVE_RECON`` and scope-gates their target, and Burp's REST pull is egress-gated. The lead->fact
BRIDGE (``confirm_web_lead``) is proven against a real local target, and proven NOT to rubber-stamp.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.agents.tools.base import ToolRegistry
from framework.v2.intel.ingest import IntelIngest
from framework.v2.intel.models import IntelSourceKind
from framework.v2.sensors import (
    BurpWebSensor,
    NucleiResultsImportSensor,
    NucleiTemplateSensor,
    NucleiWebSensor,
    WebLead,
    ZapWebSensor,
    confirm_web_lead,
    default_registry,
    run_sensor,
    web_lead_from_finding,
    web_lead_observations,
    web_leads_from_findings,
)
from framework.v2.sensors.web_scanner import _WEB_SCANNER_RELIABILITY, _is_safe_url_target
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import NodeKind

TARGET = "http://127.0.0.1:9"

# --- captured real-format tool outputs (tools NOT installed; the parsers are the tested unit). -----

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

_ZAP_SAMPLE = json.dumps({
    "@version": "2.14.0",
    "site": [{
        "@name": "http://127.0.0.1:9",
        "alerts": [{
            "pluginid": "40012",
            "alert": "Cross Site Scripting (Reflected)",
            "riskdesc": "High (Medium)",
            "instances": [{"uri": "http://127.0.0.1:9/reflect?q=1", "method": "GET", "param": "q", "evidence": "<script>"}],
        }, {
            "pluginid": "40018",
            "alert": "SQL Injection",
            "riskdesc": "High (Medium)",
            "instances": [{"uri": "http://127.0.0.1:9/items", "method": "GET", "param": "filter"}],
        }],
    }],
})

_BURP_SAMPLE = json.dumps({
    "issues": [
        {"name": "Cross-site scripting (reflected)", "severity": "high", "confidence": "certain",
         "origin": "http://127.0.0.1:9", "path": "/reflect?q=1",
         "issueDetail": "The value of the q request parameter is copied into the response."},
        {"name": "SQL injection", "severity": "high", "confidence": "firm",
         "url": "http://127.0.0.1:9/items?filter=1"},
    ],
})


# ---------------------------------------------------------------------------
# isolation + charter helpers (mirror the Nmap sensor tests)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def _write_charter(tmp_path: Path, slug: str, host: str) -> None:
    (tmp_path / slug).mkdir(parents=True, exist_ok=True)
    (tmp_path / slug / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        "Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        "| Host / Surface | Notes | Auth |\n|---|---|---|\n"
        f"| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")


def _grant_active_recon(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _ctx(slug: str = "alpha") -> ToolContext:
    return ToolContext(slug=slug)


def _ingest() -> tuple[WorldModel, IntelIngest]:
    world = WorldModel()
    return world, IntelIngest(world, engagement_slug="alpha")


# ===========================================================================
# normalize — offline, pure, real-format fixtures
# ===========================================================================


def test_nuclei_normalize_mints_webapp_and_endpoint_leads() -> None:
    world, ingest = _ingest()
    obs = NucleiWebSensor().normalize(
        ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    assert world.has_node("webapp:http://127.0.0.1:9")                       # the app itself
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=payload")   # the XSS lead surface
    assert world.has_node("endpoint:http://127.0.0.1:9/items?filter=x")      # the SQLi lead surface
    # the tool's template-id is FORMAT-normalized onto our vocabulary, never forced:
    #   'reflected-xss' -> known alias 'xss'; 'sqli-error-based' -> itself (out of vocabulary)
    kinds = {o.obs_id.split("|", 1)[1] for o in obs if "|lead:" in o.obs_id}
    assert "lead:xss" in kinds and "lead:sqli_error_based" in kinds


def test_zap_normalize_mints_leads() -> None:
    world, ingest = _ingest()
    obs = ZapWebSensor().normalize(
        ToolResult(ok=True, output={"json": _ZAP_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=1")
    assert world.has_node("endpoint:http://127.0.0.1:9/items?filter")   # param appended by the ZAP parser


def test_burp_normalize_mints_leads() -> None:
    world, ingest = _ingest()
    obs = BurpWebSensor(api_url="http://127.0.0.1:1337").normalize(
        ToolResult(ok=True, output={"json": _BURP_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=1")
    assert world.has_node("endpoint:http://127.0.0.1:9/items?filter=1")


def test_source_kind_and_reliability_are_web_scanner_moderate() -> None:
    obs = NucleiWebSensor().normalize(
        ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    assert obs, "expected observations"
    assert all(o.source_kind is IntelSourceKind.WEB_SCANNER for o in obs)
    assert all(o.source_reliability == _WEB_SCANNER_RELIABILITY for o in obs)
    # moderate: clearly below the active first-party sensors — a template match is not proof.
    assert 0.0 < _WEB_SCANNER_RELIABILITY.weight() < 0.8


def test_leads_project_as_grounding_intel_never_a_fact() -> None:
    world, ingest = _ingest()
    obs = NucleiWebSensor().normalize(
        ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    ep = world.get_node("endpoint:http://127.0.0.1:9/reflect?q=payload")
    assert ep.grounding == "intel" and ep.provenance.startswith("intel:")   # a LEAD, not oracle-grounded
    # a web sensor NEVER mints a FINDING node (that is the fact tier).
    assert not any(n.kind is NodeKind.FINDING for n in world.all_nodes())


def test_tool_confirmed_flag_is_recorded_but_not_trusted() -> None:
    # Burp's first issue is confidence 'certain' -> NormalizedFinding.confirmed True. The lead RECORDS
    # that (transparency) but the observation reliability stays moderate and nothing is confirmed.
    from framework.v2.eval.adapters import parse_burp
    leads = web_leads_from_findings(parse_burp(_BURP_SAMPLE), target=TARGET)
    certain = [l for l in leads if l.tool_confirmed]
    assert certain and certain[0].bug_class_raw.lower().startswith("cross-site scripting")
    obs = web_lead_observations(TARGET, parse_burp(_BURP_SAMPLE), seq=1, source="burp")
    assert all(o.source_reliability == _WEB_SCANNER_RELIABILITY for o in obs)   # 'certain' does NOT elevate


# ===========================================================================
# determinism / idempotency
# ===========================================================================


def test_normalize_is_deterministic() -> None:
    s = NucleiWebSensor()
    a = s.normalize(ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=7)
    b = s.normalize(ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=7)
    assert [o.obs_id for o in a] == [o.obs_id for o in b]


def test_reingest_is_idempotent_no_node_inflation() -> None:
    world, ingest = _ingest()
    obs = ZapWebSensor().normalize(
        ToolResult(ok=True, output={"json": _ZAP_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    ingest.ingest(obs, seq=1)
    n1 = len(world.all_nodes())
    ingest.ingest(obs, seq=1)   # replay the same batch
    assert len(world.all_nodes()) == n1   # claim-keyed obs_ids -> no new nodes


def test_reordering_findings_yields_same_observation_ids() -> None:
    from framework.v2.eval.adapters import parse_nuclei
    findings = parse_nuclei(_NUCLEI_SAMPLE)
    forward = {o.obs_id for o in web_lead_observations(TARGET, findings, seq=1, source="nuclei")}
    reverse = {o.obs_id for o in web_lead_observations(TARGET, list(reversed(findings)), seq=1, source="nuclei")}
    assert forward == reverse


# ===========================================================================
# scope-tight — an off-host finding never mints
# ===========================================================================


def test_off_host_finding_is_not_minted() -> None:
    from framework.v2.eval.validation import NormalizedFinding
    findings = [
        NormalizedFinding(tool="zap", bug_class="xss", location="http://127.0.0.1:9/a?q=1"),
        NormalizedFinding(tool="zap", bug_class="sqli", location="http://evil.example.com/x?y=1"),
    ]
    obs = web_lead_observations(TARGET, findings, seq=1, source="zap")
    ids = [o.subject.node_id for o in obs]
    assert "endpoint:http://127.0.0.1:9/a?q=1" in ids
    assert not any("evil.example.com" in i for i in ids)   # SCOPE-TIGHT: the off-host lead is dropped


def test_web_leads_from_findings_drops_off_host() -> None:
    from framework.v2.eval.validation import NormalizedFinding
    findings = [
        NormalizedFinding(tool="nuclei", bug_class="xss", location="http://127.0.0.1:9/a?q=1"),
        NormalizedFinding(tool="nuclei", bug_class="rce", location="http://elsewhere.test/z"),
    ]
    leads = web_leads_from_findings(findings, target=TARGET)
    assert len(leads) == 1 and leads[0].location == "http://127.0.0.1:9/a?q=1"


def test_scheme_less_foreign_host_is_dropped_not_planted() -> None:
    # nuclei's ssl/network/tcp/dns templates emit scheme-less host:port `matched-at` values. A foreign
    # one must be dropped (symmetric with require_in_scope), not read as a bare in-scope path — else it
    # plants an out-of-scope asset in the world-model. A genuine relative path stays in-scope.
    from framework.v2.eval.validation import NormalizedFinding
    findings = [
        NormalizedFinding(tool="nuclei", bug_class="exposure", location="evil.example.net:443"),
        NormalizedFinding(tool="nuclei", bug_class="exposure", location="10.9.9.9:22"),
        NormalizedFinding(tool="nuclei", bug_class="xss", location="/in/scope/path?q=1"),  # relative -> kept
    ]
    obs = web_lead_observations(TARGET, findings, seq=1, source="nuclei")
    ids = [o.subject.node_id for o in obs]
    assert not any("evil.example.net" in i or "10.9.9.9" in i for i in ids)   # foreign hosts dropped
    assert any("/in/scope/path" in i for i in ids)                             # relative path kept


# ===========================================================================
# malformed / graceful degradation (normalize)
# ===========================================================================


@pytest.mark.parametrize("bad", ["", "not json at all", '{"template-id":"x"}\nnot-json-line'])
def test_nuclei_malformed_output_yields_no_observations(bad: str) -> None:
    assert NucleiWebSensor().normalize(
        ToolResult(ok=True, output={"jsonl": bad, "target": TARGET}), _ctx(), seq=1) == []


def test_zap_and_burp_malformed_output_yields_no_observations() -> None:
    assert ZapWebSensor().normalize(
        ToolResult(ok=True, output={"json": '{"no":"site"}', "target": TARGET}), _ctx(), seq=1) == []
    assert BurpWebSensor(api_url="http://x").normalize(
        ToolResult(ok=True, output={"json": "<html>not json</html>", "target": TARGET}), _ctx(), seq=1) == []


def test_normalize_with_missing_output_or_target_yields_nothing() -> None:
    s = NucleiWebSensor()
    assert s.normalize(ToolResult(ok=True, output=None), _ctx(), seq=1) == []
    assert s.normalize(ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE}), _ctx(), seq=1) == []   # no target
    assert web_lead_observations("", [], seq=1, source="nuclei") == []


# ===========================================================================
# run() — graceful absence + target validation (subprocess/REST NOT invoked)
# ===========================================================================


def test_nuclei_absent_binary_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.sensors import web_scanner
    monkeypatch.setattr(web_scanner.shutil, "which", lambda _: None)
    res = NucleiWebSensor().run({"target": TARGET}, _ctx())
    assert not res.ok and "not on PATH" in (res.note or "")


def test_zap_absent_binaries_degrade_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.sensors import web_scanner
    monkeypatch.setattr(web_scanner.shutil, "which", lambda _: None)
    res = ZapWebSensor().run({"target": TARGET}, _ctx())
    assert not res.ok and "not on PATH" in (res.note or "")


def test_burp_no_url_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRUCIBLE_BURP_URL", raising=False)
    res = BurpWebSensor(api_url="").run({"target": TARGET}, _ctx())
    assert not res.ok and "no Burp REST URL" in (res.note or "")


def test_missing_target_is_a_failed_result_not_a_crash() -> None:
    for sensor in (NucleiWebSensor(), ZapWebSensor(), BurpWebSensor(api_url="http://x"),
                   NucleiTemplateSensor(), NucleiResultsImportSensor()):
        res = sensor.run({}, _ctx())
        assert not res.ok and "target" in (res.note or "")


@pytest.mark.parametrize("bad", [
    "-u", "--config=x", "ftp://127.0.0.1/", "127.0.0.1", "http://127.0.0.1 -x", "http://",
    "http://127.0.0.1/\t-o/tmp/x",
])
def test_unsafe_url_targets_are_refused_before_the_network(bad: str) -> None:
    assert _is_safe_url_target(bad) is False
    res = NucleiWebSensor().run({"target": bad}, _ctx())
    assert not res.ok


@pytest.mark.parametrize("good", ["http://127.0.0.1:9", "https://app.example.com/path?q=1"])
def test_safe_url_targets_accepted(good: str) -> None:
    assert _is_safe_url_target(good) is True


def test_nuclei_templates_requires_existing_templates_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # a good target but a missing/flag-like templates path fails before nuclei is consulted
    monkeypatch.setattr("framework.v2.sensors.web_scanner.shutil.which", lambda _: "/usr/bin/nuclei")
    res = NucleiTemplateSensor().run({"target": TARGET, "templates": str(tmp_path / "nope")}, _ctx())
    assert not res.ok and "not found" in (res.note or "")
    res2 = NucleiTemplateSensor().run({"target": TARGET, "templates": "-t"}, _ctx())
    assert not res2.ok and "templates" in (res2.note or "")


def test_nuclei_import_reads_a_results_file(tmp_path: Path) -> None:
    f = tmp_path / "nuclei.jsonl"
    f.write_text(_NUCLEI_SAMPLE, encoding="utf-8")
    res = NucleiResultsImportSensor().run({"target": TARGET, "results_file": str(f)}, _ctx())
    assert res.ok
    obs = NucleiResultsImportSensor().normalize(res, _ctx(), seq=1)
    assert any("endpoint:http://127.0.0.1:9/reflect?q=payload" == o.subject.node_id for o in obs)


def test_nuclei_import_missing_file_degrades_cleanly(tmp_path: Path) -> None:
    res = NucleiResultsImportSensor().run({"target": TARGET, "results_file": str(tmp_path / "nope.jsonl")}, _ctx())
    assert not res.ok and "not found" in (res.note or "")


# ===========================================================================
# gating through run_sensor (the fail-closed chain)
# ===========================================================================


def test_web_sensors_registered_in_default_registry() -> None:
    reg = default_registry()
    for name in ("nuclei_web", "nuclei_templates", "nuclei_import", "zap_web", "burp_web"):
        assert name in reg


def test_active_web_sensor_refused_without_entitlement(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "nuclei_web", {"target": TARGET}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "entitlement"
    assert res.observations == [] and res.applied == 0
    assert not world.has_node("webapp:http://127.0.0.1:9")   # a refused sensor mints NOTHING


def test_out_of_scope_target_refused_and_mints_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)                       # entitlement passes; scope must still refuse
    _write_charter(tmp_path, "alpha", "127.0.0.1")         # only 127.0.0.1 is in charter
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "nuclei_web", {"target": "http://10.9.9.9/"}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "scope"
    assert res.observations == [] and len(world.all_nodes()) == 0


def test_burp_rest_pull_is_egress_gated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _write_charter(tmp_path, "alpha", "127.0.0.1")          # the Burp server host is NOT in charter
    reg = ToolRegistry()
    reg.register(BurpWebSensor(api_url="http://burp.internal:1337"))
    world, ingest = _ingest()
    res = run_sensor(reg, "burp_web", {"target": "http://127.0.0.1/"}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "egress"   # the Burp host must be charter-allowlisted
    assert res.observations == []


def test_nuclei_import_is_tier1_but_still_scope_gated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # No entitlement grant at all: the offline importer needs none (Tier-1), but its target is still
    # scope-gated, so an out-of-scope import is refused before anything enters the world-model.
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    f = tmp_path / "nuclei.jsonl"
    f.write_text(_NUCLEI_SAMPLE, encoding="utf-8")
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "nuclei_import",
                     {"target": "http://10.9.9.9/", "results_file": str(f)}, _ctx(), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "scope"
    assert len(world.all_nodes()) == 0


# ===========================================================================
# the LEAD -> FACT bridge (an oracle re-verifies; the tool is never trusted)
# ===========================================================================


def _local_differential_context(handler):
    """A REAL differential FindingContext gathered by hitting a local demo target — the independent,
    first-party evidence CRUCIBLE would collect when re-probing a lead (NOT the tool's say-so)."""
    from framework.v2.verify.adapter import FindingContext
    from framework.v2.verify.confirmation import _http_get, _local_server

    with _local_server(handler) as base:
        baseline = _http_get(base, "obsidian-no-such-name")
        mutated = _http_get(base, "x' OR '1'='1")
    return FindingContext.from_http_responses(
        baseline, mutated, bug_class="boolean_sqli",
        discriminator={"dimensions": ["status", "length", "lexical"]})


def test_confirm_web_lead_promotes_with_independent_evidence() -> None:
    from framework.v2.verify.confirmation import DifferentialDemoHandler
    from framework.v2.verify.models import OracleKind

    lead = WebLead(tool="nuclei", bug_class="sqli", bug_class_raw="sql-injection",
                   location="/search?q=", target=TARGET, severity="high")
    ctx = _local_differential_context(DifferentialDemoHandler)
    confirmed = confirm_web_lead(lead, ctx)
    assert confirmed is not None and confirmed.confirmed is True
    assert confirmed.confirmed_by is OracleKind.DIFFERENTIAL_RESPONSE   # an oracle FIRED, not the tool


def test_confirm_web_lead_none_against_safe_target() -> None:
    from framework.v2.verify.confirmation import SafeDemoHandler

    lead = WebLead(tool="nuclei", bug_class="sqli", bug_class_raw="sql-injection",
                   location="/search?q=", target=TARGET, severity="high")
    # the same lead, re-probed against a NON-injectable twin: no differential, nothing fires.
    assert confirm_web_lead(lead, _local_differential_context(SafeDemoHandler)) is None


def test_confirm_web_lead_does_not_rubber_stamp_the_tool_say_so() -> None:
    from framework.v2.verify.adapter import FindingContext

    lead = WebLead(tool="burp", bug_class="sqli", bug_class_raw="SQL injection",
                   location="/items?filter=1", target=TARGET, severity="high", tool_confirmed=True)
    # a context carrying ONLY the tool's class (no oracle-grade evidence) can never confirm —
    # prove-don't-guess: a bare tool match is not proof, even when Burp said 'certain'.
    assert confirm_web_lead(lead, FindingContext(bug_class="sqli")) is None


def test_sensor_output_carries_no_confirmed_finding() -> None:
    # Everything a web sensor produces is a GROUNDING_INTEL observation; there is no path from a bare
    # normalize() to a ConfirmedFinding.
    obs = NucleiWebSensor().normalize(
        ToolResult(ok=True, output={"jsonl": _NUCLEI_SAMPLE, "target": TARGET}), _ctx(), seq=1)
    assert obs and all(o.source_kind is IntelSourceKind.WEB_SCANNER for o in obs)
    assert all(not getattr(o, "confirmed", False) for o in obs)   # Observations have no 'confirmed' field


# ===========================================================================
# WebLead vocabulary honesty
# ===========================================================================


def test_web_lead_oracle_provable_flag_is_honest() -> None:
    from framework.v2.eval.validation import NormalizedFinding
    xss = web_lead_from_finding(NormalizedFinding(tool="nuclei", bug_class="reflected-xss", location="/a?q=1"), target=TARGET)
    assert xss.bug_class == "xss" and xss.oracle_provable is True and xss.canonical_bug_class == "xss"
    weird = web_lead_from_finding(NormalizedFinding(tool="nuclei", bug_class="tls-version-1-0-detected", location="/"), target=TARGET)
    assert weird.oracle_provable is False and weird.canonical_bug_class is None   # unmapped -> honest lead


# ===========================================================================
# live (opt-in) — a real Nuclei scan of loopback, gated end to end
# ===========================================================================


_LIVE = os.environ.get("CRUCIBLE_LIVE_NUCLEI") and shutil.which("nuclei")


@pytest.mark.skipif(not _LIVE, reason="set CRUCIBLE_LIVE_NUCLEI=1 and have nuclei to run the live scan")
def test_nuclei_live_scan_of_localhost(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _grant_active_recon(monkeypatch)
    _write_charter(tmp_path, "alpha", "127.0.0.1")
    world, ingest = _ingest()
    res = run_sensor(default_registry(), "nuclei_web", {"target": "http://127.0.0.1"},
                     _ctx(), ingest=ingest, seq=1)
    assert res.result.ok or not res.result.refused   # gated through; findings depend on what's listening
