"""
Mock-coverage for the web-scanner sensors' run() — the SUBPROCESS / report-file
output-handling seam (Nuclei stdout JSONL, Nuclei template corpus, ZAP report file).

The parsers (``eval.adapters.parse_nuclei``/``parse_zap``) and each sensor's
``normalize`` step already have fixture coverage in ``test_web_scanner_sensors.py``.
What was ONLY exercised by the skip-gated live test (``test_nuclei_live_scan_of_localhost``,
needs a real ``nuclei``) is ``run()`` itself: building the fixed argv, invoking the
subprocess, and turning its stdout — or, for ZAP, the JSON report it writes to a temp
file — into a ``ToolResult``. Here we drive that exact code with a MOCKED
``subprocess.run`` + ``shutil.which`` (the ZAP mock writes the report the real tool
would) — the live binary stays gated; only its output-handling gets verified — then
feed the real ``run()`` result through the real ``normalize()`` into the world-model.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import NucleiTemplateSensor, NucleiWebSensor, ZapWebSensor
from framework.v2.sensors import web_scanner as ws_mod
from framework.v2.worldmodel.graph import WorldModel

TARGET = "http://127.0.0.1:9"

# A recorded `nuclei -jsonl` dump: two template matches on in-scope endpoints.
_NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "reflected-xss",
        "info": {"name": "Reflected XSS", "severity": "high"},
        "matched-at": "http://127.0.0.1:9/reflect?q=payload",
        "host": "127.0.0.1:9",
    }),
    json.dumps({
        "template-id": "sqli-error-based",
        "info": {"name": "Error-based SQLi", "severity": "critical"},
        "matched-at": "http://127.0.0.1:9/items?filter=x",
    }),
])

_ZAP_JSON = json.dumps({
    "@version": "2.14.0",
    "site": [{
        "@name": TARGET,
        "alerts": [{
            "pluginid": "40012",
            "alert": "Cross Site Scripting (Reflected)",
            "riskdesc": "High (Medium)",
            "instances": [{"uri": "http://127.0.0.1:9/reflect?q=1", "method": "GET",
                           "param": "q", "evidence": "<script>"}],
        }],
    }],
})


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _ctx() -> ToolContext:
    return ToolContext(slug="alpha")


def _mock_which(monkeypatch: pytest.MonkeyPatch, path: str = "/usr/bin/nuclei") -> None:
    monkeypatch.setattr(ws_mod.shutil, "which", lambda _b: path)


# ---------------------------------------------------------------------------
# NucleiWebSensor.run — the subprocess stdout -> ToolResult seam
# ---------------------------------------------------------------------------


def test_nuclei_run_packages_jsonl_and_builds_the_fixed_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_which(monkeypatch)
    calls: list[list[str]] = []

    def _run(argv, **_kw):
        calls.append(list(argv))
        return _FakeProc(stdout=_NUCLEI_JSONL)

    monkeypatch.setattr(ws_mod.subprocess, "run", _run)
    res = NucleiWebSensor().run({"target": TARGET}, _ctx())
    assert res.ok and res.output["jsonl"] == _NUCLEI_JSONL and res.output["target"] == TARGET
    argv = calls[0]
    assert argv[0] == "/usr/bin/nuclei"
    assert "-u" in argv and argv[argv.index("-u") + 1] == TARGET   # single scoped URL as -u's value
    assert "-jsonl" in argv and "-silent" in argv
    # nuclei contacts ProjectDiscovery's update host on startup by DEFAULT. This sensor is one of the
    # nuclei routes into the engine and was the one missing the suppression, so a scan here left the
    # host on every run — a no-egress breach with no gate to catch it, because it is the tool's own
    # default rather than anything the argv asked for. Pinned so a future edit cannot drop it silently.
    assert "-disable-update-check" in argv, "nuclei web sensor egresses a version check on every run"
    # And the second, subtler egress on the same route: nuclei's OAST/interactsh templates register
    # with a public interaction server (oast.pro) by default, which `-disable-update-check` does not
    # cover. Pinned so a future edit cannot re-open the no-egress breach it left before.
    assert "-no-interactsh" in argv, "nuclei web sensor egresses an OAST registration on every run"


def test_nuclei_run_result_flows_through_normalize_into_leads(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_which(monkeypatch)
    monkeypatch.setattr(ws_mod.subprocess, "run", lambda argv, **_kw: _FakeProc(stdout=_NUCLEI_JSONL))
    ctx = _ctx()
    sensor = NucleiWebSensor()
    res = sensor.run({"target": TARGET}, ctx)
    world = WorldModel()
    obs = sensor.normalize(res, ctx, seq=1)
    IntelIngest(world, engagement_slug="alpha").ingest(obs, seq=1)
    assert world.has_node("webapp:http://127.0.0.1:9")                      # the app itself
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=payload")  # XSS lead surface
    assert world.has_node("endpoint:http://127.0.0.1:9/items?filter=x")     # SQLi lead surface
    # a web-scanner match enters as a GROUNDING_INTEL lead, never a fact
    assert world.get_node("endpoint:http://127.0.0.1:9/reflect?q=payload").provenance.startswith("intel:")
    kinds = {o.obs_id.split("|", 1)[1] for o in obs if "|lead:" in o.obs_id}
    assert "lead:xss" in kinds and "lead:sqli_error_based" in kinds


def test_nuclei_run_empty_stdout_is_ok_but_mints_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    # a clean nuclei run (no matches) is a successful result carrying empty jsonl -> zero leads.
    _mock_which(monkeypatch)
    monkeypatch.setattr(ws_mod.subprocess, "run", lambda argv, **_kw: _FakeProc(stdout=""))
    ctx = _ctx()
    sensor = NucleiWebSensor()
    res = sensor.run({"target": TARGET}, ctx)
    assert res.ok and res.output["jsonl"] == ""
    assert sensor.normalize(res, ctx, seq=1) == []


def test_nuclei_run_timeout_and_oserror_degrade_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_which(monkeypatch)

    def _timeout(argv, **_kw):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1)

    monkeypatch.setattr(ws_mod.subprocess, "run", _timeout)
    res = NucleiWebSensor().run({"target": TARGET}, _ctx())
    assert not res.ok and "timed out" in (res.note or "")

    def _oserror(argv, **_kw):
        raise OSError("no exec")

    monkeypatch.setattr(ws_mod.subprocess, "run", _oserror)
    res = NucleiWebSensor().run({"target": TARGET}, _ctx())
    assert not res.ok and "failed to launch" in (res.note or "")


# ---------------------------------------------------------------------------
# NucleiTemplateSensor.run — corpus path, -t templates dir as a flag value
# ---------------------------------------------------------------------------


def test_nuclei_template_run_passes_templates_and_normalizes(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_which(monkeypatch)
    templates = tmp_path / "templates"
    templates.mkdir()
    calls: list[list[str]] = []

    def _run(argv, **_kw):
        calls.append(list(argv))
        return _FakeProc(stdout=_NUCLEI_JSONL)

    monkeypatch.setattr(ws_mod.subprocess, "run", _run)
    ctx = _ctx()
    sensor = NucleiTemplateSensor()
    res = sensor.run({"target": TARGET, "templates": str(templates)}, ctx)
    assert res.ok and res.output["jsonl"] == _NUCLEI_JSONL
    argv = calls[0]
    assert "-t" in argv and argv[argv.index("-t") + 1] == str(templates)   # corpus path as -t's value
    # The third nuclei route into the engine — same startup update check, same no-egress reason.
    assert "-disable-update-check" in argv, "nuclei template runner egresses a version check on every run"
    # And the same OAST/interactsh registration to oast.pro that the update check does not cover.
    assert "-no-interactsh" in argv, "nuclei template runner egresses an OAST registration on every run"
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(sensor.normalize(res, ctx, seq=1), seq=1)
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=payload")


# ---------------------------------------------------------------------------
# ZapWebSensor.run — the JSON-report-file output-handling seam (distinct from stdout)
# ---------------------------------------------------------------------------


def test_zap_run_reads_the_written_report_and_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    # ZAP is driven by an automation plan, and the plan's report job names the artifact — so the mock
    # READS THE PLAN to find out where to write, exactly as ZAP does. A mock that guessed the path
    # instead would keep passing even if the plan named a different file, which is the one break in
    # this seam worth catching. It also asserts the property the scan hangs on: the active scan is
    # aimed at the CONTEXT (every URL the crawl found), never at a single URL. A seed-node scan sends
    # ZERO parameter requests and returns a report identical to a clean target's — measured, and the
    # reason this sensor no longer uses `-quickurl`.
    monkeypatch.setattr(ws_mod.shutil, "which", lambda _b: "/usr/bin/zap.sh")

    def _run(argv, **_kw):
        assert "-quickurl" not in argv, "the quick scan active-scans only the node it is seeded with"
        plan = Path(argv[argv.index("-autorun") + 1]).read_text(encoding="utf-8")
        assert plan.index("- type: spider") < plan.index("- type: activeScan"), (
            "an active scan that runs before the crawl has only its seed node to attack")
        active = plan.split("- type: activeScan", 1)[1].split("  - type:", 1)[0]
        assert "context:" in active and "url:" not in active, (
            "the active scan must take the CONTEXT, not one URL")
        assert "failOnError: true" in plan, "an unreachable target must fail, not report clean"
        report = dict(line.strip().split(": ", 1) for line
                      in plan.split("- type: report", 1)[1].splitlines() if ": " in line)
        out_path = Path(report["reportDir"].strip("'")) / report["reportFile"].strip("'")
        out_path.write_text(_ZAP_JSON, encoding="utf-8")
        return _FakeProc(stdout="", returncode=0)

    monkeypatch.setattr(ws_mod.subprocess, "run", _run)
    ctx = _ctx()
    sensor = ZapWebSensor()
    res = sensor.run({"target": TARGET}, ctx)
    assert res.ok and res.output["json"] == _ZAP_JSON and res.output["target"] == TARGET
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(sensor.normalize(res, ctx, seq=1), seq=1)
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=1")


def test_zap_run_missing_report_is_a_clean_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    # subprocess ran but wrote no report (crash / bad invocation) -> a failed ToolResult, not a crash.
    monkeypatch.setattr(ws_mod.shutil, "which", lambda _b: "/usr/bin/zap.sh")
    monkeypatch.setattr(ws_mod.subprocess, "run", lambda argv, **_kw: _FakeProc(returncode=1))
    res = ZapWebSensor().run({"target": TARGET}, _ctx())
    assert not res.ok and "no JSON report" in (res.note or "")
