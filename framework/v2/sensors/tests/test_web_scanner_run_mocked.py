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
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(sensor.normalize(res, ctx, seq=1), seq=1)
    assert world.has_node("endpoint:http://127.0.0.1:9/reflect?q=payload")


# ---------------------------------------------------------------------------
# ZapWebSensor.run — the JSON-report-file output-handling seam (distinct from stdout)
# ---------------------------------------------------------------------------


def test_zap_run_reads_the_written_report_and_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    # ZAP writes its JSON report to the -quickout path; the mock plays the tool by writing
    # exactly that file, so run()'s report-read output-handling is exercised end to end.
    monkeypatch.setattr(ws_mod.shutil, "which", lambda _b: "/usr/bin/zap.sh")

    def _run(argv, **_kw):
        out_path = Path(argv[argv.index("-quickout") + 1])
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
