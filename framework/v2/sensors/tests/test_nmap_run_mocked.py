"""
Mock-coverage for NmapServiceSensor.run() — the SUBPROCESS output-handling seam.

The pure XML parser (``parse_nmap_xml``) and the ``normalize`` step already have
fixture coverage in ``test_nmap_sensor.py``. What was ONLY exercised by the
skip-gated live test (``test_nmap_live_scan_of_localhost``, needs a real ``nmap``)
is ``run()`` itself: building the fixed argv, invoking the subprocess, and turning
its stdout / exit code into a ``ToolResult``. Here we drive that exact code with a
MOCKED ``subprocess.run`` + ``shutil.which`` — the live binary stays gated; only its
output-handling gets verified — then feed the real ``run()`` result through the real
``normalize()`` into the world-model, covering the full run->normalize seam offline.
"""

from __future__ import annotations

import subprocess

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import NmapServiceSensor
from framework.v2.sensors import nmap as nmap_mod
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind

# A minimal but representative `nmap -oX -` document: one up host, one open service
# with product/version, one closed port (not minted), one service-less open port.
_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/></port>
    </ports>
  </host>
</nmaprun>
"""


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _mock_nmap(monkeypatch: pytest.MonkeyPatch, proc: _FakeProc) -> list[list[str]]:
    """Pretend nmap is installed and returns ``proc``; capture the argv it was called with."""
    calls: list[list[str]] = []
    monkeypatch.setattr(nmap_mod.shutil, "which", lambda _b: "/usr/bin/nmap")

    def _run(argv, **_kw):  # signature mirrors subprocess.run's positional argv
        calls.append(list(argv))
        return proc

    monkeypatch.setattr(nmap_mod.subprocess, "run", _run)
    return calls


def test_run_packages_stdout_into_a_toolresult_and_builds_the_fixed_argv(
        monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _mock_nmap(monkeypatch, _FakeProc(stdout=_XML))
    res = NmapServiceSensor().run({"target": "127.0.0.1", "ports": "1-1024"}, ToolContext(slug="alpha"))
    assert res.ok
    assert res.output["xml"] == _XML and res.output["target"] == "127.0.0.1"
    argv = calls[0]
    # fixed, no-shell argv: XML to stdout, no-ping, service-version, ports as -p's value,
    # end-of-options guard, then the single scoped target as the final token.
    assert argv[:5] == ["/usr/bin/nmap", "-oX", "-", "-Pn", "-sV"]
    assert "-p" in argv and argv[argv.index("-p") + 1] == "1-1024"
    assert argv[-2:] == ["--", "127.0.0.1"]


def test_run_result_flows_through_normalize_into_the_world_model(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_nmap(monkeypatch, _FakeProc(stdout=_XML))
    ctx = ToolContext(slug="alpha")
    sensor = NmapServiceSensor()
    res = sensor.run({"target": "127.0.0.1"}, ctx)   # no ports -> no -p token
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(sensor.normalize(res, ctx, seq=1), seq=1)
    # the full run->normalize seam mints the same shape the pure-normalize test asserts
    assert world.has_node("host:127.0.0.1")
    assert world.has_node("service:127.0.0.1:443/tcp")
    assert world.get_edge("service:127.0.0.1:443/tcp", "application:nginx", EdgeKind.RUNS) is not None
    assert world.has_node("service:127.0.0.1:8080/tcp")      # service-less open port still mints
    assert not world.has_node("service:127.0.0.1:22/tcp")    # the CLOSED port does not
    # a sensor mints GROUNDING_INTEL, never a fact
    assert world.get_node("service:127.0.0.1:443/tcp").provenance.startswith("intel:")


def test_run_with_empty_stdout_is_a_clean_failure_not_a_crash(
        monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_nmap(monkeypatch, _FakeProc(stdout="   \n", stderr="host down", returncode=1))
    res = NmapServiceSensor().run({"target": "127.0.0.1"}, ToolContext(slug="alpha"))
    assert not res.ok and "no XML" in (res.note or "")


def test_run_subprocess_timeout_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_mod.shutil, "which", lambda _b: "/usr/bin/nmap")

    def _boom(argv, **_kw):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1)

    monkeypatch.setattr(nmap_mod.subprocess, "run", _boom)
    res = NmapServiceSensor().run({"target": "127.0.0.1"}, ToolContext(slug="alpha"))
    assert not res.ok and "timed out" in (res.note or "")


def test_run_subprocess_launch_oserror_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_mod.shutil, "which", lambda _b: "/usr/bin/nmap")

    def _boom(argv, **_kw):
        raise OSError("exec format error")

    monkeypatch.setattr(nmap_mod.subprocess, "run", _boom)
    res = NmapServiceSensor().run({"target": "127.0.0.1"}, ToolContext(slug="alpha"))
    assert not res.ok and "failed to launch" in (res.note or "")


def test_run_zero_exit_but_empty_stdout_is_still_a_clean_failure(
        monkeypatch: pytest.MonkeyPatch) -> None:
    # nmap exit 0 but empty stdout (e.g. everything filtered) — still no XML, still a clean failure,
    # and an empty-XML result through normalize is a no-op (belt and suspenders).
    _mock_nmap(monkeypatch, _FakeProc(stdout="", returncode=0))
    sensor = NmapServiceSensor()
    ctx = ToolContext(slug="alpha")
    res = sensor.run({"target": "127.0.0.1"}, ctx)
    assert not res.ok
    assert sensor.normalize(ToolResult(ok=True, output={"xml": ""}), ctx, seq=1) == []
