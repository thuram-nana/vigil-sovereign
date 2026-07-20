"""
Mock-coverage for TsharkFlowSensor.run() — the SUBPROCESS output-handling seam.

``parse_tshark_fields`` and ``_observations_from_records`` already have fixture
coverage in ``test_tshark_sensor.py``. What was ONLY exercised by the skip-gated
live tests (``test_real_tshark_reads_a_synack_pcap_and_mints_the_service`` /
``test_tshark_reads_a_real_pcap_end_to_end``, both needing a real ``tshark``) is
``run()`` itself: building the fixed ``-T fields`` argv (with every ``-e`` field),
invoking the subprocess, and turning its stdout / exit code into a ``ToolResult``.
Here we drive that exact code with a MOCKED ``subprocess.run`` + ``shutil.which``
over a real (but never-read) temp pcap path — the live binary stays gated; only its
output-handling gets verified — then feed the real ``run()`` result through the real
``normalize()`` into the world-model, covering the full run->normalize seam offline.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import TsharkFlowSensor
from framework.v2.sensors import tshark as tshark_mod
from framework.v2.sensors.tshark import _FIELDS
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind

_IDX = {"ip_src": 0, "ip_dst": 1, "ip6_src": 2, "ip6_dst": 3, "syn": 4, "ack": 5,
        "tcp_sport": 6, "qname": 7, "dns_a": 8, "dns_aaaa": 9, "sni": 10}


def _line(**vals) -> str:
    row = [""] * len(_IDX)
    for k, v in vals.items():
        row[_IDX[k]] = str(v)
    return "\t".join(row)


# A canned `tshark -T fields` dump: a SYN-ACK (open service), a DNS answer, and a TLS SNI.
_DUMP = "\n".join([
    _line(ip_src="10.0.0.5", ip_dst="10.0.0.9", syn="True", ack="True", tcp_sport="443"),
    _line(ip_src="10.0.0.2", ip_dst="10.0.0.9", qname="example.com", dns_a="93.184.216.34"),
    _line(ip_src="10.0.0.9", ip_dst="10.0.0.5", sni="secure.example.com"),
])


class _FakeProc:
    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _mock_tshark(monkeypatch: pytest.MonkeyPatch, proc: _FakeProc) -> list[list[str]]:
    calls: list[list[str]] = []
    monkeypatch.setattr(tshark_mod.shutil, "which", lambda _b: "/usr/bin/tshark")

    def _run(argv, **_kw):
        calls.append(list(argv))
        return proc

    monkeypatch.setattr(tshark_mod.subprocess, "run", _run)
    return calls


def _pcap(tmp_path: Path) -> str:
    p = tmp_path / "capture.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1")   # a real path so os.path.isfile passes; never actually read
    return str(p)


def test_run_builds_the_fields_argv_and_packages_stdout(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _mock_tshark(monkeypatch, _FakeProc(stdout=_DUMP))
    pcap = _pcap(tmp_path)
    res = TsharkFlowSensor().run({"pcap": pcap, "display_filter": "tcp"}, ToolContext(slug="alpha"))
    assert res.ok
    assert res.output["fields"] == _DUMP and res.output["pcap"] == pcap
    argv = calls[0]
    # fixed argv: read the pcap, tab-separated fields, every declared -e field, and the display filter.
    assert argv[:6] == ["/usr/bin/tshark", "-r", pcap, "-T", "fields", "-E"]
    for f in _FIELDS:
        assert f in argv                         # every column requested
    assert "-Y" in argv and argv[argv.index("-Y") + 1] == "tcp"


def test_run_result_flows_through_normalize_into_the_world_model(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_tshark(monkeypatch, _FakeProc(stdout=_DUMP))
    ctx = ToolContext(slug="alpha")
    sensor = TsharkFlowSensor()
    res = sensor.run({"pcap": _pcap(tmp_path)}, ctx)
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(sensor.normalize(res, ctx, seq=1), seq=1)
    # open service from the SYN-ACK
    assert world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    # DNS resolution edge
    assert world.get_edge("domain:example.com", "host:93.184.216.34", EdgeKind.RESOLVES_TO) is not None
    # TLS SNI domain
    assert world.has_node("domain:secure.example.com")
    # a packet-capture observation is GROUNDING_INTEL, never oracle-proof
    assert world.get_node("domain:example.com").provenance.startswith("intel:")


def test_run_nonzero_exit_with_empty_stdout_is_a_clean_failure(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _mock_tshark(monkeypatch, _FakeProc(stdout="", stderr="unrecognized file format", returncode=2))
    res = TsharkFlowSensor().run({"pcap": _pcap(tmp_path)}, ToolContext(slug="alpha"))
    assert not res.ok and "exited 2" in (res.note or "")


def test_run_nonzero_exit_but_with_stdout_is_still_ok(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # tshark can exit non-zero on a truncated capture yet still emit parseable rows — keep them.
    _mock_tshark(monkeypatch, _FakeProc(stdout=_DUMP, stderr="cut short", returncode=2))
    res = TsharkFlowSensor().run({"pcap": _pcap(tmp_path)}, ToolContext(slug="alpha"))
    assert res.ok and res.output["fields"] == _DUMP


def test_run_subprocess_timeout_degrades_cleanly(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tshark_mod.shutil, "which", lambda _b: "/usr/bin/tshark")

    def _boom(argv, **_kw):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=1)

    monkeypatch.setattr(tshark_mod.subprocess, "run", _boom)
    res = TsharkFlowSensor().run({"pcap": _pcap(tmp_path)}, ToolContext(slug="alpha"))
    assert not res.ok and "timed out" in (res.note or "")


def test_run_subprocess_launch_oserror_degrades_cleanly(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tshark_mod.shutil, "which", lambda _b: "/usr/bin/tshark")

    def _boom(argv, **_kw):
        raise OSError("permission denied")

    monkeypatch.setattr(tshark_mod.subprocess, "run", _boom)
    res = TsharkFlowSensor().run({"pcap": _pcap(tmp_path)}, ToolContext(slug="alpha"))
    assert not res.ok and "failed to launch" in (res.note or "")
