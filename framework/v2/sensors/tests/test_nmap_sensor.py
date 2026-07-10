"""
Tests for Wave 2.2 — the Nmap network-service sensor.

Nmap is the first mature external engine driven as a gated CRUCIBLE sensor. The normalize path is
PURE (parse -oX XML -> the shared service_observations minter), tested offline against a fixture; the
subprocess path degrades cleanly when the binary is absent; and the sensor is Tier-2 active, so
run_sensor refuses it without the ACTIVE_RECON entitlement. A live scan runs only opt-in.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import NmapServiceSensor, default_registry, parse_nmap_xml, run_sensor
from framework.v2.sensors.nmap import _NMAP_RELIABILITY, _is_single_host_target
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind


# A representative `nmap -oX -` fragment: an up host with an open service (product/version), a closed
# port (not minted), a service-less open port, and a separate down host (not minted).
_FIXTURE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.example.com"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.9" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")


def test_parse_nmap_xml_extracts_up_hosts_and_ports() -> None:
    parsed = parse_nmap_xml(_FIXTURE_XML)
    assert len(parsed) == 1                       # the down host is dropped
    host, services = parsed[0]
    assert host == "10.0.0.5"                     # the IP address, not the hostname
    ports = {s["port"]: s for s in services}
    assert set(ports) == {443, 22, 8080}          # all ports parsed; state filtering is the minter's job
    assert ports[443]["product"] == "nginx" and ports[443]["service"] == "https"
    assert ports[22]["state"] == "closed"


def test_nmap_normalize_mints_the_same_shape_as_the_declared_sensor() -> None:
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    s = NmapServiceSensor()
    obs = s.normalize(ToolResult(ok=True, output={"xml": _FIXTURE_XML}), ToolContext(slug="alpha"), seq=1)
    ingest.ingest(obs, seq=1)
    # HOST + open SERVICE nodes + HOSTS edge + SERVICE--RUNS-->application (product known)
    assert world.has_node("host:10.0.0.5")
    assert world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    assert world.get_edge("service:10.0.0.5:443/tcp", "application:nginx", EdgeKind.RUNS) is not None
    assert world.has_node("service:10.0.0.5:8080/tcp")     # the service-less open port still mints
    assert not world.has_node("service:10.0.0.5:22/tcp")   # the CLOSED port does not
    # a sensor mints GROUNDING_INTEL, never a fact
    assert world.get_node("service:10.0.0.5:443/tcp").provenance.startswith("intel:")


def test_nmap_service_descriptor_lands_on_the_service_node() -> None:
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(
        NmapServiceSensor().normalize(
            ToolResult(ok=True, output={"xml": _FIXTURE_XML}), ToolContext(slug="alpha"), seq=1),
        seq=1)
    svc = world.get_node("service:10.0.0.5:443/tcp")
    assert svc.attrs.get("port") == 443 and svc.attrs.get("product") == "nginx"
    assert "port" not in world.get_node("host:10.0.0.5").attrs   # host not polluted (W2.1 fix reused)


def test_nmap_source_reliability_is_active_first_party() -> None:
    # a scan we ran directly is a reliable source (Admiralty A), content probably-true (C2) — the
    # W2.3 oracle still has to re-verify "open" before it is a fact.
    obs = NmapServiceSensor().normalize(
        ToolResult(ok=True, output={"xml": _FIXTURE_XML}), ToolContext(slug="alpha"), seq=1)
    assert all(o.source == "nmap" and o.source_reliability == _NMAP_RELIABILITY for o in obs)


@pytest.mark.parametrize("bad", ["", "not xml at all", "<nmaprun><host></nmaprun>", "<html/>"])
def test_nmap_malformed_or_empty_xml_yields_no_observations(bad: str) -> None:
    assert parse_nmap_xml(bad) == []
    s = NmapServiceSensor()
    assert s.normalize(ToolResult(ok=True, output={"xml": bad}), ToolContext(slug="alpha"), seq=1) == []
    assert s.normalize(ToolResult(ok=True, output=None), ToolContext(slug="alpha"), seq=1) == []


def test_nmap_absent_binary_degrades_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    from framework.v2.sensors import nmap as nmap_mod
    monkeypatch.setattr(nmap_mod.shutil, "which", lambda _: None)
    res = NmapServiceSensor().run({"target": "10.0.0.5"}, ToolContext(slug="alpha"))
    assert not res.ok and "not on PATH" in (res.note or "")   # a reason, never a crash


def test_nmap_missing_target_is_a_failed_result_not_a_crash() -> None:
    res = NmapServiceSensor().run({}, ToolContext(slug="alpha"))
    assert not res.ok and "target" in (res.note or "")


@pytest.mark.parametrize("good", ["10.0.0.5", "192.168.1.1", "web.example.com", "localhost", "a-b.co"])
def test_single_host_target_accepts_one_host(good: str) -> None:
    assert _is_single_host_target(good) is True


@pytest.mark.parametrize("bad", [
    "10.0.0.5/24", "10.0.0.5/0", "10.0.0.1-50", "10.0.0.*", "10.0.0.1,2,3",
    "-sV", "-oN", "--script=win.example.com", "--datadir=x.example.com",
    "10.0.0.5 -oN /tmp/x", "10.0.0.5\t-p-", "", "  ",
])
def test_single_host_target_rejects_cidr_range_list_and_flags(bad: str) -> None:
    assert _is_single_host_target(bad) is False


def test_run_rejects_cidr_and_flag_and_range_targets_before_the_network() -> None:
    s = NmapServiceSensor()
    for bad in ("10.0.0.5/24", "--script=x.example.com", "10.0.0.1-50", "10.0.0.*"):
        res = s.run({"target": bad}, ToolContext(slug="alpha"))
        assert not res.ok and "single host" in (res.note or "")


def test_run_rejects_a_malformed_ports_value() -> None:
    res = NmapServiceSensor().run({"target": "10.0.0.5", "ports": "-oN"}, ToolContext(slug="alpha"))
    assert not res.ok and "port spec" in (res.note or "")


def test_cidr_target_whose_base_ip_is_in_scope_is_still_refused_and_mints_nothing(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The scope gate (URL-shaped) would ALLOW '10.0.0.5/24' because its base IP 10.0.0.5 is in the
    # charter — but the sensor's single-host guard refuses it, so nmap never runs and no out-of-scope
    # subnet is probed or minted. This is the security regression for the review's headline finding.
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)   # grant ACTIVE_RECON
    (tmp_path / "alpha").mkdir(parents=True, exist_ok=True)
    (tmp_path / "alpha" / "charter.md").write_text(
        "# Engagement charter — `alpha`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        "Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        "| Host / Surface | Notes | Auth |\n|---|---|---|\n| `10.0.0.5` | Host | Yes |\n\n"
        "## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "nmap", {"target": "10.0.0.5/24"},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert not res.ok                              # refused by the sensor's single-host guard
    assert res.observations == [] and res.applied == 0
    assert len(world.all_nodes()) == 0             # nothing from the /24 entered the world-model


def test_nmap_is_registered_in_the_default_registry() -> None:
    assert "nmap" in default_registry()


def test_nmap_refused_without_the_active_recon_entitlement(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nmap is active, so it declares capability=ACTIVE_RECON: run_sensor refuses it at the entitlement
    # gate (before scope, before any subprocess) when the grant is absent — and mints nothing.
    from framework.v2 import entitlement

    def _deny(cap):
        raise RuntimeError(f"not entitled to {cap}")

    monkeypatch.setattr(entitlement, "require_capability", _deny)
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "nmap", {"target": "10.0.0.5"},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert res.result.refused and res.result.gate == "entitlement"
    assert res.observations == [] and res.applied == 0
    assert not world.has_node("host:10.0.0.5")


_LIVE = os.environ.get("CRUCIBLE_LIVE_NMAP") and shutil.which("nmap")


@pytest.mark.skipif(not _LIVE, reason="set CRUCIBLE_LIVE_NMAP=1 and have nmap to run the live scan")
def test_nmap_live_scan_of_localhost(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # An authorized live scan of loopback: a signed in-scope charter + a granted ACTIVE_RECON
    # entitlement, driven end to end through run_sensor's gate chain into the world-model.
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)   # grant ACTIVE_RECON
    (tmp_path / "alpha").mkdir(parents=True, exist_ok=True)
    (tmp_path / "alpha" / "charter.md").write_text(
        "# Engagement charter — `alpha`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        "Signed: `tester`     Date: `2026-05-04`\n\n## 2. In-scope systems\n\n"
        "| Host / Surface | Notes | Auth |\n|---|---|---|\n| `127.0.0.1` | loopback | Yes |\n\n"
        "## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "nmap", {"target": "127.0.0.1", "ports": "1-1024"},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert res.ok
    assert world.has_node("host:127.0.0.1")
