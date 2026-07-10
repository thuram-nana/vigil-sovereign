"""
Tests for Wave 3.2 — the tshark packet/flow sensor.

tshark is driven as a gated passive sensor over an operator-provided pcap. The parse + normalize path
is PURE (tab-separated `-T fields` -> observations), tested offline against a synthetic fixture; the
subprocess path degrades cleanly when the binary or the pcap is absent. A real pcap runs opt-in.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from framework.v2.agents.tools import ToolContext, ToolResult
from framework.v2.intel.ingest import IntelIngest
from framework.v2.sensors import TsharkFlowSensor, default_registry, parse_tshark_fields, run_sensor
from framework.v2.sensors.tshark import _observations_from_records
from framework.v2.worldmodel.graph import WorldModel
from framework.v2.worldmodel.models import EdgeKind


# tshark -T fields column order (must match sensors.tshark._FIELDS).
_IDX = {"ip_src": 0, "ip_dst": 1, "ip6_src": 2, "ip6_dst": 3, "syn": 4, "ack": 5,
        "tcp_sport": 6, "qname": 7, "dns_a": 8, "dns_aaaa": 9, "sni": 10}


def _line(**vals) -> str:
    row = [""] * len(_IDX)
    for k, v in vals.items():
        row[_IDX[k]] = str(v)
    return "\t".join(row)


# NB: tshark -T fields renders boolean flag fields as "True"/"False" (verified against a real
# SYN-ACK pcap), NOT "1"/"0" — the fixture uses the real rendering so it can't mask a flag-parse bug.
_FIXTURE = "\n".join([
    _line(ip_src="10.0.0.5", ip_dst="10.0.0.9", syn="True", ack="True", tcp_sport="443"),   # SYN-ACK -> svc
    _line(ip_src="10.0.0.9", ip_dst="10.0.0.5", syn="True", ack="False", tcp_sport="51000"),  # bare SYN -> no
    _line(ip_src="10.0.0.2", ip_dst="10.0.0.9", qname="example.com", dns_a="93.184.216.34"),
    _line(ip_src="10.0.0.2", ip_dst="10.0.0.9", qname="api.test.", dns_a="1.1.1.1,1.0.0.1"),
    _line(ip_src="10.0.0.9", ip_dst="10.0.0.5", sni="secure.example.com"),
    _line(ip_src="10.0.0.9", ip_dst="10.0.0.2", qname="5.0.0.10.in-addr.arpa"),         # PTR -> skipped
    "garbled\tshort\tline",                                                            # too few cols -> skipped
    "",                                                                                  # blank -> skipped
])


def test_parse_extracts_services_dns_and_sni() -> None:
    p = parse_tshark_fields(_FIXTURE)
    assert p["services"] == [("10.0.0.5", "443")]                 # only the SYN-ACK responder
    assert ("example.com", ("93.184.216.34",)) in p["dns"]
    assert ("api.test", ("1.0.0.1", "1.1.1.1")) in p["dns"]        # trailing dot stripped, answers sorted
    assert p["sni"] == ["secure.example.com"]
    assert all("arpa" not in name for name, _ in p["dns"])         # PTR query dropped


def test_normalize_mints_service_domain_resolution_and_sni() -> None:
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(
        _observations_from_records(parse_tshark_fields(_FIXTURE), seq=1), seq=1)
    # open service from the SYN-ACK
    assert world.has_node("host:10.0.0.5") and world.has_node("service:10.0.0.5:443/tcp")
    assert world.get_edge("host:10.0.0.5", "service:10.0.0.5:443/tcp", EdgeKind.HOSTS) is not None
    # dns resolution: domain --RESOLVES_TO--> host
    assert world.has_node("domain:example.com")
    assert world.get_edge("domain:example.com", "host:93.184.216.34", EdgeKind.RESOLVES_TO) is not None
    # tls sni domain
    assert world.has_node("domain:secure.example.com")
    # a packet-capture observation is GROUNDING_INTEL, never oracle-proof
    assert world.get_node("domain:example.com").provenance.startswith("intel:")
    # the bare-SYN client port is NOT minted as a service
    assert not world.has_node("service:10.0.0.9:51000/tcp")


def test_normalize_is_deterministic_and_idempotent() -> None:
    a = _observations_from_records(parse_tshark_fields(_FIXTURE), seq=1)
    b = _observations_from_records(parse_tshark_fields(_FIXTURE), seq=1)
    assert [o.obs_id for o in a] == [o.obs_id for o in b]
    world = WorldModel()
    ing = IntelIngest(world, engagement_slug="alpha")
    ing.ingest(a, seq=1)
    n = len(world.all_nodes())
    r2 = ing.ingest(b, seq=1)             # re-ingest same claims at same seq -> no change
    assert r2.applied == 0 and len(world.all_nodes()) == n


@pytest.mark.parametrize("syn,ack,expect_svc", [
    ("True", "True", True), ("1", "1", True),          # both tshark renderings mint the service
    ("True", "False", False), ("1", "0", False),       # SYN without ACK is not an open service
    ("False", "True", False), ("", "", False),
])
def test_syn_ack_flag_rendering_both_true_and_1(syn, ack, expect_svc) -> None:
    line = _line(ip_src="10.0.0.7", ip_dst="10.0.0.9", syn=syn, ack=ack, tcp_sport="8443")
    svcs = parse_tshark_fields(line)["services"]
    assert (("10.0.0.7", "8443") in svcs) is expect_svc


def test_multi_question_dns_names_are_split_not_comma_joined() -> None:
    # tshark comma-joins a multi-question packet's dns.qry.name — mint each name, never one garbage node
    line = _line(ip_src="10.0.0.2", ip_dst="10.0.0.9",
                 qname="_airplay._tcp.local,_raop._tcp.local,host.local")
    names = [n for n, _ in parse_tshark_fields(line)["dns"]]
    assert "_airplay._tcp.local" in names and "host.local" in names
    assert not any("," in n for n in names)                       # no comma-joined garbage node


@pytest.mark.parametrize("bad", [
    "10.9.9.9", "2001:db8::5",                    # IP-literal SNI/qname is a HOST, not a DOMAIN
    "a,b.com", "a\\tb.com", "with space.com", "with/slash.com", "5.0.0.10.in-addr.arpa", "",
])
def test_clean_name_rejects_ip_literals_and_garbage(bad: str) -> None:
    from framework.v2.sensors.tshark import _clean_name
    assert _clean_name(bad) == ""


@pytest.mark.parametrize("good", ["example.com", "api.test", "_sip._tcp.example.com", "host.local", "a-b.co"])
def test_clean_name_keeps_valid_names(good: str) -> None:
    from framework.v2.sensors.tshark import _clean_name
    assert _clean_name(good) == good


def test_ip_literal_sni_is_not_minted_as_a_domain() -> None:
    world = WorldModel()
    IntelIngest(world, engagement_slug="alpha").ingest(
        _observations_from_records(parse_tshark_fields(_line(sni="10.9.9.9")), seq=1), seq=1)
    assert not world.has_node("domain:10.9.9.9")   # an IP is a HOST tier, never a DOMAIN


def test_parse_is_total_on_garbage() -> None:
    for junk in ["", "\n\n", "not\tenough", "a\tb\tc\td\te\tf\tg\th\ti\tj\tk\tl\tm"]:
        p = parse_tshark_fields(junk)
        assert isinstance(p["services"], list) and isinstance(p["dns"], list)


def test_run_missing_pcap_arg_is_a_clean_failure() -> None:
    assert not TsharkFlowSensor().run({}, ToolContext(slug="alpha")).ok


def test_run_nonexistent_pcap_is_a_clean_failure() -> None:
    res = TsharkFlowSensor().run({"pcap": "/no/such/file.pcap"}, ToolContext(slug="alpha"))
    assert not res.ok and "not found" in (res.note or "")


def test_run_absent_binary_degrades_cleanly(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")   # a file that exists (contents irrelevant; tshark is absent)
    from framework.v2.sensors import tshark as tshark_mod
    monkeypatch.setattr(tshark_mod.shutil, "which", lambda _: None)
    res = TsharkFlowSensor().run({"pcap": str(pcap)}, ToolContext(slug="alpha"))
    assert not res.ok and "not on PATH" in (res.note or "")


def test_registered_in_default_registry() -> None:
    assert "tshark_flow" in default_registry()


def _write_synack_pcap(path: Path) -> None:
    """Write a minimal Ethernet/IPv4 pcap with ONE TCP SYN-ACK from 10.0.0.5:443 — a real capture the
    installed tshark parses, so the run()->normalize() path is exercised against tshark's ACTUAL
    -T fields output (the boolean flag rendering that a synthetic fixture can't pin down)."""
    import struct

    def cksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return (~s) & 0xFFFF

    src_ip, dst_ip = bytes([10, 0, 0, 5]), bytes([10, 0, 0, 9])
    tcp = struct.pack("!HHIIBBHHH", 443, 51000, 1, 1, (5 << 4), 0x12, 64240, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", cksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip[:10] + struct.pack("!H", cksum(ip)) + ip[12:]
    eth = bytes([0, 0, 0, 0, 0, 2]) + bytes([0, 0, 0, 0, 0, 1]) + struct.pack("!H", 0x0800)
    pkt = eth + ip + tcp
    gh = struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack("!IIII", 0, 0, len(pkt), len(pkt)) + pkt
    path.write_bytes(gh + rec)


@pytest.mark.skipif(not shutil.which("tshark"), reason="tshark not installed")
def test_real_tshark_reads_a_synack_pcap_and_mints_the_service(tmp_path: Path) -> None:
    pcap = tmp_path / "synack.pcap"
    _write_synack_pcap(pcap)
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "tshark_flow", {"pcap": str(pcap)},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert res.ok
    # the SYN-ACK responder is minted as an open service — proves the flag parsing matches real tshark
    assert world.has_node("service:10.0.0.5:443/tcp")


_LIVE_PCAP = os.environ.get("CRUCIBLE_LIVE_PCAP")


@pytest.mark.skipif(not (_LIVE_PCAP and shutil.which("tshark")),
                    reason="set CRUCIBLE_LIVE_PCAP=<path> and have tshark to run the live pcap parse")
def test_tshark_reads_a_real_pcap_end_to_end() -> None:
    world = WorldModel()
    ingest = IntelIngest(world, engagement_slug="alpha")
    res = run_sensor(default_registry(), "tshark_flow", {"pcap": _LIVE_PCAP},
                     ToolContext(slug="alpha"), ingest=ingest, seq=1)
    assert res.ok   # parsed without error; the world may or may not gain nodes depending on the capture
