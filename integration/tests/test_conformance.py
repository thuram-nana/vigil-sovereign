"""PHASE 0.6 — the reusable ToolSpec conformance battery (integration criterion 10), run over a REAL tool.

Proves the acceptance harness itself: nmap's ToolSpec, driven through the real gated runner, passes every
property (positive FACT that re-verifies offline; a deceptive proposal mints NO fact; a tool timeout is the
typed ERROR outcome; a tripped kill-switch and an out-of-scope target each refuse before traffic). This is
the gate a tool must pass before the capability matrix may mark it fact_capable.

Offense-process test (loads framework.*): CI runs it in the offense group (see ci.yml).
"""
from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.verify", reason="CRUCIBLE not importable here")

from vigil_core import AuthorizerKey, TrustRoot, generate_keypair  # noqa: E402
from vigil_gateway.scope_source import StaticScopeSource  # noqa: E402
from vigil_integration.live.conformance import run_toolspec_conformance  # noqa: E402
from vigil_integration.live.external_tool import (  # noqa: E402
    LocalSubprocessBackend,
    ScopeGate,
    ToolOutcome,
    amass_subdomain_scan,
    arp_scan_host_scan,
    enum4linux_ng_smb_scan,
    masscan_service_scan,
    naabu_service_scan,
    nbtscan_host_scan,
    nmap_service_scan,
    run_external_tool,
    rustscan_service_scan,
    smbmap_smb_scan,
    subfinder_subdomain_scan,
    unicornscan_service_scan,
    zmap_service_scan,
)

_SIGNER = generate_keypair()
SIGNERS = [("root0", _SIGNER.private_key_b64)]
TRUST = TrustRoot(threshold=1, authorizers=[
    AuthorizerKey(key_id="root0", name="root0", public_key_b64=_SIGNER.public_key_b64)])


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from framework.v2.common import paths
    monkeypatch.setattr(paths, "killswitch_path", lambda slug: tmp_path / f"{slug}.halt")
    monkeypatch.setattr(paths, "target_dir", lambda slug: tmp_path / slug)
    monkeypatch.setattr(paths, "charter_path", lambda slug: tmp_path / slug / "charter.md")
    from framework.v2 import entitlement
    monkeypatch.setattr(entitlement, "require_capability", lambda cap: None)


def _charter(tmp_path, host, slug="alpha"):
    d = tmp_path / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "charter.md").write_text(
        f"# Engagement charter — `{slug}`\n\n**Status:** Final\n\n## 1. Operator attestation\n\n"
        f"Signed: `t`  Date: `2026-08-08`\n\n## 2. In-scope systems\n\n"
        f"| Host | Notes | Auth |\n|---|---|---|\n| `{host}` | Host | Yes |\n\n## 7. Posture\n\n- [x] **TEST**\n",
        encoding="utf-8")


class _DeceptiveNmapBackend:
    """Claims a CLOSED port is open — the runner's own re-drive handshake must fail → NO fact."""
    name = "deceptive"

    def __init__(self, closed_port):
        self._p = closed_port

    def available(self):
        return True, ""

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, f"Host: 127.0.0.1 ()\tPorts: {self._p}/open/tcp//x///\n", "",
                           self.name)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap not installed (present-tool path)")
def test_nmap_toolspec_passes_the_full_conformance_battery(tmp_path):
    from framework.v2.authority import KillSwitch

    _charter(tmp_path, "127.0.0.1")
    # a real open loopback port (positive) + a definitely-closed port (deceptive)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name="nmap",
            positive_spec=nmap_service_scan(ports=str(open_port)), positive_backend=LocalSubprocessBackend(),
            deceptive_spec=nmap_service_scan(ports=str(closed_port)),
            deceptive_backend=_DeceptiveNmapBackend(closed_port),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=60.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    # EVERY required property was actually exercised + True (no silently-missing check)
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{prop} not satisfied: {report.summary()}"


def test_conformance_report_non_conformant_when_a_check_fails():
    # a report with a failing check is NOT conformant (the gate a caller uses to withhold fact_capable)
    from vigil_integration.live.conformance import ConformanceReport
    r = ConformanceReport(tool="x", checks={"positive_fact": True, "deceptive_no_fact": False})
    assert r.conformant is False and "deceptive_no_fact" in r.summary()


def test_conformant_requires_the_full_property_set_no_vacuous_pass():
    """Red-pen BLOCK-1 pin: a report MISSING a required property (e.g. kill-switch omitted) is NON-conformant
    — not vacuously conformant over the present subset."""
    from vigil_integration.live.conformance import ConformanceReport, REQUIRED_PROPERTIES
    # all-but-killswitch present + True
    checks = {p: True for p in REQUIRED_PROPERTIES if p != "killswitch_refused_no_traffic"}
    r = ConformanceReport(tool="x", checks=checks)
    assert r.conformant is False and "killswitch_refused_no_traffic" in r.summary()
    # add it → now conformant
    checks["killswitch_refused_no_traffic"] = True
    assert ConformanceReport(tool="x", checks=checks).conformant is True


def test_deceptive_backend_proposing_nothing_is_non_conformant(tmp_path):
    """Red-pen BLOCK-2 pin: a deceptive backend that proposes NOTHING must NOT pass the crit-6 property —
    deceptive_proposed is False, so the report is non-conformant even though no fact resulted."""
    from framework.v2.authority import KillSwitch
    _charter(tmp_path, "127.0.0.1")

    class _EmptyBackend:      # proposes nothing
        name = "empty"
        def available(self):  # noqa: E704
            return True, ""
        def run(self, argv, *, timeout=0):
            return ToolOutcome(list(argv), 0, "", "", self.name)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0)); srv.listen(8)
    open_port = srv.getsockname()[1]
    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name="nmap", positive_spec=nmap_service_scan(ports=str(open_port)),
            positive_backend=LocalSubprocessBackend(),
            deceptive_spec=nmap_service_scan(ports="1"), deceptive_backend=_EmptyBackend(),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("c"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True), timeout=60.0)
    finally:
        srv.close()
    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")
    assert report.checks.get("deceptive_proposed") is False
    assert report.conformant is False and "deceptive_proposed" in report.summary()


# ===================================================================================================
# H5 — the SERVICE_REACHABILITY reuse ToolSpecs (masscan / rustscan / naabu) each PASS the full
# conformance battery through the REAL gated runner. These are HERMETIC: the tool binaries need not be
# installed, because the FACT is the runner's OWN gated handshake against a real open loopback port — the
# canned backend only supplies each tool's real-format PROPOSAL (exactly the doctrine: the tool is a
# proposer, VIGIL's re-drive is the fact authority). This is the gate each tool passed before the
# capability matrix marks it fact_capable=SERVICE_REACHABILITY.
# ===================================================================================================
_H5_BUILDERS = {
    "masscan": masscan_service_scan,
    "rustscan": rustscan_service_scan,
    "naabu": naabu_service_scan,
}


def _h5_stdout(tool: str, port: int, host: str = "127.0.0.1") -> str:
    if tool == "masscan":
        return f"Discovered open port {port}/tcp on {host}\n"
    if tool == "rustscan":
        return f"{host} -> [{port}]\n"
    if tool == "naabu":
        return f"{host}:{port}\n"
    raise AssertionError(tool)


class _CannedBackend:
    """Returns a fixed stdout for ANY argv — supplies a tool's real-format proposal with no binary present."""
    name = "canned"

    def __init__(self, stdout: str) -> None:
        self._stdout = stdout

    def available(self):
        return True, "canned"

    def run(self, argv, *, timeout=0):
        return ToolOutcome(list(argv), 0, self._stdout, "", self.name)


@pytest.mark.parametrize("tool", ["masscan", "rustscan", "naabu"])
def test_h5_reachability_toolspec_passes_the_full_conformance_battery(tool: str, tmp_path):
    from framework.v2.authority import KillSwitch

    build = _H5_BUILDERS[tool]
    _charter(tmp_path, "127.0.0.1")
    # a real OPEN loopback port (positive: the runner's handshake reproduces it) + a definitely-CLOSED port
    # (deceptive: the tool proposes it, the runner's handshake refuses → no fact).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=build(ports=str(open_port)),
            positive_backend=_CannedBackend(_h5_stdout(tool, open_port)),
            deceptive_spec=build(ports=str(closed_port)),
            deceptive_backend=_CannedBackend(_h5_stdout(tool, closed_port)),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


# ===================================================================================================
# H5 BATCH 2 — MORE network-discovery ToolSpecs (zmap / unicornscan), LEAD-ONLY BY DEFAULT.
#
# Per the H5 checkpoint these ship LEAD-only by default: VIGIL performs its OWN gated capture_handshake
# against each proposed port and the oracle fires, but the outcome is admitted to the LEAD-only
# hexstrike.service_reachability branch (fired over a non-FACT-capable branch => LEAD, never a FACT).
# Constructing the spec with fact_capable=True (DEFAULT-OFF, flag-gated) routes the IDENTICAL re-drive to the
# already-FACT-capable service_reachability.tcp_handshake twin — the sanctioned FACT path (an EXISTING
# FACT-capable family, VIGIL's own re-drive crossing admit()); no new oracle, no new FACT branch. These
# tests prove (a) the PROMOTED spec passes the FULL conformance battery through the real gated runner, and
# (b) the DEFAULT spec emits a channel-confirmed LEAD and NEVER a FACT, and (c) every flag is server-side
# (a model/brain-supplied value is rejected at build time), so no flag reaches the tool.
# ===================================================================================================


def _h5b_promoted_spec(tool: str, port: int):
    """The FACT-mode (flag-gated ON) spec — used only to PROVE fact-readiness via the existing family."""
    if tool == "zmap":
        return zmap_service_scan(port=port, fact_capable=True)
    return unicornscan_service_scan(ports=str(port), fact_capable=True)


def _h5b_default_spec(tool: str, port: int):
    """The shipped DEFAULT spec — LEAD-only."""
    if tool == "zmap":
        return zmap_service_scan(port=port)
    return unicornscan_service_scan(ports=str(port))


def _h5b_stdout(tool: str, port: int) -> str:
    """Each tool's REAL-format output line proposing the given port (host pinned to the target by the parser,
    never read from the tool's bytes)."""
    if tool == "zmap":
        return "127.0.0.1\n"      # zmap prints one responding IP per line for the single scanned port
    if tool == "unicornscan":
        return f"TCP open  svc[ {port}]  from 127.0.0.1  ttl 64\n"
    raise AssertionError(tool)


@pytest.mark.parametrize("tool", ["zmap", "unicornscan"])
def test_h5_batch2_toolspec_passes_full_conformance_in_promoted_fact_mode(tool: str, tmp_path):
    """The PROMOTED (fact_capable=True) spec passes the full conformance battery through the REAL gated
    runner — the gate the matrix requires before the FACT path may be turned on. HERMETIC: the tool binary
    need not be installed; the FACT is the runner's OWN gated handshake against a real open loopback port,
    the canned backend only supplies each tool's real-format proposal."""
    from framework.v2.authority import KillSwitch

    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=_h5b_promoted_spec(tool, open_port),
            positive_backend=_CannedBackend(_h5b_stdout(tool, open_port)),
            deceptive_spec=_h5b_promoted_spec(tool, closed_port),
            deceptive_backend=_CannedBackend(_h5b_stdout(tool, closed_port)),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


@pytest.mark.parametrize("tool", ["zmap", "unicornscan"])
def test_h5_batch2_default_spec_is_lead_only_never_a_fact(tool: str, tmp_path):
    """LEAD-by-default (the H5 checkpoint): the SHIPPED default spec, run against a REAL open loopback port,
    yields a channel-confirmed LEAD (VIGIL's own handshake fired) and mints ZERO facts — the fired oracle is
    admitted to the LEAD-only hexstrike.service_reachability branch. This is the runtime proof that the
    adapter 'emits LEADs; mints no new live FACT by default'."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    try:
        res = run_external_tool(
            _h5b_default_spec(tool, open_port), "127.0.0.1",
            scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            backend=_CannedBackend(_h5b_stdout(tool, open_port)),
            engagement_slug="alpha", signers=SIGNERS, timeout=30.0)
    finally:
        srv.close()

    assert res.status == "ran", res.reason
    assert res.proposed, f"{tool}: the tool proposed no service (fixture wrong)"
    assert res.facts == [], f"{tool}: minted a FACT by DEFAULT — must be LEAD-only per the H5 checkpoint"
    assert res.leads, f"{tool}: expected a channel-confirmed LEAD by default, got none"
    # the LEAD was admitted to the LEAD-only hexstrike branch (never the FACT-capable twin)
    lead = res.leads[0]
    assert not getattr(lead, "is_fact", False)


def test_h5_batch2_argv_is_server_side_and_rejects_model_supplied_values():
    """The typed-schema property: build_argv is a FIXED server-side construction and every free value passes
    a STRICT schema, so a model/brain-supplied value that could inject a flag is rejected at build time —
    never reaching the tool argv."""
    for bad in ("80; rm -rf /", "$(id)", "-oG -", "1-2,3", "80,443", "0", "70000", ""):
        with pytest.raises(ValueError):
            zmap_service_scan(port=bad)
    for bad in ("80;rm", "$(id)", "-p 22", "a-b", "", "1-2-3"):
        with pytest.raises(ValueError):
            unicornscan_service_scan(ports=bad)
    # a valid spec builds a fixed server-side argv: no positional the model controls beyond the (already
    # scope-authorised) target, and no free-form flag.
    assert zmap_service_scan(port=443).build_argv("10.0.0.5") == \
        ["zmap", "-p", "443", "-q", "-o", "-", "10.0.0.5"]
    assert unicornscan_service_scan(ports="22,80").build_argv("10.0.0.5") == \
        ["unicornscan", "-mT", "10.0.0.5:22,80"]


# ===================================================================================================
# M1.1 — the HOST / SUBDOMAIN / SMB discovery proposers each PASS the full conformance battery through the
# REAL gated runner. HERMETIC: the tool binaries need not be installed; the FACT is the runner's OWN gated
# handshake against a real open loopback port, and the canned backend only supplies each tool's real-format
# PROPOSAL. Two shapes, one doctrine (the tool proposes; VIGIL's re-drive is the fact authority):
#   * subfinder / amass / arp-scan / nbtscan surface a HOST; VIGIL re-dials it on the server-side re-dial port
#     set (scoped surfaced-host re-drive) — a surfaced host with no open TCP port mints NOTHING.
#   * enum4linux-ng / smbmap enumerate SMB on the (scope-authorised) target; the host is PINNED to target and
#     the SMB port(s) are re-proven by the runner's default service_reachability.tcp_handshake re-drive.
# This is the gate each tool passed before docs/capability-matrix/hexstrike.json marks it fact_capable.
# ===================================================================================================


def _m1_spec(tool: str, port: int):
    """The shipped spec for each M1.1 tool. For the surfacing tools the server-side re-dial port is the
    battery's open/closed loopback port; smbmap parses the port from its own output, so its spec takes none."""
    if tool == "subfinder":
        return subfinder_subdomain_scan(ports=str(port))
    if tool == "amass":
        return amass_subdomain_scan(ports=str(port))
    if tool == "arp-scan":
        return arp_scan_host_scan(ports=str(port))
    if tool == "nbtscan":
        return nbtscan_host_scan(ports=str(port))
    if tool == "enum4linux-ng":
        return enum4linux_ng_smb_scan(ports=str(port))
    if tool == "smbmap":
        return smbmap_smb_scan()
    raise AssertionError(tool)


def _m1_stdout(tool: str, port: int, host: str = "127.0.0.1") -> str:
    """Each tool's REAL-format output line proposing the loopback host (surfacing tools) or an SMB service on
    the target (SMB tools). The host is pinned to the target by the SMB parsers and re-authorised at dial time
    by the surfacing parsers' scoped capture, never trusted from these bytes beyond the parse."""
    if tool in ("subfinder", "amass"):
        return f"{host}\n"                                       # one host per line (subfinder -silent / amass)
    if tool == "arp-scan":
        return f"{host}\t00:11:22:33:44:55\tVendorCorp Inc.\n"   # <ip>\t<mac>\t<vendor>
    if tool == "nbtscan":
        return f"{host}     WORKGROUP        <00>  UNIQUE\n"      # <ip>  <name> ...
    if tool == "enum4linux-ng":
        return f"[*] Enumerating workgroup/domain on {host}\n[+] SMB session established; shares on {host}\n"
    if tool == "smbmap":
        return f"[+] IP: {host}:{port}\tName: {host}\n[+] Disk      Permissions\n----      -----------\n"
    raise AssertionError(tool)


_M1_TOOLS = ["subfinder", "amass", "arp-scan", "nbtscan", "enum4linux-ng", "smbmap"]


@pytest.mark.parametrize("tool", _M1_TOOLS)
def test_m1_discovery_toolspec_passes_the_full_conformance_battery(tool: str, tmp_path):
    from framework.v2.authority import KillSwitch

    _charter(tmp_path, "127.0.0.1")
    # a real OPEN loopback port (positive: the runner's handshake reproduces it) + a definitely-CLOSED port
    # (deceptive: the tool proposes the host/service, the runner's handshake refuses → no fact).
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()

    halt = tmp_path / "alpha.halt"
    try:
        report = run_toolspec_conformance(
            tool_name=tool,
            positive_spec=_m1_spec(tool, open_port),
            positive_backend=_CannedBackend(_m1_stdout(tool, open_port)),
            deceptive_spec=_m1_spec(tool, closed_port),
            deceptive_backend=_CannedBackend(_m1_stdout(tool, closed_port)),
            target="127.0.0.1",
            scope_gate_in=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            scope_gate_out=ScopeGate(scope=StaticScopeSource(["10.99.99.99"]), loopback_allowed_if_scoped=True),
            engagement_slug="alpha", signers=SIGNERS, trust_root=TRUST,
            trip_killswitch=lambda: KillSwitch("alpha").trip("conformance"),
            clear_killswitch=lambda: halt.unlink(missing_ok=True),
            timeout=30.0)
    finally:
        srv.close()

    assert report.conformant, report.summary() + " | notes: " + "; ".join(report.notes)
    from vigil_integration.live.conformance import REQUIRED_PROPERTIES
    for prop in REQUIRED_PROPERTIES:
        assert report.checks.get(prop) is True, f"{tool}: {prop} not satisfied: {report.summary()}"


def test_m1_surfaced_host_out_of_scope_is_refused_no_fact(tmp_path):
    """A surfaced host that is NOT attributable to a non-wildcard charter row is refused at dial time by the
    scoped surfaced-host capture (charter-scope-over-ADDRESSES), so VIGIL never connects and no FACT is minted
    — the scope floor is re-applied to a surfaced host, not only to the tool target. Here the TOOL TARGET is
    the in-scope loopback (so the run is authorised and the tool executes), but subfinder SURFACES a different,
    out-of-charter host; the handshake to it is refused and the result carries zero facts."""
    _charter(tmp_path, "127.0.0.1")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    open_port = srv.getsockname()[1]
    try:
        res = run_external_tool(
            subfinder_subdomain_scan(ports=str(open_port)), "127.0.0.1",
            scope_gate=ScopeGate(scope=StaticScopeSource(["127.0.0.1"]), loopback_allowed_if_scoped=True),
            # the tool surfaces 10.10.10.10 (NOT in the 127.0.0.1 charter) — the scoped capture must refuse it
            backend=_CannedBackend("10.10.10.10\n"),
            engagement_slug="alpha", signers=SIGNERS, timeout=30.0)
    finally:
        srv.close()

    assert res.status == "ran", res.reason
    assert res.proposed, "the surfaced host must be PROPOSED (so the refusal is at the re-drive, not the parse)"
    assert res.facts == [], "an out-of-scope SURFACED host must mint NO fact (scope floor re-applied at dial)"


def test_m1_argv_is_server_side_and_rejects_model_supplied_redial_ports():
    """The typed-schema property: every flag is a fixed server-side construction and the re-dial port set
    passes a STRICT single-port-list schema (no ranges, no flags), so a model/brain value that could inject a
    flag or sweep a range is rejected at build time — never reaching the tool argv."""
    for builder in (subfinder_subdomain_scan, amass_subdomain_scan, arp_scan_host_scan,
                    nbtscan_host_scan, enum4linux_ng_smb_scan):
        for bad in ("80; rm -rf /", "$(id)", "-p 22", "1-1024", "80-90", "0", "70000", "", "80,", ",80"):
            with pytest.raises(ValueError):
                builder(ports=bad)
    # a valid spec builds a FIXED server-side argv (target only as a flag value, no free-form flag)
    assert subfinder_subdomain_scan(ports="443,80").build_argv("example.com") == \
        ["subfinder", "-silent", "-d", "example.com"]
    assert amass_subdomain_scan(ports="443").build_argv("example.com") == \
        ["amass", "enum", "-passive", "-silent", "-d", "example.com"]
    assert arp_scan_host_scan(ports="80").build_argv("10.0.0.0/24") == \
        ["arp-scan", "--retry=1", "10.0.0.0/24"]
    assert nbtscan_host_scan(ports="139").build_argv("10.0.0.0/24") == ["nbtscan", "10.0.0.0/24"]
    assert enum4linux_ng_smb_scan(ports="445").build_argv("10.0.0.5") == ["enum4linux-ng", "-A", "10.0.0.5"]
    assert smbmap_smb_scan().build_argv("10.0.0.5") == ["smbmap", "-H", "10.0.0.5"]
