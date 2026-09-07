"""S3 — prove the sandbox boundary EMPIRICALLY, by trying to escape it.

Structural tests can show that VIGIL pins the sandbox to an ``--internal`` network. They cannot show that
the pin actually stops traffic. This battery does: it launches a real container on the same kind of network
VIGIL pins the Strix sandbox to and attempts to leave by every route an agent (or a tool it spawns) could
take — raw TCP to a public address, DNS, a direct-IP HTTP request, IPv6, an altered proxy environment, and
a subprocess that ignores the proxy entirely.

WHY A POSITIVE CONTROL IS MANDATORY HERE. "Nothing got out" is also what a broken probe, a missing image or
a container that never started looks like. Every escape attempt is therefore run TWICE — once on the gated
(internal) network and once on an ordinary bridge — and the bridge run must SUCCEED. A battery whose
control does not reach the internet proves nothing and fails loudly rather than reporting a false all-clear.

These tests need a working Docker daemon. When one is absent they SKIP with an explicit reason; they never
pass vacuously. The skip is visible in CI output on purpose — a silent skip on an egress control is the
failure mode this file exists to prevent.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid

import pytest

_IMAGE = "python:3.11-slim"
_TIMEOUT = 120

# One probe, run identically on both networks. Raw sockets + a subprocess, so nothing depends on the
# proxy environment being honoured — an agent with a shell can always ignore it.
_PROBE = r"""
import json, socket, subprocess
def tcp(host, port, family=socket.AF_INET):
    s = socket.socket(family, socket.SOCK_STREAM); s.settimeout(3)
    try:
        s.connect((host, port)); return True
    except Exception:
        return False
    finally:
        s.close()
def udp_dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
                 ("8.8.8.8", 53))
        s.recvfrom(512); return True
    except Exception:
        return False
    finally:
        s.close()
def subproc():
    try:
        r = subprocess.run(["python", "-c",
                            "import socket;s=socket.socket();s.settimeout(3);s.connect(('1.1.1.1',443))"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False
def v6():
    try:
        return tcp("2606:4700:4700::1111", 443, socket.AF_INET6)
    except Exception:
        return False
print(json.dumps({
    "raw_tcp_public":   tcp("1.1.1.1", 443),
    "direct_ip_http":   tcp("1.1.1.1", 80),
    "dns_udp":          udp_dns(),
    "ipv6":             v6(),
    "subprocess_tcp":   subproc(),
}))
"""

#: Every escape route the battery asserts is closed on the gated network.
ROUTES = ("raw_tcp_public", "direct_ip_http", "dns_udp", "ipv6", "subprocess_tcp")


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


def _run_probe(network: str) -> dict:
    """Run the probe container on `network` and return its verdict dict."""
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", network, _IMAGE, "python", "-c", _PROBE],
        capture_output=True, text=True, timeout=_TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"probe container failed on {network!r}: {proc.stderr[-400:]}")
    line = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    if not line:
        raise RuntimeError(f"probe produced no verdict on {network!r}: {proc.stdout[-300:]!r}")
    return json.loads(line[-1])


@pytest.fixture(scope="module")
def networks():
    """An --internal network (what VIGIL pins the sandbox to) and an ordinary bridge (the control)."""
    if not _docker_ok():
        pytest.skip("no usable Docker daemon — the egress bypass battery cannot run here")
    if subprocess.run(["docker", "image", "inspect", _IMAGE],
                      capture_output=True).returncode != 0:
        if subprocess.run(["docker", "pull", _IMAGE], capture_output=True,
                          timeout=_TIMEOUT).returncode != 0:
            pytest.skip(f"probe image {_IMAGE} unavailable — cannot run the egress battery")
    tag = uuid.uuid4().hex[:8]
    gated, control = f"vigil_bat_int_{tag}", f"vigil_bat_br_{tag}"
    subprocess.run(["docker", "network", "create", "--internal", gated],
                   capture_output=True, check=True, timeout=60)
    try:
        subprocess.run(["docker", "network", "create", control],
                       capture_output=True, check=True, timeout=60)
        try:
            yield gated, control
        finally:
            subprocess.run(["docker", "network", "rm", control], capture_output=True, timeout=60)
    finally:
        subprocess.run(["docker", "network", "rm", gated], capture_output=True, timeout=60)


@pytest.fixture(scope="module")
def verdicts(networks):
    """Both verdicts, or a LOUD skip when the control cannot escape.

    If the host itself has no egress (an air-gapped or restricted runner) then "nothing escaped the gated
    network" is unfalsifiable, and every assertion below would pass while proving nothing. That is an
    environment limitation, not a VIGIL defect, so the battery declines to run rather than either failing a
    required job or — far worse — reporting a false all-clear. The wiring itself stays guarded structurally
    by invariant 2 in test_production_invariants.py, which needs no Docker.
    """
    gated, control = networks
    control_verdict = _run_probe(control)
    if not control_verdict.get("raw_tcp_public"):
        pytest.skip(
            "THE BOUNDARY WAS NOT PROVEN IN THIS RUN: the positive control could not reach 1.1.1.1:443 "
            "from an ordinary bridge, so this host cannot distinguish a working boundary from a broken "
            "probe. Re-run where the control has real egress."
        )
    return {"gated": _run_probe(gated), "control": control_verdict}


def test_the_control_actually_reaches_the_internet(verdicts):
    """Non-vacuity, restated as an assertion for the report: the control did escape."""
    assert verdicts["control"]["raw_tcp_public"], "the positive control did not escape"


@pytest.mark.parametrize("route", ROUTES)
def test_no_route_escapes_the_gated_network(verdicts, route):
    """Every escape route an agent could take is closed on the network VIGIL pins the sandbox to.

    A route is only asserted closed when the CONTROL proved it open on this host. Otherwise the assertion
    would be a tautology: an IPv6 route that no host on this machine can use is "blocked" whether or not
    the boundary works, and counting it as a pass would inflate the battery's apparent coverage. Measured
    here: direct-IP and IPv6 were unreachable even from an ordinary bridge until the probe address was
    corrected, so this rule is not hypothetical.
    """
    if not verdicts["control"][route]:
        pytest.skip(
            f"{route} is unavailable from an ordinary bridge on this host, so asserting it blocked on the "
            f"gated network would prove nothing (no IPv6 / no route). NOT counted as a pass."
        )
    assert verdicts["gated"][route] is False, (
        f"ESCAPE: {route} succeeded from the gated (--internal) network — the Strix sandbox boundary "
        f"does not hold, and traffic could leave outside the signed scope"
    )


def test_the_boundary_is_a_difference_not_an_outage(verdicts):
    """At least one route must work on the control, and none on the gated net — a real DIFFERENCE.

    Guards the case where the whole host has no egress: then both sides would report all-false and every
    per-route assertion above would pass while proving nothing.
    """
    gated, control = verdicts["gated"], verdicts["control"]
    assert any(control[r] for r in ROUTES), "the control escaped by NO route — see the control test"
    assert not any(gated[r] for r in ROUTES), (
        f"the gated network leaked: {[r for r in ROUTES if gated[r]]}"
    )


def test_the_probe_covers_the_routes_an_agent_would_actually_use(verdicts):
    """A battery that only tested one route would be a weak proof; pin the coverage set itself."""
    assert set(verdicts["gated"]) == set(ROUTES), (
        "the probe's route set drifted from the asserted set — a route could silently stop being tested"
    )
    assert len(ROUTES) >= 5


def test_the_battery_exercised_a_meaningful_number_of_routes(verdicts):
    """Guard against a run where almost every route was skipped as unavailable.

    Without this, a host with only one working egress route would report "all routes blocked" and look
    like a thorough proof. The battery states how much it actually proved.
    """
    exercised = [r for r in ROUTES if verdicts["control"][r]]
    assert len(exercised) >= 3, (
        f"only {len(exercised)} of {len(ROUTES)} escape routes were exercisable here ({exercised}); the "
        f"boundary proof is too thin to rely on. Run the battery where the control has real egress."
    )


# =====================================================================================================
# S3 remainder — the nftables BACKSTOP. The battery above proves the ``--internal`` pin blocks egress.
# These prove the SECOND, independent layer — the host-side nftables ruleset the gateway bring-up now
# loads automatically (the `vigil-gateway-firewall` compose sidecar). The sandbox is governed by INTERFACE
# (family-agnostic: v4 AND v6), so the backstop blocks each bypass-battery route regardless of address
# family — the netns test verifies this against the LOADED ruleset, and the routed-bridge battery below
# drops each route (including v6, on a dual-stack bridge) that its positive control proved open. The
# backstop catches arbitrary TCP/UDP that ignores the ``*_PROXY`` env, and is the boundary itself on a
# host-bridge deployment where Docker installs no ``--internal`` deny-default.
# =====================================================================================================
def _netns_ok() -> bool:
    if not (shutil.which("unshare") and shutil.which("nft")):
        return False
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10).returncode == 0
    except Exception:
        return False


def _committed_sidecar_env() -> dict[str, str]:
    """The env the committed compose `vigil-gateway-firewall` sidecar actually sets, parsed from the
    artifact — so this test loads the SAME ruleset the automatic apply-firewall would, and a revert of the
    IPv6-governance wiring (dropping the iface / pinned bridge) is caught here rather than assumed away."""
    import pathlib
    import re
    repo = pathlib.Path(__file__).resolve().parents[2]
    committed = (repo / "infra" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    sidecar = committed.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]
    env_block = sidecar.split("environment:")[1].split("command:")[0]
    env: dict[str, str] = {}
    for line in env_block.splitlines():
        m = re.match(r'\s+(VIGIL_GATEWAY_[A-Z_]+):\s*"([^"]*)"\s*$', line)
        if m:
            val = m.group(2)
            # subnet/IP are compose interpolations (relocatable subnet); at rest the env is unset so compose
            # substitutes the `:-default` — resolve it here to load the SAME ruleset apply-firewall would.
            dm = re.match(r'^\$\{[A-Z_]+:-(.*)\}$', val)
            env[m.group(1)] = dm.group(1) if dm else val
    return env


def test_the_launch_path_backstop_ruleset_loads_for_real_and_closes_every_route(monkeypatch, tmp_path):
    """A REAL kernel load (rootless netns) of the EXACT ruleset the launch path applies — not a string
    match — and every bypass-battery route maps to a rule in the LOADED ruleset: only the gateway proxy
    and the gateway DNS are accepted exits, everything else (raw TCP, direct-IP HTTP, public DNS, a
    subprocess doing the same) hits the catch-all drop, and metadata is hard-dropped.

    IPv6 governance is verified structurally against the LOADED ruleset: the forward hook governs the
    sandbox by INTERFACE (family-agnostic — v4 AND v6), and the deny-default egress chain accepts no v6
    exit, so a v6 sandbox packet is jumped in and dropped. (Before the sx-s3 fix the sidecar matched by
    v4 source-subnet only, leaving v6 riding the forward `policy accept`.) The packet-level v6 drop on a
    routed interface needs root and lives in the docker battery below (skipped off a privileged runner).
    """
    if not _netns_ok():
        pytest.skip("requires nft + rootless user/network namespaces (unshare -rn) to load a real ruleset")
    from vigil_gateway.config import firewall_from_env

    monkeypatch.delenv("VIGIL_GATEWAY_DNS_IP", raising=False)
    monkeypatch.delenv("VIGIL_GATEWAY_SANDBOX_IFACE", raising=False)
    # exactly the env the compose `vigil-gateway-firewall` sidecar sets (incl. the bridge iface) — so this
    # loads the SAME ruleset the automatic apply-firewall would, not a bespoke one.
    env = _committed_sidecar_env()
    assert env.get("VIGIL_GATEWAY_SANDBOX_IFACE"), (
        "the committed sidecar must set VIGIL_GATEWAY_SANDBOX_IFACE so the backstop governs v6 (sx-s3)"
    )
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    iface = env["VIGIL_GATEWAY_SANDBOX_IFACE"]
    gip = env["VIGIL_GATEWAY_GATEWAY_IP"]

    ruleset = firewall_from_env().render()
    path = tmp_path / "backstop.nft"
    path.write_text(ruleset)
    proc = subprocess.run(["unshare", "-rn", "bash", "-c", f"nft -f {path} && nft list ruleset"],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"the launch-path ruleset failed to load: {proc.stderr}"
    loaded = proc.stdout

    assert "chain sandbox_egress" in loaded, "the deny-default egress chain must be live"
    # the ONLY accepted exits — raw TCP / direct-IP / subprocess routes have no other way out:
    assert "tcp dport 48081 accept" in loaded
    # public DNS route is closed: only the gateway resolver is an accepted DNS exit, never 8.8.8.8:
    assert f"{gip} udp dport 53 accept" in loaded
    assert "8.8.8.8" not in loaded and "1.1.1.1" not in loaded
    # metadata / SSRF route hard-dropped, and the whole thing ends in a deny-default drop:
    assert "169.254.0.0/16" in loaded
    assert "drop" in loaded
    # IPv6 route is GOVERNED, not tautologically "present": the forward hook jumps the sandbox by
    # interface (covers v6), and the deny-default chain accepts no v6 exit — so a v6 packet is dropped.
    fwd = loaded.split("chain forward")[1].split("}")[0]
    assert f'iifname "{iface}" jump sandbox_egress' in fwd, (
        "the loaded forward hook must govern the sandbox by interface (family-agnostic v4+v6), not a "
        f"v4-only source-subnet match that lets v6 ride policy-accept:\n{fwd}"
    )
    assert "ip saddr" not in fwd  # no v4-only saddr jump that would miss v6
    sbx = loaded.split("chain sandbox_egress")[1].split("chain output")[0]
    assert not [ln for ln in sbx.splitlines()
                if ln.strip().startswith("ip6 daddr") and ln.strip().endswith("accept")], (
        "the deny-default chain must accept NO v6 exit — a jumped v6 packet must fall to the drop"
    )


def _root_docker_ok() -> bool:
    return os.geteuid() == 0 and _docker_ok() and bool(shutil.which("nft"))


@pytest.mark.skipif(not _root_docker_ok(),
                    reason="the packet-level backstop battery needs root (to load host nftables affecting "
                           "bridge traffic) + a working Docker daemon + nft")
def test_the_nftables_backstop_drops_every_route_on_a_routed_bridge():
    """The true empirical backstop proof: on an ORDINARY (routed) bridge — where Docker installs NO
    deny-default — applying the host nftables backstop drops every escape route the control proved open,
    while the identical probe on the same bridge WITHOUT the backstop escapes. This isolates the nftables
    layer from the ``--internal`` pin: it is the boundary the host-bridge topology relies on, and the belt
    over ``*_PROXY``-ignoring traffic in the internal topology.

    The bridge is created DUAL-STACK (``--ipv6`` + a v6 subnet) and the backstop governs BOTH families
    (v4 ``ip saddr`` + v6 ``ip6 saddr`` jumps), so the IPv6 route is a real positive-control-backed drop
    assertion where the host has v6 egress — not skipped for want of a v6-capable bridge (sx-s3). Where the
    host cannot route v6 even without the backstop, the control gates the v6 route out (non-vacuity), so
    this never claims to have proven a v6 drop it did not exercise.
    """
    from vigil_gateway.nftables import GatewayFirewall

    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        if subprocess.run(["docker", "pull", _IMAGE], capture_output=True, timeout=_TIMEOUT).returncode != 0:
            pytest.skip(f"probe image {_IMAGE} unavailable — cannot run the backstop battery")

    tag = uuid.uuid4().hex[:8]
    net = f"vigil_bs_br_{tag}"
    subnet = "172.29.71.0/24"
    subnet6 = "fd00:29:71::/64"
    subnets = [subnet]
    # DUAL-STACK bridge so the v6 route is genuinely exercisable. Best-effort: a daemon without ipv6
    # support falls back to a v4-only bridge (the v6 route then gates out on the control, as before).
    v6 = subprocess.run(
        ["docker", "network", "create", "--subnet", subnet, "--ipv6", "--subnet", subnet6, net],
        capture_output=True, text=True, timeout=60)
    if v6.returncode == 0:
        subnets.append(subnet6)
    else:
        subprocess.run(["docker", "network", "create", "--subnet", subnet, net],
                       capture_output=True, check=True, timeout=60)
    # govern BOTH families the bridge carries (v4 always, v6 when the dual-stack create succeeded).
    fw = GatewayFirewall(sandbox_subnets=subnets, gateway_ip="172.29.71.1", proxy_port=48081)
    try:
        # POSITIVE CONTROL: a routed bridge with NO backstop must escape, or the proof is vacuous.
        control = _run_probe(net)
        if not control.get("raw_tcp_public"):
            pytest.skip("THE BACKSTOP WAS NOT PROVEN: the routed-bridge control could not reach the "
                        "internet, so a drop cannot be distinguished from a broken probe.")
        # apply the host backstop for this bridge's subnet(s), then re-probe: every route the control
        # proved open must now be dropped.
        fw.delete()
        fw.apply()
        gated = _run_probe(net)
        for route in ROUTES:
            if not control[route]:
                continue  # only assert routes the control proved open on this host (non-vacuity)
            assert gated[route] is False, (
                f"ESCAPE: {route} survived the nftables backstop on a routed bridge — the host-side L3/L4 "
                f"deny-default does not hold"
            )
        assert any(control[r] for r in ROUTES), "the control escaped by no route — see the internal battery"
        assert not any(gated[r] for r in ROUTES), (
            f"the backstop leaked: {[r for r in ROUTES if gated[r]]}"
        )
    finally:
        fw.delete()
        subprocess.run(["docker", "network", "rm", net], capture_output=True, timeout=60)
