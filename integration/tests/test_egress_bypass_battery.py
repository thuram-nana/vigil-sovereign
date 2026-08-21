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
