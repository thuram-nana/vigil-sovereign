"""Release gate #1 — the gateway BYPASS battery, as an honest, deterministic scoreboard.

WHAT THIS FILE IS. The release gate (plan Part III, "The release gate") is ready for a controlled pilot only
when, among other things, *"Strix cannot reach a target except through enforced VIGIL controls (proven by the
bypass battery)."* The empirical proof of that lives in ``test_egress_bypass_battery.py``, which launches
real containers and tries to escape by every route — but it needs a working Docker daemon and real host
egress, so in CI it SKIPS (loudly). A skipped security control is not a proven one.

This file is the companion the required job can always run: a per-route scoreboard over the SAME enforcement
the launch path applies, evaluated in-process from the COMMITTED gateway config — no Docker, no kernel, no
network. It proves the *wiring* that closes each bypass route; the Docker battery proves the kernel then
enforces that wiring. Together they cover the gate.

HOW IT STAYS HONEST (the model is ``test_production_invariants.py``).
  * A route the enforcement closes gets an ordinary passing row that genuinely inspects the rendered ruleset.
  * A route the system does NOT yet close gets a row asserting the TRUE bar, marked
    ``@pytest.mark.xfail(strict=True, reason="<slice>")`` — a strict xfail turns an unexpected PASS into a
    FAILURE, so the board self-updates when the enabling slice lands.
  * Every route carries a negative control proving the probe is not vacuous — the ONE allowed exit (the
    gateway proxy + resolver) IS open, so "everything else is closed" is a real difference, not a blanket
    outage that would trivially "close" every route while also breaking the gateway.

NO FRAMEWORK IMPORTS. Everything imports only ``vigil_integration`` / ``vigil_gateway`` + the stdlib, so this
runs in the "integration two-env boundary (P5)" job in BOTH legs and needs no entry in the ci.yml offense-leg
run-list (the ``test_ci_framework_tests_run_in_offense_leg`` guard).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from vigil_gateway.nftables import GatewayFirewall

_REPO = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO / "infra" / "docker" / "docker-compose.yml"

# The escape routes the release gate names (plan: "raw sockets, direct IPs, DNS, IPv6, altered proxy env,
# subprocesses"). Each is closed by the SAME host-side L3/L4 deny-default, which is exactly why unsetting the
# in-sandbox proxy env or spawning a subprocess buys nothing: the firewall understands only packets.
#: route -> (family, destination, description)
ROUTES: dict[str, tuple[str, str, str]] = {
    "raw_tcp_public":   ("ip",  "1.1.1.1",                "a raw TCP socket to a public address"),
    "direct_ip_http":   ("ip",  "1.1.1.1",                "a direct-IP HTTP request (no DNS)"),
    "dns_udp":          ("ip",  "8.8.8.8",                "a UDP DNS query to a public resolver"),
    "ipv6":             ("ip6", "2606:4700:4700::1111",   "an IPv6 TCP socket to a public address"),
    "altered_proxy_env": ("ip", "1.1.1.1",                "traffic after the agent UNSETS *_PROXY"),
    "subprocess_tcp":   ("ip",  "1.1.1.1",                "a subprocess that ignores the proxy entirely"),
}


# ---------------------------------------------------------------------------------------------------------
# The ruleset under test: the EXACT one the committed launch path (the `vigil-gateway-firewall` compose
# sidecar) applies. Parsing it from the artifact means a revert of the governance wiring is caught here, not
# assumed away.
# ---------------------------------------------------------------------------------------------------------
def _committed_sidecar_env() -> dict[str, str]:
    committed = _COMPOSE.read_text(encoding="utf-8")
    sidecar = committed.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]
    env_block = sidecar.split("environment:")[1].split("command:")[0]
    env: dict[str, str] = {}
    for line in env_block.splitlines():
        m = re.match(r'\s+(VIGIL_GATEWAY_[A-Z_]+):\s*"([^"]*)"\s*$', line)
        if m:
            env[m.group(1)] = m.group(2)
    return env


def _firewall_from_committed_env() -> GatewayFirewall:
    """Build the firewall exactly as the committed sidecar's env would, WITHOUT touching process env or
    importing config's os.environ reader — a pure construction from the parsed artifact."""
    env = _committed_sidecar_env()
    subnet = env.get("VIGIL_GATEWAY_SANDBOX_SUBNET", "").strip()
    return GatewayFirewall(
        sandbox_subnets=[subnet] if subnet else [],
        gateway_ip=env["VIGIL_GATEWAY_GATEWAY_IP"],
        proxy_port=int(env.get("VIGIL_GATEWAY_PROXY_PORT", "48081")),
        sandbox_iface=env.get("VIGIL_GATEWAY_SANDBOX_IFACE", "").strip() or None,
        dns_ip=env.get("VIGIL_GATEWAY_DNS_IP", "").strip() or None,
    )


def _chain(ruleset: str, name: str) -> str:
    """The body lines of one nft chain, from ``chain <name> {`` to its closing ``}``."""
    marker = f"chain {name} {{"
    start = ruleset.index(marker) + len(marker)
    end = ruleset.index("}", start)
    return ruleset[start:end]


def _egress_accepts(ruleset: str) -> list[str]:
    """The accept lines of the deny-default sandbox_egress chain, EXCLUDING the stateful ct-established rule
    (which readmits only replies to already-permitted flows, never a new escape)."""
    out = []
    for ln in _chain(ruleset, "sandbox_egress").splitlines():
        s = ln.strip()
        if s.endswith("accept") and not s.startswith("ct state"):
            out.append(s)
    return out


@pytest.fixture(scope="module")
def ruleset() -> str:
    return _firewall_from_committed_env().render()


@pytest.fixture(scope="module")
def gateway_ip() -> str:
    return _committed_sidecar_env()["VIGIL_GATEWAY_GATEWAY_IP"]


# ---------------------------------------------------------------------------------------------------------
# The per-route board — one row per named bypass route.
# ---------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("route", list(ROUTES))
def test_route_has_no_accepted_exit_in_the_deny_default_chain(route, ruleset, gateway_ip):
    """Every escape route's destination is absent from the sandbox_egress accept set, so it falls through to
    the deny-default drop. Because the whole chain is L3/L4, the ``altered_proxy_env`` and ``subprocess``
    routes are closed by the SAME rule as a raw socket — unsetting an env var or forking a child cannot
    conjure an accepted exit that does not exist in the ruleset."""
    family, dest, _desc = ROUTES[route]
    accepts = _egress_accepts(ruleset)
    # the deny-default chain must terminate in an unconditional drop
    assert _chain(ruleset, "sandbox_egress").strip().splitlines()[-1].strip().endswith("drop"), (
        "the sandbox_egress chain does not end in a deny-default drop — an unmatched packet would be accepted"
    )
    # the route's public destination is not among the accepted exits (the only accepts are to the gateway IP)
    offenders = [a for a in accepts if dest in a]
    assert not offenders, (
        f"ESCAPE WIRING: {route} ({dest}) is an accepted exit in the deny-default egress chain: {offenders}"
    )
    # and the address literally does not appear anywhere as an accept target — belt to the braces above
    assert dest != gateway_ip, "test misconfigured: a route dest equals the gateway IP"


def test_negative_control_the_one_allowed_exit_IS_open(ruleset, gateway_ip):
    """Non-vacuity: the ruleset is a DIFFERENCE, not a blanket outage. The gateway forward-proxy and resolver
    ARE accepted — so "every route above is closed" means "closed except the one governed path", not "the
    renderer emitted drop-everything" (which would pass every route row while breaking the gateway itself)."""
    accepts = _egress_accepts(ruleset)
    assert any(gateway_ip in a and "accept" in a for a in accepts), (
        "the gateway's own proxy/DNS exit is NOT accepted — the ruleset is a blanket outage, so the per-route "
        "'closed' assertions prove nothing"
    )
    # the ONLY accepted destinations are the gateway itself (proxy + resolver), nothing public
    non_gateway = [a for a in accepts if gateway_ip not in a]
    assert not non_gateway, f"the deny-default chain accepts a non-gateway exit: {non_gateway}"


def test_the_sandbox_is_governed_by_interface_so_ipv6_and_subprocesses_are_covered(ruleset):
    """The forward hook jumps sandbox-sourced traffic into the deny-default chain by INPUT INTERFACE, which
    is family-agnostic (v4 AND v6) and netns-wide (every process, including a subprocess). A v4-only
    ``ip saddr`` match would let IPv6 ride the forward ``policy accept`` — the sx-s3 regression this pins."""
    fwd = _chain(ruleset, "forward")
    assert re.search(r'iifname "[^"]+" jump sandbox_egress', fwd), (
        "the forward hook does not govern the sandbox by interface — IPv6 (and any spoofed source) could ride "
        "policy-accept out"
    )
    assert "ip saddr" not in fwd, (
        "the forward hook uses a v4-only source-subnet jump; IPv6 escapes governance"
    )
    # the deny-default chain accepts NO v6 exit, so any jumped v6 packet falls to the drop
    v6_accepts = [ln.strip() for ln in _chain(ruleset, "sandbox_egress").splitlines()
                  if ln.strip().startswith("ip6 daddr") and ln.strip().endswith("accept")]
    assert not v6_accepts, f"the deny-default chain accepts a v6 exit: {v6_accepts}"


def test_cloud_metadata_is_hard_dropped_on_every_hook(ruleset):
    """The 169.254.169.254 / .170.2 / .170.23 metadata + container-credential endpoints are hard-dropped on
    forward AND output, so even a proxy bug on the host cannot reach them (SSRF-to-metadata)."""
    for hook in ("forward", "output"):
        assert "@host_backstop4" in _chain(ruleset, hook), (
            f"the {hook} hook no longer hard-drops the cloud metadata backstop set"
        )
    assert "169.254.169.254/32" in ruleset, "the metadata endpoint dropped out of the denylist"


def test_the_committed_launch_path_governs_by_interface(ruleset):
    """The committed sidecar must set ``VIGIL_GATEWAY_SANDBOX_IFACE`` — otherwise the firewall falls back to a
    v4-only source-subnet match and IPv6 rides policy-accept. This is what makes the interface-governance row
    above true of the SHIPPED config, not just of a hand-built firewall."""
    env = _committed_sidecar_env()
    assert env.get("VIGIL_GATEWAY_SANDBOX_IFACE"), (
        "the committed vigil-gateway-firewall sidecar does not set VIGIL_GATEWAY_SANDBOX_IFACE (S3 / sx-s3)"
    )
    assert env.get("VIGIL_GATEWAY_GATEWAY_IP"), "the committed sidecar sets no gateway IP to permit as the exit"


def test_the_backstop_is_auto_applied_on_bring_up_not_manual_only():
    """S3 named the real gap: the nftables backstop was 'never applied, reachable only via a manual
    ``vigil-gateway apply-firewall``'. The committed launch path must APPLY it on bring-up — a one-shot
    sidecar with NET_ADMIN that runs ``apply-firewall`` — or the deny-default ruleset above governs nothing
    in a default deployment."""
    committed = _COMPOSE.read_text(encoding="utf-8")
    sidecar = committed.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]
    assert '"apply-firewall"' in sidecar or "apply-firewall" in sidecar, (
        "the committed firewall sidecar does not run `apply-firewall` — the backstop is manual-only again (S3)"
    )
    assert "NET_ADMIN" in sidecar, "the firewall sidecar lacks NET_ADMIN, so `nft -f` fails and it fail-OPENs"


def test_negative_control_an_ungoverned_firewall_leaves_the_routes_open():
    """Proves the whole battery discriminates: a firewall built with NO sandbox governance (no iface, no
    subnet) renders a forward hook that jumps NOTHING into the deny-default chain — so the sandbox keeps the
    forward ``policy accept`` and every route above would escape. The committed ruleset must not look like
    this."""
    ungoverned = GatewayFirewall(sandbox_subnets=[], gateway_ip="172.31.240.2", proxy_port=48081).render()
    fwd = _chain(ungoverned, "forward")
    assert "jump sandbox_egress" not in fwd, (
        "an ungoverned firewall unexpectedly still jumps into the deny-default chain — the control does not "
        "discriminate, so the per-route assertions would pass vacuously"
    )


# ---------------------------------------------------------------------------------------------------------
# The launch pre-flight is fail-closed — a run cannot silently degrade from gated to ungated egress.
# ---------------------------------------------------------------------------------------------------------
class _Net:
    """Stands in for ``gateway.docker.SandboxNetworking`` — deterministic, no Docker."""

    def __init__(self, state="running", present=True, network="vigil_sandbox"):
        self.sandbox_network = network
        self._state, self._present = state, present

    def container_state(self, name="vigil-gateway"):
        return self._state

    def network_exists(self, name=None):
        return self._present

    def strix_env(self):
        return {"STRIX_DOCKER_SANDBOX_NETWORK": self.sandbox_network}

    def sandbox_gateway_ip(self):
        return "172.31.240.2"


@pytest.fixture(autouse=True)
def _no_ambient_ungated(monkeypatch):
    monkeypatch.delenv("VIGIL_ALLOW_UNGATED_STRIX_EGRESS", raising=False)


def test_a_healthy_gateway_pins_the_sandbox_to_the_gated_network():
    from vigil_integration.strix_sandbox import preflight

    pinned = preflight(networking=_Net())
    assert pinned.ok and pinned.gated, "a healthy gateway topology must pin the sandbox to the gated network"
    assert pinned.env.get("STRIX_DOCKER_SANDBOX_NETWORK"), "the pin env was not produced"


@pytest.mark.parametrize("broken", [
    dict(state="exited"),          # gateway container not running
    dict(present=False),           # engagement network absent
])
def test_a_broken_gateway_topology_refuses_the_launch_never_runs_ungated(broken):
    """With the gateway down or the network absent the launch must be REFUSED, not silently run on Docker's
    default bridge (which has a route to the LAN, the internet and 169.254.169.254 — the FATAL-1 default)."""
    from vigil_integration.strix_sandbox import preflight

    out = preflight(networking=_Net(**broken))
    assert not out.ok and out.env == {}, (
        f"a broken topology ({broken}) did not refuse — the sandbox could start with ungated egress"
    )


def test_negative_control_the_only_way_past_a_down_gateway_is_an_explicit_opt_in(monkeypatch):
    """Proves the refusal is real and the escape hatch is never silent: only the explicit operator opt-in
    continues past a down gateway, and it does so WITHOUT the gated pin (it is honestly ungated)."""
    from vigil_integration.strix_sandbox import UNGATED_ENV, preflight

    monkeypatch.setenv(UNGATED_ENV, "1")
    out = preflight(networking=_Net(state="exited"))
    assert out.ok, "the explicit opt-in did not continue"
    assert not out.gated, "the ungated opt-in falsely reported the sandbox as gated"


# ---------------------------------------------------------------------------------------------------------
# The scoreboard itself.
# ---------------------------------------------------------------------------------------------------------
def test_the_route_set_is_the_one_the_release_gate_names():
    """Pin the coverage set so a route cannot silently stop being tested."""
    assert set(ROUTES) == {
        "raw_tcp_public", "direct_ip_http", "dns_udp", "ipv6", "altered_proxy_env", "subprocess_tcp",
    }, "the bypass-route set drifted from the routes the release gate enumerates"
    assert len(ROUTES) >= 6


def test_no_route_row_is_a_non_strict_xfail():
    """A non-strict xfail would swallow an XPASS and the board would stop self-updating."""
    module = __import__(__name__, fromlist=["*"])
    for name, obj in vars(module).items():
        if not (name.startswith("test_") and callable(obj)):
            continue
        for mark in getattr(obj, "pytestmark", []):
            if mark.name == "xfail":
                assert mark.kwargs.get("strict"), f"{name} uses a non-strict xfail and would hide a regression"
