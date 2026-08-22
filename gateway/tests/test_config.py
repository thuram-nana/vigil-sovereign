"""config wiring — the spoof-proof iifname mode and dual-stack governance are REACHABLE
via the supported from_env path (red-pen P6 BLOCK-1 / BLOCK-3)."""

from __future__ import annotations

from vigil_gateway.config import GatewayConfig
from vigil_gateway.scope_source import StaticScopeSource


def _cfg_from_env(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return GatewayConfig.from_env(scope=StaticScopeSource(["example.com"]))


def test_sandbox_iface_is_wired_and_produces_spoof_proof_rules(monkeypatch):
    cfg = _cfg_from_env(
        monkeypatch,
        VIGIL_GATEWAY_SANDBOX_IFACE="br-abc123",
        VIGIL_GATEWAY_GATEWAY_IP="172.31.240.1",
    )
    assert cfg.sandbox_iface == "br-abc123"
    txt = cfg.firewall().render()
    assert 'iifname "br-abc123" jump sandbox_egress' in txt
    assert 'iifname "br-abc123" jump sandbox_ingress' in txt
    # spoof-proof: NO source-subnet jump (which a NET_RAW-forged source could bypass)
    assert "ip saddr 172.31.240.0/24 jump" not in txt


def test_multi_family_subnets_are_all_governed(monkeypatch):
    cfg = _cfg_from_env(
        monkeypatch,
        VIGIL_GATEWAY_SANDBOX_SUBNET="172.31.240.0/24, fd00:5a11::/64",
        VIGIL_GATEWAY_GATEWAY_IP="172.31.240.1",
    )
    assert cfg.all_subnets() == ["172.31.240.0/24", "fd00:5a11::/64"]
    txt = cfg.firewall().render()
    # both families jumped into the deny-default chain — v6 no longer bypasses the proxy
    assert "ip saddr 172.31.240.0/24 jump sandbox_egress" in txt
    assert "ip6 saddr fd00:5a11::/64 jump sandbox_egress" in txt


def test_default_subnet_when_env_absent(monkeypatch):
    monkeypatch.delenv("VIGIL_GATEWAY_SANDBOX_SUBNET", raising=False)
    monkeypatch.delenv("VIGIL_GATEWAY_SANDBOX_IFACE", raising=False)
    cfg = GatewayConfig.from_env(scope=StaticScopeSource(["example.com"]))
    assert cfg.sandbox_subnet == "172.31.240.0/24"
    assert cfg.extra_subnets == []
    assert cfg.sandbox_iface is None


# --------------------------------- A7 proxy-hardening wiring ---------------------------

def test_proxy_host_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("VIGIL_GATEWAY_PROXY_HOST", raising=False)
    cfg = GatewayConfig.from_env(scope=StaticScopeSource(["example.com"]))
    assert cfg.proxy_host == "127.0.0.1"   # never 0.0.0.0 (A7)


def test_a7_proxy_env_is_threaded_into_the_proxy(monkeypatch):
    cfg = _cfg_from_env(
        monkeypatch,
        VIGIL_GATEWAY_PROXY_TOKEN="s3cr3t",
        VIGIL_GATEWAY_ALLOWED_PORTS="443, 8443, 9443",
        VIGIL_GATEWAY_HEADER_TIMEOUT="4.5",
        VIGIL_GATEWAY_MAX_CONNS="32",
    )
    assert cfg.proxy_token == "s3cr3t"
    assert cfg.allowed_ports == frozenset({443, 8443, 9443})
    assert cfg.header_timeout == 4.5
    assert cfg.max_connections == 32
    # the values actually reach the EgressProxy the config builds
    p = cfg.proxy()
    assert p._proxy_secret == "s3cr3t"
    assert p._allowed_ports == frozenset({443, 8443, 9443})
    assert p._header_timeout == 4.5
    assert p._max_connections == 32


def test_a7_proxy_env_defaults(monkeypatch):
    for k in ("VIGIL_GATEWAY_PROXY_TOKEN", "VIGIL_GATEWAY_ALLOWED_PORTS",
              "VIGIL_GATEWAY_HEADER_TIMEOUT", "VIGIL_GATEWAY_MAX_CONNS"):
        monkeypatch.delenv(k, raising=False)
    cfg = GatewayConfig.from_env(scope=StaticScopeSource(["example.com"]))
    assert cfg.proxy_token is None          # no auth unless a token is set
    assert cfg.allowed_ports is None        # proxy applies its {80, 443, 8080, 8443} default
    p = cfg.proxy()
    assert p._allowed_ports == frozenset({80, 443, 8080, 8443})


# --------------------- S3 backstop: the firewall builds/runs WITHOUT a charter scope -------------------
# The L3/L4 firewall is pure packet policy — only the L7 proxy needs the signed charter. `firewall_from_env`
# and the render/check/apply-firewall CLI must therefore run with NO VIGIL_GATEWAY_CHARTER_SLUG, which is
# exactly what lets the compose `vigil-gateway-firewall` sidecar load the backstop automatically at bring-up.

import pytest  # noqa: E402

from vigil_gateway.config import firewall_from_env  # noqa: E402


def _clear_fw_env(monkeypatch):
    for k in ("VIGIL_GATEWAY_SANDBOX_SUBNET", "VIGIL_GATEWAY_GATEWAY_IP", "VIGIL_GATEWAY_PROXY_PORT",
              "VIGIL_GATEWAY_SANDBOX_IFACE", "VIGIL_GATEWAY_DNS_IP", "VIGIL_GATEWAY_CHARTER_SLUG"):
        monkeypatch.delenv(k, raising=False)


def test_firewall_from_env_builds_without_a_charter_scope(monkeypatch):
    _clear_fw_env(monkeypatch)
    monkeypatch.setenv("VIGIL_GATEWAY_GATEWAY_IP", "172.31.240.2")
    # no VIGIL_GATEWAY_CHARTER_SLUG set — this must NOT raise (unlike GatewayConfig.from_env())
    txt = firewall_from_env().render()
    assert "table inet vigil_gateway" in txt
    assert "172.31.240.2 tcp dport 48081 accept" in txt
    assert "chain sandbox_egress" in txt and "drop" in txt


def test_firewall_from_env_is_fail_closed_without_a_gateway_ip(monkeypatch):
    _clear_fw_env(monkeypatch)
    with pytest.raises(RuntimeError, match="VIGIL_GATEWAY_GATEWAY_IP is required"):
        firewall_from_env()   # no guessed default for the sandbox's one permitted exit


def test_firewall_from_env_honours_iface_and_dual_stack(monkeypatch):
    _clear_fw_env(monkeypatch)
    monkeypatch.setenv("VIGIL_GATEWAY_GATEWAY_IP", "172.31.240.1")
    monkeypatch.setenv("VIGIL_GATEWAY_SANDBOX_IFACE", "br-abc123")
    monkeypatch.setenv("VIGIL_GATEWAY_SANDBOX_SUBNET", "172.31.240.0/24, fd00:5a11::/64")
    txt = firewall_from_env().render()
    assert 'iifname "br-abc123" jump sandbox_egress' in txt          # spoof-proof matching wired
    assert "ip saddr 172.31.240.0/24 jump" not in txt                # ...so no bypassable saddr jump
    # both families governed — the v6 subnet is not left ungoverned
    assert "hard_deny6" in txt or "host_backstop6" in txt


def test_render_firewall_cli_needs_no_charter_slug(monkeypatch, capsys):
    """The regression the sidecar depends on: `vigil-gateway render-firewall` used to demand a charter
    slug (GatewayConfig.from_env) even though the firewall needs none. It must now run scope-free."""
    from vigil_gateway.cli import main

    _clear_fw_env(monkeypatch)
    monkeypatch.setenv("VIGIL_GATEWAY_GATEWAY_IP", "172.31.240.2")
    rc = main(["render-firewall"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "table inet vigil_gateway" in out and "sandbox_egress" in out


# --------- S3 red-pen regression: the AUTO-APPLIED backstop must deny-default IPv6 sandbox egress ---------
# BLOCK (sx-s3): the compose `vigil-gateway-firewall` sidecar used to set only v4 vars and NO
# VIGIL_GATEWAY_SANDBOX_IFACE, so firewall_from_env() built a v4-only saddr-matched ruleset. The forward
# hook is `policy accept` and only jumped the v4 subnet, so a sandbox that acquired a v6 address egressed
# FREELY over IPv6 — straight past the proxy. These tests load the EXACT env the committed sidecar sets
# (parsed from the artifact, so a revert is caught) and prove a v6 sandbox packet is DROPPED, not accepted.

import pathlib  # noqa: E402
import re as _re  # noqa: E402


def _committed_firewall_sidecar_env() -> dict[str, str]:
    """Parse the `vigil-gateway-firewall` service's environment: block from the COMMITTED compose file.

    Binding the regression to the real artifact means reverting the fix (dropping the iface env, or the
    pinned bridge name) makes firewall_from_env() rebuild the v4-only ruleset and these assertions fail.
    """
    repo = pathlib.Path(__file__).resolve().parents[2]
    committed = (repo / "infra" / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    sidecar = committed.split("vigil-gateway-firewall:")[1].split("\n  vigil-gateway:")[0]
    env_block = sidecar.split("environment:")[1].split("command:")[0]
    env: dict[str, str] = {}
    for line in env_block.splitlines():
        m = _re.match(r'\s+(VIGIL_GATEWAY_[A-Z_]+):\s*"([^"]*)"\s*$', line)
        if m:
            env[m.group(1)] = m.group(2)
    return env


def test_auto_applied_backstop_denies_default_ipv6_sandbox_egress(monkeypatch):
    _clear_fw_env(monkeypatch)
    env = _committed_firewall_sidecar_env()
    assert env.get("VIGIL_GATEWAY_GATEWAY_IP"), "the sidecar must set the gateway IP"
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    txt = firewall_from_env().render()

    # 1) The forward hook (policy accept) must send v6 sandbox traffic INTO the deny-default chain, not
    #    leave it to the accept policy. Family-agnostic iifname matching does this for BOTH v4 and v6;
    #    a v6 saddr jump would too. A v4-only `ip saddr ... jump` is exactly the bug (v6 slips past).
    fwd = txt.split("chain forward")[1].split("chain sandbox_egress")[0]
    iface = env.get("VIGIL_GATEWAY_SANDBOX_IFACE", "")
    governs_v6 = (bool(iface) and f'iifname "{iface}" jump sandbox_egress' in fwd) or (
        "ip6 saddr" in fwd and "jump sandbox_egress" in fwd
    )
    assert governs_v6, (
        "the auto-applied backstop leaves IPv6 sandbox egress POLICY-ACCEPTED — the forward hook only "
        f"governs v4:\n{fwd}"
    )
    assert "policy accept" in fwd  # the hook stays accept for co-tenants; governance is scoped to the sandbox

    # 2) Once jumped, the deny-default chain gives a v6 packet NO exit: the only accepts are v4 daddr
    #    (proxy + DNS), so a v6 sandbox packet falls through to the catch-all drop.
    sbx = txt.split("chain sandbox_egress")[1].split("chain output")[0]
    v6_accepts = [ln.strip() for ln in sbx.splitlines()
                  if ln.strip().startswith("ip6 daddr") and ln.strip().endswith("accept")]
    assert not v6_accepts, f"a v6 exit was accepted in the deny-default chain: {v6_accepts}"
    assert 'log prefix "vigil-gw-drop " drop' in sbx  # v6 (and everything unmatched) is dropped

    # 3) The v4 allowed path is untouched: the proxy exit still accepts.
    assert f"ip daddr {env['VIGIL_GATEWAY_GATEWAY_IP']} tcp dport" in sbx


def test_v4_only_saddr_backstop_would_leak_ipv6_the_regression_guards_against():
    """Pin the failure mode itself: a saddr-only (no-iface, v4-subnet-only) ruleset — the pre-fix state —
    leaves the forward hook governing only v4, so a v6 sandbox packet is NOT jumped into the deny-default
    chain and rides the `policy accept`. This documents WHY the sidecar must pass the iface."""
    from vigil_gateway.nftables import GatewayFirewall

    leaky = GatewayFirewall(sandbox_subnets=["172.31.240.0/24"], gateway_ip="172.31.240.2",
                            proxy_port=48081).render()
    fwd = leaky.split("chain forward")[1].split("chain sandbox_egress")[0]
    assert "ip saddr 172.31.240.0/24 jump sandbox_egress" in fwd
    assert "ip6 saddr" not in fwd and 'iifname "' not in fwd   # nothing catches a v6 sandbox packet
    # => a v6 sandbox packet hits the forward `policy accept` and escapes. The fix (iface OR v6 subnet)
    #    is what closes this; test_auto_applied_backstop_denies_default_ipv6_sandbox_egress proves it closed.
