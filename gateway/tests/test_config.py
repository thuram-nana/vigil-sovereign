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
