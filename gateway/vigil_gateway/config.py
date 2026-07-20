"""
config — assemble the gateway from the environment / charter.

One small object ties the three layers together: the scope (from a signed charter), the
forward proxy (L7), and the firewall (L3/L4). Env vars:

  VIGIL_GATEWAY_CHARTER_SLUG   the target slug whose signed charter defines scope (required
                               for live use; tests inject a StaticScopeSource instead)
  VIGIL_GATEWAY_PROXY_HOST     proxy bind address           (default 0.0.0.0)
  VIGIL_GATEWAY_PROXY_PORT     proxy bind port              (default 48081)
  VIGIL_GATEWAY_SANDBOX_SUBNET sandbox docker subnet(s), comma-separated for dual-stack
                               (default 172.31.240.0/24). ALL listed families are governed —
                               omitting the v6 subnet on a dual-stack net would leave v6 egress
                               ungoverned (it would bypass the proxy).
  VIGIL_GATEWAY_SANDBOX_IFACE  the sandbox bridge interface (e.g. br-abc123). STRONGLY
                               recommended for the host-bridge topology: interface matching is
                               spoof-proof, whereas source-subnet matching can be bypassed by a
                               NET_RAW-forged source IP. Family-agnostic, so it also governs v6.
  VIGIL_GATEWAY_GATEWAY_IP     the gateway's IP on the sandbox net (for the firewall)
  VIGIL_GATEWAY_DNS_IP         the resolver the sandbox may reach (default = gateway IP)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .docker import SandboxNetworking
from .nftables import GatewayFirewall
from .proxy import EgressProxy
from .scope_source import CharterScopeSource, ScopeSource, StaticScopeSource


def _parse_subnets(raw: str) -> list[str]:
    return [s.strip() for s in raw.split(",") if s.strip()]


@dataclass
class GatewayConfig:
    scope: ScopeSource
    proxy_host: str = "0.0.0.0"
    proxy_port: int = 48081
    sandbox_subnet: str = "172.31.240.0/24"     # primary (used for docker network creation)
    extra_subnets: list[str] = field(default_factory=list)  # additional families (e.g. the v6 subnet)
    sandbox_iface: str | None = None            # bridge iface — spoof-proof matching when set
    gateway_ip: str = ""
    dns_ip: str | None = None

    @classmethod
    def from_env(cls, *, scope: ScopeSource | None = None) -> "GatewayConfig":
        if scope is None:
            slug = os.environ.get("VIGIL_GATEWAY_CHARTER_SLUG", "").strip()
            if not slug:
                raise RuntimeError(
                    "VIGIL_GATEWAY_CHARTER_SLUG is required (or pass an explicit scope). "
                    "The gateway refuses to run without a scope source — fail closed."
                )
            scope = CharterScopeSource(slug)
        subnets = _parse_subnets(os.environ.get("VIGIL_GATEWAY_SANDBOX_SUBNET", "172.31.240.0/24"))
        primary = subnets[0] if subnets else "172.31.240.0/24"
        return cls(
            scope=scope,
            proxy_host=os.environ.get("VIGIL_GATEWAY_PROXY_HOST", "0.0.0.0"),
            proxy_port=int(os.environ.get("VIGIL_GATEWAY_PROXY_PORT", "48081")),
            sandbox_subnet=primary,
            extra_subnets=subnets[1:],
            sandbox_iface=os.environ.get("VIGIL_GATEWAY_SANDBOX_IFACE", "").strip() or None,
            gateway_ip=os.environ.get("VIGIL_GATEWAY_GATEWAY_IP", "").strip(),
            dns_ip=os.environ.get("VIGIL_GATEWAY_DNS_IP", "").strip() or None,
        )

    def all_subnets(self) -> list[str]:
        return [self.sandbox_subnet, *self.extra_subnets]

    def proxy(self) -> EgressProxy:
        return EgressProxy(self.scope)

    def firewall(self) -> GatewayFirewall:
        if not self.gateway_ip:
            raise RuntimeError(
                "gateway_ip is required to render the firewall (set VIGIL_GATEWAY_GATEWAY_IP)"
            )
        return GatewayFirewall(
            sandbox_subnets=self.all_subnets(),
            gateway_ip=self.gateway_ip,
            proxy_port=self.proxy_port,
            sandbox_iface=self.sandbox_iface,
            dns_ip=self.dns_ip,
        )

    def networking(self) -> SandboxNetworking:
        return SandboxNetworking(sandbox_subnet=self.sandbox_subnet, proxy_port=self.proxy_port)


def static_config(hosts: list[str], **kw) -> GatewayConfig:
    """Convenience for tests / ad-hoc runs: a fixed scope instead of a charter."""
    return GatewayConfig(scope=StaticScopeSource(hosts), **kw)
