"""
config — assemble the gateway from the environment / charter.

One small object ties the three layers together: the scope (from a signed charter), the
forward proxy (L7), and the firewall (L3/L4). Env vars:

  VIGIL_GATEWAY_CHARTER_SLUG   the target slug whose signed charter defines scope (required
                               for live use; tests inject a StaticScopeSource instead)
  VIGIL_GATEWAY_PROXY_HOST     proxy bind address           (default 127.0.0.1; a public /
                               unspecified bind is refused by proxy.bind_ok)
  VIGIL_GATEWAY_PROXY_PORT     proxy bind port              (default 48081)
  VIGIL_GATEWAY_PROXY_TOKEN    Basic proxy-auth secret; when set, clients must present
                               Proxy-Authorization: Basic base64(vigil:<token>). Unset =
                               no client auth (rely on the bind address + nftables).
  VIGIL_GATEWAY_ALLOWED_PORTS  comma-separated destination port allowlist for BOTH CONNECT and
                               absolute-form HTTP (default 80,443,8080,8443)
  VIGIL_GATEWAY_HEADER_TIMEOUT seconds to read the request head, slow-loris cap (default 10)
  VIGIL_GATEWAY_MAX_CONNS      concurrent client connection cap; refuse 503 beyond (default 256)
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


def _parse_ports(raw: str) -> frozenset[int] | None:
    """Parse a comma-separated destination-port allowlist. Empty/unset → None (proxy default)."""
    ports = {int(p) for p in raw.split(",") if p.strip().isdigit()}
    return frozenset(ports) or None


@dataclass
class GatewayConfig:
    scope: ScopeSource
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 48081
    proxy_token: str | None = None
    allowed_ports: frozenset[int] | None = None  # None → proxy default {80, 443, 8080, 8443}
    header_timeout: float = 10.0
    max_connections: int = 256
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
            proxy_host=os.environ.get("VIGIL_GATEWAY_PROXY_HOST", "127.0.0.1"),
            proxy_port=int(os.environ.get("VIGIL_GATEWAY_PROXY_PORT", "48081")),
            proxy_token=os.environ.get("VIGIL_GATEWAY_PROXY_TOKEN", "").strip() or None,
            allowed_ports=_parse_ports(os.environ.get("VIGIL_GATEWAY_ALLOWED_PORTS", "")),
            header_timeout=float(os.environ.get("VIGIL_GATEWAY_HEADER_TIMEOUT", "10")),
            max_connections=int(os.environ.get("VIGIL_GATEWAY_MAX_CONNS", "256")),
            sandbox_subnet=primary,
            extra_subnets=subnets[1:],
            sandbox_iface=os.environ.get("VIGIL_GATEWAY_SANDBOX_IFACE", "").strip() or None,
            gateway_ip=os.environ.get("VIGIL_GATEWAY_GATEWAY_IP", "").strip(),
            dns_ip=os.environ.get("VIGIL_GATEWAY_DNS_IP", "").strip() or None,
        )

    def all_subnets(self) -> list[str]:
        return [self.sandbox_subnet, *self.extra_subnets]

    def proxy(self) -> EgressProxy:
        return EgressProxy(
            self.scope,
            proxy_secret=self.proxy_token,
            allowed_ports=self.allowed_ports,
            header_timeout=self.header_timeout,
            max_connections=self.max_connections,
        )

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


def firewall_from_env() -> GatewayFirewall:
    """Build the L3/L4 firewall from the environment WITHOUT requiring a charter scope.

    The firewall is pure packet policy — only the L7 proxy needs the signed charter (scope). So the
    ``render/check/apply-firewall`` commands, and the one-shot compose init service that loads the
    backstop before Strix starts, can build it with just the network coordinates and NO
    ``VIGIL_GATEWAY_CHARTER_SLUG``. This is what lets ``apply-firewall`` run automatically at gateway
    bring-up. FAIL-CLOSED: ``VIGIL_GATEWAY_GATEWAY_IP`` is required — there is no safe default for the
    address the sandbox's one permitted exit lives on, so a missing one refuses rather than guessing.
    """
    subnets = _parse_subnets(os.environ.get("VIGIL_GATEWAY_SANDBOX_SUBNET", "172.31.240.0/24"))
    primary = subnets[0] if subnets else "172.31.240.0/24"
    gateway_ip = os.environ.get("VIGIL_GATEWAY_GATEWAY_IP", "").strip()
    if not gateway_ip:
        raise RuntimeError(
            "VIGIL_GATEWAY_GATEWAY_IP is required to build the firewall (the sandbox's one permitted "
            "exit); refusing to load an egress backstop with a guessed gateway address"
        )
    return GatewayFirewall(
        sandbox_subnets=[primary, *subnets[1:]],
        gateway_ip=gateway_ip,
        proxy_port=int(os.environ.get("VIGIL_GATEWAY_PROXY_PORT", "48081")),
        sandbox_iface=os.environ.get("VIGIL_GATEWAY_SANDBOX_IFACE", "").strip() or None,
        dns_ip=os.environ.get("VIGIL_GATEWAY_DNS_IP", "").strip() or None,
    )


def static_config(hosts: list[str], **kw) -> GatewayConfig:
    """Convenience for tests / ad-hoc runs: a fixed scope instead of a charter."""
    return GatewayConfig(scope=StaticScopeSource(hosts), **kw)
