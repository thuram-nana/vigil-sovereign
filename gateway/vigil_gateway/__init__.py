"""
vigil_gateway — the host-side egress gate for the VIGIL offense sandbox (FATAL-1 fix).

Two enforcement layers over one charter scope:
  * nftables (L3/L4, :mod:`vigil_gateway.nftables`) — deny-default; the sandbox's only
    route out is the gateway proxy, and the metadata/link-local/reserved ranges are
    hard-dropped even on the gateway's own egress.
  * a filtering forward proxy (L7, :mod:`vigil_gateway.proxy`) — per-connection hostname
    scope check + resolved-IP denylist re-check (DNS-rebinding defence) + IP pinning.

Scope is CRUCIBLE's, reused not reinvented (:mod:`vigil_gateway.scope_source`). The
always-denied ranges live in :mod:`vigil_gateway.denylist`. The sandbox is pinned onto a
Docker ``internal: true`` network (:mod:`vigil_gateway.docker`) so Docker itself blocks
direct egress, with NET_ADMIN dropped so the sandbox cannot rewrite its own firewall.
"""

from __future__ import annotations

from . import denylist, docker, nftables, proxy, scope_source
from .config import GatewayConfig, static_config
from .denylist import is_egress_denied, is_hard_denied
from .docker import SandboxNetworking
from .nftables import GatewayFirewall
from .proxy import ConnectDecision, EgressProxy, authorize
from .scope_source import CharterScopeSource, ScopeSource, StaticScopeSource

__all__ = [
    "denylist",
    "docker",
    "nftables",
    "proxy",
    "scope_source",
    "is_egress_denied",
    "is_hard_denied",
    "authorize",
    "ConnectDecision",
    "EgressProxy",
    "GatewayFirewall",
    "SandboxNetworking",
    "ScopeSource",
    "StaticScopeSource",
    "CharterScopeSource",
    "GatewayConfig",
    "static_config",
]
