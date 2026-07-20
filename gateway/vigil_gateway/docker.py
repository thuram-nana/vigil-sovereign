"""
docker — pin the offense sandbox onto a locked-down network with the gateway as its only exit.

Recommended topology (Docker enforces the deny-default; the proxy enforces scope):

    ┌─ vigil_sandbox (internal: true) ─┐        ┌─ vigil_egress ─┐
    │  Strix Kali sandbox              │        │                │
    │   (STRIX_DOCKER_SANDBOX_NETWORK) │        │                │
    │            │ only reachable peer │        │                │
    │            ▼                     │        │                │
    │        vigil-gateway ────────────┼────────┼──► internet    │
    └──────────────────────────────────┘        └────────────────┘

``internal: true`` means Docker installs NO default route out of ``vigil_sandbox`` — the
sandbox physically cannot reach the internet, the operator LAN, or 169.254.169.254 except
by going through the gateway container, which runs the filtering proxy (proxy.py). Because
the sandbox reaches the world only via an HTTP proxy, it never needs external DNS itself
(the proxy resolves the CONNECT/absolute-form hostname), so name resolution is not an
escape hatch either.

The sandbox is pinned to this network by Strix's existing ``STRIX_DOCKER_SANDBOX_NETWORK``
env var — no Strix change is needed for pinning. Separately, docker_client.py is patched so
the sandbox no longer receives ``NET_ADMIN`` by default (it cannot rewrite its own
netfilter/routing), keeping only ``NET_RAW`` for SYN scanning, and only when opted in.

The nftables layer (nftables.py) is the host-side backstop for this topology and the
primary control for the alternative topology where the proxy runs on the host bridge.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

SANDBOX_NETWORK = "vigil_sandbox"
EGRESS_NETWORK = "vigil_egress"
STRIX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"


@dataclass(frozen=True)
class SandboxNetworking:
    sandbox_network: str = SANDBOX_NETWORK
    egress_network: str = EGRESS_NETWORK
    sandbox_subnet: str = "172.31.240.0/24"
    proxy_port: int = 48081

    def strix_env(self) -> dict[str, str]:
        """The env a caller must set so Strix pins the sandbox onto the locked-down net."""
        return {STRIX_NETWORK_ENV: self.sandbox_network}

    def render_compose(self, *, gateway_image: str = "vigil-gateway:latest", charter_slug: str = "") -> str:
        """A docker-compose fragment for the gateway + the two networks.

        The Strix sandbox is NOT declared here — Strix launches it itself; it only needs
        STRIX_DOCKER_SANDBOX_NETWORK set to ``sandbox_network``.
        """
        return f"""\
# vigil-gateway egress topology. The Strix sandbox is launched by Strix with
# {STRIX_NETWORK_ENV}={self.sandbox_network}; it is not defined here.
networks:
  {self.sandbox_network}:
    name: {self.sandbox_network}
    internal: true              # Docker installs no route out — the deny-default boundary
    ipam:
      config:
        - subnet: {self.sandbox_subnet}
  {self.egress_network}:
    name: {self.egress_network}

services:
  vigil-gateway:
    image: {gateway_image}
    networks:
      - {self.sandbox_network}  # sandbox-facing: receives the proxied egress
      - {self.egress_network}   # world-facing: the only interface with a default route
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    environment:
      VIGIL_GATEWAY_PROXY_PORT: "{self.proxy_port}"
      VIGIL_GATEWAY_CHARTER_SLUG: "{charter_slug}"
    command: ["vigil-gateway", "serve-proxy", "--host", "0.0.0.0", "--port", "{self.proxy_port}"]
"""

    # -- imperative network creation (alternative to compose) --------------------------

    @staticmethod
    def _docker_bin() -> str:
        d = shutil.which("docker")
        if not d:
            raise RuntimeError("docker binary not found")
        return d

    def _network_exists(self, name: str) -> bool:
        proc = subprocess.run(
            [self._docker_bin(), "network", "inspect", name],
            capture_output=True, text=True,
        )
        return proc.returncode == 0

    def ensure_networks(self) -> None:
        """Create the sandbox (internal) and egress networks if absent (idempotent)."""
        d = self._docker_bin()
        if not self._network_exists(self.sandbox_network):
            subprocess.run(
                [d, "network", "create", "--internal",
                 "--subnet", self.sandbox_subnet, self.sandbox_network],
                check=True, capture_output=True, text=True,
            )
        if not self._network_exists(self.egress_network):
            subprocess.run(
                [d, "network", "create", self.egress_network],
                check=True, capture_output=True, text=True,
            )
