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

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass

SANDBOX_NETWORK = "vigil_sandbox"
EGRESS_NETWORK = "vigil_egress"
STRIX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"
DEFAULT_IMAGE = "vigil-gateway:latest"


@dataclass(frozen=True)
class SandboxNetworking:
    sandbox_network: str = SANDBOX_NETWORK
    egress_network: str = EGRESS_NETWORK
    sandbox_subnet: str = "172.31.240.0/24"
    proxy_port: int = 48081

    def strix_env(self) -> dict[str, str]:
        """The env a caller must set so Strix pins the sandbox onto the locked-down net."""
        return {STRIX_NETWORK_ENV: self.sandbox_network}

    def sandbox_gateway_ip(self) -> str:
        """The static sandbox-net address the gateway binds to (A7). The proxy binds ONLY this
        interface, not 0.0.0.0, so it is reachable from the sandbox but never from the
        world-facing egress network. Docker's bridge takes the first host address (.1); the
        gateway container takes the second (.2)."""
        hosts = ipaddress.ip_network(self.sandbox_subnet, strict=False).hosts()
        next(hosts)             # .1 — Docker's own bridge gateway
        return str(next(hosts)) # .2 — the vigil-gateway container

    def render_compose(self, *, gateway_image: str = DEFAULT_IMAGE, charter_slug: str = "") -> str:
        """A docker-compose fragment for the gateway + the two networks.

        The Strix sandbox is NOT declared here — Strix launches it itself; it only needs
        STRIX_DOCKER_SANDBOX_NETWORK set to ``sandbox_network``.
        """
        # charter_slug is templated into the YAML — refuse anything but a simple slug so a value with a
        # quote / newline can never break out of the string and inject compose config.
        if charter_slug and not re.fullmatch(r"[A-Za-z0-9._-]+", charter_slug):
            raise ValueError("charter_slug must be a simple slug ([A-Za-z0-9._-]); refusing to template "
                             "an unsafe value into the compose file")
        bind_ip = self.sandbox_gateway_ip()
        return f"""\
# vigil-gateway egress topology. The Strix sandbox is launched by Strix with
# {STRIX_NETWORK_ENV}={self.sandbox_network}; it is not defined here.
#
# A7 client authentication: set VIGIL_GATEWAY_PROXY_TOKEN in your shell before `docker compose
# up` (compose interpolates ${{VIGIL_GATEWAY_PROXY_TOKEN}} below), and point the sandbox's
# proxy at http://vigil:$VIGIL_GATEWAY_PROXY_TOKEN@{bind_ip}:{self.proxy_port} so it presents
# the Basic credential. Unset = no client auth (the bind address + internal:true network are
# then the only thing keeping the proxy sandbox-only).
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
    container_name: vigil-gateway   # a deterministic name so `vigil services status/down` can find it
    networks:
      {self.sandbox_network}:
        ipv4_address: {bind_ip}   # pinned so the proxy can bind ONLY the sandbox interface
      {self.egress_network}: {{}}   # world-facing: the only interface with a default route
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true
    environment:
      VIGIL_GATEWAY_PROXY_PORT: "{self.proxy_port}"
      VIGIL_GATEWAY_PROXY_HOST: "{bind_ip}"
      VIGIL_GATEWAY_PROXY_TOKEN: "${{VIGIL_GATEWAY_PROXY_TOKEN:-}}"
      VIGIL_GATEWAY_CHARTER_SLUG: "{charter_slug}"
    command: ["vigil-gateway", "serve-proxy", "--host", "{bind_ip}", "--port", "{self.proxy_port}"]
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

    # -- image + container lifecycle (create-if-absent bring-up) ------------------------
    # These make `vigil services up` bring the gateway topology up from nothing: build the image if it
    # is missing, then `docker compose up -d` — which itself creates ONLY what is absent (the two
    # networks + the gateway container), so the whole thing is idempotent and re-runnable.

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run([self._docker_bin(), *args], capture_output=True, text=True)

    def image_exists(self, image: str = DEFAULT_IMAGE) -> bool:
        return self._run(["image", "inspect", image]).returncode == 0

    def ensure_image(self, context_dir, image: str = DEFAULT_IMAGE) -> bool:
        """Build the gateway image if it is absent (idempotent). Returns True iff a build actually ran."""
        if self.image_exists(image):
            return False
        proc = self._run(["build", "-t", image, str(context_dir)])
        if proc.returncode != 0:
            raise RuntimeError(f"docker build of {image} failed: {proc.stderr.strip()[-800:]}")
        return True

    def container_state(self, name: str = "vigil-gateway") -> str:
        """"running" | "exited" | … (docker's own state string) | "absent" if there is no such container."""
        proc = self._run(["inspect", "-f", "{{.State.Status}}", name])
        if proc.returncode != 0:
            return "absent"
        return proc.stdout.strip() or "unknown"

    def compose_up(self, compose_file, *, build: bool = True, context_dir=None,
                   image: str = DEFAULT_IMAGE) -> dict:
        """Bring the gateway topology up via `docker compose up -d` — idempotent: it creates ONLY the
        networks/containers that do not already exist. Builds the image first if it is absent (and a
        context dir is given). Returns a small status dict."""
        built = self.ensure_image(context_dir, image) if (build and context_dir is not None) else False
        proc = self._run(["compose", "-f", str(compose_file), "up", "-d"])
        if proc.returncode != 0:
            raise RuntimeError(f"docker compose up failed: {proc.stderr.strip()[-800:]}")
        return {"image_built": built, "gateway": self.container_state()}

    def compose_down(self, compose_file) -> None:
        """Stop + remove the gateway container (idempotent; the networks are left in place)."""
        self._run(["compose", "-f", str(compose_file), "down"])

    def status(self, image: str = DEFAULT_IMAGE) -> dict:
        """A create-if-absent readiness snapshot: which networks/image/container already exist."""
        return {
            "networks": {self.sandbox_network: self._network_exists(self.sandbox_network),
                         self.egress_network: self._network_exists(self.egress_network)},
            "image": self.image_exists(image),
            "gateway": self.container_state(),
        }
