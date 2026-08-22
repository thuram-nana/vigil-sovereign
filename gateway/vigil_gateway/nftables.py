"""
nftables — the L3/L4 boundary (deny-default) rendered from the denylist.

This is the layer a prompt-injected agent cannot argue with. Where the proxy understands
hostnames and scope, the firewall understands only packets, and it is deliberately dumb:

  * From the sandbox subnet, DROP everything except two destinations — the gateway's
    forward proxy, and the gateway's DNS resolver. There is no direct route to the
    internet, so unsetting the in-sandbox proxy env (which the agent can do) buys nothing:
    the packets are dropped at the host. This is what makes the proxy's L7 policy the
    *only* way out.
  * Hard-deny the metadata/link-local/reserved ranges explicitly (and on the gateway's own
    OUTPUT path), so even a bug in the proxy cannot reach 169.254.169.254. The denylist is
    the single source of truth for those ranges (denylist.hard_deny_cidrs()).

The forward hook uses ``policy accept`` and only *jumps* sandbox-sourced traffic into the
deny-default regular chain, so co-tenant containers on the same host are untouched — the
gateway governs the sandbox, not the whole box.

The container itself is pinned to the sandbox network via Strix's existing
``STRIX_DOCKER_SANDBOX_NETWORK`` env var (no Strix code change needed for pinning), and its
``NET_ADMIN`` capability is dropped (see docker.py) so it cannot rewrite even its own
netfilter rules — but host-side rules live in the host's network namespace and are
authoritative regardless.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass, field

from . import denylist

_TABLE = "vigil_gateway"


def _split_family(cidrs: list[str]) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


@dataclass(frozen=True)
class GatewayFirewall:
    """The parameters of the host-side egress firewall for one sandbox network."""

    sandbox_subnets: list[str]        # e.g. ["172.31.0.0/24"] (docker bridge subnet)
    gateway_ip: str                   # the gateway's address on the sandbox network
    proxy_port: int                   # the forward-proxy port on the gateway
    sandbox_iface: str | None = None  # the sandbox bridge iface (e.g. "br-abc123"); when set,
                                      # traffic is governed by input interface — spoof-proof,
                                      # since NET_RAW lets the sandbox forge a source IP but not
                                      # the interface a packet physically arrives on.
    dns_ip: str | None = None         # gateway DNS resolver IP (defaults to gateway_ip)
    dns_port: int = 53
    log_drops: bool = True
    extra_hard_deny: list[str] = field(default_factory=list)

    def _dns_ip(self) -> str:
        return self.dns_ip or self.gateway_ip

    def _hard_deny(self) -> tuple[list[str], list[str]]:
        return _split_family([*denylist.hard_deny_cidrs(), *self.extra_hard_deny])

    def _host_backstop(self) -> tuple[list[str], list[str]]:
        # A7: the narrow set the GLOBAL forward/output hooks may drop without breaking the host
        # (loopback/link-local/multicast) or co-tenant containers — just the metadata endpoints.
        return _split_family(denylist.host_backstop_cidrs())

    def _sandbox_by_family(self) -> tuple[list[str], list[str]]:
        return _split_family(self.sandbox_subnets)

    def render(self) -> str:
        """Return the complete, loadable nft ruleset as text."""
        hd4, hd6 = self._hard_deny()
        hb4, hb6 = self._host_backstop()
        sb4, sb6 = self._sandbox_by_family()
        gip = ipaddress.ip_address(self.gateway_ip)
        dns = ipaddress.ip_address(self._dns_ip())
        log = 'log prefix "vigil-gw-drop " ' if self.log_drops else ""
        logh = 'log prefix "vigil-gw-hard " ' if self.log_drops else ""

        def elems(items: list[str]) -> str:
            return ", ".join(items)

        def govern(target_chain: str) -> list[str]:
            # Prefer interface matching — spoof-proof: NET_RAW lets the sandbox forge a
            # source IP but not the interface a packet physically arrives on. Fall back to
            # source-subnet matching when the bridge iface name is unknown (document the
            # spoofing caveat; the internal:true topology structurally prevents egress).
            if self.sandbox_iface:
                return [f'    iifname "{self.sandbox_iface}" jump {target_chain}']
            out = [f"    ip saddr {s} jump {target_chain}" for s in sb4]
            out += [f"    ip6 saddr {s} jump {target_chain}" for s in sb6]
            return out

        lines: list[str] = [f"table inet {_TABLE} {{"]

        # Hard-deny sets (denylist single source of truth) — used by the SANDBOX chains, where
        # dropping loopback/link-local/etc. is correct because only the sandbox is governed.
        if hd4:
            lines += ["  set hard_deny4 {", "    type ipv4_addr; flags interval;",
                      f"    elements = {{ {elems(hd4)} }}", "  }"]
        if hd6:
            lines += ["  set hard_deny6 {", "    type ipv6_addr; flags interval;",
                      f"    elements = {{ {elems(hd6)} }}", "  }"]

        # Host-backstop sets (A7) — the narrow metadata-only subset the GLOBAL forward/output
        # hooks drop, so the host keeps loopback/link-local and co-tenants are untouched.
        if hb4:
            lines += ["  set host_backstop4 {", "    type ipv4_addr; flags interval;",
                      f"    elements = {{ {elems(hb4)} }}", "  }"]
        if hb6:
            lines += ["  set host_backstop6 {", "    type ipv6_addr; flags interval;",
                      f"    elements = {{ {elems(hb6)} }}", "  }"]

        # INPUT hook: govern what the sandbox may reach ON the gateway host itself (the
        # host-bridge topology). Only the proxy + DNS ports; every other host service is
        # unreachable from the sandbox.
        lines.append("  chain input {")
        lines.append("    type filter hook input priority 0; policy accept;")
        lines += govern("sandbox_ingress")
        lines.append("  }")
        lines.append("  chain sandbox_ingress {")
        lines.append("    ct state established,related accept")
        lines.append(f"    tcp dport {self.proxy_port} accept")
        lines.append(f"    udp dport {self.dns_port} accept")
        lines.append(f"    tcp dport {self.dns_port} accept")
        lines.append(f"    {log}drop")
        lines.append("  }")

        # FORWARD hook: nothing forwarded through this host may reach cloud metadata (covers
        # the gateway container's OWN egress too), then govern sandbox-sourced egress. The
        # backstop is metadata-only so co-tenant containers keep loopback/link-local/RFC1918;
        # the sandbox's FULL hard-deny is enforced in sandbox_egress, not here.
        lines.append("  chain forward {")
        lines.append("    type filter hook forward priority 0; policy accept;")
        if hb4:
            lines.append(f"    ip daddr @host_backstop4 {logh}drop")
        if hb6:
            lines.append(f"    ip6 daddr @host_backstop6 {logh}drop")
        lines += govern("sandbox_egress")
        lines.append("  }")

        # The deny-default egress chain for the sandbox: only the gateway proxy + DNS exit.
        lines.append("  chain sandbox_egress {")
        lines.append("    ct state established,related accept")
        if hd4:
            lines.append(f"    ip daddr @hard_deny4 {logh}drop")
        if hd6:
            lines.append(f"    ip6 daddr @hard_deny6 {logh}drop")
        if gip.version == 4:
            lines.append(f"    ip daddr {gip} tcp dport {self.proxy_port} accept")
            lines.append(f"    ip daddr {dns} udp dport {self.dns_port} accept")
            lines.append(f"    ip daddr {dns} tcp dport {self.dns_port} accept")
        else:
            lines.append(f"    ip6 daddr {gip} tcp dport {self.proxy_port} accept")
            lines.append(f"    ip6 daddr {dns} udp dport {self.dns_port} accept")
            lines.append(f"    ip6 daddr {dns} tcp dport {self.dns_port} accept")
        lines.append(f"    {log}drop")
        lines.append("  }")

        # OUTPUT backstop: the gateway HOST's own egress may never reach the known cloud
        # metadata + container-credential endpoints (169.254.169.254 / .170.2 / .170.23 /
        # fd00:ec2::/32), so even a proxy bug on the host cannot touch them. Endpoint-scoped so
        # the host keeps loopback (127/8, ::1), IPv6 NDP (fe80::/10), and multicast/broadcast —
        # dropping the full hard-deny set here would break the host.
        lines.append("  chain output {")
        lines.append("    type filter hook output priority 0; policy accept;")
        if hb4:
            lines.append(f"    ip daddr @host_backstop4 {logh}drop")
        if hb6:
            lines.append(f"    ip6 daddr @host_backstop6 {logh}drop")
        lines.append("  }")

        lines.append("}")
        return "\n".join(lines) + "\n"

    # -- application -------------------------------------------------------------------

    @staticmethod
    def _nft_bin() -> str:
        nft = shutil.which("nft")
        if not nft:
            raise RuntimeError("nft binary not found; install nftables to apply the gateway firewall")
        return nft

    def check(self) -> subprocess.CompletedProcess:
        """Validate the ruleset without applying it (`nft --check -f -`). Raises on invalid."""
        proc = subprocess.run(
            [self._nft_bin(), "--check", "-f", "-"],
            input=self.render(),
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"nft --check rejected the ruleset: {proc.stderr.strip()}")
        return proc

    def _require_sandbox_iface(self) -> None:
        """FAIL-CLOSED (sx-s3 MEDIUM): when the ruleset governs the sandbox by INTERFACE, that interface
        MUST exist in the netns we are loading into, or the deny-default jump matches no packets and the
        sandbox rides the forward `policy accept` ungoverned — a silent fail-OPEN. The pinned docker bridge
        (VIGIL_GATEWAY_SANDBOX_IFACE, e.g. ``vigil-sbx0``) is created when the ``vigil_sandbox`` network is
        created, so at apply time (the one-shot sidecar runs after compose creates the networks) it must be
        present. If it is absent — a mis-pinned bridge name, a pre-existing network with a different bridge,
        or apply-firewall run before the network exists — REFUSE rather than load a ruleset that governs
        nothing. (When sandbox_iface is unset the ruleset matches by source-subnet and this check is N/A.)
        """
        if not self.sandbox_iface:
            return
        if not os.path.isdir(f"/sys/class/net/{self.sandbox_iface}"):
            raise RuntimeError(
                f"the pinned sandbox bridge interface {self.sandbox_iface!r} does not exist "
                f"(/sys/class/net/{self.sandbox_iface} is absent); refusing to load an interface-governed "
                f"backstop that would match no sandbox traffic — fail closed. Ensure the vigil_sandbox "
                f"network (which pins this bridge name) is created before apply-firewall runs."
            )

    def apply(self) -> subprocess.CompletedProcess:
        """Load the ruleset (`nft -f -`). Requires CAP_NET_ADMIN in the caller's netns.

        IDEMPOTENT: the table is deleted first, so re-applying on every gateway bring-up re-loads a
        clean ruleset instead of erroring with "File exists" on the already-present chains. delete() is
        best-effort (it swallows "no such table"); a genuine privilege failure surfaces on the load below,
        which is the authoritative "could we actually apply it?" check.

        FAIL-CLOSED: if the ruleset governs by a pinned interface, that interface must exist first
        (``_require_sandbox_iface``) — otherwise a backstop that matches no packets would report success.
        """
        self._require_sandbox_iface()
        self.delete()
        proc = subprocess.run(
            [self._nft_bin(), "-f", "-"],
            input=self.render(),
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"nft -f failed to load the ruleset: {proc.stderr.strip()}")
        return proc

    def delete(self) -> None:
        """Remove the gateway table (idempotent)."""
        subprocess.run(
            [self._nft_bin(), "delete", "table", "inet", _TABLE],
            text=True,
            capture_output=True,
        )
