# vigil-gateway — host-side egress gate (P6 / FATAL-1)

The VIGIL offense sandbox (Strix on Kali) is autonomous and prompt-injectable. Left alone
it runs on Docker's default bridge with `NET_ADMIN`/`NET_RAW` and `host.docker.internal`
reachability, and its only "scope" is a Caido view-filter the agent can rewrite. Nothing
stops it reaching the operator LAN, a third party, or `169.254.169.254` (cloud metadata).
That is **FATAL-1**. This package closes it at the network layer, not the prompt layer.

## Two layers over one scope

| Layer | Module | Enforces |
|------|--------|----------|
| L3/L4 firewall (deny-default) | `nftables.py` | From the sandbox, DROP everything except the gateway proxy + gateway DNS. Hard-drop metadata/link-local/reserved on the forward hook (all forwarded traffic) and the gateway's own output. Governs sandbox traffic by **input interface** when `sandbox_iface` is set (spoof-proof), else by source subnet (see the NET_RAW caveat below). |
| L7 forward proxy | `proxy.py` | Per-connection: host must be in charter scope; resolve once; **refuse if any resolved IP is on the denylist** (DNS-rebinding defence); pin the exact validated IP (TOCTOU-safe). |

Scope is **CRUCIBLE's**, reused not reinvented (`scope_source.py` → `host_matches_scope` /
`parse_scope`). The always-denied ranges are in `denylist.py` (single source of truth for
both layers), including IPv4-mapped/6to4/NAT64 **and IPv4-compatible `::/96`** IPv6 forms so
neither `::ffff:169.254.169.254` nor `::169.254.169.254` can slip past.

## Topology (strongest form)

```
vigil_sandbox (internal: true)         vigil_egress
  Strix sandbox  ──►  vigil-gateway  ──────────►  internet
```

`internal: true` means Docker installs **no route out** of the sandbox network — the only
reachable peer is the gateway, which runs the proxy. The sandbox reaches the world only via
the proxy, so it needs no external DNS (the proxy resolves), removing that escape hatch. This
topology is spoof-proof *by construction* (Docker forwards nothing off an internal network).

The sandbox is pinned to this net by Strix's existing `STRIX_DOCKER_SANDBOX_NETWORK`. The
`NET_ADMIN` capability is dropped (`vendor/strix/.../docker_client.py`) so it cannot rewrite
its own firewall. **`NET_RAW` is retained by default** (nmap `-sS` and other raw-socket
tools need it) — drop it with `STRIX_SANDBOX_NET_CAPS=""` if SYN scanning isn't required.

### Host-bridge (alternative) topology — set `sandbox_iface`
If you run the sandbox on a shared host bridge instead of the internal:true topology, the
nftables layer is the boundary. Because `NET_RAW` lets the agent forge a source IP, matching
sandbox traffic by *source subnet* is bypassable; **set `VIGIL_GATEWAY_SANDBOX_IFACE=br-<id>`
so traffic is matched by input interface (spoof-proof) and both address families are governed.**
List every subnet (dual-stack) in `VIGIL_GATEWAY_SANDBOX_SUBNET` (comma-separated) — an omitted
v6 subnet would leave v6 egress ungoverned. Without `sandbox_iface`, source-subnet matching is
best-effort; prefer internal:true.

## Usage

```bash
# render / validate / apply the firewall (apply needs CAP_NET_ADMIN)
VIGIL_GATEWAY_CHARTER_SLUG=acme VIGIL_GATEWAY_GATEWAY_IP=172.31.240.1 \
  VIGIL_GATEWAY_SANDBOX_IFACE=br-abc123 vigil-gateway render-firewall
vigil-gateway check-firewall

# the locked-down docker topology
vigil-gateway render-compose --charter-slug acme
vigil-gateway ensure-networks

# run the proxy (the sandbox's only exit)
VIGIL_GATEWAY_CHARTER_SLUG=acme vigil-gateway serve-proxy --host 0.0.0.0 --port 48081
```

## Scope caveat
A **literal** (non-wildcard) in-scope host that resolves to a private IP is reachable through
the proxy (operators legitimately scope internal staging by name). If such a name is under
adversarial DNS control, it authorises whatever private IP it resolves to. Scope only names
you control; the metadata/link-local hard-deny is never liftable this way.

## Tests
- `tests/test_proxy_gate.py` — the L7 enforcement over **real sockets**: off-scope, metadata,
  and DNS-rebinding CONNECTs all get a real `403`; the tunnel is pinned to the validated IP.
  This is the genuine packet-level refusal evidence.
- `tests/test_netns_gate.py` — loads the rendered ruleset into a real (rootless) network
  namespace and asserts it installs with the deny-default structure + the metadata-drop rule
  and only the proxy/DNS accepts. It verifies the ruleset is real and loadable — it does **not**
  send packets; a full veth packet-drop to a live metadata IP needs root and is left to a
  privileged runner.
- `tests/test_denylist.py` / `tests/test_config.py` — every metadata encoding denied; the
  spoof-proof iifname mode and dual-stack governance reachable via `from_env`.

Runtime deps: none (stdlib). Reuses CRUCIBLE `framework.v2.common.ethics` via a path
bootstrap; tests run in the offense venv (`/home/kali/vigil/.venv-offense`).
