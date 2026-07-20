# vigil-gateway — host-side egress gate (P6 / FATAL-1)

The VIGIL offense sandbox (Strix on Kali) is autonomous and prompt-injectable. Left alone
it runs on Docker's default bridge with `NET_ADMIN`/`NET_RAW` and `host.docker.internal`
reachability, and its only "scope" is a Caido view-filter the agent can rewrite. Nothing
stops it reaching the operator LAN, a third party, or `169.254.169.254` (cloud metadata).
That is **FATAL-1**. This package closes it at the network layer, not the prompt layer.

## Two layers over one scope

| Layer | Module | Enforces |
|------|--------|----------|
| L3/L4 firewall (deny-default) | `nftables.py` | From the sandbox subnet, DROP everything except the gateway proxy + gateway DNS. Hard-drop metadata/link-local/reserved even on the gateway's own egress. |
| L7 forward proxy | `proxy.py` | Per-connection: host must be in charter scope; resolve once; **refuse if any resolved IP is on the denylist** (DNS-rebinding defence); pin the exact validated IP (TOCTOU-safe). |

Scope is **CRUCIBLE's**, reused not reinvented (`scope_source.py` → `host_matches_scope` /
`parse_scope`). The always-denied ranges are in `denylist.py` (single source of truth for
both layers), including IPv4-mapped/6to4/NAT64 IPv6 forms so `::ffff:169.254.169.254`
cannot slip past.

## Topology (strongest form)

```
vigil_sandbox (internal: true)         vigil_egress
  Strix sandbox  ──►  vigil-gateway  ──────────►  internet
```

`internal: true` means Docker installs **no route out** of the sandbox network — the only
reachable peer is the gateway, which runs the proxy. The sandbox reaches the world only via
the proxy, so it needs no external DNS (the proxy resolves), removing that escape hatch.
The sandbox is pinned to this net by Strix's existing `STRIX_DOCKER_SANDBOX_NETWORK`; the
`NET_ADMIN` capability is dropped (`vendor/strix/.../docker_client.py`) so it cannot rewrite
its own firewall. nftables is the host-side backstop.

## Usage

```bash
# render / validate / apply the firewall (apply needs CAP_NET_ADMIN)
VIGIL_GATEWAY_CHARTER_SLUG=acme VIGIL_GATEWAY_GATEWAY_IP=172.31.240.1 \
  vigil-gateway render-firewall
vigil-gateway check-firewall

# the locked-down docker topology
vigil-gateway render-compose --charter-slug acme
vigil-gateway ensure-networks

# run the proxy (the sandbox's only exit)
VIGIL_GATEWAY_CHARTER_SLUG=acme vigil-gateway serve-proxy --host 0.0.0.0 --port 48081
```

## The gate test (the ship-blocker)

`tests/test_netns_gate.py` proves, in a rootless network namespace, that the rendered
nftables ruleset loads and DROPs traffic to `169.254.169.254` / an off-scope RFC1918 host /
an off-scope public host while permitting the gateway proxy path; `tests/test_proxy_gate.py`
proves the L7 proxy refuses off-scope hosts, metadata, and DNS-rebinding answers over real
sockets, and only connects to the pinned in-scope IP. A full two-namespace veth packet-drop
test to a live metadata IP requires root and is provided guarded (skipped without it).

Runtime deps: none (stdlib). Reuses CRUCIBLE `framework.v2.common.ethics` via a path
bootstrap; tests run in the offense venv (`/home/kali/vigil/.venv-offense`).
