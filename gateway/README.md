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

### How the container gets its scope (B2, option c — host-verified snapshot)

The gateway container is **stdlib-only** and never reads the charter or imports the CRUCIBLE
parser. Instead, the launcher (`vigil up` / `vigil services up`), which runs in the offense venv
where the charter and its parser live, **verifies the SIGNED charter and parses its scope
host-side**, then injects the resolved host list as `VIGIL_GATEWAY_SCOPE_HOSTS`. `config.from_env`
enforces exactly that snapshot via `StaticScopeSource` (precedence: a non-empty
`VIGIL_GATEWAY_SCOPE_HOSTS` wins; else a directly-readable `VIGIL_GATEWAY_CHARTER_SLUG`; else it
**fail-closes** — refuses to run without a scope source).

The per-connection MATCH itself runs in the container: `scope_source` prefers CRUCIBLE's
`framework.v2.common.ethics` matcher when framework is importable (host-run), and falls back to a
**verbatim stdlib-only port** (`scope_match.py`) inside the container where framework is absent — so the
injected scope is actually enforced there, not raised-and-denied. The port is kept in lock-step with the
original by a drift-guard (`integration/tests/test_scope_match_parity.py`); charter *parsing* is never
ported (that stays the launcher's host-side job). Two honest bounds:

* **Signature is verified host-side, not in-container.** The trust root is the launcher; the
  container trusts the launcher-injected snapshot. (The charter `Signed:` line is a plaintext
  attestation, not a cryptographic signature — a true in-container crypto check would need
  cryptographically-signed charters + a pinned pubkey baked into the image.)
* **Snapshot, not live.** Scope is captured at bring-up; a mid-engagement scope change requires a
  gateway restart. A missing/unsigned charter, or a signed-but-empty scope, refuses the bring-up
  (never a deny-all/ungated gateway). The never-liftable metadata/RFC1918 floor above is
  charter-independent and applies regardless.

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

### Fail-closed bring-up (`vigil up --services`)
`vigil up --services` brings this topology up as a docker preflight. That leg **fails closed**: if the
gateway topology does not come up, `vigil up` is **REFUSED** (exit non-zero) rather than silently continuing
with the sandbox on Docker's default bridge — a silent downgrade from gated to ungated egress is the FATAL-1
above, so it is never taken by default. To deliberately run without the gate (accepting ungated egress for
that run) pass `--allow-ungated-egress`, which downgrades the refusal to a loud warning and continues. The
sibling root-services leg (qdrant/neo4j/otel — not security-critical) stays best-effort.

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
