# W6-1 — Real `/healthz` (liveness) and `/readyz` (dependency-checking readiness) on every server

Issue: [#452](https://github.com/thuram-nana/vigil-sovereign/issues/452) ·
Milestone: W6 — OBSERVABILITY & HEALTH · Blocks [W6-2] #453 · Feeds [W6-7] #458.

## The defect

The only "health" surfaces were decorative or unusable as an orchestrator probe:

- the posture `/healthz` returned a constant;
- the witness `/health` returned an in-memory attribute;
- the one real probe, `/__vigil/plane/status`, is auth-, private-peer- and Host-gated — so a k8s/LB
  probe (which presents none of those) cannot use it, and it depends on the very plane it reports on.

None of them checked a dependency, and none was reachable by a credential-less probe.

## The claim (registered in the claims registry — [W0-3] #398, id `W6-1`)

<!-- CLAIM:W6-1 -->
> **Registered claim (W0-3 #398):** Every VIGIL HTTP server — the sovereign glass-cockpit UI, the WireGuard bridge, the offense Ops Console, the unified `vigil up` reverse proxy, the loopback external API, and the AEGIS gateway — exposes an UNAUTHENTICATED, Host-ungated `/healthz` liveness route (the process answers, 200, no secret) and a `/readyz` readiness route that probes THAT server's real dependency and returns 503 when it is down, and 200 when it is up; the probe routes sit BEFORE every auth/Host gate so a credential-less k8s/LB probe can reach them, and their bodies carry no token, path, or backend address.

The per-server dependency each `/readyz` probes: the spine store for the cockpit and bridge, the writable
working directory for the console, the sovereign backend for the reverse proxy, and the fixed upstream for
the gateway.

The registry entry pins this invariant through the AEGIS gateway as the representative enforcing symbol
(`AegisGatewayHandler._handle_probe`, proved by `test_gateway_health_readyz.py`). The same invariant is
proved per-server by the sibling suites:

| Server | Route added in | Real `/readyz` dependency | Proving test |
|--------|----------------|---------------------------|--------------|
| glass-cockpit UI | `apps/sigil/sigil/ui/server.py` | the sovereign spine store opens | `apps/sigil/tests/test_health_readyz.py` |
| WireGuard bridge | `apps/sigil/sigil/bridge/server.py` | the sovereign spine store opens | `apps/sigil/tests/test_health_readyz.py` |
| offense Ops Console | `engine/crucible/framework/v2/console/server.py` | the console working dir is writable | `engine/crucible/framework/v2/console/tests/test_health_readyz.py` |
| unified reverse proxy | `integration/vigil_integration/uiproxy.py` | the sovereign backend is listening | `integration/tests/test_uiproxy_health_readyz.py` |
| loopback external API | `engine/crucible/framework/v2/api/server.py` | the console working dir is writable | `engine/crucible/framework/v2/api/tests/test_health_readyz.py` |
| AEGIS gateway | `engine/crucible/framework/v2/aegis/gateway.py` | the fixed upstream is reachable | `engine/crucible/framework/v2/aegis/tests/test_gateway_health_readyz.py` |
| witness server | `integration/vigil_integration/witness_service.py` | the durable tip store is writable | `integration/tests/test_witness_health_readyz.py` |

The witness server (whose old `/health` returning an in-memory attribute was the cited evidence) also
gains the same `/healthz` + `/readyz` pair; its `/health` alias is retained for existing pollers. Its
`/readyz` probes the witness's real dependency — durable persistence of the co-signed tip (A8) — so a
witness that could equivocate on restart is drained rather than trusted.

## Why this shape

- **`/healthz` = liveness only.** It answers 200 as long as the process can serve a request. It performs
  no dependency I/O — a dependency outage must NOT cause a liveness failure (which would make an
  orchestrator kill an otherwise-healthy process instead of draining it).
- **`/readyz` = readiness.** It performs ONE cheap, real check of the server's actual dependency and
  returns 503 when that dependency is down, so a load balancer drains the node rather than serving errors
  from it. Each check is fail-closed: any error in the probe itself yields not-ready, never a false 200.
- **Unauthenticated and Host-ungated.** A k8s/LB probe presents no session token / device envelope and
  not the operator's Host, so the two routes are matched before every gate. They are the deliberate
  exception to each server's auth/anti-rebinding posture — justified because they expose no sensitive
  state (a boolean plus a check name; on failure the exception TYPE only, never its message, which could
  carry a filesystem path).
- **Gateway interception is exact-path only.** The gateway is a transparent proxy; it answers `/healthz`
  and `/readyz` locally for GET/HEAD on those two exact paths only, so ordinary traffic (including any
  other path) still forwards to the upstream unchanged.

## Negative controls

Each `/readyz` test drives the REAL dependency down and asserts the 503 (not a constant): a spine whose
home is a regular file (cockpit/bridge), a console working dir that cannot be written, a sovereign
backend pointed at a dead port (proxy), and an upstream pointed at a dead port (gateway). Each also
asserts the 200 when the dependency is up, and that the probe bodies leak no secret.

## Follow-on

[W6-2] #453 builds on these probes; [W6-7] #458 already added the integrity-checked `/readyz` on the
read-only posture endpoint (`vigil_integration/posture/endpoint.py`), which this slice leaves unchanged.
