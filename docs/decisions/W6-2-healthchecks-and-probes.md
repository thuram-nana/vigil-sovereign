# W6-2 — Dockerfile `HEALTHCHECK`s and REAL k8s liveness/readiness probes wired to `/readyz` + `/healthz`

Issue: [#453](https://github.com/thuram-nana/vigil-sovereign/issues/453) ·
Milestone: W6 — OBSERVABILITY & HEALTH · Builds on [W6-1] #452 (the `/healthz` + `/readyz` routes).

## The defect

W6-1 (#452) added the real health surfaces; nothing was wired to them:

- **No `HEALTHCHECK` in any Dockerfile** — a shipped image was never marked unhealthy.
- **The k8s probes were shallow** — the proxy Deployment and the sovereign StatefulSet did a `GET /` on
  the STATIC bundle. That page returns 200 as long as the web tier can read a file off disk, so **a proxy
  whose sovereign backend is dead stays Ready** and the load balancer keeps routing to it.
- **No liveness probe at all on the single-writer sovereign StatefulSet** — the one workload where a
  wedged process is most dangerous (a hung single writer is never restarted).

## The claim (registered in the claims registry — [W0-3] #398, id `W6-2`)

<!-- CLAIM:W6-2 -->
> **Registered claim (W0-3 #398):** Every VIGIL k8s workload — the single-writer sovereign StatefulSet, the active-active reverse-proxy Deployment, and the Qdrant, Neo4j and otel-collector backends — declares BOTH a liveness and a readiness probe; the two VIGIL-owned workloads wire readiness to the W6-1 httpGet `/readyz` route (which returns 503 when that server's real dependency is down, so a proxy whose sovereign backend is dead is drained rather than served) and liveness to the httpGet `/healthz` route (which does no dependency I/O, so a dependency outage does not get an otherwise-healthy process killed), never the pre-fix shallow `GET /` on the static bundle; every shipped VIGIL server image declares a Dockerfile `HEALTHCHECK` (the AEGIS gateway's exercises `/readyz`; the egress forward proxy, a CONNECT proxy with no HTTP routes, uses a TCP connect to its bind); and `tools/ha/deploy.sh` REFUSES to apply the stack — its `tools/ha/require_probes.py` preflight exits non-zero — unless all of this holds.

## What changed

| Workload / image | Before | After |
|---|---|---|
| `sovereign-statefulset.yaml` (`vigil-sovereign`) | readiness `GET /`; **no liveness** | readiness `GET /readyz`, liveness `GET /healthz` (cockpit :8733) |
| `proxy-deployment.yaml` (`vigil-proxy`) | readiness `GET /` (static bundle); liveness `tcpSocket` | readiness `GET /readyz` (drains when the sovereign backend is dead), liveness `GET /healthz` (:8770) |
| `qdrant-statefulset.yaml` | readiness `GET /readyz` (native); no liveness | + liveness `GET /livez` (Qdrant's own liveness) |
| `neo4j-statefulset.yaml` | readiness `tcpSocket bolt`; no liveness | + liveness `tcpSocket` on the HTTP port (lenient) |
| `otel-deployment.yaml` | readiness `tcpSocket`; no liveness | + liveness `tcpSocket` on the OTLP receiver port |
| `engine/crucible/framework/v2/aegis/Dockerfile` | no `HEALTHCHECK` | `HEALTHCHECK` exercising `/readyz` on :8080 (stdlib `urllib`) |
| `gateway/Dockerfile` | no `HEALTHCHECK` | `HEALTHCHECK` = TCP connect to the proxy bind (stdlib `socket`) |

## Why this shape

- **VIGIL-owned workloads are wired to the W6-1 endpoints.** readiness → `/readyz` (a live probe of the
  server's real dependency: the spine store for the cockpit, the sovereign backend for the proxy — 503
  when down), so a load balancer drains a degraded replica. liveness → `/healthz`, which does NO
  dependency I/O — a dependency outage must not cause a liveness failure (which would make the orchestrator
  KILL an otherwise-healthy process instead of draining it). Both routes are the unauthenticated,
  Host-ungated ones a credential-less kubelet can reach.
- **Third-party backends use their own real health surfaces.** Qdrant has native `/livez` + `/readyz`;
  Neo4j and the otel-collector are probed on their listening ports (they expose no VIGIL `/readyz`). The
  point of the acceptance criterion is that **no workload ships without both probes**, and none now does.
- **The egress forward proxy has no `/readyz`.** It is a CONNECT/forward proxy, not an HTTP-routes server
  (W6-1's server list deliberately excludes it). Its readiness surface IS the listening socket, so its
  Dockerfile `HEALTHCHECK` is a TCP connect to the bind — the same check
  `infra/docker/docker-compose.yml` already used at the compose layer, now baked into the image itself.

## Enforcement + proof

- **Deploy-time gate.** `tools/ha/require_probes.py` (`require`) refuses (exit 3) if any workload lacks
  both probes, a VIGIL-owned workload is not wired to `/readyz` + `/healthz`, or a shipped server
  Dockerfile has no `HEALTHCHECK`. `tools/ha/deploy.sh` runs it as a second preflight before `kubectl
  apply`, alongside the NetworkPolicy preflight.
- **Manifest-parsing test (required CI).** `apps/sigil/tests/test_ha_probes_required.py` asserts, over the
  real manifests + Dockerfiles, that every workload declares both probes, the sovereign StatefulSet has a
  liveness probe, VIGIL-owned readiness is `/readyz` (not the shallow `/`) and liveness is `/healthz`, and
  the shipped Dockerfiles declare a `HEALTHCHECK`. It runs in the required `SIGIL governor gates (P7 —
  offense gate + authn)` job (the whole `apps/sigil/tests/` directory). It **fails on a tree without this
  change** (the failure was observed, not assumed).
- **Negative controls in the same run.** The suite mutates a real workload to drop a probe, to point
  readiness back at the shallow `/`, and to point liveness at `/readyz`, and asserts the SAME checker
  REJECTS each — proving the gate is not a rubber stamp. A Dockerfile with no `HEALTHCHECK` (or
  `HEALTHCHECK NONE`) is likewise rejected.
- **The endpoint's own behaviour** (503 when the dependency is down) is proved by the W6-1 per-server
  suites (e.g. `integration/tests/test_uiproxy_health_readyz.py`
  `test_readyz_503_when_sovereign_down_negative_control`); this slice proves the probes are WIRED to it.
- **Real cluster (reproducible, operator-run).** `tools/livefire/k8s_probes_livefire.sh` spins up a
  throwaway k3s cluster, deploys a proxy whose readinessProbe is `httpGet /readyz` (the real manifest
  shape) over a backend, KILLS the backend, and asserts the kubelet flips the pod to `Ready=False`, then
  restores the backend and asserts it returns to `Ready=True` (the negative control: the probe reflects
  the real backend state — not stuck NotReady, not stuck Ready). It is operator-run (it needs a privileged
  container to run k3s, which the required ubuntu-latest CI lacks), mirroring
  `tools/livefire/k8s_rbac_livefire.sh`.
