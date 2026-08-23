# VIGIL HA on Kubernetes

These manifests implement the HA profile in
[`docs/architecture/HA-PROFILE.md`](../../../docs/architecture/HA-PROFILE.md).
Read that first — especially §2 (why the spine cannot be multi-writer) and the
verbatim non-claim. **This profile does NOT provide multi-writer high
availability of the sovereign spine.**

## The shape

| Manifest | Kind | Replicas | HA posture |
|---|---|---|---|
| `proxy-deployment.yaml` | Deployment (+HPA) | 3 (→10) | **Active-active** stateless read/proxy tier. Genuinely scalable. Runs `vigil up --proxy-only` — spawns NO backends, federates `/sovereign/*` to the central writer (`vigil-sovereign:8733`). See "proxy-only" below. |
| `sovereign-statefulset.yaml` | StatefulSet (+PDB) | **1 by design** | **Single writer.** Anti-rollback readiness-gate initContainer; active-passive failover only. `replicas>1` is a data-corruption bug, not scale. |
| `qdrant-statefulset.yaml` | StatefulSet | 1 | Durable single node. HA needs distributed mode (≥2 nodes + replication_factor≥2) — documented, not shipped. |
| `neo4j-statefulset.yaml` | StatefulSet | 1 | **Community = no clustering.** Durable single instance only; HA needs Neo4j Enterprise. |
| `otel-deployment.yaml` | Deployment | 2 | Active-active stateless. |
| `services.yaml` | Services | — | ClusterIP + a **headless** Service for the StatefulSet. Sticky sessions on the proxy Service. |
| `networkpolicy.yaml` | NetworkPolicy | — | **REQUIRED (enforced in the deploy path — not optional).** Restricts ingress to `vigil-sovereign:8733` to the proxy pods only — the cockpit serves its owner token token-free at `GET /`, so it must be reachable only via the authenticating proxy. The first resource of `kustomization.yaml`; `tools/ha/deploy.sh` REFUSES to deploy without it (or without a NetworkPolicy controller). |

## Health probes (liveness + readiness) — W6-2

Every workload declares **both** a liveness and a readiness probe (a CI test —
`apps/sigil/tests/test_ha_probes_required.py` — and the `tools/ha/deploy.sh`
preflight both REFUSE a set where one is missing):

| Workload | Readiness | Liveness |
|---|---|---|
| `vigil-sovereign` (cockpit :8733) | `GET /readyz` — live probe of the spine store (503 when it cannot open) | `GET /healthz` — the process answers, no dependency I/O |
| `vigil-proxy` (:8770) | `GET /readyz` — live probe of the **sovereign backend** it federates to (503 when that writer is down) | `GET /healthz` |
| `qdrant` (:6333) | `GET /readyz` (native) | `GET /livez` (native) |
| `neo4j` (bolt :7687 / http :7474) | `tcpSocket` bolt (accepts Cypher) | `tcpSocket` http (process up; lenient) |
| `otel-collector` (:4318) | `tcpSocket` OTLP receiver | `tcpSocket` OTLP receiver (lenient) |

The two **VIGIL-owned** workloads wire readiness to the **W6-1 `/readyz`** route and
liveness to **`/healthz`** — never the pre-fix shallow `GET /` on the static bundle,
which returned 200 even when the real backend was dead (so a proxy whose sovereign
backend was down stayed Ready). `/readyz` returns **503** when the server's real
dependency is down, so the Service **drains** a degraded replica; `/healthz` does no
dependency I/O, so a dependency outage does not get an otherwise-healthy process
**killed**. Both are the unauthenticated, Host-ungated routes a credential-less kubelet
can reach (matched before the cockpit's auth/anti-rebinding gates). The single-writer
sovereign StatefulSet — which had **no liveness probe at all** — now has one, so a hung
writer is restarted. See the kubelet-probe caveat in `networkpolicy.yaml` (some CNIs
enforce policy on probe traffic and need the node source allowed).

Shipped VIGIL **server images** also declare a Dockerfile `HEALTHCHECK`: the AEGIS
gateway (`engine/crucible/framework/v2/aegis/Dockerfile`) exercises `/readyz`; the
egress forward proxy (`gateway/Dockerfile`), a CONNECT proxy with no HTTP routes, uses
a TCP connect to its bind. Details: [`docs/decisions/W6-2-healthchecks-and-probes.md`](../../../docs/decisions/W6-2-healthchecks-and-probes.md).

## Why the proxy runs `--proxy-only` (and binds the pod IP)

`vigil up` is **not** a stateless proxy by default: it LAUNCHES the sovereign
cockpit (8733) and both offense backends (8787/8799) as children on fixed loopback
ports, then proxies to them. In N replicas that means N sovereign cockpits — N
signed-spine **writers** = a fork the floor + witnesses reject (HA-PROFILE.md §2).

So the Deployment runs **`vigil up --proxy-only`**: it spawns nothing and federates
`/sovereign/*` to the **one** central writer via `--sovereign-addr
vigil-sovereign:8733` (the headless writer Service). Both tiers bind their **own pod
IP** (`--host $(POD_IP)`, from the downward API) — never `0.0.0.0`, which `bind_ok`
refuses (the process would exit 2); a pod IP is RFC1918, which `bind_ok` accepts.
`--domain vigil.example.com` is the advertised authority for your Ingress/TLS edge,
not a bind.

**The offense plane is NOT clustered by this profile — on purpose.** The offense
console/api bind **loopback only** (`serve()` raises on any non-loopback host — a
single-operator, on-host surface by design) and stay **native** (they drive the host
Docker daemon; the two-process boundary keeps them out of the sovereign-only
`vigil/runtime:local` image). They are therefore unreachable cross-pod. `/offense/*`
works only against an offense plane **co-located** with the proxy on loopback (a
sidecar the operator adds, holding the docker socket); left at the loopback default
with no such sidecar it returns 502, while `/sovereign/*` serves through the proxy.
This profile clusters the **sovereign writer + the stateless proxy tier**, and does
not pretend `/offense/*` is horizontally scalable. See HA-PROFILE.md §1.1.

## The sovereign cockpit is proxy-only — apply the NetworkPolicy (REQUIRED)

`/sovereign/*` serving through the proxy does **not** make the sovereign plane safe to
expose. The cockpit serves its OWN owner token at `GET /` **token-free**
(`<body data-token="<owner token>">` — a single-operator surface by design), and the
headless `vigil-sovereign` Service has no auth of its own. The **proxy is the
authenticating boundary**: per-user identity (delegated whoami) **and** a value-agnostic
scrub that blanks any backend's embedded `data-token="..."` out of relayed HTML (so even
a remote cockpit's own token — which the proxy never holds — never reaches a browser).

`networkpolicy.yaml` enforces that the cockpit is reachable **only** from the proxy
pods (ingress to `vigil-sovereign:8733` restricted to `app: vigil-proxy`). It is
**REQUIRED, not optional, and enforced in the deploy path** — do not run the sovereign
StatefulSet without it: any in-cluster workload that reached the Service directly could
scrape the owner token off `GET /` and act as owner. You do not have to remember to
apply it by hand: it is the first resource of `kustomization.yaml` (so a single
`kubectl apply -k` cannot omit it), and **`tools/ha/deploy.sh` REFUSES to deploy** — its
`tools/ha/require_networkpolicy.py` preflight exits non-zero — when the policy is absent,
does not deny the cross-workload path, is not wired into the kustomization, **or the
cluster has no NetworkPolicy controller (CNI) to enforce it** (an unenforced NetworkPolicy
object is silently a no-op). Note the kubelet-probe caveat in that file (some CNIs need
the node source allowed too). The proxy→cockpit hop is still cleartext HTTP on the pod
network (bearer + owner console credential): the policy bounds *who* connects, not
confidentiality — add a mesh mTLS / encrypted CNI if your pod network is untrusted
(HA-PROFILE.md §1.2 / §4).

## The single-writer invariant (do not "fix" it)

`sovereign-statefulset.yaml` is `replicas: 1` **on purpose**. The spine is an
append-only, owner-signed, hash-chained log with a durable anti-rollback floor;
two concurrent writers produce two owner-signed heads at one `entry_count` — a
fork the floor (`check_floor`) and the witnesses (`is_split`) exist to detect and
reject. Raising the replica count does not scale the writer; it corrupts the log.
HA of the writer is **active-passive failover**, gated by the interlock below. A
CI test asserts this file keeps `replicas: 1`.

## The anti-rollback readiness gate (failover interlock)

The StatefulSet's `anti-rollback-gate` initContainer runs
`tools/ha/spine_failover_guard.py` before the writer serves. It refuses to let the
pod become Ready (exit 2) if the PVC-restored/synced spine head is **below** the
off-box witnessed checkpoint — so a pod that came up on a stale mirror never
rolls the floor back and the headless Service never routes writes to it.

The witnessed checkpoint is supplied as a Secret **retained independently of the
spine PVC** (a copy rolled back with the PVC is worthless as an anchor):

```
# emit on the current active, retain the envelope OFF-BOX, then load it as the Secret:
sigil checkpoint emit --out checkpoint.witnessed.json
kubectl create secret generic vigil-witnessed-checkpoint \
    --from-file=checkpoint.witnessed.json=./checkpoint.witnessed.json
```

Refresh that Secret after every promotion so the next restart anchors against a
current height.

## Images and secrets

- `vigil/runtime:local` — an operator-built image carrying the **sovereign** venv
  and the repo at `/app` (the sovereign plane only; the OFFENSE plane stays native
  per the two-process boundary — do not add it here). Digest-pin before prod.
- `vigil-secrets` — `crucible-api-key`, `neo4j-auth`.
- `vigil-witnessed-checkpoint` — the off-box witnessed checkpoint (above).

## Apply

**Use the gated deploy** — it makes the REQUIRED NetworkPolicy required *in the deploy
path*, refusing to proceed if the policy is absent, does not deny the cross-workload
path, is not wired into the kustomization, or the cluster has no NetworkPolicy
controller to enforce it — and (W6-2) refusing unless every workload declares real
liveness+readiness probes wired to `/healthz` + `/readyz`:

```
tools/ha/deploy.sh
# If your cluster enforces NetworkPolicy via a CNI the preflight cannot auto-detect,
# attest it out of band (do NOT use this to bypass a cluster with no enforcement):
#   VIGIL_NETPOL_CONTROLLER_CONFIRMED=1 tools/ha/deploy.sh
```

The whole set is one kustomization, so the manifest-level equivalent still cannot omit
the NetworkPolicy (it is the first resource):

```
kubectl apply -k infra/ha/k8s/
```

Front the `vigil-proxy` Service with your own Ingress + TLS (nothing here is
publicly exposed; the Ingress/tunnel is the boundary — see
[`apps/sigil/deploy/REMOTE-HOSTING.md`](../../../apps/sigil/deploy/REMOTE-HOSTING.md)).

## Failover (manual, anti-rollback-safe)

1. Fence the old active writer (scale the StatefulSet to 0 or confirm the node is
   gone). **Two writers must never be live at once.**
2. Ensure the passive/replacement pod's PVC holds a mirror **at or above** the
   retained witnessed checkpoint (sync it out-of-band: volume snapshot, rsync,
   storage replication).
3. Bring the StatefulSet back to `replicas: 1`. The `anti-rollback-gate`
   initContainer runs the guard; if the mirror is stale it fails and the pod stays
   un-Ready — investigate rather than force it.
4. After it is Ready, emit a fresh witnessed checkpoint and refresh the Secret.
