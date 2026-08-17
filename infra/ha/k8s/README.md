# VIGIL HA on Kubernetes

These manifests implement the HA profile in
[`docs/architecture/HA-PROFILE.md`](../../../docs/architecture/HA-PROFILE.md).
Read that first — especially §2 (why the spine cannot be multi-writer) and the
verbatim non-claim. **This profile does NOT provide multi-writer high
availability of the sovereign spine.**

## The shape

| Manifest | Kind | Replicas | HA posture |
|---|---|---|---|
| `proxy-deployment.yaml` | Deployment (+HPA) | 3 (→10) | **Active-active** stateless read/proxy tier. Genuinely scalable. |
| `sovereign-statefulset.yaml` | StatefulSet (+PDB) | **1 by design** | **Single writer.** Anti-rollback readiness-gate initContainer; active-passive failover only. `replicas>1` is a data-corruption bug, not scale. |
| `qdrant-statefulset.yaml` | StatefulSet | 1 | Durable single node. HA needs distributed mode (≥2 nodes + replication_factor≥2) — documented, not shipped. |
| `neo4j-statefulset.yaml` | StatefulSet | 1 | **Community = no clustering.** Durable single instance only; HA needs Neo4j Enterprise. |
| `otel-deployment.yaml` | Deployment | 2 | Active-active stateless. |
| `services.yaml` | Services | — | ClusterIP + a **headless** Service for the StatefulSet. Sticky sessions on the proxy Service. |

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

```
kubectl apply -f infra/ha/k8s/services.yaml
kubectl apply -f infra/ha/k8s/qdrant-statefulset.yaml
kubectl apply -f infra/ha/k8s/neo4j-statefulset.yaml
kubectl apply -f infra/ha/k8s/otel-deployment.yaml
kubectl apply -f infra/ha/k8s/sovereign-statefulset.yaml
kubectl apply -f infra/ha/k8s/proxy-deployment.yaml
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
