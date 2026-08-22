# VIGIL HA / Cluster profile — an HONEST high-availability posture

Claim 6, Piece B. This document describes what VIGIL can and **cannot** do for
high availability, and it is deliberately conservative about the one thing that
matters most: the **sovereign spine is single-writer by design**. A second
concurrent writer is not scale — it is a **detectable fork**. This profile makes
the stateless read/proxy tier genuinely active-active, documents the server-mode
upgrades the stateful backends need, and gives the single-writer spine an
**anti-rollback-safe active-passive failover** with a witnessed-floor interlock.

> **The explicit non-claim (verbatim, load-bearing — a CI test asserts this
> string is present):**
>
> **VIGIL does not provide, and this profile does not claim, multi-writer high
> availability of the sovereign spine. The spine is single-writer; the floor and
> witness quorum make a second concurrent writer a detectable fork.**

Cross-reference: [`apps/sigil/deploy/REMOTE-HOSTING.md`](../../apps/sigil/deploy/REMOTE-HOSTING.md)
(the tunnel + reverse-proxy network boundary), the root
[`docker-compose.yml`](../../docker-compose.yml) (the backing services, all bound
to `127.0.0.1`), and [`infra/ha/`](../../infra/ha/) (the compose + k8s manifests
that implement this profile).

---

## 1. The honest HA matrix

Each row states the HA posture **truthfully** — what is genuinely redundant, what
requires a paid/enterprise upgrade you must supply, and what is *anti*-available
on purpose.

| Component | HA posture | Mechanism / limit |
|---|---|---|
| `vigil up --proxy-only` reverse proxy / `uiproxy.py` | **Active-active** (read/proxy) | Stateless. N replicas behind an LB, **each in `--proxy-only` mode** so it spawns NO backends and federates `/sovereign/*` to the one central writer (§1.1). A plain `vigil up` would spawn a per-pod cockpit = a second writer (a fork); `--proxy-only` is what makes replication correct. Needs a shared token store **or** sticky sessions (documented below). |
| otel-collector | **Active-active** | Stateless OTLP→stdout receiver; run N replicas. |
| Qdrant (vector store) | **HA ONLY in server + distributed mode** | SIGIL defaults to an **embedded/local** store (`config.py` `QDRANT_PATH`) which is NOT HA. HA requires switching to `QDRANT_URL` server mode with Qdrant's own replication — you must run and pay for that; this profile documents the switch, it does not make embedded Qdrant magically clustered. |
| Neo4j (knowledge graph) | **NOT HA in community** | `docker-compose.yml` pins `neo4j:5-community` — a **single instance**. A causal cluster is a Neo4j **Enterprise** feature. This profile does NOT ship a cluster and does not imply one. |
| Witnesses (`vigil-witness@.service`) | **Independence nodes, NOT failover** | More witnesses = stronger split-view resistance, **not** writer availability (see `integration/vigil_integration/transparency.py` and `apps/sigil/sigil/spine/witness.py`). Scaling the witness roster does **not** make the writer highly available. |
| **Sovereign spine** (single-writer + anti-rollback floor) | **CANNOT be multi-writer HA** | Active-**passive** only, with a witnessed-floor failover interlock (§3). Two concurrent writers = two owner-signed heads at one `entry_count` = a fork the floor and witnesses exist to DETECT. |
| Offense `{slug}.spine` | **Single-writer per engagement** | Same active-passive pattern. New engagements may start on any node; a given engagement's spine has exactly one writer. |

The stateless tier (proxy, otel) scales horizontally with no correctness cost.
The stateful backends (Qdrant, Neo4j) are HA only if you deploy their own
server/enterprise HA — this profile documents that boundary and refuses to fake
it. The spine is single-writer, full stop.

### 1.1 `--proxy-only`: why the read tier does not spawn its own backends

`vigil up` is **not a stateless proxy by default.** A plain `vigil up` LAUNCHES
three children — the sovereign cockpit (`sigil serve`, 8733) and both offense
backends (`crucible console` 8787, `crucible api` 8799) — as processes it owns on
fixed loopback ports, and only *then* reverse-proxies to them. Running that in N
replicas is a **correctness bug, not scale**: each replica would spawn its **own**
sovereign cockpit, i.e. an Nth signed-spine **writer** — the exact "same height,
different head" fork the floor + witnesses exist to reject (§2). (It would also
collide on the fixed backend ports.)

`vigil up --proxy-only` is the fix and the mode the HA proxy Deployment runs. In
this mode the process **spawns nothing** and federates to **remote** backends given
by flags/env (all fail-closed-parsed `host:port`, empty ⇒ the loopback default so
the non-HA path is byte-identical):

| Flag | Env | Federation target | k8s value |
|---|---|---|---|
| `--sovereign-addr` | `VIGIL_SOVEREIGN_ADDR` | `/sovereign/*` → the cockpit | `vigil-sovereign:8733` (the headless writer Service) |
| `--offense-console-addr` | `VIGIL_OFFENSE_CONSOLE_ADDR` | `/offense/*` read+SSE | `127.0.0.1:8787` (co-located; see below) |
| `--offense-api-addr` | `VIGIL_OFFENSE_API_ADDR` | `/offense/api/v1/*` | `127.0.0.1:8799` (co-located; see below) |

Per-user auth is likewise delegated to the **remote** sovereign whoami
(`--sovereign-addr`), and the proxy still refuses a public/`0.0.0.0` bind — the pods
bind their **own RFC1918 pod IP** (`--host $(POD_IP)` via the k8s downward API,
which `bind_ok` accepts) and advertise `--domain` for the Ingress/TLS edge.

**Honest scope — what this profile actually clusters:** the **sovereign spine
writer** (single-writer StatefulSet) and the **stateless proxy tier**. The
**offense plane is NOT a clustered, cross-pod workload here**, for two independent
reasons that are *by design*, not oversight:

1. **The offense console/api bind loopback ONLY.** `serve()`
   (`engine/crucible/framework/v2/console/server.py`) *raises* on any non-loopback
   host — "the console is a single-operator, on-host surface by design (sovereignty);
   the unified reverse proxy is the only public listener." They cannot bind a pod IP,
   so they are unreachable from another pod.
2. **The offense plane stays native.** It drives the host Docker daemon for
   sandboxed scans; containerizing it would mean handing it the host docker socket,
   weakening the two-process boundary — so the `vigil/runtime:local` image carries the
   **sovereign** venv only, deliberately not the offense venv.

Consequently `/sovereign/*` is federated to the one central writer, while
`/offense/*` works only against an offense plane **co-located with the proxy on
loopback** (a sidecar the operator adds, holding the docker socket per the
two-process boundary). Left at the loopback default with no such sidecar,
`/offense/*` returns 502 while `/sovereign/*` serves through the proxy. This profile
does not ship the offense sidecar and does not pretend `/offense/*` is horizontally
scalable.

### 1.2 The sovereign cockpit MUST be reachable only via the authenticating proxy

`/sovereign/*` being federated does **not** mean the sovereign plane is safe to
expose. The cockpit serves its OWN owner token at `GET /` **token-free**
(`<body data-token="<owner token>">` — a single-operator, on-host surface by design),
and the headless `vigil-sovereign` Service has no auth of its own. The **proxy is the
authenticating boundary**: it establishes per-user identity (delegated whoami) and
**scrubs the backend's embedded owner token out of any relayed HTML** (value-agnostic
`data-token=""`, so it holds even for a remote cockpit whose token the proxy never
captured). Therefore:

- **A `NetworkPolicy` is REQUIRED, not optional** (`infra/ha/k8s/networkpolicy.yaml`):
  it restricts ingress to `vigil-sovereign:8733` to the `vigil-proxy` pods only. Any
  other in-cluster workload that reached the cockpit Service directly could scrape the
  owner token off `GET /` and act as OWNER. It is **enforced in the deploy path**, not
  left to operator discipline: it is the first resource of `infra/ha/k8s/kustomization.yaml`
  (so a single `kubectl apply -k` cannot omit it), and the gated deploy
  **`tools/ha/deploy.sh` REFUSES to proceed** (its `tools/ha/require_networkpolicy.py`
  preflight exits non-zero) when the policy is absent, does not deny the cross-workload
  path, is not wired into the kustomization, **or the cluster has no NetworkPolicy
  controller (CNI) to enforce it** — an unenforced NetworkPolicy object is silently a
  no-op and leaves the leak open. Do not run the sovereign StatefulSet without it.
- **The proxy→cockpit hop is cleartext HTTP inside the pod network** (MEDIUM residual,
  §4): it carries the per-user bearer and the substituted owner console credential. The
  NetworkPolicy bounds *who* may connect; it does not *encrypt* the hop. A cluster whose
  pod network an attacker can sniff needs transport isolation too — a service-mesh mTLS
  (Istio/Linkerd) or an encrypted CNI (WireGuard/IPsec overlay). Do not assume the pod
  network is confidential by default.

---

## 2. Why multi-writer of the spine is a correctness violation, not a missing feature

This is the crux, and it is the reason the non-claim above is stated so bluntly.

The sovereign spine is an **append-only, owner-signed, hash-chained log** with a
durable **anti-rollback floor** (`apps/sigil/sigil/spine/floor.py`). Its integrity
model assumes exactly one writer advancing one monotonic head. Concretely:

- **The head is monotonic.** `Floor.entry_count` is the ABSOLUTE record count and
  is the primary anti-rollback quantity (`floor.py` `check_floor`, lines ~175-198).
  The floor refuses any head whose `entry_count` / `last_seq` / `base_*` would go
  backwards, and — for v2 heads — enforces meta-chain parent linkage.
- **Two concurrent writers produce two owner-signed heads at the same
  `entry_count`.** Both are validly signed (both hold, or share, the owner key).
  That is *precisely* the "same height, different head" fork that
  `transparency.is_split` (`transparency.py`, `is_split`, lines ~301-314) and the
  witness `consistent`/`verify_against_external` checks (`witness.py`) exist to
  **catch**. The floor's meta-chain check likewise treats a second, different
  owner-signed child of the same parent as a **META-CHAIN BREAK**.

So multi-writer HA of the spine would make the fork — the exact thing the whole
anti-rollback + transparency apparatus is built to detect and reject — the
**normal, steady-state** condition. You cannot both (a) detect equivocation and
reject rolled-back/forked heads, and (b) run two writers that each advance the
head independently. The floor and the witness quorum are **anti-availability by
design**: they trade "the writer is always up" for "the log can never be
silently forked or rolled back." That trade is the product. HA must respect it.

The honest consequence: the sovereign writer is a **single point of write
availability**. We make its *failover* safe (§3) and its read/proxy tier
horizontally scalable (§1), but we do **not** pretend the writer is
multi-active. Anyone who tells you a signed, single-owner, anti-rollback spine is
"multi-master HA" is selling you a fork.

---

## 3. Active-passive failover — the runbook with the anti-rollback interlock

The sovereign spine runs as **one ACTIVE writer** plus one or more **PASSIVE**
standbys that hold a **synced mirror** of `~/.sigil` but do **NOT** write. Failover
promotes a passive to active. The danger this runbook exists to prevent is
promoting an **untrusted mirror** — a mirror whose head has been **rolled back**
(stale), **forged** (a head not signed by the owner), or **forked** (a *different*
owner-signed history at the same height, since a passive shares the owner key —
§4). Promoting any of those would roll the durable floor backwards or activate a
divergent history — the "cold verifier off an untrusted mirror" gap documented in
`floor.py` (HONEST LIMIT, lines ~15-24). The interlock closes it by
**authenticating the local head's owner signature and binding it to the off-box
witnessed checkpoint** (head authenticated + fork-bound + extension-proven) before
it will promote — not merely comparing self-declared record counts.

### 3.1 Prerequisite: SCHEDULE the off-box witnessed checkpoint (and fail on a stale anchor)

The active writer must emit a witnessed checkpoint and retain it **off the active
host** (a second machine, a USB stick, a remote commit, or the paired device over
WireGuard). It must do so **on a schedule, not by hand** — a checkpoint emitted
manually ages between runs, and a months-old anchor silently widens the rollback
window to whatever the operator's last manual run was (W7-5, #463). So a **timer**
ships and is enabled in the production posture:

```
# sovereign (owner-signed) — apps/sigil/deploy/systemd/sigil-checkpoint.{service,timer}
systemctl --user enable --now sigil-checkpoint.timer      # sigil checkpoint emit --out <off-box>, every 15 min
# offense (governance-signed) — infra/systemd/vigil-checkpoint.{service,timer}
systemctl --user enable --now vigil-checkpoint.timer      # vigil floor witness --watch, every 15 min

# a manual emit is still available:
sigil checkpoint emit --out /retained/off-box/checkpoint.witnessed.json
```

Each emit **stamps an `emitted_at` timestamp** into the envelope (unsigned top-level
metadata — it does **not** change the checkpoint's signed identity, so the anchor
still verifies and stays byte-compatible across planes). The scheduled emitter
refreshes that timestamp every cycle — **even on an idle spine** (a liveness touch),
so a healthy anchor is never more than one cadence old — writes a **dead-man
heartbeat**, and **alarms if the anchor it is about to refresh was already stale**
(a *warning* while still usable, *critical* once past the refusal bound) so
staleness is surfaced *before* the guard would refuse.

**FRESHNESS BOUND (fail-closed).** The failover guard and the `verify-witnessed`
path **REFUSE an anchor older than `VIGIL_ANCHOR_REFUSE_AFTER_S` (default 24h)** — or
one carrying **no** `emitted_at` (un-datable → cannot be proven fresh), or one dated
in the **future** past the skew tolerance. A *warning* bound
(`VIGIL_ANCHOR_WARN_AFTER_S`, default 6h) alerts earlier. Keep the timer cadence well
under the warn bound (the shipped timers fire every 15 min).

A witnessed checkpoint commits `entry_count` / `last_seq` (and, post-Piece-C,
`base_*` / `merkle_root`) under a witness quorum's signatures. **A copy kept only
on the active host is rolled back together with the spine and is worthless as an
anchor.** Only an off-box copy the attacker/rollback never touched is a real
floor for the failover interlock. See `sigil checkpoint emit`'s own on-screen
warning and `witness.py`'s HONEST GUARANTEE BOUNDARY.

### 3.2 Promotion is GATED by the failover guard (never automatic-and-blind)

Before a passive serves writes, run the **failover guard** on the passive:

```
# standalone:
python3 tools/ha/spine_failover_guard.py --witnessed /retained/off-box/checkpoint.witnessed.json
# or the sigil verb (same logic):
sigil floor promote-passive --witnessed /retained/off-box/checkpoint.witnessed.json
```

The guard (`tools/ha/spine_failover_guard.py`, and the `sigil floor
promote-passive` verb) **refuses to activate (exit 2, fail-closed)** unless:

1. the off-box envelope parses, is for **this** scope, and is signed by a
   **trusted witness quorum** (a forged/unsigned "checkpoint" is not a floor);
1a. **(W7-5) the anchor is FRESH** — its `emitted_at` is within
   `VIGIL_ANCHOR_REFUSE_AFTER_S` (default 24h). A stale, un-dated, or future-dated
   anchor is refused fail-closed: a stale anchor means the scheduled off-box emitter
   stopped and the rollback window has silently widened, so it must not gate a
   promotion. (`emitted_at` is a freshness signal, distinct from the anchor's
   signature in step 1 — a same-host key-holder who could forward-date it already
   defeats the local floor, the documented irreducible limit.);
2. the **local head is authenticated** — the guard runs the *same* owner-signature
   authentication the live spine runs before `check_floor`
   (`checkpoint.classify_head` → `reuse.verify_head`): the **owner Ed25519
   signature** at the owner threshold **and** binding of `head_hash`/`last_seq`/
   `entry_count` to the passive's actual live chain. An unsigned, attacker-key-signed,
   or count-inflated head is refused *before any of its scalar fields is trusted*;
3. `check_floor(local_head, floor_of_the_witnessed_checkpoint)` passes — the
   authenticated head does not roll any monotonic quantity below the witnessed
   anchor, and its `entry_count`/`last_seq` are **≥** the witnessed checkpoint's
   (belt-and-suspenders on the exact witnessed height); **and**
4. the authenticated head is **tied to the witnessed history**, not merely at/above
   its count: at **equal height** `local_head.head_hash` **must equal** the witnessed
   `head_hash` (a different one is an owner-key equivocation / same-height fork); when
   **grown**, `witness.verify_against_external` proves an **append-only extension**
   (the current record at the retained `last_seq` carries the retained `head_hash`, so
   records `0..retained` are byte-identical — a real superset, not a divergent longer
   history).

A passive on a **stale** mirror (head below the witnessed checkpoint), a **forged**
head (attacker key, or a self-declared count past the live chain), or a **forked**
head (same/grown height, divergent `head_hash`) therefore **cannot** be promoted —
the guard exits non-zero and no rollback/fork is activated. Only a passive whose
**authenticated** head equals-and-is-head_hash-bound-to, or **provably extends**, the
retained witnessed checkpoint activates.

### 3.3 The manual cutover (after the guard passes)

1. **Fence the old active.** Stop the old active writer (or confirm it is
   already down). Two writers must never be live at once — see §2.
2. **Authenticate the head** on the passive with `sigil verify` (a mandatory,
   independent head-authentication step). It **fail-closes (exit 2)** if the synced
   head exists but is **not authentically owner-signed** (absent/bad signature,
   rewritten, or stale). This enforces head authentication **by composition** — even
   if the guard in step 3 is ever bypassed, a forged/unsigned head fails here first.
3. **Run the guard on the passive** (§3.2). If it exits non-zero, DO NOT
   promote; investigate the untrusted mirror (stale/forged/forked) / retain a
   fresher off-box checkpoint. (The guard *also* re-authenticates the head, then
   binds/extension-proves it against the witnessed checkpoint — step 2 is the
   independent, composition-level backstop.)
4. **Repoint the LB / VIP** at the newly-promoted node's loopback backend.
5. **Emit a fresh witnessed checkpoint** from the new active and retain it
   off-box, so the next failover has a current anchor.

In k8s the same interlock runs as **two sequential initContainers** on the
sovereign StatefulSet (`infra/ha/k8s/sovereign-statefulset.yaml`): a
**head-authentication gate** (`sigil verify`) runs first, then the **anti-rollback
readiness-gate** (the failover guard). The writer pod does not become Ready — and
the Service does not route to it — until **both** pass, so head authentication is
enforced by composition even if the guard is bypassed. The StatefulSet is pinned
`replicas: 1` **by design** (a `PodDisruptionBudget{minAvailable: 1}` keeps the
single writer scheduled); a comment block in that file states plainly that
`replicas > 1` there is a **data-corruption bug, not scale.**

---

## 4. Honest limits (stated, not buried)

- **Failover is manual/orchestrated, not automatic split-brain-proof leader
  election.** We deliberately do NOT ship auto-promotion, because
  auto-promotion *without* the witnessed-floor check is exactly the rollback hole
  in §3. The k8s readiness gate automates the *check*, not a blind promotion:
  it gates a pod becoming Ready on the guard passing; a human still fences the
  old active and repoints the VIP.
- **Neo4j community and embedded Qdrant are NOT HA.** This profile documents the
  enterprise (Neo4j causal cluster) and server-mode (Qdrant distributed)
  upgrades required, and ships neither. Running the k8s `neo4j-statefulset.yaml`
  gives you a durable single instance, not a cluster.
- **The witnessed-floor interlock is only as strong as the retained anchor's
  independence.** At the default **owner-only, threshold-1** witness set, the
  anchor is **rollback DETECTION via off-box retention**, NOT independent
  split-view prevention — the sole witness is the head signer itself. The guard
  labels this honestly ("retention-based DETECTION, NOT independence") and never
  prints "split-view-resistant" for a solo self-witness. Independent prevention
  requires ≥2 independent witness keys at a strict majority, which is a
  **deployment property** code cannot verify (see `witness.py` `guarantee_label`).
- **The anchor's freshness timestamp is UNSIGNED (W7-5).** `emitted_at` is
  top-level envelope metadata, not part of the signed checkpoint (signing it would
  change the checkpoint's cross-plane signed identity). It is a fail-closed
  *operational-drift* signal: it catches a scheduled emitter that STOPPED (the real
  W7-5 hazard) and refuses an un-datable/future-dated anchor. It is **not** a tamper
  control — a same-host owner/governance key-holder who could forward-date it already
  defeats the whole local floor (the irreducible all-keys limit above). The anchor's
  SIGNATURE + the anti-rollback consistency checks remain the tamper controls; the
  freshness gate sits *on top of* them, never in their place.
- **Shared owner key across passives is a trust concession, not HA.** For a
  passive to become a valid writer it must hold the owner signing key. Every host
  that holds that key is a host that can sign a fork. HA of the writer therefore
  widens the key's blast radius; keep the passive fleet small and the key custody
  tight. This is the price of writer failover for a single-owner signed spine,
  and it is stated here rather than hidden.
- **The stateless proxy tier's session token.** Active-active `vigil up` proxies
  are stateless *except* the per-instance session token. Use sticky sessions at
  the LB (documented in `infra/ha/docker-compose.ha.yml` and the k8s
  `services.yaml`) or a shared token store; do not assume any proxy replica can
  serve any session without one of those.
- **The sovereign cockpit is not self-authenticating — the proxy is.** The cockpit
  serves its owner token at `GET /` token-free, so the `vigil-sovereign` Service must
  be reachable ONLY through the proxy. The `NetworkPolicy`
  (`infra/ha/k8s/networkpolicy.yaml`) enforces that (proxy pods only, port 8733); the
  proxy scrubs the embedded owner token out of any relayed HTML (value-agnostic
  `data-token=""`). Running the sovereign StatefulSet WITHOUT that NetworkPolicy leaves
  any in-cluster workload able to scrape owner off the cockpit directly (§1.2).
- **The proxy→backend auth hop is cleartext HTTP on the pod network** (per-user bearer
  + substituted owner console credential). The NetworkPolicy bounds *who* connects; it
  does not encrypt. If your pod network is not trusted, add transport isolation — a
  service-mesh mTLS (Istio/Linkerd) or an encrypted CNI (WireGuard/IPsec). This path is
  NOT silently assumed confidential (§1.2).
- **`--host $(POD_IP)` requires an RFC1918 / ULA pod IP.** `bind_ok` accepts loopback,
  IPv4 RFC1918 (10/172.16-31/192.168), Tailscale-CGNAT (100.64/10), and IPv6 ULA
  (fc00::/7) / link-local — and REFUSES everything else, including a globally-routable
  IPv6 GUA (`2000::/3`) or a public-IP CNI. A CNI that assigns the pod a non-RFC1918/ULA
  address makes `--host $(POD_IP)` fail `bind_ok`, so the container **exits 2 and
  crash-loops**. This is intentional (never-public bind), not a bug — but it means this
  profile requires a cluster whose pod network is private (the overwhelming default:
  RFC1918 IPv4, or IPv6 ULA). On a public-IP or GUA-only CNI, bind a private interface
  instead (or front with a private overlay); do not relax `bind_ok`.

---

## 5. What this profile ships

- `infra/ha/docker-compose.ha.yml` — active-active proxy + otel, server-mode
  Qdrant (2-node note), one active sovereign backend + a labeled passive under
  `--profile passive` that does NOT auto-write. All host ports loopback/VIP-only.
- `infra/ha/k8s/` — `proxy-deployment.yaml` (replicas 3, `vigil up --proxy-only`
  federating to `vigil-sovereign:8733`, `--host $(POD_IP)` bind, readiness probe),
  `sovereign-statefulset.yaml` (replicas 1 by design, PDB, anti-rollback readiness
  gate, `sigil serve --host $(POD_IP)`), `qdrant-statefulset.yaml`,
  `neo4j-statefulset.yaml` (community caveat), `otel-deployment.yaml`, `services.yaml`
  (headless for the StatefulSet), `networkpolicy.yaml` (**required** — cockpit ingress
  restricted to the proxy pods, §1.2), and a `README.md`. Both tiers bind the pod's own
  RFC1918 IP via the downward API — never `0.0.0.0` (which `bind_ok` refuses).
- `vigil up --proxy-only` (+ `--sovereign-addr` / `--offense-console-addr` /
  `--offense-api-addr`, or the `VIGIL_*_ADDR` env equivalents) — the spawn-nothing
  read/proxy mode that federates to remote backends (§1.1). Default (no `--proxy-only`)
  is byte-identical to the historical spawn-local `vigil up`.
- `tools/ha/spine_failover_guard.py` + `sigil floor promote-passive` — the
  witnessed-floor failover interlock (§3).
