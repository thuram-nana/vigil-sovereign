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
| `vigil up` reverse proxy / `uiproxy.py` | **Active-active** (read/proxy) | Stateless except the per-instance session token. N replicas behind an LB; needs a shared token store **or** sticky sessions (documented below). |
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
promotes a passive to active. The danger this runbook exists to prevent is a
**rollback on promotion**: a passive booting from a *stale* mirror would carry an
older head, and naively promoting it would roll the durable floor backwards —
exactly the "cold verifier off an untrusted mirror" gap documented in
`floor.py` (HONEST LIMIT, lines ~15-24).

### 3.1 Prerequisite: retain a witnessed checkpoint OFF-BOX

The active writer must periodically emit a witnessed checkpoint and retain it
**off the active host** (a second machine, a USB stick, a remote commit, or the
paired device over WireGuard):

```
sigil checkpoint emit --out /retained/off-box/checkpoint.witnessed.json
```

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
2. `check_floor(local_head, floor_of_the_witnessed_checkpoint)` passes — the
   local synced head does not roll back any monotonic quantity below the
   witnessed anchor; **and**
3. the local head's `entry_count` **and** `last_seq` are **≥** the witnessed
   checkpoint's (belt-and-suspenders on the exact witnessed height).

A passive booting from a stale mirror (local head **below** the witnessed
checkpoint) therefore **cannot** be promoted — the guard exits non-zero and the
floor is never rolled back. Only a passive whose head is **at or above** the
retained witnessed height activates.

### 3.3 The manual cutover (after the guard passes)

1. **Fence the old active.** Stop the old active writer (or confirm it is
   already down). Two writers must never be live at once — see §2.
2. **Run the guard on the passive** (§3.2). If it exits non-zero, DO NOT
   promote; investigate the stale mirror / retain a fresher off-box checkpoint.
3. **Repoint the LB / VIP** at the newly-promoted node's loopback backend.
4. **Emit a fresh witnessed checkpoint** from the new active and retain it
   off-box, so the next failover has a current anchor.

In k8s the same interlock runs as the sovereign StatefulSet's **anti-rollback
readiness-gate initContainer** (`infra/ha/k8s/sovereign-statefulset.yaml`): the
writer pod does not become Ready — and the Service does not route to it — until
the guard passes. The StatefulSet is pinned `replicas: 1` **by design** (a
`PodDisruptionBudget{minAvailable: 1}` keeps the single writer scheduled); a
comment block in that file states plainly that `replicas > 1` there is a
**data-corruption bug, not scale.**

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

---

## 5. What this profile ships

- `infra/ha/docker-compose.ha.yml` — active-active proxy + otel, server-mode
  Qdrant (2-node note), one active sovereign backend + a labeled passive under
  `--profile passive` that does NOT auto-write. All host ports loopback/VIP-only.
- `infra/ha/k8s/` — `proxy-deployment.yaml` (replicas 3, readiness probe),
  `sovereign-statefulset.yaml` (replicas 1 by design, PDB, anti-rollback readiness
  gate), `qdrant-statefulset.yaml`, `neo4j-statefulset.yaml` (community caveat),
  `otel-deployment.yaml`, `services.yaml` (headless for the StatefulSet), and a
  `README.md`.
- `tools/ha/spine_failover_guard.py` + `sigil floor promote-passive` — the
  witnessed-floor failover interlock (§3).
