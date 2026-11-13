# Hosting & Persistence runbook

How VIGIL stores its data, what a host must provide, and the exact gates between a running
install and charging real customers. The *why* behind each gate; for the turnkey, ordered command
sequence see `GO-LIVE-quickstart.md`. Companion to `REMOTE-HOSTING.md` (the reverse-proxy /
never-public-bind topology), `snapshot-down-migration.md`, and `egress-posture.md`.

> **The one rule:** the cloud provides *durable storage + compute + backing services + the TLS
> edge*. VIGIL owns the *integrity of its own state* (the owner‑signed spine + the owner key).
> You never hand the system of record to a managed mutable database — that would break the
> sovereignty / tamper‑evidence model the product is built on.

---

## 1. The data architecture (what the "database" is)

VIGIL's **system of record is the spine** (`apps/sigil/sigil/spine/store.py`): an append‑only,
hash‑chained, Ed25519‑owner‑signed log under `SIGIL_HOME/spine/`. Every money/auth/authority/audit
fact is a signed, append‑only record — not editable or deletable, and independently replayable.
There is **no Postgres/MySQL/Mongo/Redis** in VIGIL's own stack by design.

Durability properties already in the store: durable atomic writes (`fsync` + atomic manifest/segment
`os.replace`), cross‑process `flock` + in‑process `RLock` serialization, at‑rest encryption of
sensitive payloads (owner‑vault‑sealed DEK), schema‑versioned snapshots/folds, prune tripwires, and
crash‑safe backup/migrate/rollback (`sigil backup` / `restore` / `checkpoint`; `sigil upgrade`).

**Auxiliary engines hold derived, rebuildable data — never truth:**

| Store | Holds | Config | Notes |
|---|---|---|---|
| Qdrant | vector / semantic memory | embedded `SIGIL_HOME/qdrant`, or server via `SIGIL_QDRANT_URL` | rebuildable from the spine + intel |
| Neo4j / Kuzu | knowledge graph | `SIGIL_HOME/graph` (embedded) or the `graph` compose profile | optional; rebuildable |
| SQLite | public CVE catalog | `SIGIL_HOME/cve/catalog.db` (`sigil cve ingest`) | read‑mostly reference set |

If you ever want Postgres, its only correct role is a **read‑model / reporting projection fed from
the spine** — never the source of truth.

**Data directories:**
- `SIGIL_HOME` (default `~/.sigil`) — private state: spine, owner keys, the sealed DEK, embedded
  Qdrant/graph/CVE, the customer session/token ledgers. **This is the one directory that must be on
  durable, backed‑up storage.**
- `VIGIL_BASE_DIR` (default `.vigil-live`) — published owner‑signed artifacts + the cross‑plane seam
  (credit leases and their settlement + pause markers, monitoring authorities, the offense engine's own
  keys and state). Durable, and **not** rebuildable from the spine: the sovereign `sigil backup`
  deliberately excludes it, and the offense `vigil backup` captures it only when its `--base-dir` is this
  directory (`vigil doctor` notes a mismatch). Launch settlement does not rely on it alone: a settle is
  decided under a cross‑process lock beside the spine (`<stem>.settle.lock`), and a settle that moved
  money (a refund, or any postpaid settle) is on the spine. With `VIGIL_SETTLE_SPINE_RECORD=1` (default
  off) every fresh settle — a completed run's zero‑refund settle included — first writes an
  owner‑signed `governor.launch_settled` record carrying its whole decision (mode, reservation,
  consumption and the exact plan / wallet / postpaid refund split), and a later settle that finds it
  finishes it at the recorded amounts. **Set the flag identically for the cockpit, the customer
  server, the settle drain and `ops-sweep`.** A lost or stale settlement marker then cannot re‑open the
  refund of a settled launch — but only while BOTH hold: the launch was settled by a process with the
  flag on (or a refund of it landed), and its owner‑signed evidence is still in the LIVE spine. A hard
  prune past the settle removes that evidence (the scan is live, not snapshot‑seeded), after which a lost
  marker is again the only record.

  **Settle locks.** Every lock on the settle path is a bounded wait that ends in a retry, never a hang:
  the settle lock waits `VIGIL_SETTLE_LOCK_WAIT_S` seconds (default 10, clamped to 0.1–120), then a
  settle answers "busy; retry" — the settle drain defers the completion (back to `incoming/`), the
  sweep reports `deferred`, a customer cancel / start is refused with a retry hint. A pause waits at
  most 2 s and then records the halt anyway (`linearized: false`) — as it also does when the settle
  lock cannot be opened or, with the flag on, the spine cannot be read (only the seam settlement
  marker then decides whether the launch is already settled); a resume never takes the settle
  lock. With the flag on, a start on a host whose previous launch has a recorded settlement with
  money still to land is refused with a retry until that settlement is finished through the previous
  launch's lease on the seam, which a start would otherwise replace. The settle drain finishes it on
  its next pass, with no operator: with the flag on, every pass finishes each recorded settle of a
  lease in its scope that was interrupted — whatever decided it (a completion, a cancel, a sweep, an
  expired pause) — moving only the recorded decision, exactly once, then retires the lease, and prints
  `interrupted settles: N finished, M left for the next pass` when it acted. `ops-sweep reservations
  --apply` finishes it too. `vigil doctor` (with the flag on in its environment or `sigil.env`) reports a
  lease still published more than 10 minutes after its settlement was recorded as a hard issue
  (`launch_settlements.unfinished`), so such a hold is never silent. The lock files are transients that
  both backup legs skip: `<stem>.settle.lock` beside the spine, the settlement, pause and
  paused‑past‑expiry `<slug>.json.lock` files beside their markers, and `<spool>/.spool.lock` in the
  completion spool (created by the settle drain). **Run `ops-sweep reservations --apply` as the service
  user.** As root it refuses to run unless the seam, the spine and (where they exist) the
  settlement‑marker, completion‑spool and model‑meter directories are owned by root: a root sweep would
  create settlement markers, their locks and spine files the services can no longer write. A root
  report‑only `ops-sweep` that must create `<spool>/.spool.lock` hands it to the owner of the spool.

  **`ops-sweep reservations` statuses** added by this: `completion_pending` / `completion_unknown` /
  `pause_changed` / `pause_unknown` when the settle's in‑lock re‑check of the spool or the pause state
  refuses it (nothing written; the next pass decides), `deferred` for a busy lock or meter,
  `settle_completed` (with the amounts moved) when a settle finished a recorded decision a crash
  interrupted, and — with the flag on — `settle_interrupted` (report only) for a listed lease whose
  recorded decision has entries not yet landed; `--apply` finishes it. Do **not** move files from the
  completion spool's `rejected/` back to `incoming/` by hand while a `sweep --apply` is running. A
  completion whose own launch is already settled while a later launch holds the seam is archived as a
  no‑op (a stderr line names it), not quarantined.

  **One launch per host, superseded reservations.** With `VIGIL_ONE_LAUNCH_PER_HOST=1` (default off) a
  customer holds at most one outstanding launch per (org, host): a second reserve is refused while an
  earlier one is unsettled and may still run, and a start never replaces another launch's unsettled lease
  on the seam, whatever the billing mode (decided under the settle lock). `ops-sweep reservations` also
  reads launch reservations from the spine and lists one that a later launch of the same target replaced
  on the seam (`superseded`), past its longest lease window plus `--ttl`; `--apply` refunds it through the
  same exactly‑once settle (`released`). It is never released while a completion that could charge it is
  anywhere in the completion spool (`completion_pending` / `completion_unknown`), when the spine and the
  seam disagree about the target (`outcome_recorded` / `seam_inconsistent`), or when it was published
  metered (`metered` / `metered_unknown`: it is charged for what it used, through its completion or a
  cancel). With the settle record on, a release a crash interrupted is finished by `--apply`
  (`settle_completed`) and reported `settle_interrupted` without it.

  **Expired paused launches.** A paused launch whose lease window closed (or whose pause was lifted only
  after it closed) can no longer run. `vigil doctor` reports it as a hard issue once the settle grace
  (`VIGIL_PAUSED_EXPIRY_SETTLE_GRACE_SECONDS`, default 86400, from the later of the window end, the pause
  and the late resume) has passed and nothing settled it. `ops-sweep reservations --apply` settles it by
  the paused‑launch rule (metered: charged for what it used; flat: refunded); with
  `VIGIL_PAUSED_EXPIRY_SETTLE=1` (default off; set it for the settle‑drain unit) the settle drain does the
  same after each pass's completions, re‑checking the completion spool, the pause state and that it is
  still due inside the settle lock, and prints `expired paused launches: N settled, M still held`.

---

## 2. Hosting topology

Processes run **natively** (not containerized — the offense side drives the host Docker daemon for
strix; containerizing it would hand over the docker socket and weaken the two‑plane boundary).
`docker-compose.yml` provides **backing services only**, every port bound to `127.0.0.1`.

```
Internet ──TLS──▶ reverse proxy (Caddy/nginx, :443)     [the only public listener]
                   ├─ vigil.example.com      ▶ 127.0.0.1:8735  pubui (public site; keyless)
                   ├─ app.vigil.example.com  ▶ 127.0.0.1:8734  custui (tenant app)
                   └─ console.vigil.example  ▶ 127.0.0.1:8770  vigil up (operator; keep private/SSO/VPN)
```

Nothing binds a public interface — every surface fails closed (`bind_ok`, exit 2) on `0.0.0.0`/public.
Templates live in `apps/sigil/deploy/reverse-proxy/` and systemd units in `apps/sigil/deploy/systemd/`.
The customer edge reaches the owner‑key‑holding provisioner only over loopback + `VIGIL_PROVISION_HOP_KEY`.

---

## 3. Durable storage + backups (host responsibility)

1. Put `SIGIL_HOME` on a **durable block volume** (cloud persistent disk), not ephemeral/instance
   storage. The spine is the irreplaceable asset.
2. Schedule off‑host backups: `sigil backup` produces a whole‑spine‑dir tar.gz **outside** the spine
   dir; ship it to object storage (S3/GCS/B2) on a timer (the `sigil-checkpoint.timer` unit is the
   in‑product cadence). Keep ≥ 2 generations.
3. Test restore: `sigil restore <backup>` into a scratch home + `sigil verify` must re‑verify the
   chain and match record counts. **A backup you have not restored is not a backup.**
4. Schema upgrades are crash‑safe + rolling‑back (`sigil upgrade`); the down‑migration path is in
   `snapshot-down-migration.md`.

---

## 4. Owner‑key custody (the single most important secret)

The owner Ed25519 key is vault/TPM‑sealed (`owner_vault`, fail‑closed; `OWNER_PRIV_CONTEXT`). In cloud:
- Back the seal with a **cloud KMS/HSM** (AWS KMS / GCP KMS / an HSM). The key must never sit as a
  plaintext file on a shared disk in production (the dev/unsealed file mode is for local only).
- The key lives **only** in the sovereign provisioner process — never in the keyless edges
  (`custui`/`pubui`) or the offense plane (FATAL‑2).

---

## 5. Backing services at scale

- Qdrant: run managed or as the pinned compose container; point VIGIL at it with `SIGIL_QDRANT_URL`.
  Rebuildable, so lower stakes.
- Neo4j/Kuzu: optional; the `graph` profile or a managed graph DB.
- All backing data is derived — a lost backing store is a re‑index, not a data‑loss event.

---

## 6. Scale / HA posture (decide against expected tenant volume)

The spine is a **single‑writer, single‑node** append log (one host serializes writes via `flock`).
This is efficient to real scale (appends + snapshot folds are cheap), but it is **not multi‑node
replicated out of the box**. Therefore:
- **HA today =** durable, replicated **storage** (cloud volume with snapshots/replication) + a **warm
  standby host** that attaches the volume on failover. Writes remain single‑host.
- **Horizontal read replicas** (serving tenant reads off spine projections) are a future build item,
  not required for launch.

---

## 7. The two go‑live gates (do NOT skip)

With `VIGIL_POSTURE=production`, `vigil up` / `vigil engage` **refuse to start** unless **all five**
production preconditions hold (each prints the failing control; see `vigil doctor`):

1. **vault SEALED** — owner key under the sealed vault (not the dev file mode).
2. **sovereignty non‑PERMISSIVE** — the posture is not the permissive dev setting.
3. **entitlement ACTIVE** — a valid owner entitlement.
4. **backups ON** — the backup/checkpoint path is configured.
5. **charter PRESENT** — the signed engagement charter is in place.

**Beyond those, two switches are the literal "charge real customers / run against real targets"
controls and are a deliberate, separate owner act:**

- **`VIGIL_CUSTOMER_PROD_EXECUTION`** — the K4 customer production‑target execution hold. Default OFF;
  `vigil up`/`engage` refuse a live customer arm while off (loopback/staging proceed). Flip only after
  the full K4‑6 acceptance matrix is green for your deployment.
- **A real payment‑provider transaction verifier** — `sigil billing-drain` is fail‑closed and mints
  nothing until an owner provisions the server‑side Flutterwave `/v3/transactions/{id}/verify` caller
  (`cli._billing_transaction_verifier`). This needs your Flutterwave **secret key** (never in the repo
  or an env var in plaintext — inject via the KMS/secret manager at the provisioner only).

---

## 8. Pricing & unit‑economics (owner confirms before the prod flip)

The owner catalog (`apps/sigil/sigil/governor/catalog.py`) is the **sole money anchor** — no on‑the‑wire
amount ever decides money. Before go‑live, confirm **three inputs** that only you have:

1. **COGS per credit.** A credit is consumed per authorized assessment (flat‑per‑run). Measure the real
   compute/LLM/infra cost of one run, divide by credits‑per‑run, to get cost/credit. Set prices to your
   target gross margin above that. *(The committed defaults assume a low single‑digit‑cent cost/credit;
   validate against your real COGS — underpricing here loses money on every run.)*
2. **Price coherence.** Subscriptions must give a **better** effective per‑credit rate than one‑time
   top‑ups (commitment discount) — a separate PR recalibrates the ladder so this holds.
3. **Provider plan‑id binding.** Each subscription `price_id` (e.g. `vigil_pro_monthly`) must equal the
   **real Flutterwave payment_plan id** you create in your Flutterwave dashboard; each top‑up
   `price_id` must be set as the checkout `meta.price_id`. VIGIL cannot mint these — they live in your
   provider account. The catalog's `amount_minor` is the defense‑in‑depth cross‑check, not the charge.

Changing a price is an owner‑reviewed commit + deploy (same trust root as the owner key); the catalog
is validated fail‑closed at import, so a malformed price can never ship.

---

## 9. Go‑live checklist

- [ ] `SIGIL_HOME` on a durable, replicated volume; off‑host backups scheduled + a restore drill passed.
- [ ] Owner key sealed by a cloud KMS/HSM; no plaintext key on disk.
- [ ] Reverse proxy terminates TLS; every surface bound loopback/private; SSE paths buffering‑off.
- [ ] Qdrant (+ optional Neo4j) reachable; `SIGIL_QDRANT_URL` set if managed.
- [ ] `vigil doctor` green: vault sealed · sovereignty non‑permissive · entitlement active · backups on · charter present.
- [ ] Catalog prices confirmed against real COGS/margin; subscription `price_id`s bound to real Flutterwave payment_plan ids; top‑up `meta.price_id` wired at checkout.
- [ ] Real payment‑provider verifier provisioned at the provisioner (secret via KMS).
- [ ] **Only then:** flip `VIGIL_CUSTOMER_PROD_EXECUTION` for customer execution — a deliberate owner act, after the K4‑6 acceptance matrix is green.
