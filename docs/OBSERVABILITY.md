# Continuous integrity verification (W6-7)

The whole thesis of this system is a tamper-evident, anti-rollback, **signed spine hash-chain**. Until W6-7,
nothing checked that property *between* manual `vigil verify` / `sigil verify` runs. A broken chain link, a
replayed stale head, a rolled-back anti-rollback floor, or a skewed clock could sit undetected until the next
human ran a verify by hand.

W6-7 adds a **continuous verifier** with three real seams. Everything below is true of the code in
`integration/vigil_integration/integrity_verifier.py` (plus the doctor / posture-endpoint / systemd wiring).

## What it checks

`verify_integrity(home)` reads the sovereign spine home (`spine.jsonl`, `head.json`, `floor.json`) as **inert
bytes** and returns a per-check report:

| check | fails when | severity |
|-------|-----------|----------|
| `chain` | a record's payload no longer binds to its `cert_digest`, or the entries do not link cleanly (delete / reorder / truncate / entry-hash tamper) | FAIL |
| `head_freshness` | a spine has records but no head anchors it, or the signed head does not anchor the current spine tail (a replayed old head / truncated spine); with a pinned trust root, also when the head signature does not verify | FAIL (idle-but-consistent → WARN) |
| `floor` | the head has rolled back below the durable anti-rollback floor, or the floor itself dropped below a height the verifier already retained (a head+floor co-rewrite) | FAIL |
| `clock_skew` | the newest record is dated in the future beyond tolerance, or a supplied trusted reference clock diverges from the local clock beyond tolerance | FAIL |
| `vault` | (advisory) secrets-at-rest state — sealed KEK vs plaintext `sigil.env` | WARN |
| `disk` | headroom under the spine home below the critical floor (an append that cannot fsync corrupts the tail) | FAIL (low → WARN) |

Only a `FAIL` flips the overall verdict. `ABSENT` (a fresh, never-written spine) is **not** a failure — the
verifier never bricks a clean install.

## Where it is wired

- **`vigil doctor`** grows a *Spine integrity* block. A genuine integrity violation is a hard issue (doctor
  exits non-zero); an idle/absent state is not. It also runs the dead-man check below.
- **`/readyz`** on the posture endpoint runs the verifier and returns **HTTP 503** when the integrity property
  is violated (so an orchestrator drains a node whose spine has broken) and 200 when it holds. `/healthz`
  stays a pure liveness probe.
- **`vigil verify-integrity`** runs one audit (exit non-zero on any violation) or, with `--watch`, a periodic
  loop that raises an alarm on failure.
- **`infra/systemd/vigil-integrity.{service,timer}`** fire `vigil verify-integrity --once` on a cadence
  (opt-in). The default cadence is every 15 minutes.

## The alarm path and the dead-man

Each monitor cycle:

1. runs the audit (consulting the verifier's own retained high-water watermark, which catches a head+floor
   co-rewrite a single-disk read would miss),
2. writes a **heartbeat** (`integrity-heartbeat.json`) recording that it ran and the verdict,
3. on any failure, emits a `critical` **integrity-violation** alarm to `integrity-alarms.jsonl` and stderr /
   journal, and invokes any injected callbacks (the seam a real notifier — W8-1 #467 — plugs onto).

If the audit **itself crashes**, the cycle emits a `verifier-error` alarm and still writes a *failing*
heartbeat. And `heartbeat_is_stale(...)` — consumed by `vigil doctor` and `/readyz` — fires when the heartbeat
is absent or older than `VIGIL_INTEGRITY_MAX_HEARTBEAT_STALENESS_S` (default 3600s), so the verifier's **own
failure to run** is itself alarmed (dead-man semantics).

## Honest scope (do not overclaim)

The `chain` + binding checks are **unkeyed** sha-256 checks — exactly the scope of `sigil.spine.store.verify`.
They catch corruption, a naive field/payload tamper, a delete/reorder/truncate, a replayed stale head, and a
floor rolled back below the head. They do **not** by themselves prove authenticity against a writer who can
recompute digests *and* re-sign the head; that requires verifying the owner-signed head under a **pinned**
trusted key (`head_trust_root` / the pinned-key path), which the verifier does only when such a key is
supplied — otherwise the head is reported `signature NOT checked`. The continuous check is **detection between
manual runs**, not a replacement for the signed verify.

The clock-skew check needs a trusted reference to catch a *uniformly* wrong local clock; without one it still
catches a future-dated record (a writer clock ahead). A trusted reference can be sourced from the off-box
witnessed anchor (W7-5 #463) or an NTP probe.

## Configuration

All thresholds are env-overridable with fail-closed defaults — see
`infra/systemd/vigil-integrity.env.example` (`VIGIL_INTEGRITY_MAX_HEAD_AGE_S`,
`VIGIL_INTEGRITY_MAX_CLOCK_SKEW_S`, `VIGIL_INTEGRITY_MIN_DISK_{WARN,CRIT}_BYTES`,
`VIGIL_INTEGRITY_MAX_HEARTBEAT_STALENESS_S`).

## Residuals (blocked on other work)

- **`/readyz` as a first-class endpoint on every server** is W6-1 (#452); today the readiness probe lives on
  the posture endpoint. The verifier exposes `default_readyz()` for #452 to reuse verbatim.
- **A real notifier** (email / webhook / pager) for the alarm callbacks is W8-1 (#467); the alarm sink ships
  the durable log + the callback seam.
- **Claims-registry registration** of this behaviour is W0-3 (#398); the registry does not exist yet.

---

## Scheduled off-box witnessed checkpoint + stale-anchor refusal (W7-5, #463)

The witnessed checkpoint is the off-box anchor the HA anti-rollback / failover interlock depends on
(`docs/architecture/HA-PROFILE.md` §3). Before W7-5 it was emitted **by hand**; a months-old anchor still
passed the guard, silently widening the rollback window to the operator's last manual run. W7-5 schedules the
emit and makes the guard **fail on a stale anchor**.

**Scheduled emitter.** Each emit stamps an unsigned `emitted_at` timestamp into the envelope (top-level
metadata — it does *not* change the checkpoint's signed identity, so the anchor still verifies and stays
byte-compatible across the sovereign and offense planes). Two timers ship and are enabled in the production
posture:

- **`apps/sigil/deploy/systemd/sigil-checkpoint.{service,timer}`** — `sigil checkpoint emit --out <off-box>`
  (owner-signed), every 15 min.
- **`infra/systemd/vigil-checkpoint.{service,timer}`** — `vigil floor witness --watch` (offense
  governance-signed), every 15 min.

Each cycle refreshes `emitted_at` **even on an idle spine** (a liveness touch, so the anchor is never more
than one cadence old), writes a **dead-man heartbeat** (`<retain>.emit-heartbeat.json`), and — before
refreshing — **alarms** (`<retain>.emit-alarms.jsonl` + journal) if the anchor was already stale: `warning`
while it is still usable, `critical` once past the refusal bound, and `error` if the emit itself fails. If the
timer stops firing, the heartbeat goes stale (`witnessed_anchor.emit_heartbeat_is_stale`).

**Stale-anchor refusal (fail-closed).** `sigil floor promote-passive` / `tools/ha/spine_failover_guard.py`,
`sigil floor verify-witnessed`, and `vigil floor verify-witnessed` **REFUSE (exit 2)** an anchor older than
`VIGIL_ANCHOR_REFUSE_AFTER_S` (default 24h), one carrying **no** `emitted_at` (un-datable), or one dated in the
**future** past a 5-min skew tolerance. `VIGIL_ANCHOR_WARN_AFTER_S` (default 6h) is the earlier *warning*
bound. Keep the timer cadence well under the warn bound (the shipped timers fire every 15 min). Bounds are
plane-neutral (`vigil_integration.witnessed_anchor.freshness_verdict`), so the offense and sovereign guards
cannot drift.

**Honest scope.** `emitted_at` is a fail-closed *operational-drift* signal (it catches a stopped emitter). It
is **not** a tamper control: a same-host owner/governance key-holder who could forward-date it already defeats
the local floor (the irreducible all-keys limit in HA-PROFILE §4). The anchor's signature + the anti-rollback
consistency checks remain the tamper controls. **Claims-registry registration** of this behaviour is W0-3
(#398), which does not exist yet — the claim is stated in `docs/decisions/W7-5-scheduled-witnessed-checkpoint-freshness.md`
ready to fold in when it lands.
