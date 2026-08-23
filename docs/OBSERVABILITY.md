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
- **A real notifier** (webhook / exec such as email / pager) for the alarm callbacks landed in W8-1 (#467) —
  see [HA / timer heartbeat staleness alarms](#ha--timer-heartbeat-staleness-alarms-w8-1) below. It reuses
  this module's `Alarm` / `AlarmSink` primitives and adds the push transports, the per-unit heartbeats and the
  delivery dead-man.
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

---

# HA / timer heartbeat staleness alarms (W8-1)

Until W8-1 nothing monitored the HA pair or any timer unit. A **backup**, an **off-host push**, a **recovery
drill** or the **HA mirror-sync** could fail — or its timer could stop firing — for months, and the only way
to notice was a human running `journalctl`. A silent HA gap is the worst kind: you learn the standby was never
synced at the moment you need to fail over to it.

W8-1 (`integration/vigil_integration/unit_alerts.py`, wired via `vigil alerts` / `vigil unit-heartbeat` +
`infra/systemd/vigil-alerts.*`) gives every scheduled unit a heartbeat and a staleness monitor. Everything
below is true of the code.

## The monitored units

The registry (`unit_alerts.HA_UNITS`) covers every scheduled unit, each with a cadence-derived staleness bound
(`cadence × 1.5 + the timer's RandomizedDelaySec` — it fires after ~1.5 missed periods, so a single skipped
run is caught without flapping on jitter; overridable per unit via
`VIGIL_ALERT_MAX_STALENESS_<UNIT>`):

| unit | timer | cadence | default staleness bound |
|------|-------|---------|-------------------------|
| `vigil-backup.service` | daily | 24h | ~36.5h |
| `vigil-backup-push.service` | daily | 24h | ~36.5h |
| `vigil-backup-drill.service` | weekly | 7d | ~10.6d |
| `vigil-ha-mirror.service` | 15m | 15m | ~23.5m |
| `vigil-integrity.service` | 15m | 15m | ~23.5m |
| `vigil-posture.service` | 30m | 30m | ~45m |
| `vigil-reprove.service` | 6h | 6h | ~9h |

A guard test asserts **every** `infra/systemd/vigil-*.timer` (except the monitor's own) has a registry entry,
so a new scheduled unit added without registration fails CI rather than going silently unmonitored.

## How it works

- **Each unit writes a heartbeat when it runs.** Every service file carries
  `ExecStopPost=… vigil unit-heartbeat %n` plus `StateDirectory=vigil` and
  `Environment=VIGIL_ALERT_STATE_DIR=%S/vigil/unit-heartbeats`. `ExecStopPost` runs on **both** success and
  failure, and systemd exports `$SERVICE_RESULT` into its environment — so the heartbeat records whether the
  run **succeeded**, and a unit that RAN and FAILED is distinguishable from one that never ran.
- **`vigil alerts` classifies every watched unit** as `healthy` / `failed` / `stale` / `absent` and raises an
  alarm for every non-healthy one. **Fail-closed:** an `absent` heartbeat (never ran / removed) or an
  undated/unreadable one is a staleness alarm, never silently healthy. A clean, fresh fleet raises **nothing**
  (the monitor is not a no-op). `vigil alerts --status` is a read-only view; `--watch` runs it on a cadence
  (systemd: `vigil-alerts.timer`, every 10m — tighter than the shortest unit bound).
- **Alerts are push-based.** `build_notifier_from_env` reads `VIGIL_ALERT_WEBHOOK_URL` (HTTP POST each alarm
  as JSON) and/or `VIGIL_ALERT_EXEC` (a command fed the alarm JSON on stdin — e.g. `sendmail`, a pager CLI).
  A non-2xx / non-zero exit / transport error is a delivery **failure**. Every alarm is **also** appended to a
  durable local log, so a total push outage is still discoverable on the box.
- **Alert delivery is itself dead-man'd.** A successful push advances an `alert-delivery-heartbeat.json`; a
  delivery that fails on *every* target writes a distinct `alert-delivery-failed` marker to the local log; and
  `delivery_is_stale(...)` — surfaced by `vigil alerts --status` and `vigil doctor` — fires when no alert has
  been delivered within `VIGIL_ALERT_DELIVERY_MAX_STALENESS_S` (default 26h). So the failure of the alerting
  path is observable, not silent.
- **`vigil doctor`** grows an advisory *unit alerts* block: it names any stale/failed unit and the delivery
  dead-man (a NOTE — the alert timer is opt-in, like the integrity one, so it never flips doctor's exit code).

## Honest scope (do not overclaim)

The **logic** — enumeration, per-unit cadence-derived staleness, fail-closed absent-is-an-alarm,
exactly-one-alarm-per-bad-unit, push delivery with a local fallback, and the delivery dead-man — is exercised
in CI (`integration/tests/test_unit_alerts.py`) with an **injected clock** and an **in-process fake
transport**. What is **live-only** and cannot be exercised in CI: whether real systemd actually invokes the
`ExecStopPost` hook on every unit, and whether a real webhook / `sendmail` endpoint accepts the push. Those
are wired but their firing against real infrastructure is not asserted here. The monitor does **not**
heartbeat-monitor itself (that would be circular); the monitor's own liveness is the delivery dead-man.

## Configuration

See `infra/systemd/vigil-alerts.env.example`: `VIGIL_ALERT_WEBHOOK_URL`, `VIGIL_ALERT_EXEC`,
`VIGIL_ALERT_STATE_DIR`, per-unit `VIGIL_ALERT_MAX_STALENESS_<UNIT>`, and
`VIGIL_ALERT_DELIVERY_MAX_STALENESS_S`.

## Residual (blocked on other work)

- **Claims-registry registration** of this behaviour is W0-3 (#398); that registry does not exist in the tree
  yet, so this section is the authoritative, code-true description until it does.

---

# OpenMetrics `/metrics` per plane (W6-3)

Each plane server exposes a Prometheus/OpenMetrics endpoint at **`/metrics`**, rendered by the stdlib-only
`vigil_core.metrics.MetricsRegistry` (no new dependency — neither hash lock changes). It carries:

- **RED** — `vigil_requests_total` (by method + status class), `vigil_request_errors_total` (5xx / handler
  crash), and the `vigil_request_duration_seconds` histogram (`_bucket`/`_sum`/`_count`).
- **process** — `vigil_process_resident_memory_bytes`, `vigil_process_open_fds`,
  `vigil_process_uptime_seconds`, `vigil_process_start_time_seconds` (read from `/proc/self` at scrape time).
- **domain** — `vigil_facts_total`, `vigil_leads_total`, `vigil_refusals_total` (folded from the
  business-counter JSON snapshot) and `vigil_gate_denials_total` (incremented on every authorization-gate
  DENY). Every series is labelled `plane="sovereign"|"offense"`.

**Exposure / auth posture.** `/metrics` is UNAUTHENTICATED and Host-ungated — the same probe posture as
`/healthz`+`/readyz` — because each plane server binds loopback or a private (WireGuard/Tailscale) address
only; a public serve goes behind the operator's TLS reverse proxy, which is where scrape-side authentication
is applied. The body carries no token, path, or backend address. Registered as claim `W6-3` in
`docs/claims/registry.json` ([W0-3] #398); see `docs/decisions/W6-3-openmetrics-exposition.md`.

**Artifacts.** Example alert rules (`infra/observability/vigil-alerts.yml`) and a Grafana dashboard
(`infra/observability/vigil-dashboard.json`) ship with the product — a starting point for [W8-1] #467
alerting.

---

## Unified structured logging (W6-5, #456)

Before W6-5, three logging stacks disagreed: the offense engine had structlog JSON + redaction +
rotation, the sovereign SIGIL plane logged **plain text to stderr with no redaction**, and the host
gateway used a bare `logging.basicConfig`. The `.vigil-live/ui/logs/*.log` child-capture files were
unbounded, and only `SIGIL_LOG_LEVEL` existed — governing one of the three planes.

W6-5 unifies them on ONE setup, reused across every plane because it lives in `vigil_core` (a member of
BOTH isolated environments, importing no `framework.*` / `strix.*` / `sigil.*`, so FATAL-2 is intact):

- **`vigil_core.redact`** — the single shared redaction helper. `scrub_log_event` masks secret-keyed
  structured fields (recursing into nested dicts/lists); `redact_log_message` masks credential SHAPES in
  a free-text message (a `Bearer` token, an `Authorization`/`Cookie` header line, a `secret=value`
  assignment). The offense engine's `framework/v2/common/redact.py` is now a thin re-export of this
  module, so offense behaviour is byte-identical and the masker is maintained once.
- **`vigil_core.logging_setup`** — the single stdlib-only setup: a `RedactingJsonFormatter` (JSON lines;
  the message and every structured `extra=` field pass through the shared redactor before emission), a
  secure rotating file handler, a `RotatingLineWriter` for subprocess-output capture, and one
  `VIGIL_LOG_LEVEL` resolver. Stdlib-only because the gateway declares zero third-party runtime deps and
  structlog is not in the sovereign environment.
- **The sovereign** (`apps/sigil/sigil/obs.py`) and **gateway** (`gateway/vigil_gateway/cli.py`) install
  the shared handler; the **offense** engine keeps its structlog pipeline but now resolves its level from
  `VIGIL_LOG_LEVEL` and redacts through the same shared helper.
- **Rotation everywhere.** Every log destination — the offense engagement log, the sovereign/gateway
  handlers (when file-backed), and the previously-unbounded `.vigil-live/ui/logs/*.log` child captures —
  is size-bounded with retention via `VIGIL_LOG_MAX_BYTES` (default 64 MiB) and `VIGIL_LOG_BACKUP_COUNT`
  (default 16). The UI child logs are piped and pumped through a `RotatingLineWriter` (0600 file, 0700
  dir) instead of an unbounded append, so a chatty backend can no longer fill the disk.

**One level variable.** `VIGIL_LOG_LEVEL` governs all planes; the deprecated `SIGIL_LOG_LEVEL` is still
honoured, with a one-time deprecation warning, when `VIGIL_LOG_LEVEL` is unset. Set it in the service
environment (systemd / shell / compose) so every child `vigil up` spawns inherits it.

Registered as claim `W6-5` in `docs/claims/registry.json` ([W0-3] #398); see
`docs/decisions/W6-5-unified-structured-logging.md`. Proven by
`packages/core/vigil_core/tests/test_logging_unified.py` (required `vigil_core` CI job), with per-plane
negative controls in the sovereign, offense, gateway and integration test suites.
