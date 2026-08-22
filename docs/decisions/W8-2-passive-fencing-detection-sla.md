# W8-2 — Passive fencing is ADVISORY; the accepted limitation is a fork-DETECTION SLA

Issue: [#468](https://github.com/thuram-nana/vigil-sovereign/issues/468) ·
Milestone: W8 — HIGH AVAILABILITY.
Interacts with [W8-3](https://github.com/thuram-nana/vigil-sovereign/issues/469) and
[W7-5](https://github.com/thuram-nana/vigil-sovereign/issues/463) (scheduled off-box witnessed
checkpoint + freshness).

## The defect

Passive fencing in the HA profile is **advisory**. The whole mechanism is a shell guard in
`tools/ha/mirror-sync.sh` (`assert_passive_readonly` refuses to sync where a `sigil serve` writer is
live) plus a `:ro` bind of the mirror in one optional compose profile
(`infra/ha/docker-compose.ha.yml`, `--profile passive`). **Nothing at the storage or orchestration
layer PREVENTS a second concurrent writer.** A misconfigured operator, a stale orchestrator, or a
split-brain during failover can bring up a second `sigil serve` that advances and signs its own head.

## The decision: document the limitation with a detection SLA (path (b)), do NOT add a prevention lease

Issue #468 offers two closes: (a) a real storage-layer fencing token / lease that PREVENTS a second
writer, or (b) an accepted, tested limitation with a detection SLA. The issue constrains: *do NOT add a
lease that contradicts the witnessed-floor doctrine without a design decision — prefer (b) unless a lease
clearly fits the doctrine.* **We take path (b).** A prevention lease does not fit the doctrine, for two
reasons stated so no future edit re-opens the question:

1. **A prevention lease contradicts the witnessed-floor doctrine.** `docs/architecture/HA-PROFILE.md`
   §2/§4 makes the product's core trade explicit: the sovereign spine is single-writer, and a second
   owner-signed head is **always a detectable fork, never scale**. The floor + witness quorum are
   *anti-availability by design* — they trade "the writer is always up" for "the log can never be
   silently forked or rolled back." A lease that the operator trusts to *prevent* a second writer would
   manufacture a false sense of prevention on top of a model whose whole point is that prevention is
   **not** what protects the log — detection + fail-closed promotion is. It would also invite the very
   thing the doctrine forbids: treating the writer as if it could be safely multi-active behind a lock.
2. **A distributed lease cannot actually prevent the hazard it claims to.** The classic fencing-token
   failure (a lease holder that GC-pauses or partitions while its TTL expires, letting a second node
   acquire the lease and BOTH write) means a lease reduces to *detection after the fact* anyway — which
   is exactly what the witnessed floor already provides, soundly and cryptographically, without adding a
   liveness dependency the sovereign spine deliberately does not have (§4: "failover is manual/orchestrated,
   not automatic split-brain-proof leader election … we deliberately do NOT ship auto-promotion").

So prevention stays out. The limitation is **accepted and tested**, with the SLA below.

## The claim (register in the claims registry, [W0-3] #398, id `W8-2`)

<!-- CLAIM:W8-2 -->
> **Registered claim (W0-3 #398):** Passive fencing is advisory and does NOT prevent a second concurrent writer; the accepted, tested limitation is a fork-DETECTION SLA — a second writer's divergent owner-signed head is detected as a fork (the audited same-height/different-`head_hash` `is_split` signal) within one witness-checkpoint cadence (the shipped 15-minute timer, `FORK_DETECTION_SLA_S`), and a detected-or-undetected fork can never be silently PROMOTED because the failover guard refuses a same-height fork and the freshness gate refuses any anchor older than a 24h fail-closed ceiling.

This claim is TRUE of the code as of W8-2:

- **The limitation is real and named.** `tools/ha/fork_detection_sla.py` documents that fencing is
  advisory and states the SLA; it adds **no new policy engine** — `detect_fork` delegates to the audited
  `vigil_integration.transparency.is_split` (same `entry_count`, different `head_hash` = a fork).
- **The detection MECHANISM.** A witness / any checkpoint-comparing reader that obtains two witnessed
  checkpoints at one height with different heads has cryptographic proof of a fork (`is_split`;
  `transparency.consistent` likewise rejects a same-height different-head as not-an-extension). Two live
  writers necessarily produce exactly that.
- **The detection SLA (nominal): one witness-checkpoint cadence = 15 minutes.** The off-box witnessed
  checkpoint is emitted on the shipped timers (`apps/sigil/deploy/systemd/sigil-checkpoint.timer` +
  `infra/systemd/vigil-checkpoint.timer`, every 15 min — W7-5 #463). A witness therefore obtains each
  live writer's head at most one cadence after it advances; worst case, a second writer that comes up
  just after a tick is detected at the next tick — **within one cadence** (`FORK_DETECTION_SLA_S =
  WITNESS_CHECKPOINT_CADENCE_S = 900s`). The SLA test drives a checkpoint-comparing monitor over a real
  timeline and **measures** the detection latency against this bound.
- **The fail-closed CEILING (backstop, 24h).** If the scheduled emitter degrades and detection lags, a
  fork is still never silently **promoted**: the failover guard refuses a same-height fork
  (`tools/ha/spine_failover_guard.py`, "SAME-HEIGHT FORK"), and the W7-5 freshness gate refuses to anchor
  any promotion off an anchor older than `VIGIL_ANCHOR_REFUSE_AFTER_S` (default **24h**,
  `FORK_PROMOTION_REFUSE_CEILING_S`, imported from `witnessed_anchor` so it cannot drift).

Pinned by `apps/sigil/tests/test_ha_fork_detection_sla.py` (runs in the required **SIGIL governor gates
(P7 — offense gate + authn)** CI job, which executes the whole `apps/sigil/tests/` directory):

- a test that **FAILS on a tree without this change** — `tools/ha/fork_detection_sla.py` and this decision
  record do not exist pre-W8-2, so the import and the doc assertions fail there;
- a **measured** SLA test — a deliberately started second writer's divergent head is detected by the real
  `is_split` monitor, and the measured latency is asserted `<= FORK_DETECTION_SLA_S`;
- a **negative control** asserted in the same run — a legitimate single-writer append-only extension
  (count 2 → 3) is NOT flagged as a fork (`is_split` False, `consistent` True), proving the detector is
  not a no-op that flags everything;
- a **composition backstop** test — the failover guard refuses (exit 2) to promote the second writer's
  forked head against the true active's witnessed checkpoint.

## Honest scope (do not overclaim)

- This is **detection within an SLA, not prevention.** Between the second writer coming up and the next
  witness cadence (≤ 15 min nominal), two heads can exist. The guarantee is that the divergence is
  detected within that window and can never be silently promoted, not that it is impossible.
- The SLA's *independence* strength is the witnessed-floor doctrine's (HA-PROFILE §4): at the default
  owner-only, threshold-1 witness set the anchor is retention-based **detection**, not independent
  split-view **prevention**. Independent prevention needs ≥2 independent witness keys at a strict
  majority — a deployment property code cannot verify.
- The all-keys-compromised case (an attacker holding both the owner key and a witness quorum) is not
  closed here, exactly as documented for the failover guard; no code can close it.

## Registration

Register the claim id `W8-2` in `docs/claims/registry.json`, matching the guard's schema
(`enforced_by` → `tools/ha/fork_detection_sla.py:detection_within_sla`, `proved_by` →
`apps/sigil/tests/test_ha_fork_detection_sla.py`).
