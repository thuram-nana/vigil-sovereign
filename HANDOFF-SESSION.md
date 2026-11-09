# VIGIL — HANDOFF (concrete, end-to-end) — 2026-11-09

> Supersedes the prior HANDOFF-SESSION.md. Written for a **fresh agent (or human) to take over cleanly**.
> Continuation session: `session_01ECVf2R5rvPTWpcXSTvghmG` (prior: `session_01KWuLkRRktuxFkoybzaDd9s`). `main` is at **`26a38b6`** (all green) — **pause/resume PR-3 (#1036) + PR-4a (#1041) + PR-4b (#1043) + PR-5 (#1045) merged this session**.
> **USAGE-LIMIT HANDOFF:** this session is approaching its usage limit. The **entire pause/resume chain (PR-1..PR-5) is COMPLETE** — the feature is fully built behind its default-OFF flag (`VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED`); enabling it + at-scale verification are owner acts. **The next agent's top item is Front A — #73 (network recovery + deploy maturity) and #70 (backups-everywhere + evidence-DEK, KMS-owner-blocked)** (§3), then Front B, then the 1M tenant-sharding long pole (§3 Front C). Sub-agents / red-pen Workflows DID run this session. Direct tools + GitHub PR tools all work. **Also done this session: #69 (money production-gate/alerting) re-grounded → DONE/closeable (§3/§4).**

---

## 0. OPERATING DISCIPLINE (read first — this is "how")

**Repo / planes.** Two-plane monorepo at `/home/user/vigil-sovereign`:
- **Sovereign plane** — `apps/sigil` + `packages/core/vigil_core`, framework-free, owner Ed25519 trust root; the **Provisioner** (`apps/sigil/sigil/ui/provision.py`, reached only over the loopback hop) is the ONLY owner-key holder.
- **Offense plane** — `engine/crucible` (CRUCIBLE), keyless, only *verifies* owner signatures.
- **FATAL-2 boundary:** `assert_no_offense()` at import; `uiproxy.py` stays stdlib-only; framework imports in sovereign code stay lazy. `integration/tests/test_two_env_boundary.py::_PROBE` enforces it — register every new `live`/edge module there.

**Per-slice discipline (NON-NEGOTIABLE, applied to every PR this session):**
`build → mutation-verify (break each guard → its named test REDS → restore → green) → heaviest adversarial red-pen (Workflow: disjoint lenses → perspective-diverse 3-skeptic verify, survives iff ≥2 confirm) → fold CONFIRMED findings (each fix mutation-verified) → PR → merge only on CI green + mergeable clean`. One slice per PR, each **default-OFF + fail-closed**, off fresh `origin/main`.
**A red-pen "confirmed" is a CLAIM to verify against ground truth yourself, not an order** — this session caught a real HIGH in C1b *and* refuted its over-claims; it folded a real fail-closed hole in pause PR-1 and *documented* (not folded) a non-reachable RMW race.

**Test legs** (always `SIGIL_HOME=$(mktemp -d)`, venv `/home/user/vigil-sovereign/.venv-sovereign/bin/python`):
- Sovereign: `PYTHONPATH="apps/sigil:packages/core/vigil_core"`
- Integration superset: `PYTHONPATH="apps/sigil:integration:engine/crucible:gateway:packages/core/vigil_core:."`
- Gates: `ruff check <files>`; `bash tools/governance/mypy_ratchet.sh` (ceiling 15 — new modules must be type-clean and NOT appear in the error list).

**Worktree pattern** (branches are often held by agent worktrees; use detached worktrees):
```
WT=/tmp/claude-0/.../scratchpad/wt-<slice>; git -C /home/user/vigil-sovereign fetch origin main
git -C /home/user/vigil-sovereign worktree add --detach "$WT" origin/main
# edit/commit on detached HEAD, then:
git push origin HEAD:refs/heads/claude/<branch>     # fully-qualified refname is required from a detached HEAD
git worktree remove --force "$WT"                    # after merge
```
Open PRs with `mcp__github__create_pull_request` (base `main`). **Do NOT `git push origin main`** (PR-only).

**NEVER-CROSS (owner's standing constraints):**
1. Do **not** flip `VIGIL_CUSTOMER_PROD_EXECUTION` (customer prod execution stays flag-held).
2. Do **not** inject/commit any real Flutterwave secret (`VIGIL_FLW_SECRET_KEY` is read from env at call time; tests use dummies).
3. Do **not** ratify money-doctrine numbers (margins, $/token, catalog prices) — owner-set.
4. Do **not** dismiss security alerts (an A14/supply-chain red is handled, not ignored; the CDN-504 transient is confirmed-transient by a clean re-run, never waved through).
Everything new ships **default-OFF + fail-closed**, byte-identical when off.

**Attribution (binding) — every commit & PR:**
- Commit message ends with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_01KWuLkRRktuxFkoybzaDd9s`
- PR body ends with: `🤖 Generated with [Claude Code](https://claude.com/claude-code)` + blank line + `https://claude.ai/code/session_01KWuLkRRktuxFkoybzaDd9s`
- **No model identifier anywhere else** in a pushed artifact (code/comments/PR title).

**Merge authorization (owner, standing):** "on every PR once all checks are fully green and tested you can merge." GitHub ops via `mcp__github__*`. Squash-merge (repo convention).

---

## 1. CURRENT STATE — merged to `main` (`a21b866`)

Recent merges (newest first): `26a38b6` pause/resume **PR-5 #1045** (doctor surfaces paused launches as an expected held state — chain complete) · `04c5403` pause/resume **PR-4b #1043** (customer pause/resume actions + UI + flag, default-OFF) · `3e6c29b` pause/resume **PR-4a #1041** (pause money-safe at the enqueue gate + arm precondition) · `a21b866` pause/resume **PR-3 #1036** (in-flight cooperative halt) · `f882dfdb` pause/resume **PR-2 #1034** · `6567fff2` pause/resume **PR-1 #1033** · `93ee42cc` **C1b #1032** (group-commit coalescing) · `2be9bbd5` **JOBQ-75 #1031** (durable job queue in backup) · `a3cb1b03` NTF-3 #1030 · … (#1024–#1029 production-readiness).

**Recent slices (each red-penned + mutation-verified; #1031–1034 + C1b by the prior session, #1036 by this one):**
- **#1031 JOBQ-75** — the paid SecurityJob queue now defaults under `base_dir` so backup captures it (host loss no longer strands in-flight paid jobs); 41-agent red-pen 0 survivors; folded 2 LOWs (restore owner-only perms + fingerprint-survival test).
- **#1032 C1b** — 1M-scale concurrent-append coalescing on the signed spine (default-OFF). Red-pen caught a **real HIGH** (locked-vault seal share-fate → content appends routed DIRECT) + a serialization-mismatch poison-isolation bug (pre-flight now `canonical_json`) + an attribution false-green test; all folded + mutation-verified.
- **#1033 pause/resume PR-1** — `integration/vigil_integration/live/credit_lease_pause.py`: a reversible, nonce-scoped, **fail-CLOSED** pause marker (sibling of the settlement marker). Red-pen caught a real fail-closed hole (`is_file()` outside the try raises on EACCES on the keyless plane) → folded; RMW-race documented as the caller-serialization contract.
- **#1034 pause/resume PR-2** — adds `is_lease_paused` to the ONE shared verify chokepoint `engine/crucible/framework/v2/launch_lease.py::_verify_and_bind_lease`, refusing a paused lease on both consume paths **without burning the single-use floor** (resume re-arms the same lease). **INERT/default-OFF** (nothing calls `record_lease_pause` yet). ⚠️ Its red-pen **verify phase did not run** (weekly limit) — I verified the 2 surfaced HIGHs myself: **not reachable** at PR-2 (no pause-marker writer), but they are **HARD PR-4 constraints** (see §2).
- **#1036 pause/resume PR-3** — in-flight COOPERATIVE HALT (default-OFF/INERT). A customer launch already RUNNING when its lease is paused stops traffic at the next gated action (`http_executor` `halt_check`, a kill-switch sibling) and the engine RAISES a re-driveable `EngagementPaused` after the traffic phase (`engage.py` post-scan, outside the PhaseLedger swallow-wrappers). The worker (`engage_worker`) classifies it BY TYPE before the FAILED-settle path: NO settle (no premature refund/tombstone), rolls back its attempt slot (gated on a real slot mint — `_mark_attempt` now returns `(attempt, slot_created)`), records a resume-required marker so the re-drive resumes WITHOUT re-burning the floor. New: `launch_lease.read_verified_launch_nonce` (+ a `check_pause=False` path so the halt-binding nonce is readable while paused). 13 tests + **8/8 mutation-verify**; **3-lens red-pen** (money / termination / boundary) found **0 reachable HIGH/MED in PR-3 scope**, 1 LOW folded. The surviving HIGH (strand) + MED (worker self-defense) are **PR-4** work, written out in §2.
- **#1041 pause/resume PR-4a** — the two HARD money constraints from the PR-3 red-pen, both default-OFF/inert. HARD #1 (strand): `authorize.build_customer_launch_gate` now returns `LEASE_PAUSED_DENIAL` (not `no_lease`) for a reversible paused-lease refusal (PR-3 nonce read + `is_lease_paused`, fail-safe toward terminal), and `runner.run_one` RELEASES the delivery on it → a paused-but-queued launch is HELD by the seam poller and re-admitted on resume, never stranded. HARD #2 (arm-window): `engage_worker` treats a non-`EngagementPaused` failure whose lease is NOW paused as reversible — NO FAILED settle, slot rolled back, and NO resume-required (the precondition refused BEFORE `_advance_floor`, floor NOT burned → recording it would be a FREE RUN; mutation-verified MB2). 14 tests + 5/5 mutation-verify; FATAL-2 green; manual red-pen (verified the poller-holds-paused dependency + fail-safe directions + the free-run caution). The A14 red on this PR was a confirmed GitHub-release-CDN 504 transient, cleared by a clean re-run.
- **#1043 pause/resume PR-4b** — the customer pause/resume ACTIONS that take the feature OFF inert (default-OFF flag `VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED`). `config.customer_pause_resume_enabled()`; `LaunchGate.pause_launch`/`resume_launch` (owner-pinned verify + tenant-bind, then `record_lease_pause`/`clear_lease_pause` UNDER the spine lock = the PR-1 RMW serialization; pause moves NO money; a settled lease is refused); `provision.launch_pause`/`launch_resume` (flag + `admit_customer(run_engagement)` + step-up + audit, mirroring `launch_cancel`); `ui/server.py` hop dispatch + `ui/custui.py` `/api/customer/launch/pause|resume` routes (session-bound, flag-gated). 8 acceptance tests + 4/4 mutation-verify; 210+ regression; FATAL-2 + ruff + mypy clean. The sovereign producer records/clears the EXACT `is_lease_paused` marker PR-4a's offense plumbing acts on (the two planes can't co-load, so the composition is the proof). Pause/resume is now feature-complete behind the flag — only PR-5 (doctor) remains.
- **#1045 pause/resume PR-5** — doctor/observability reconciliation; **the pause/resume chain is now COMPLETE (PR-1..PR-5)**. `credit_lease_pause.paused_launches(base_dir)` (read-only, total, fail-safe enumeration of currently-paused `(slug,[nonces])`); `doctor.collect()` reports `report["paused_launches"]` + an ADVISORY note when any are paused — it NEVER flips `ok` (a positively-recorded hold is expected, not a failure) and is NOT an alarm suppressor (a genuinely stuck lease has no pause marker; the #69 money-drain gate is untouched). Default-OFF: no markers ⇒ byte-identical. 4 tests + 2/2 mutation-verify; #69-gate + FATAL-2 + ruff green. Runs in the P5 leg directly (no `framework` import).

---

## 2. PAUSE/RESUME — ✅ COMPLETE (PR-1..PR-5); kept here as the chain reference. Next work is Front A (§3).

Lifecycle chokepoints (grounded): reserve → `provision.launch_reserve` → `LaunchGate.reserve_launch` (mints owner-signed `CreditLaunchLease`); start → `provision.launch_start` → `LaunchGate.publish_lease` → seam `credit_lease_broker.write_credit_lease`; drain → `launch_drain.LaunchSeamDrain` → `jobs/launch_trigger.LaunchTrigger` (`verify_customer_launch_lease(consume=False)`) enqueues a `SecurityJob` keyed on `launch_delivery_id(slug,nonce)`; run → `jobs/runner.JobRunner.run_one` → `jobs/authorize.build_customer_launch_gate` (consume=False) → `jobs/engage_worker` → `engage.run_engagement` → `engage._engage_launch_lease_precondition` (`verify_customer_launch_lease(consume = not resume)` — the ONE authoritative floor-burn); settle → `inbound/completion_spool.CompletionSpoolWatcher.drain` → `LaunchGate.settle_launch` (refund `reserved−consumed` + settlement marker + tombstone). Worker crash-resume already exists (`engage_worker._mark_attempt`, `resume=attempt>1`, `_MAX_ARM_ATTEMPTS=3`) and re-validates WITHOUT re-burning the floor — REUSE it.

**PR-3 — in-flight cooperative halt — ✅ DONE (#1036, default-OFF).** Files: `http_executor.py` (`halt_check` field + `_authority_gate` branch), `engage.py` (`EngagementPaused`, `_engage_lease_nonce`/`_lease_is_paused`, halt_check wiring, the post-scan raise), `launch_lease.py` (`read_verified_launch_nonce`, `_verify_and_bind_lease(..., check_pause=False)`), `engage_worker.py` (`_release_attempt`/`_record_resume_required`/`_resume_required`/`_is_engagement_paused`, `_mark_attempt`→`(attempt, slot_created)`). Tests: `engine/.../tests/test_engage_pause_halt.py`, `integration/tests/test_engage_worker_pause_redrive.py` (the latter is REGISTERED in the offense-leg run-list of `.github/workflows/ci.yml` — framework-dependent integration tests MUST be, or the `test_ci_framework_tests_run_in_offense_leg` guard REDs; they skip cleanly on a single plane). NOTE: the original "~engage.py:1441" anchor was the arsenal-only closure (default-OFF); the real per-action kill-switch lives in the executor, so the halt rides the executor gate + an authoritative post-scan raise.

**PR-4a — pause money-safe at the enqueue gate + arm precondition — ✅ DONE (#1041, default-OFF).** Both HARD money constraints are closed. HARD #1 (strand): a paused lease at PICKUP → `build_customer_launch_gate` returns the reversible `LEASE_PAUSED_DENIAL` (via `_lease_refusal_is_pause` = the PR-3 nonce read + `is_lease_paused`, fail-safe toward terminal) → `jobs/runner.py` `run_one` RELEASES the delivery on that code → the seam poller HOLDS the paused lease (its own `verify(consume=False)` refuses to re-produce) and re-admits on resume — no strand, no churn. HARD #2 (gate→arm window): `engage_worker` (`_lease_currently_paused` + the except branch after `_is_engagement_paused`) treats a non-`EngagementPaused` failure whose lease is NOW paused as reversible — skips the FAILED settle, rolls back the slot, records **NO** resume-required (floor not burned → re-arm must consume; recording it = free run, mutation-verified MB2). Files: `jobs/authorize.py` (`LEASE_PAUSED_DENIAL`, `_lease_refusal_is_pause`), `jobs/runner.py`, `jobs/engage_worker.py`. Tests: `integration/tests/test_launch_pause_redrive_gate.py` (registered in the CI offense leg) + the HARD #2 cases in `test_engage_worker_pause_redrive.py`.

**PR-4b — customer pause/resume actions + UI + flag — ✅ DONE (#1043, default-OFF).** Pause/resume is now feature-complete behind `config.customer_pause_resume_enabled()` (`VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED`). Files: `apps/sigil/sigil/config.py`, `ui/launch_gate.py` (`pause_launch`/`resume_launch` + `_verify_lease_for_pause` — owner-pinned verify + tenant-bind, record/clear UNDER `self._lock`, settled-refused, idempotent), `ui/provision.py` (`launch_pause`/`launch_resume` — flag + `admit_customer(run_engagement)` + step-up + audit), `ui/server.py` (hop dispatch), `ui/custui.py` (`/api/customer/launch/pause|resume` routes). Decision taken (confirm with owner): pause/resume is a **customer** action, not owner-only `manage_launch`. Test: `apps/sigil/tests/test_launch_pause_resume_actions.py` (runs in CI via the P7 wholesale `apps/sigil/tests/` run).

**PR-5 — doctor/observability reconciliation — the LAST slice of the pause/resume chain — ✅ DONE (#1045, read-only).** Files: `integration/vigil_integration/live/credit_lease_pause.py` (`paused_launches(base_dir)` — read-only, total, fail-safe; scans `pauses_root/*.json`, returns `(stem, holds)` for non-empty), `integration/vigil_integration/doctor.py` (probe before `return report`: `report["paused_launches"]={count,holds,slugs}` + an advisory `_note(...)` — never `_issue`, never flips `ok`; a paused `(slug,nonce)` reads as an expected held-reservation, not a stuck-lease/unsettled-drain alarm, while a genuinely stuck lease still alarms). Test: `integration/tests/test_doctor_paused_launch.py` (registered in the CI offense leg).
- `doctor.py` is the **highest-contention file** across the remaining program — serialize edits (see §3); Front A/B/C all touch it.
- **Enduring by-design posture (LOW, do not "fix" naively):** a paused-then-CANCELED lease leaves a lingering pause marker (moot — the lease is tombstoned/non-runnable; `settle_launch`/`launch_cancel` do not clear it), so doctor must not mistake it for a live held-reservation; `_engage_lease_nonce` fails OPEN to no-halt-binding on a transient glitch (deliberate — failing closed would halt healthy PAID runs; the pause is cooperative + re-appliable + kill-switch-backstopped); a pause cleared mid-scan still charges full flat-per-run for a degraded scan; a long-paused lease outliving `not_after` is recovered only by the manual `ops-sweep reservations --apply` (default-OFF).

---

## 3. REMAINING PROGRAM (full forward plan, de-conflicted)

### Front A — production hardening (mostly done)
- **Pause/resume** ✅ COMPLETE — PR-1..PR-5 all merged (feature-complete behind the default-OFF `VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED` flag; doctor reconciliation landed in PR-5). The whole chain is the §2 reference. Nothing left here.
- **Network recovery + deploy maturity (#73, "Item B")** — scope reconstructed from real code (the label taxonomy is program-internal; files are real). There is NO central retry helper; the house pattern is *degrade/fail-safe, never fail-open* — add bounded reconnect ONLY where a transient drop should auto-recover.
  - NET-2: `integration/vigil_integration/live/net_recovery.py` (bounded backoff, injectable clock) adopted by `otel_export.py` reachability + the drain `watch()` loops; default-OFF, never widens the egress floor.
  - NET-4: degraded-mode surfacing + a `doctor.py` network-recovery posture line (advisory, never gates a launch).
  - DEP-2: readiness-gated bring-up (`infra/systemd/vigil-bringup.service` gated on `vigil doctor`+readyz; `sovereign_deploy/acceptance.py`) — gating ≠ enabling prod execution.
  - DEP-3: upgrade/rollback + down-migration **drill** automation (mirror `vigil-backup-drill.timer`; exercises `spine/upgrade.py`).
- **#70 backups-everywhere tail** — the job queue is now covered (#1031); remaining is G2/G3/G4 coverage of the rest + the **evidence-DEK KMS escrow** whose *live* path is **owner-blocked** (needs a real AWS KMS key).
- **#69 money production-gate / alerting** — ✅ **RE-GROUNDED → DONE/closeable** (this session). The money-OUT "nothing-lost" pipeline is gated + alerted + tested: `vigil doctor` goes RED on an unhealthy watched money drain (`doctor.py` `_MONEY_DRAIN_UNITS` = settle-drain + finding-drain; `test_doctor_money_drain_gate.py` 4/4 green), a quarantined drain never reads HEALTHY (MONEY-4, `test_drain_quarantine_alarm.py` 8/8 green), dead-man + alert-delivery dead-man + NTF tenant notifications (#1030/#1016), billing-spool crash-reclaim (#1022). One Front-B item (NOT a #69 blocker, split out below): there is NO `vigil-billing-drain` systemd timer — the money-IN billing-webhook drain runs via CLI, so a stall DELAYS credit grants (recoverable), it does not LOSE money (correctly outside #69's money-OUT scope).

### Front C — 1,000,000 users (the long pole)
- Group-commit (C1a + C1b) **DONE**.
- **Tenant sharding — DESIGN NOT COMPLETE.** The design Workflow (`wf_395eee7a-e41`) ran 8 architecture-grounding agents + 2 of 3 candidate designs, then the **weekly limit** killed the 6 critics + the synthesis. **Resume it after the limit resets:**
  `Workflow({scriptPath:'/root/.claude/.../workflows/scripts/design-tenant-sharding-wf_395eee7a-e41.js', resumeFromRunId:'wf_395eee7a-e41'})` (cached agents replay free; only the failed critics+synthesis re-run). Journal (10 results) at `…/subagents/workflows/wf_395eee7a-e41/journal.jsonl`.
  The 3 candidate angles: (A) self-contained cells/shard-per-node; (B) global routing + an owner-signed shard-assignment record; (C) minimal-diff consistent-hash pre-sharding (reuse the per-org/per-slug dirs + the `CRUCIBLE_TENANT` worker hint, shard the worker fleet + job queue + tenant dirs first). The 6 invariants every design must preserve are in the script's `INVARIANTS` const (signed spine never forks, isolation only stronger, FATAL-2, money exactly-once + EC-5 pool, default-OFF/fail-closed, online reversible migration). **Report the synthesized design + slice plan to the owner before building** (core-touching).
- **Build dimensions the design must slice (knowable NOW, pre-design — so the work is not a black box):** the exact slice list comes from the resumed design, but every candidate must cover these, and they are the unit of PR-by-PR delivery:
  1. **Shard key + assignment** — a deterministic `org_id → shard_id` map. In design B/C an **owner-signed `ShardAssignment` spine record** (mirror `MonitoringAuthority`/lease records: new domain tag in `vigil_core/spine_domains.py`, sign in the Provisioner, verify keyless at the routing edge). Default-OFF: one shard = today's single-node behavior, byte-identical.
  2. **Routing layer** — `uiproxy.py` + the custui/provision edges resolve a request's org to its shard and forward there (keyless, stdlib-only; verify the signed assignment against the pinned owner root). A wrong/missing assignment fails **closed**.
  3. **Worker-fleet sharding** — the `jobs/{queue,runner,launch_trigger,engage_worker}` fleet already carries the `CRUCIBLE_TENANT` hint + `authorize_job._reconcile_tenant` cross-tenant refusal; extend so each worker process owns a shard's queue + tenant dirs only, and an org-A job in an org-B shard still refuses (the isolation invariant must get *stronger*, never weaker, under sharding).
  4. **Per-shard signed spine** — each shard keeps its OWN hash-chained spine (the global spine must never fork: §INVARIANT-1). The owner trust root is shared/pinned; shard spines are independent chains, never merged.
  5. **Money at scale** — the **EC-5 global pool meter + graduated kill-switch is cross-shard**: it must aggregate reservations/spend across shards (a per-shard local meter would let the global cap be breached N×). Reserve/settle stays exactly-once per `(slug,nonce)` within a shard; the pool read is global. This is the sharpest money hazard — red-pen it hardest.
  6. **Online reversible migration** (§INVARIANT-6) — move a tenant's dirs + open leases + credential rows between shards with **no spine fork, no isolation drop, no double-charge, no lost in-flight paid job**, reversible mid-flight. Likely a drain-pause-copy-verify-cutover-resume cycle reusing the pause/resume substrate (another reason pause/resume PR-3/4/5 lands first).
  7. **Global tenant registry / coordinator** — a lookup from org → shard that the routing layer and `vigil doctor` consult; owner-signed source of truth; fail-closed.
- **Scale-acceptance gate (the explicit "1M is done" bar — build this as the closing slice, mirror K4-6's flag-hold):** a load harness driving **N tenants × M concurrent engagements** to owner-set target numbers (throughput, p99 latency, spine-append contention), proving under load: (a) no signed-spine fork across shards; (b) cross-tenant isolation holds **during a live shard migration**; (c) the EC-5 global cap is never breached cross-shard; (d) no in-flight paid job is stranded by a migration or a node loss; (e) exactly-once survives the fleet. Production multi-shard stays **flag-held** until this is green (owner flips it, like `VIGIL_CUSTOMER_PROD_EXECUTION`). Owner sets the target numbers (money/capacity doctrine — not the agent's to invent).

### Front B — fully hostable / pay round-trip + go-live (round-trip built, flag-held)
- Customer-app **checkout UI** + `…/billing/return` page; **`sigil serve-customer` CLI** + marketing-domain reverse-proxy vhost (follow `apps/sigil/deploy/reverse-proxy/vigil.nginx.conf`); **NTF enablement tail** (enable `vigil-alerts.timer` + `--test-delivery`); optional **CVE catalog NVD/EPSS enrichment** (operator-run, rate-limited; KEV already gives a browsable catalog).
- **money-IN drain automation (from the #69 re-grounding):** there is a `billing_spool` drain (`apps/sigil/sigil/inbound/billing_spool.py`, "vigil billing-drain" CLI) but NO `vigil-billing-drain.service`/`.timer` — unlike `vigil-settle-drain`/`vigil-finding-drain`. For a hands-off money-IN pipeline, add the systemd unit+timer (mirror the settle/finding drain units in `infra/systemd/`) so inbound billing webhooks are drained automatically. A stall only DELAYS credit grants (recoverable), so this is go-live polish, not a money-loss gate.

### Owner-only (held — NOT the agent's to do)
Provision the real **Flutterwave secret**; flip **`VIGIL_CUSTOMER_PROD_EXECUTION`**; **ratify money numbers**; **DNS/TLS cutover** for `vigilguard.net`; the **AWS KMS key** for evidence-DEK + KEK.

### Housekeeping
7 open **Dependabot** PRs (incl. a MAJOR `huggingface-hub` 1→2 and a `python 3.13→3.15` base-image bump) — riskier, left untriaged; triage individually, don't bulk-merge. Merged-PR branches (`claude/pauseresume-pr1/pr2`, `claude/jobq75-…`, etc.) can be deleted. Reference design detail: the Wave-3 grounding agent's full file-anchored plan is in this session's transcript.

---

## 4. DEFINITION OF 100% — the closing gates (what "done" means)

The system is NOT 100% until every line below is true. Items marked **[agent]** are the next agent's to build/verify; **[owner]** are deliberate owner acts the agent must never do.

1. ✅ **DONE** Pause/resume chain: **PR-1 + PR-2 + PR-3 (#1036) + PR-4a (#1041) + PR-4b (#1043) + PR-5 (#1045) all merged** — the feature is complete behind its default-OFF `VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED` flag, with doctor reconciliation landed. §2. (Owner still turns the flag on in prod — that is gate 6's posture, not agent work.)
2. **[agent]** Front A tail: #73 (network recovery + deploy maturity) and #70 (backups-everywhere + evidence-DEK **live path owner-blocked on a real KMS key**) merged; **#69 (money-gate/alerting) re-grounded → DONE/closeable this session** (one Front-B billing-drain-timer item split out, §3). §3.
3. **[agent]** Front B surface closed: checkout UI + billing-return page, `sigil serve-customer` CLI, marketing-domain vhost, NTF enablement tail. §3.
4. **[agent]** **1M scaling** — tenant-sharding design resumed + synthesized + owner-approved, then built slice-by-slice across the 7 build dimensions (§3 Front C), then the **scale-acceptance gate green** (N tenants × M concurrent; no spine fork; isolation-under-migration; EC-5 global cap cross-shard; no stranded paid job; exactly-once). This is the largest remaining body of work and the real distance to "1,000,000 users."
5. **[agent]** A final **personal hands-on end-to-end + at-scale verification** (the #25 analog, now including load): drive signup → pay → authorize → run → oracle-confirmed FACT → settle, AND the scale harness, adversarially. Report honestly WITH EVIDENCE; do not trust per-slice red-pens alone.
6. **[owner]** The held flips, none of which the agent performs: provision the real **Flutterwave secret**; flip **`VIGIL_CUSTOMER_PROD_EXECUTION`**; flip the **multi-shard production flag** (after gate 4); **ratify the money numbers** (margins, $/token, catalog prices, and the scale target numbers); **DNS/TLS cutover** for `vigilguard.net`; the **AWS KMS key** for evidence-DEK + KEK.

Honest status line: the **customer-SaaS product, money loop, offense breadth, production-hardening, and AWS/deploy substrate are built and merged**; the **distance to 100% is dominated by item 4 (tenant sharding → scale-acceptance)**, which is designed-but-not-built, plus the finite Front A/B tails (items 1–3) and the owner-only flips (item 6). Everything built ships default-OFF + fail-closed, so `main` is always in a safe, shippable-at-single-node state.

---

## 5. KEY ANCHORS (quick map)
- Signed spine: `apps/sigil/sigil/spine/store.py` (`append`/`append_many`/`_write_record_locked`, `spine_lock`), `vigil_core/canonical.py` + `chain.py`.
- Money seam: `integration/vigil_integration/live/credit_lease_broker.py` (leases/settlements/**pauses**), `governor/{wallet,metering}.py`, EC-4 cost ledger, EC-5 pool.
- Launch verify chokepoint: `engine/crucible/framework/v2/launch_lease.py::_verify_and_bind_lease` (now contains the pause re-check).
- Jobs: `integration/vigil_integration/jobs/{queue,runner,authorize,launch_trigger,engage_worker}.py`.
- Isolation: `admit_customer`, `_derive_tenant_id`/`_TENANT_RE`, owner-signed `OrgRegistry`.
- Router: `integration/vigil_integration/uiproxy.py` (keyless, stdlib-only).
- Doctor/durability: `doctor.py`, `spine/{snapshot,prune,upgrade}.py`, `integration/vigil_integration/backup.py`.
