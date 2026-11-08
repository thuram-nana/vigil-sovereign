# VIGIL — HANDOFF (concrete, end-to-end) — 2026-11-08

> Supersedes the prior HANDOFF-SESSION.md. Written for a **fresh agent (or human) to take over cleanly**.
> Session of record: `session_01KWuLkRRktuxFkoybzaDd9s`. `main` is at **`f882dfdb`** (all green).
> **BLOCKER right now:** the account hit its **weekly usage limit (resets 2026-11-13 05:00 UTC)** — spawning sub-agents / Workflows FAILS until then. **Direct tools (Bash, Read/Write, git, GitHub PR tools) still work.** So a human, or an agent after the reset, picks this up.

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

## 1. CURRENT STATE — merged to `main` (`f882dfdb`)

Recent merges (newest first): `f882dfdb` pause/resume **PR-2 #1034** · `6567fff2` pause/resume **PR-1 #1033** · `93ee42cc` **C1b #1032** (group-commit coalescing) · `2be9bbd5` **JOBQ-75 #1031** (durable job queue in backup) · `a3cb1b03` NTF-3 #1030 · … (#1024–#1029 production-readiness).

**This session shipped 5 PRs, each red-penned + mutation-verified:**
- **#1031 JOBQ-75** — the paid SecurityJob queue now defaults under `base_dir` so backup captures it (host loss no longer strands in-flight paid jobs); 41-agent red-pen 0 survivors; folded 2 LOWs (restore owner-only perms + fingerprint-survival test).
- **#1032 C1b** — 1M-scale concurrent-append coalescing on the signed spine (default-OFF). Red-pen caught a **real HIGH** (locked-vault seal share-fate → content appends routed DIRECT) + a serialization-mismatch poison-isolation bug (pre-flight now `canonical_json`) + an attribution false-green test; all folded + mutation-verified.
- **#1033 pause/resume PR-1** — `integration/vigil_integration/live/credit_lease_pause.py`: a reversible, nonce-scoped, **fail-CLOSED** pause marker (sibling of the settlement marker). Red-pen caught a real fail-closed hole (`is_file()` outside the try raises on EACCES on the keyless plane) → folded; RMW-race documented as the caller-serialization contract.
- **#1034 pause/resume PR-2** — adds `is_lease_paused` to the ONE shared verify chokepoint `engine/crucible/framework/v2/launch_lease.py::_verify_and_bind_lease`, refusing a paused lease on both consume paths **without burning the single-use floor** (resume re-arms the same lease). **INERT/default-OFF** (nothing calls `record_lease_pause` yet). ⚠️ Its red-pen **verify phase did not run** (weekly limit) — I verified the 2 surfaced HIGHs myself: **not reachable** at PR-2 (no pause-marker writer), but they are **HARD PR-4 constraints** (see §2).

---

## 2. IMMEDIATE NEXT — finish pause/resume (PR-3 → PR-4 → PR-5)

Lifecycle chokepoints (grounded): reserve → `provision.launch_reserve` → `LaunchGate.reserve_launch` (mints owner-signed `CreditLaunchLease`); start → `provision.launch_start` → `LaunchGate.publish_lease` → seam `credit_lease_broker.write_credit_lease`; drain → `launch_drain.LaunchSeamDrain` → `jobs/launch_trigger.LaunchTrigger` (`verify_customer_launch_lease(consume=False)`) enqueues a `SecurityJob` keyed on `launch_delivery_id(slug,nonce)`; run → `jobs/runner.JobRunner.run_one` → `jobs/authorize.build_customer_launch_gate` (consume=False) → `jobs/engage_worker` → `engage.run_engagement` → `engage._engage_launch_lease_precondition` (`verify_customer_launch_lease(consume = not resume)` — the ONE authoritative floor-burn); settle → `inbound/completion_spool.CompletionSpoolWatcher.drain` → `LaunchGate.settle_launch` (refund `reserved−consumed` + settlement marker + tombstone). Worker crash-resume already exists (`engage_worker._mark_attempt`, `resume=attempt>1`, `_MAX_ARM_ATTEMPTS=3`) and re-validates WITHOUT re-burning the floor — REUSE it.

**PR-3 — in-flight cooperative halt** (branch `claude/pauseresume-pr3-inflight-halt`):
- Add an `is_lease_paused(slug,nonce)` cooperative-halt check at `engage.py`'s existing `KillSwitch(slug).is_tripped()` scan-loop checkpoint (~`engage.py:1441`). On pause → raise a **re-driveable, NON-terminal** error (NOT a kill-switch trip, NOT a terminal FAILED settle).
- In `engage_worker.py` (~265-280) classify the pause-halt like a transient failure → `failed` + `release_delivery` → re-enqueue. It must **NOT** emit the terminal FAILED settle (no premature refund) and **NOT** consume an arm-attempt toward `_MAX_ARM_ATTEMPTS` (so repeat pause/resume can't force a spurious terminal abandonment — likely needs the attempt marker to distinguish "paused" from "crashed").
- Tests: `engine/crucible/framework/v2/tests/test_engage_pause_halt.py` + `integration/tests/test_engage_worker_pause_redrive.py`. Red-pen lenses: no-refund-on-pause, no-floor-reburn-on-resume, attempt-not-consumed, re-drive exactly-once.

**PR-4 — customer pause/resume actions + UI + flag** (branch `claude/pauseresume-pr4-actions`):
- `LaunchGate.pause_launch`/`resume_launch` (mirror `publish_lease`/`settle_launch`): verify the owner-signed lease, `expect_org_id` tenant-bind, then `record_lease_pause`/`clear_lease_pause` **under `spine_lock`** (this is the caller-serialization the PR-1 RMW note requires).
- `provision.launch_pause`/`launch_resume` (mirror `launch_cancel`/`launch_start`: `admit_customer(run_engagement)` + `_require_stepup` + audit). `custui.py` routes `/api/customer/launch/pause|resume`. `config.customer_pause_resume_enabled()` default-OFF (copy `customer_monitoring_enabled()`).
- **⚠️ HARD CONSTRAINT (the two unverified PR-2 red-pen HIGHs — DO NOT LOSE THIS):** pausing an **already-enqueued** launch must NOT strand the paid lease. Either (a) pause *before* enqueue, and/or (b) ensure the gate-refusal for an already-enqueued job **RELEASES the delivery for re-drive on resume** rather than terminally failing it and keeping the one-shot `delivery_id` marker (which would make the job un-re-admittable). Add an explicit test: enqueue → pause → (job refused) → resume → job RE-ADMITS and runs; the lease is never stranded, never double-charged. This is money-critical — red-pen it hard.
- Decision to confirm with owner: pause/resume as a **customer** action (default; reuses `run_engagement` + step-up) vs **owner-only** (`manage_launch`). Default taken = customer.

**PR-5 — doctor/observability reconciliation** (branch `claude/pauseresume-pr5-doctor`):
- `integration/vigil_integration/doctor.py` money/drain posture (~`doctor.py:1133,1373`) must treat a paused `(slug,nonce)` as an expected held-reservation, NOT a stuck-lease/unsettled-drain alarm (a genuinely stuck lease must still alarm — pause is a *positively-recorded* state, not an alarm suppressor). Optional advisory paused projection via `completion_spool._record_outcome` (no amount). `integration/tests/test_doctor_paused_launch.py`.
- `doctor.py` is the **highest-contention file** across Wave-3 — serialize edits (see §3).

---

## 3. REMAINING PROGRAM (full forward plan, de-conflicted)

### Front A — production hardening (mostly done)
- **Pause/resume** PR-3/4/5 (above).
- **Network recovery + deploy maturity (#73, "Item B")** — scope reconstructed from real code (the label taxonomy is program-internal; files are real). There is NO central retry helper; the house pattern is *degrade/fail-safe, never fail-open* — add bounded reconnect ONLY where a transient drop should auto-recover.
  - NET-2: `integration/vigil_integration/live/net_recovery.py` (bounded backoff, injectable clock) adopted by `otel_export.py` reachability + the drain `watch()` loops; default-OFF, never widens the egress floor.
  - NET-4: degraded-mode surfacing + a `doctor.py` network-recovery posture line (advisory, never gates a launch).
  - DEP-2: readiness-gated bring-up (`infra/systemd/vigil-bringup.service` gated on `vigil doctor`+readyz; `sovereign_deploy/acceptance.py`) — gating ≠ enabling prod execution.
  - DEP-3: upgrade/rollback + down-migration **drill** automation (mirror `vigil-backup-drill.timer`; exercises `spine/upgrade.py`).
- **#70 backups-everywhere tail** — the job queue is now covered (#1031); remaining is G2/G3/G4 coverage of the rest + the **evidence-DEK KMS escrow** whose *live* path is **owner-blocked** (needs a real AWS KMS key).
- **#69 money production-gate / alerting** — tracker shows in-progress but MONEY-4 merged and NTF alerting shipped; **re-ground before counting it** — likely mostly done. Verify, then close or finish the tail.

### Front C — 1,000,000 users (the long pole)
- Group-commit (C1a + C1b) **DONE**.
- **Tenant sharding — DESIGN NOT COMPLETE.** The design Workflow (`wf_395eee7a-e41`) ran 8 architecture-grounding agents + 2 of 3 candidate designs, then the **weekly limit** killed the 6 critics + the synthesis. **Resume it after the limit resets:**
  `Workflow({scriptPath:'/root/.claude/.../workflows/scripts/design-tenant-sharding-wf_395eee7a-e41.js', resumeFromRunId:'wf_395eee7a-e41'})` (cached agents replay free; only the failed critics+synthesis re-run). Journal (10 results) at `…/subagents/workflows/wf_395eee7a-e41/journal.jsonl`.
  The 3 candidate angles: (A) self-contained cells/shard-per-node; (B) global routing + an owner-signed shard-assignment record; (C) minimal-diff consistent-hash pre-sharding (reuse the per-org/per-slug dirs + the `CRUCIBLE_TENANT` worker hint, shard the worker fleet + job queue + tenant dirs first). The 6 invariants every design must preserve are in the script's `INVARIANTS` const (signed spine never forks, isolation only stronger, FATAL-2, money exactly-once + EC-5 pool, default-OFF/fail-closed, online reversible migration). **Report the synthesized design + slice plan to the owner before building** (core-touching).

### Front B — fully hostable / pay round-trip + go-live (round-trip built, flag-held)
- Customer-app **checkout UI** + `…/billing/return` page; **`sigil serve-customer` CLI** + marketing-domain reverse-proxy vhost (follow `apps/sigil/deploy/reverse-proxy/vigil.nginx.conf`); **NTF enablement tail** (enable `vigil-alerts.timer` + `--test-delivery`); optional **CVE catalog NVD/EPSS enrichment** (operator-run, rate-limited; KEV already gives a browsable catalog).

### Owner-only (held — NOT the agent's to do)
Provision the real **Flutterwave secret**; flip **`VIGIL_CUSTOMER_PROD_EXECUTION`**; **ratify money numbers**; **DNS/TLS cutover** for `vigilguard.net`; the **AWS KMS key** for evidence-DEK + KEK.

### Housekeeping
7 open **Dependabot** PRs (incl. a MAJOR `huggingface-hub` 1→2 and a `python 3.13→3.15` base-image bump) — riskier, left untriaged; triage individually, don't bulk-merge. Merged-PR branches (`claude/pauseresume-pr1/pr2`, `claude/jobq75-…`, etc.) can be deleted. Reference design detail: the Wave-3 grounding agent's full file-anchored plan is in this session's transcript.

---

## 4. KEY ANCHORS (quick map)
- Signed spine: `apps/sigil/sigil/spine/store.py` (`append`/`append_many`/`_write_record_locked`, `spine_lock`), `vigil_core/canonical.py` + `chain.py`.
- Money seam: `integration/vigil_integration/live/credit_lease_broker.py` (leases/settlements/**pauses**), `governor/{wallet,metering}.py`, EC-4 cost ledger, EC-5 pool.
- Launch verify chokepoint: `engine/crucible/framework/v2/launch_lease.py::_verify_and_bind_lease` (now contains the pause re-check).
- Jobs: `integration/vigil_integration/jobs/{queue,runner,authorize,launch_trigger,engage_worker}.py`.
- Isolation: `admit_customer`, `_derive_tenant_id`/`_TENANT_RE`, owner-signed `OrgRegistry`.
- Router: `integration/vigil_integration/uiproxy.py` (keyless, stdlib-only).
- Doctor/durability: `doctor.py`, `spine/{snapshot,prune,upgrade}.py`, `integration/vigil_integration/backup.py`.
