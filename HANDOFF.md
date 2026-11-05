# VIGIL — Session Handoff / Recovery Checkpoint

> Living checkpoint for the current continuous-delivery session. Updated after every
> completed milestone. **No credentials in this file** — secrets are referenced by
> name/location only.

## Current position

- **Branch:** `claude/e2e-verification-25-ph9x2k` (fresh off `origin/main`)
- **Base:** `main` @ `7c74200` — "Merge #990: VIGIL customer-SaaS program"
- **Active task:** #25 — FINAL hands-on end-to-end verification (the capstone)
- **Last checkpoint commit:** see `git log` on this branch (this doc's commit)

## Environment (verified at startup)

- Python 3.13.17 present as `python3.13` (default `python3` = 3.11 — always invoke 3.13 explicitly).
- Stack built via `./bootstrap.sh --yes`: `.venv-sovereign` + `.venv-offense`, WARDEN kernel, Qdrant up.
  Optional offense recon tools httpx/nuclei/joern/trufflehog did **not** auto-install (not needed for the
  loopback customer loop).
- `dockerd` started manually via sudo (was not running at session start; ephemeral).
- `trivy` 0.73.0 installed to `/usr/local/bin` (needed for A14 / supply-chain / `make gate`).
- pytest added into `.venv-sovereign` via `uv pip install --python .venv-sovereign/bin/python -r
  infra/supply-chain/ci-tooling.lock.txt` (venvs ship without pip; CI installs pytest on the runner).
- `uv` is 0.8.17 (NOT the 0.11.29 required for `vendor/strix/uv.lock` regen — install that only if strix is touched).

### Capability gaps (flagged to owner)

- **No `mcp__github__actions_*` tools** — cannot directly list push-to-main Actions runs or pull cron job
  logs. CI status is read via PR check-runs only. Affects #3 (livefire cron root-cause needs the job logs).
- No `subscribe_pr_activity` / `send_later` PR-watch tools in this toolset.
- Opus Workflow / subagents rate-limited until **Nov 6 05:00 UTC** — heavy multi-lens red-pen deferred to then.

## Completed work (this session)

### Milestone 1 — main-green confirmation + SIGIL test baseline ✅

- **main green:** PR #990 head (`50571d5`, the identical tree that produced merge `7c74200`) had **30/30
  blocking checks green**; only `CodeQL` (default setup) failed = advisory/non-blocking (known 8 triaged FPs);
  `CodeQL Python (advisory)` passed. A14 self-resolves on main.
  - **Caveat:** the push-to-main workflow run for `7c74200` itself was NOT independently verified (no Actions
    tool). Assertion rests on the identical pre-merge tree being fully green + A14 self-resolution.
- **Full SIGIL suite run as CI's P7 job does** (`SIGIL_HOME=<fresh> PYTHONPATH=apps/sigil:integration
  python -m pytest apps/sigil/tests/ -q`): **2320 collected → 2308 passed, 10 skipped, 2 failed.**
  - Both failures are **environment artifacts, not regressions**, consistent with CI green:
    1. `test_mcp_server_migration.py::test_live_server_registers_eight_tools` — expects a pristine empty spine
       (count 0); the shared `SIGIL_HOME` accumulated 11 records during the full run. **Passes in isolation
       with a pristine home (verified).**
    2. `test_embed_backend.py::test_golden_vectors_match` — ONNX embedding float drift (2.25e-04 > 1e-05 atol)
       across CPU hardware vs the committed golden fixture.
  - Both tests `importorskip` onnxruntime/mcp, so in CI's offense-lock P7 job they SKIP and never execute —
    which is why CI is green. They only ran here because the full sovereign ML venv was used.
- The #25 automated backbone is green: `test_customer_e2e.py` (password+step-up+billing≠testing; OIDC & passkey
  as customer-never-operator sessions; cross-tenant & cross-plane isolation; replay/forgery inertness) and
  `test_k45_loopback_e2e.py` (reserve→settle-to-consumption, refund, no double-settle/refund, per-slug tenant
  isolation) all pass.

### Milestone 2 — loopback-engagement harness (FACT → offline re-verify leg of #25) ✅

Ran `tools/loopback-engagement/run_loopback_engagement.sh` (hermetic; target = `infra/loopback/vulnapp.py`
on 127.0.0.1; offense venv; clean-checkout re-verify dir = a `git worktree` at HEAD). All four asserted legs
passed:
- **POSITIVE:** 3 oracle-confirmed FACTs (error_based_sqli 0.88, boolean_sqli 0.95, xss 0.95); full corpus
  (11 built-in + 138 library checks); all carry re-verifiable certificates.
- **RE-VERIFY:** `framework.v2 verify` reproduced 3/3 certificates **offline on the independent checkout**.
- **TAMPER:** a relabelled cert (error_based_sqli → remote_code_execution_TAMPER_never_proved) was REJECTED
  (CLAIM-MISMATCH, verify rc=2) — proves the re-verify gate is not a no-op.
- **NEGATIVE:** patched twin (`vulnapp --safe`) → 0 confirmed findings over the full corpus = sound clean.
- Note: pass an **absolute** interpreter path via `VIGIL_LE_PYTHON` (the harness `cd`s into the clean checkout,
  so a relative `.venv-offense/bin/python` fails rc=127).

### Milestone 3 — B (sandbox money-loop) + A (#3 cron) investigation ✅ (evidence gathered)

**B — money-loop (sandbox):**
- Suites green: `test_billing.py` + `test_billing_spool.py` + `test_k45_loopback_e2e.py` + `test_catalog.py`
  = 88 tests pass. Money-doctrine chain verified (verif-hash → inert spool → drainer → mandatory server-side
  re-verify → catalog-keyed sovereign mint → wallet credit → gate → billing≠testing).
- Live HTTP front-door is `vigil_integration.uiproxy` `POST /webhooks/billing` — **default-OFF**, enabled via
  `VIGIL_BILLING_WEBHOOK_SPOOL` (spool dir) + `VIGIL_BILLING_WEBHOOK_SECRET` (verif-hash, off-spine). The
  customer edge `custui` is also **default-OFF** in `vigil up`; opt in with `--with-saas`. `vigil up` stands up
  cleanly at one origin (127.0.0.1:8770, sovereign token-gated); `/customer` 502s until `--with-saas`.
- **Blocked for a faithful live drive:** Flutterwave's real sandbox-API re-verify needs owner sandbox keys
  (not present; will not store). Money-SAFE by construction either way (under-credit recoverable, never
  over-credit). NEXT: `vigil up --with-saas` + billing webhook env → POST a signed sandbox webhook → observe
  spool→drain→mint→credit→gate, using the mock verifier as the documented deterministic sandbox.

**A — #3 livefire cron root-cause (partial; needs the job log to finalize):**
- `tools/livefire/range.sh up src` → content ids match manifest (PASS locally).
- `range.sh up all && range.sh verify` → **PASS locally** (all planted weaknesses fired, all controls silent;
  dvwa/juice/mutillidae/vampi/vulnapp confirmed; meridian/webgoat brought-up-only by design).
- Pinned dvwa digest resolves; Docker Hub pulls work from here.
- **Conclusion:** the nightly cron failure is environmental on the GitHub runner, not a code regression (only
  one recent commit touches `tools/livefire`, a merge). Four nightly jobs run on `schedule`
  (`livefire-full`, `livefire-range`, `livefire-k8s-rbac`, `livefire-secret-github`; the last SKIPs cleanly
  without a PAT). Most probable: Docker Hub anonymous pull-rate-limit (`livefire-range`), from-source nikto /
  Go install (`livefire-full`), or k3s stand-up (`livefire-k8s-rbac`).
- **To finalize:** need the failing run's job log (runs 41620914942 / 41815807225) — no Actions-log tool in
  this toolset. Owner to enable the Actions tool or paste which job+step is red.

### Milestone 4 — B: LIVE sandbox money-loop driven end-to-end over real HTTP ✅

Stood up `vigil up --with-saas` with `VIGIL_BILLING_WEBHOOK_SPOOL=/tmp/billing-spool` +
`VIGIL_BILLING_WEBHOOK_SECRET=<sandbox verif-hash, local-only, not a real key>`. Origin
127.0.0.1:8770; `/customer/`→200; `/webhooks/billing`→405 on GET (POST-only).

- **Stage 2 (live HTTP front-door, `uiproxy POST /webhooks/billing`):** forged verif-hash → **401**;
  missing → **401**; wrong method → **405**; authentic → **202** `{"ok":true,"spooled":true}`. One inert
  envelope written (`0600` in `0700`), schema `vigil.webhook.billing.v1`, body recoverable; **verif-hash
  secret absent from the spool** (grep-asserted) — only `body_b64`.
- **Stage 3 (sovereign drain over the REAL spooled envelope; `BillingSpoolWatcher` + `BillingSigner` +
  `FlutterwaveBillingProvider` with an injected sandbox re-verifier + owner catalog):**
  - untrusted webhook → server-side re-verify → owner-signed mint: `minted:1`, orgA credited.
  - **no on-the-wire amount decides money:** webhook body `amount:49`; the **catalog** minted **500** credits.
  - **exactly-once:** re-spooled the same tx (fresh wrapper) → wallet stayed **500** (no double-credit).
  - **org-scoped:** orgB available = 0.
- **Not exercised (documented):** Flutterwave's real sandbox `/v3/transactions/{id}/verify` API — needs owner
  sandbox keys (not stored). The injected verifier is the documented deterministic sandbox stand-in.
- **Finding (ops):** the billing drain has **no bundled CLI/serve entrypoint** (unlike `sigil inbound` /
  `sigil settle-drain`); it exists as the `BillingSpoolWatcher` API only. Part of the owner-infra deferral —
  worth an ops ticket so a deployed stack actually drains the billing spool.

Scratch driver: `/tmp/stage3_drive.py` (not committed — local evidence only).

### Milestone 5 — #25 gates: ruff + mypy-ratchet + make gate (CI-faithful) ✅

Ran in a throwaway venv built to **CI's exact lint env** (`engine/crucible/framework/v2/requirements.lock.txt`
+ `vigil_core --no-deps` + `infra/supply-chain/ci-tooling.lock.txt`; mypy 2.3.1 = CI pin):
- `make gate` (`framework.v2 benchmark --gate --no-incumbents`): **PASS** — precision 1.000, recall 1.000,
  f1 1.000, 0 FP / 0 FN (11/11).
- `ruff check sigil`: **All checks passed**.
- `tools/governance/mypy_ratchet.sh`: **OK** — 15 not-yet-clean modules at ceiling 15; every other module
  type-clean and blocking.
- NOTE: running the ratchet under the **full sovereign ML venv** falsely reports `voice/components.py` as STALE
  (its imports resolve there but not in CI's lighter lint env). Do NOT act on that — removing it would RED CI.
  Always run ruff/ratchet in the CI-faithful lint env. (I changed only docs, so main's ratchet is unaffected.)

### #25 status rollup (what is verified here, green)
- Automated backbone: 2308/2320 (customer-e2e composed journeys + k45 money-loop settlement).
- Loopback engagement: FACT → offline re-verify → tamper-rejected → sound-negative.
- Live sandbox money-loop over real HTTP: front-door 401/202 + inert spool (no secret), drain re-verify →
  catalog-decides-money mint → exactly-once → org-scoped.
- Gates: ruff + mypy-ratchet + make gate all green (CI-faithful).
- STILL OPEN for #25: Opus multi-lens adversarial red-pen (after Nov 6 05:00 UTC); a drive against
  Flutterwave's REAL sandbox `/verify` API (needs owner sandbox keys — not stored).

### Milestone 6 — A (#3 livefire cron): diagnosis (evidence-backed; definitive pin needs the job log)

The `schedule` event runs FOUR nightly jobs. Reproduced locally (docker up):
- `livefire-range`: **green** (full container range `verify` — all planted weaknesses fired, all controls silent).
- `livefire-k8s-rbac`: **green** (throwaway k3s; "All checks held against real cluster evidence"; cert re-verified offline).
- `livefire-secret-github`: SKIPs cleanly without `VIGIL_LIVEFIRE_GH_PAT` (honest `exit 0`, not a failure).
- `livefire-full`: provisioning reproduced green — Go tools install (`nuclei@v3.3.7`, `httpx@v1.6.9`,
  `ffuf@v2.1.0`), the pinned **nikto SHA `d506740…` is reachable** (clone+checkout OK), and the version probe
  reports **2.6.1 ≥ 2.6** once `libnet-ssleay-perl` + `libxml-writer-perl` are present.

**Root-cause conclusion:** the failures (runs 41620914942 / 41815807225) are **runner-environmental, not a code
or pin regression** (livefire.yml unchanged since the Oct-7 squash merge #918; only one livefire-touching commit,
that merge). The single most fragile, workflow-documented point is the **nikto `XML::Writer` perl dependency**:
without it, `nikto -Version` prints `Required module not found: XML::Writer`, the version `sed` reads empty, and
`livefire-full` fails the `< 2.6` check. The workflow's own comment records this exact flake ("a runner image
that ships without XML::Writer"). Reproduced here: missing dep → probe fails; `apt-get install libxml-writer-perl`
→ probe passes.

**Proposed fix (NOT yet landed — speculative without the job log; safe/additive):** harden the `livefire-full`
nikto provisioning to self-heal + fail-fast with a clear message — e.g. after the apt install, assert
`perl -MXML::Writer -e1` and, if absent, `cpan -T XML::Writer` fallback; and have the version probe print the
raw `nikto -Version` on an empty parse so the next failure names its cause. This is a non-blocking nightly and
the change weakens nothing.

**To finalize definitively:** need the failing run's job log (which of the 4 jobs + which step). No Actions-log
tool in this toolset — owner to enable it or paste the red job's step log. I will land the fix (or a different
one) once the log confirms the exact step.

### Milestone 7 — #4 design-critique closeout: grounded status (verify-before-build) ✅ (investigation)

Verified against the actual tree (several handoff notes are STALE — built in #990):
- **Cross-tenant isolation merge-gate: ALREADY BUILT** — `test_custui.py::test_cross_tenant_isolation_two_customer_orgs`
  ("governance R3 MERGE-GATE": session-scoped reads, IDOR `?org_id=` ignored, billing/invoices/assessments
  covered) + `test_customer_e2e.py::test_e2e_cross_tenant_and_cross_plane_isolation` (customer cookie ⊥ operator
  cockpit `/sovereign/*`, and vice-versa) + per-surface cross-tenant 403s (`test_ui_billing`, `test_ui_assessments`,
  `test_invoices` IDOR). The design-critique "CONFIRMED MISSING" is stale. (Residual: `monitoring` surface = #42,
  not built yet; an explicit customer→`do_action` mutation-refusal assertion is implied by cookie=anon-on-operator.)
- **`_ALL_ORACLES` frozen: CONFIRMED** — guarded at exactly 15 by `test_defensive_capability`, `test_twin_refresh`,
  `test_witness_quorum::test_all_oracles_stays_exactly_fifteen_no_new_kind`.
- **W-track LEAD-only soundness: wired** — `verify.verifier.DIFFERENTIAL_LEAD_ONLY_CLASSES` referenced across
  producer/critic/sensor suites + `oracle_probe_executor`. (TODO: spot-confirm nosqli/ldap/xpath stay LEAD and
  IAM-over-permission is LEAD-or-discriminator.)
- **W5 `SECURITY_GROUP_EXPOSURE`: GENUINELY ABSENT** — no code/JSON hits → real work item (ship a sound
  LEAD-or-oracle + a prose↔oracle conformance test; audit `evidence-branches.json` for an overclaim).
- **Offboarding cascade: PARTIAL** — `orgs.revoke_org` cascades org + memberships (reactivation guard) and
  `asset_ownership` revokes on offboarding, but there is **no single cascade** covering
  account+org+wallet+subscription+invoices+credentials+monitoring → real work item.
- **E0 per-org billing perms: NOT FOUND by name** (`view_own_billing`/`manage_own_billing`) — RBAC model exists
  (viewer<analyst<operator<owner, capped below run_engagement/offense_authority) but billing-specific perms are
  not named → confirm the gating path / add if missing.
- **Pending:** `make gate` byte-identical (run twice + diff); ops sweeps (abandoned reservations, dangling
  tx_ref); snapshot down-migration runbook; unified egress posture; kill-switch-default decision.

GENUINE remaining #4 build items: W5 oracle, offboarding single-cascade, E0 billing perms (+ the pending ops/docs).
Each touches money/auth → gets the per-slice build→mutation-verify→red-pen; heavy red-pen deferred to post-Nov-6.

- **E0 per-org billing perms: SUBSTANTIALLY PRESENT** — a per-org `org_admin` role exists ("Slice E0: billing +
  member admin for THIS org, never run_engagement/offense_authority"); billing reads gated by `view_billing`
  permission, per-org scoped (`server.py:459` `org_role_can(... permission="view_billing")`). Functionality
  (own-billing view/manage, capped below testing authority) exists; just not named
  `view_own_billing`/`manage_own_billing`. → naming/doc confirmation, not a missing feature. (TODO: confirm the
  mutation/manage side uses a perm too.)

GENUINE remaining #4 build items (narrowed): **W5 oracle** (absent), **one offboarding cascade** (partial today),
**ops sweeps/runbooks + make-gate determinism + egress/kill-switch decision**. Each = its own slice + PR; heavy
red-pen deferred to post-Nov-6.

### Milestone 8 — #4 W5 SECURITY_GROUP_EXPOSURE: verified COMPLETE (no build) ✅

The handoff's "NOT FOUND" is STALE. Security-group exposure is covered, sound, and guarded:
- **Oracle backing:** the `CLOUD_POSTURE` oracle (`verify/cloud_posture.py`, `cloud_posture_oracle`) confirms an
  SG ingress literally open to `0.0.0.0/0` in the target's OWN IaC artifact or a VIGIL-owned live capture.
  Two registered branches in `docs/capability-matrix/evidence-branches.json`:
  `iac.cloud_posture.achieved_state` + `cloud_live.cloud_posture.achieved_state`. No new OracleKind
  (`_ALL_ORACLES` stays 15).
- **Not an overclaim:** ambiguous/partial exports stay INCONCLUSIVE (the branch prose already hedges;
  `fact_capable` discipline applies).
- **Prose↔oracle conformance guard EXISTS and PASSES:** `scanner/tests/test_claim_discipline.py`
  (`test_the_capability_matrix_does_not_lag_the_branch_registry`) + `aegis/tests/test_gate_invariants.py`
  (binds the branch registry to `BUG_CLASS_ORACLES`, incl. `CLOUD_POSTURE`). Ran both: **45 passed**.

GENUINE remaining #4 build items now: **one offboarding cascade** (partial today) + ops sweeps/runbooks +
make-gate determinism + egress/kill-switch decision. (W5, cross-tenant gate, _ALL_ORACLES frozen, W-track LEAD,
E0 — all verified present.)

### Milestone 9 — #4 offboarding/decommission cascade BUILT → PR #991 ✅ (red-pen pending)

- Branch `claude/offboarding-cascade-ph9x2k` (fresh off main), commit `f559694`, PR
  https://github.com/thuram-nana/vigil-sovereign/pull/991 (NOT merged).
- `governor/decommission.py::decommission_org` composes existing safe-direction latches: revoke_org FIRST
  (+membership cascade) → subscription cancel → credential+account revoke ONLY if it was the customer's last
  active org (no cross-tenant collateral). Money history retained-but-unreachable. MonitoringAuthority revoke
  joins when #42 lands. Not yet wired to a UI/CLI verb (follow-up).
- Verified: test_decommission 4/4; mutation-verify 4/4 killed; critical-set registered (+test passes);
  ruff + mypy ratchet green (CI-faithful); related governor suites + docs/tests completeness pass.
- Env-only failure seen locally: docs/tests/test_security_scan_policy::test_gitleaks_negative_control_real_catch
  (bootstrap installed an unversioned dev gitleaks; CI pins its own) — unrelated to this slice.
- UNTESTED here: CI on #991 (in flight at checkpoint). Heavy red-pen deferred to post-Nov-6.

### #42 AEGIS-SaaS — NOT STARTED (owner asked; answered)
Reuse: aegis engine (`framework/v2/aegis/`) + `vigil_core/monitoring_authority.py`. Build order AE-0 (confirm
MonitoringAuthority snapshot fold + prune tripwire) → AE-1 sovereign mint (`provision.py monitor_authorize` +
custui route, OBSERVE default) → AE-2 keyless gateway per-request authority verify (FATAL-2, no key) → AE-3
enforcement gating (BLOCK authority + fired oracle+cert + AEGIS_RESPOND↔billing; prod flag default-OFF) → AE-4
verdict crossing to tenant Monitoring surface (same inert spool chain; strict org isolation) → AE-5 catalog
monitoring plan → AE-6 managed gateway deploy → AE-7 acceptance + flag-hold. NEXT after #991: AE-0.

## Remaining tasks (in order)

1. **#25 hands-on (in progress):** stand up the LIVE stack (`vigil up` / custui over the loopback hop) and
   drive the real customer journey through HTTP against a running server (beyond the in-process test harness);
   run `tools/loopback-engagement/run_loopback_engagement.sh` for the FACT→offline-`verify` leg; scripted
   adversarial probes (RBAC on every mutation, console isolation, session fixation/rotation/CSRF, invoice-IDOR,
   out-of-scope offense refusal, step-up bypass). Reserve Opus multi-lens red-pen for post-Nov-6.
   Full suites + ruff + mypy-ratchet + `make gate`. Production targets stay flag-disabled.
2. **#3** livefire cron root-cause (needs the failed-run job logs: 41620914942 / 41815807225).
3. Design-critique close-out gaps (cross-tenant merge-gate BUILD; W5 SECURITY_GROUP_EXPOSURE; W-track LEAD
   soundness; `make gate` byte-identical + `_ALL_ORACLES` frozen; offboarding cascade; E0 per-org billing perms;
   ops sweeps + runbooks).
4. **#14** enterprise postpaid-invoice (deferred — ask owner; red-pen after Nov 6).
5. **#42** AEGIS-SaaS productization (deferred — ask owner; red-pen after Nov 6).
6. Deploy/ops polish (marketing vhost; NVD/EPSS enrichment; edge wiring).

## Exact next step

(UPDATED) Drive PR #991 CI to green; then start #42 AE-0 on a fresh branch. Older note below kept for history.

## Exact next step (prior)

`vigil up --with-saas` with `VIGIL_BILLING_WEBHOOK_SPOOL`/`_SECRET` set → POST a signed sandbox webhook to
`/webhooks/billing` → observe spool→drain→mint→credit→credit-gate→billing≠testing over real HTTP (mock verifier
= documented deterministic sandbox). Then `make gate` + ruff + ratchet. Reserve Opus multi-lens red-pen for
post-Nov-6. Finalize #3 once the failing job log is available.

## Blockers / open questions to owner

- **WRITE ACCESS (blocking checkpoint-push):** this session's GitHub token appears read-only — `git push` 403
  and MCP `create_branch` 403. Local commits are safe but unpushed. Need a write-scoped token or the exact
  `claude/…-<session-id>` branch name the push-token is scoped to. Thread id: `thread_01Pea9mWEbcrKAviJaWCmbL4`.
- (a) Can the GitHub **Actions** read tool be enabled? Otherwise #3 = "paste me the job logs".
- (b) Confirm **Flutterwave sandbox/test mode** only for #25 (no production payment target).

## Conventions reminder

- Branch fresh off main per unit of work; one reviewable slice per PR; drive every PR to green.
- Never merge / approve / dismiss-alert / enable-production without explicit owner instruction.
- Preserve invariants: FATAL-2 two-plane boundary, money doctrine, FACT doctrine, billing-authz≠testing-authz,
  owner-key isolation, egress floor + kill-switch, default-OFF + fail-closed.
