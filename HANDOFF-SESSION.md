# VIGIL — HANDOFF (complete, end-to-end) — 2026-11-11

> Supersedes the 2026-11-09 handoff. Written so a **fresh agent or human can take over cold**: what is on
> `main`, what every shipped slice does and where it lives, every flag and who may flip it, the exact remaining
> program in order, how to work in this repo without tripping its guards, and the definition of done.
>
> **`main` is at `397e97c5` (#1075); #1076 (S0d-3 + this handoff) is in CI and merges on green.** Since the
> 2026-11-09 handoff 30 PRs have merged (#1046–#1075; this handoff written by session
> `session_01Uzcz55Eva4w7NRFfoQPArA`): Front A is
> complete except the owner-blocked KMS escrow; Front B's pay round-trip is built (default-OFF); the 1M-user design
> was **authorised by the owner** and its first three build slices (S0a–S0c, the verified fold cache over
> customers, orgs/memberships and the money folds) are merged default-OFF. **The next agent's first item is Front C
> S0d (§4.3), then S1→S4, then Gate 5 (§5).**
>
> **Update (same session, 2026-11-11): Front C S0 is COMPLETE** — S0d merged as #1072, #1073, #1074, #1075
> and the S0d-3 PR (#1076, which carries this update). Every request-path fold is on the verified cache; per-request
> stores pay O(new records) via the tail fast path; the cache is warmed at boot and audited against the spine
> (`sigil verify`, `vigil doctor`).
>
> **HANDOVER (2026-11-11, end of session): read §10 FIRST.** The owner opened a new program the same day —
> **pricing, metered billing on ONE VIGIL API key, and Red-Pen as a customer product** — and decided or delegated
> the numbers recorded in §10.2 (the margin value is the owner's, set at deploy). The metering core and the model
> gateway (M1) ship as their own PR; the sovereign wiring (M1c-1) follows; then the slices in §10.6. Front C S1→S4
> (§4.4) and Gate 5 (§5) remain after/alongside.

---

## 0. HOW TO WORK HERE (read first)

### 0.1 Repo and planes
Two-plane monorepo at `/home/user/vigil-sovereign`:
- **Sovereign plane** — `apps/sigil` (SIGIL) + `packages/core/vigil_core`. Framework-free; the owner's Ed25519 key
  is the trust root. The **Provisioner** (`apps/sigil/sigil/ui/provision.py`, reached only over the loopback hop
  from the customer edge `ui/custui.py`) is the ONLY owner-key holder.
- **Offense plane** — `engine/crucible` (CRUCIBLE, `framework.v2.*`). Keyless: it only *verifies* owner signatures.
- **Integration glue** — `integration/vigil_integration` (doctor, backup, drains, jobs, uiproxy, live/*).
- **FATAL-2 boundary** — `assert_no_offense()` at import on the sovereign side; `uiproxy.py` stays stdlib-only;
  any framework import from sovereign/integration code stays lazy. `integration/tests/test_two_env_boundary.py`
  (`_PROBE`) enforces it — register every new `live`/edge module there.

### 0.2 Per-slice discipline (non-negotiable; every PR this session followed it)
`build → mutation-verify (break each guard → its named test goes RED → restore → green) → adversarial red-pen
(trace a realistic failure path for every claim; a "finding" is a claim to verify, not an order) → fold the
confirmed findings (each fix mutation-verified) → PR → merge only on CI green + mergeable clean`.
- One slice per PR, built off fresh `origin/main`, **default-OFF + fail-closed, byte-identical when off**.
- Fix security findings **at the source; never suppress** (owner: "Why are you trying to suppress, cant we fix
  it end to end"). Inline `# codeql[...]` comments are not honoured by this repo's analysis anyway.
- An *equivalent mutant* (a code change no test can observe) means the code is dead or the test is missing:
  either delete the code or add the test — this session did both (S0a removed two redundant guards; S0b added
  two missing tests).

### 0.3 Owner's NEVER-CROSS lines (verbatim intent — never do these)
1. Do **not** flip `VIGIL_CUSTOMER_PROD_EXECUTION` or the multi-shard production flag.
2. Do **not** inject or commit a real Flutterwave secret (`VIGIL_FLW_SECRET_KEY` is read from env at call time;
   tests use dummies).
3. Do **not** ratify money numbers — margins, $/token, catalog prices, **scale targets**.
4. Do **not** dismiss a security alert. An A14 (supply-chain) red is *handled*, never ignored; the
   GitHub-release-CDN 504 is "transient" only once a clean re-run confirms it.
5. `main` is PR-only — **never `git push origin main`**.
Merge authorization (owner, standing): merge once **all required checks are green and the change is tested**.

### 0.4 Merge mechanics (what actually works)
- Live branch protection: **strict = true** (a PR must be up to date with `main`), signed commits required,
  no force pushes. Strict ⇒ **the merge queue is serial**: each PR must be re-based on the previous merge.
- CI wall time ≈ **40 min per PR**; the long pole is `integration two-env boundary (P5)` (~16–37 min), then
  `CRUCIBLE core on vigil_core` (~21 min).
- This session merged with `merge_method="merge"` and `expectedHeadSha` (GitHub signs the merge commit, so
  signed-commit protection is satisfied). Squash also works.
- **Required checks (14)** — canonical list `.github/required-status-checks.txt`: A14 supply-chain gate · CRUCIBLE
  core on vigil_core · CRUCIBLE eval + benchmark corpus · formal (TLA+, F1) · gateway egress gate (P6) ·
  integration two-env boundary (P5) · livefire smoke · loopback engagement · SIGIL governor gates (P7) · SIGIL
  lint (ruff + mypy) · strix Claude-runtime (P8) · the briefing explains every agent and capability · vigil_core
  · WARDEN Rust kernel (A10). **Advisory** (reported, not required): CodeQL Python, **CodeQL JavaScript** (new,
  CQ-1), gitleaks, semgrep+bandit, pre-commit, perf regression, lint-config, scheduled supply-chain scan.
- A `mergeable_state` of `clean` means every required check passed; `unstable` means something (often an
  advisory or still-running job) is not green — read the check runs before deciding.

### 0.5 Branch / worktree pattern in this cloud environment
- The session branch is pre-assigned (this session: `claude/cool-meitner-v9fq6d`). **Force-push is denied.**
  Per slice: `git fetch origin main && git merge --ff-only origin/main && git cherry-pick <slice-commit>` →
  re-test → `git push -u origin <branch>` → open the PR (`mcp__github__create_pull_request`, base `main`).
- Build slices in **detached worktrees** in the scratchpad so several can be built while one is in CI:
  `git worktree add --detach <scratch>/wt-<slice> origin/main` (stack dependent slices: `worktree add <dir>
  <parent-commit>`; after the parent is amended, `git rebase --onto <new-parent> <old-parent>`).
- Subscribe to each PR (`subscribe_pr_activity`) and keep one `send_later` safety-net check-in (~50 min).

### 0.6 Test legs (exact)
Always a fresh `SIGIL_HOME=$(mktemp -d)`; venv `/home/user/vigil-sovereign/.venv-sovereign/bin/python`
(no `pytest-xdist` there — run serially; `apps/sigil/pyproject.toml` already adds `-q`, so adding `-q` again
suppresses the final tally line: omit it). Use **absolute** PYTHONPATH entries (subprocess CLIs break otherwise).
```bash
R=/home/user/vigil-sovereign
# sovereign (apps/sigil/tests, ~5 min, ~2,940 tests)
PYTHONPATH=$R/apps/sigil:$R/integration:$R/packages/core/vigil_core SIGIL_HOME=$(mktemp -d) \
  $R/.venv-sovereign/bin/python -m pytest -p no:cacheprovider apps/sigil/tests
# integration — SOVEREIGN leg (what P5 runs first): gateway on the path, the engine NOT on it
PYTHONPATH=$R/apps/sigil:$R/integration:$R/packages/core/vigil_core:$R/gateway \
  SIGIL_HOME=$(mktemp -d) $R/.venv-sovereign/bin/python -m pytest -p no:cacheprovider integration/tests -k <area>
# integration — OFFENSE-leg files (importorskip("framework")): add $R/engine/crucible, and run ONLY those files
#   (the run-list in ci.yml). Never put the engine on the path for sovereign-leg files: e.g.
#   test_uiproxy_billing_webhook.py then trips the FATAL-2 guard ("SIGIL sovereignty violation") — a false red.
# gates
$R/.venv-sovereign/bin/python -m ruff check apps/sigil/sigil <new test files>
PATH=$R/.venv-sovereign/bin:$PATH bash tools/governance/mypy_ratchet.sh   # ceiling 15; do NOT set MYPYPATH
```
Run `docs/tests` (~2.5 min) and `integration/tests/test_ci_*.py` (<1 s) before every push that touches docs,
workflows or test layout.

### 0.7 Guards and gotchas that WILL bite (learned this session)
- **Offense-leg listing guard.** A new integration test containing `importorskip("framework…")` SKIPS in the
  sovereign leg, so `test_ci_framework_tests_run_in_offense_leg` REDs P5 unless the file is listed in the
  offense leg's run-list in `.github/workflows/ci.yml` (next to its siblings). #1062 hit this; it cost one CI round.
- **Pre-commit end-of-file-fixer.** A file written with `write_text(s + "\n")` over content already ending in
  `\n` fails the advisory pre-commit job. Check `tail -c1` before pushing.
- **`SpineStore()` default path is bound at import.** A test that constructs a server/CLI with the default store
  reads whatever an earlier test wrote. Monkeypatch the module's `SpineStore` onto a private path.
- **`framework.v2.common.paths.crucible_root` is `lru_cache`d.** Call `paths._reset_cache()` after changing
  `CRUCIBLE_ROOT`, or restore assertions silently read the source tree.
- **Sandbox-only failure:** `integration/tests/test_services_doctor.py::test_doctor_notes_unreachable_local_
  backend_but_does_not_flip_ok` fails in this container on `main` too — docker is installed but its daemon is
  down, so doctor adds a "docker … daemon is not answering" note that the test's `"not answering"` substring
  matches. Green in CI. (Robust fix, if wanted: match the LLM-backend note text.)
- **Snapshot-seeded folds:** never key a cache on `(base_seq, snapshot_seq)` alone — the neutered-control tests
  (`test_snapshot_fold_{wallet,metering,subscription}.py`) swap the seed under the same boundary. S0 keys on the
  loaded `SnapshotState` **by value** (see §4.2).
- **Monitoring subscription plans** must be catalog plan ids (`aegis_observe_1h|5h`, `aegis_respond_1h|5h`).
- **A lock bump must also regenerate the committed offense SBOM.** After changing
  `engine/crucible/framework/v2/requirements.lock.txt`, run `cd engine/crucible && python3 -m
  framework.v2.tools.gen_sbom` (stdlib) — A14 step "committed OFFENSE sbom.json matches the lock" fails otherwise
  (DEPS-1 #1066 hit this). Before pushing any lock change, run `bin/verify-supply-chain.sh` for all three locks
  (offense from `engine/crucible`; sovereign / otel with `REQ_IN` + `REQ_LOCK` set) with pip-tools 7.6.1 +
  cyclonedx-bom 7.3.1 on PATH. To find WHICH A14 step failed, read the job's step conclusions
  (`actions_get get_workflow_job`) — the big Trivy CVE table at the end of the log is the ADVISORY Strix-sandbox
  SBOM scan, not the gate.
- **Hash locks:** regenerate only with pip-tools 7.6.1 under Python 3.13 from each lock's canonical CWD
  (`docs/SUPPLY-CHAIN.md` "Regenerating a lock"); use `--upgrade-package <pkg>` to move one pin; the
  shared-pin guard requires cryptography / pydantic / pydantic-core to agree across the sovereign and engine locks.

### 0.8 Attribution (binding)
End every commit and PR body with the attribution lines your own session's system reminder specifies (commit:
`Co-Authored-By:` + `Claude-Session:` trailers; PR: the "Generated with Claude Code" line + the session URL).
**No model identifier anywhere else** in a pushed artifact (code, comments, PR titles, docs). Every GitHub comment
ends with the session's attribution footer.

---

## 1. STATE OF `main` — merged since the 2026-11-09 handoff (`26a38b6`)

| PR | Merge | What landed |
|---|---|---|
| #1046 | `dabf5113` | docs(handoff): pause/resume chain complete; next is Front A |
| #1047 | `8e471a8c` | **NET-2a** — bounded half-open recovery for the OTLP sink latch (default-OFF) |
| #1048 | `fc48c7d5` | **NET-2b (OTLP)** — opt-in loopback OTLP endpoint for `vigil engage` + egress-pin hardening |
| #1049 | `fba03b88` | **NET-4** — `vigil doctor` surfaces network-recovery / telemetry posture (advisory) |
| #1050 | `4779aa10` | `learn_drain.watch()` survives a single-drain failure (sibling-drain parity) |
| #1051 | `172a14de` | **DEP-2** — `vigil ready` bring-up readiness gate + opt-in `vigil-ready.service` |
| #1052 | `420961a1` | **DEP-3** — on-box upgrade/rollback drill against a copy of the REAL spine (opt-in) |
| #1053 | `0e9f3086` | **#70** — every `SIGIL_HOME` entry the product references has a capture-or-exclude backup decision |
| #1054 | `5a36492b` | **#70b** — doctor flags when the money seam is not inside the offense backup (advisory) |
| #1055 | `ceb399db` | **Front B** — money-IN billing drain automated (`vigil-billing-drain.{service,timer}`, opt-in) |
| #1056 | `7a019ea5` | **CHK-1/CHK-1b** — customer hosted checkout (top-ups + subscription plans), default-OFF, catalog-priced |
| #1057 | `feae64c5` | Supply chain — sovereign lock's `opentelemetry-api` past GHSA-xcq7-p3pf-p88h |
| #1058 | `f43c1f8c` | Supply chain — opt-in hash lock for the OpenTelemetry SDK + OTLP/HTTP exporter |
| #1059 | `7361a6cd` | **CHK-2** — buy credits in the customer app + the billing-return page (default-OFF) |
| #1060 | `254aa828` | **NET-2b (billing)** — the billing drain auto-retries a transient processor failure (bounded, default-OFF) |
| #1061 | `de5b7783` | **CQ-1** — real CodeQL findings fixed at the source; CodeQL JavaScript in CI; triage recorded |
| #1062 | `69baaa9e` | **#70c** — the offense backup captures the CRUCIBLE tree where the engine actually keeps it |
| #1063 | `be22428a` | **MONEY-5** — `vigil doctor` goes RED on a failed money-IN billing drain |
| #1064 | `1a9b96b5` | **HOP-1** — the customer edge outwaits each action's own outbound worst case |
| #1065 | `45a7bac3` | **NTF-4** — `vigil alerts --test-delivery` proves alarms reach a human |
| #1066 | `5ae40822` | **DEPS-1** — the Dependabot minor/patch bumps through the hash-lock tooling (+ regenerated offense SBOM) |
| #1067 | `6bc3fb8b` | **FRONT-C design** — `docs/decisions/FRONT-C-1M-SCALE-DESIGN.md` (owner-authorised 2026-11-10; S4 targets open) |
| #1068 | `6ebe6aa8` | **S0a** — verified incremental fold cache for the customer registry (default-OFF) |
| #1069 | `3ae2ac61` | **S0b** — orgs + memberships (every `admit_customer`) on the fold cache; shared `governor/fold_read.py` |
| #1070 | `e836b962` | **S0c** — the money folds (wallet, plan credits incl. settle-path `debited_entry`, subscriptions) on the fold cache |
| #1071 | `8049bae6` | docs(handoff): complete end-to-end handoff after the 2026-11-10/11 queue |
| #1072 | `2f8dc3a4` | **S0d-1** — operator accounts + customer credentials (passkeys, TOTP, Google links) on the fold cache |
| #1073 | `bd68bbe1` | **S0d-2a** — invoices, the EC-4/EC-5 cost ledger (O(1) global pool position), postpaid line + arrears |
| #1074 | `8269b1ab` | **S0d-2b** — promotion, the agent budget meter, asset ownership, monitoring authority |
| #1075 | `397e97c5` | **S0d-2c** — kill switch + capability gate (append-proof), customer assessments, margin settles, `challenge()` |
| #1076 | (this PR) | **S0d-3** — fresh-store tail fast path, rebuild-and-compare audit, boot warm-up, `sigil verify` / `vigil doctor`; this handoff |

**Pricing (§10):** PRICING M1 (metering core + model gateway) ships as its own PR; M1c-1 (sovereign wiring) next.

---

## 2. WHAT SHIPPED — by front, with anchors

### Front A — production hardening ✅ (only the owner-blocked KMS escrow remains)
- **Pause/resume (PR-1..PR-5, #1033–#1045)** — complete behind `VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED`. Chain
  reference: lifecycle reserve → `provision.launch_reserve` → `LaunchGate.reserve_launch`; start →
  `LaunchGate.publish_lease` → `credit_lease_broker.write_credit_lease`; drain → `launch_drain.LaunchSeamDrain`
  → `jobs/launch_trigger`; run → `jobs/runner.run_one` → `jobs/authorize.build_customer_launch_gate` →
  `jobs/engage_worker` → `engage.run_engagement` (the ONE floor-burn: `_engage_launch_lease_precondition`);
  settle → `inbound/completion_spool` → `LaunchGate.settle_launch`. Pause markers:
  `live/credit_lease_pause.py`; verify chokepoint: `engine/crucible/framework/v2/launch_lease.py::_verify_and_bind_lease`.
- **Network recovery (#73 "Item B")** — `integration/vigil_integration/live/net_recovery.py` (bounded backoff,
  injectable clock) behind `VIGIL_NET_RECOVERY_ENABLED`: OTLP sink half-open recovery (NET-2a), opt-in loopback
  OTLP endpoint `VIGIL_OTLP_ENDPOINT` (NET-2b), the billing drain's bounded retry of a transient processor
  failure instead of quarantining a paid webhook (#1060), doctor posture lines (NET-4, advisory, never gates).
- **Deploy maturity** — `vigil ready` + `infra/systemd/vigil-ready.service` (DEP-2; readiness ≠ enabling prod
  execution); the upgrade/rollback drill against a COPY of the real spine (`infra/systemd/vigil-upgrade-drill.
  {service,timer}`, `VIGIL_UPGRADE_DRILL_ENABLED`; DEP-3, exercises `spine/upgrade.py`).
- **Backups everywhere (#70)** — `integration/vigil_integration/backup.py`:
  - #1053: every `SIGIL_HOME` entry has an explicit capture-or-exclude decision (a guard test enumerates them);
  - #1054: doctor advises when the money seam (`VIGIL_BASE_DIR` credit leases / settlements / pauses) is not
    inside the offense backup;
  - **#1062 (#70c):** `_CrucibleLayout` resolves BOTH engine roots (crucible root holds `targets/`; v2 root
    `<crucible_root>/framework/v2` holds `.blackboard`, `.console/runs`, `.memory`, `.entitlement`,
    `.authority`, `.authority-root`, `.evidence-keys`) for either spelling of `--crucible-root` / `$CRUCIBLE_ROOT`.
    Before it, the default backup silently captured no engagement, evidence, entitlement root or kill-switches.
    Every SQLite DB unit (proof DB, memory, each safe `tenants/<t>` shard) is an online-backup snapshot; symlinked
    or unsafe shards are never packaged. Test: `integration/tests/test_backup_engine_layout.py` (21; offense leg).
  - **Remaining:** evidence-DEK **KMS escrow** — stubbed; the live path needs a real AWS KMS key (**owner**).
- **Money gate (#69)** — DONE: doctor goes RED on an unhealthy money-OUT drain (settle / finding) and, with
  MONEY-5, on a failed money-IN **billing** drain (customer-impact message + re-queue steps; only when
  `VIGIL_BILLING_DRAIN_ENABLED`). `doctor.py::_MONEY_DRAIN_UNITS`.

### Front B — hostable / pay round-trip ✅ built, flag-held
- **Money-IN drain** — `apps/sigil/sigil/inbound/billing_spool.py` (`vigil billing-drain`) + systemd
  `vigil-billing-drain.{service,timer}` (#1055, `VIGIL_BILLING_DRAIN_ENABLED`).
- **Hosted checkout** (#1056) — `provision.billing_checkout`; Flutterwave hosted payment
  (`VIGIL_FLW_SECRET_KEY`, `VIGIL_FLW_API_BASE`), amounts always from the **owner catalog**
  (`governor/catalog.py`), never a client field; credit is granted **only** by the verified inbound webhook drain.
  Flags: `VIGIL_CUSTOMER_CHECKOUT_ENABLED` (top-ups), `VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED` (subscription plans;
  enable only after a sandbox renewal proves attribution), `VIGIL_BILLING_PLAN_ALARM` (quarantine an
  unaccountable paid plan charge — keep ON while any sold plan can still renew).
- **Customer app** (#1059) — buy-credits UI + `/billing/return` page (`ui/customer_app/`, display-only: it never
  credits), `VIGIL_CUSTOMER_BILLING_RETURN_URL`.
- **Edge hop budget (HOP-1)** — `ui/custui.py::_SLOW_HOP_TIMEOUTS_S` (`billing_checkout` 45 s, `oidc_finish` 45 s,
  `target_verify` 20 s, `signup_request`/`recover_request` 60 s; default 10 s) so the edge never reports failure
  for an action the cockpit completed (a retry used to create a second checkout / re-send email / burn an OIDC code).
- **Alert delivery proof (NTF-4)** — `vigil alerts --test-delivery` (`unit_alerts.cmd_test_delivery`): one
  labelled `info` alarm through exactly the configured destinations; exit 0 delivered / 1 any failed / 2 none
  configured; a success refreshes the delivery dead-man, a failure never fakes one.
- **Money doctrine (unchanged, binding):** the catalog decides price; credit comes only from the verified webhook
  drain; the return page is display-only; custom credit amounts are **not** supported (owner decision pending:
  rate, min, max, rounding).

### Supply chain / security
- #1057 / #1058 — OTel lock fixes (sovereign `opentelemetry-api` advisory; opt-in `infra/supply-chain/otel.lock.txt`).
- **CQ-1 (#1061)** — fixed at source: `tempfile.mktemp` → private 0700 dir (`perception/capture.py::private_
  capture_path`, platform android/macos/windows); `</script\b[^>]*>` end-tag in the AEGIS XSS oracle + DOM-XSS
  scanner; explicit TLS 1.2 floor on the phone-approval bridge; `--` before the operator command in console
  run-tests → `vigil sandbox`; quote-escaping `esc()` in the bridge PWA; key allowlists in `vigil-ui` `hashQuery`
  and the CVSS tool. New advisory **CodeQL JavaScript** job. Triage record: `docs/audit/CODEQL-TRIAGE.md`
  (fixed / by-design with dismissal rationale / fixtures needing the owner's scope decision / not yet triaged).
- **DEPS-1** — the Dependabot minor/patch bumps done through the hash locks (cryptography 50.0.2, mcp 2.3.0,
  onnxruntime 1.31.1, pydantic 2.14.3, qdrant-client 1.20.0, tokenizers 0.23.3; engine `pytest-httpserver>=1.2.0`);
  two latent order-dependent tests made hermetic.

### Front C — 1M users (design authorised; S0 = S0a–S0d merged, default-OFF) — see §4.

---

## 3. FLAG INVENTORY (everything new is default-OFF)

| Flag | Enables | Who flips |
|---|---|---|
| `VIGIL_CUSTOMER_PROD_EXECUTION` | customer launches executing against production targets | **owner only — never the agent** |
| multi-shard production flag (S2/S4, not yet built) | production multi-shard routing | **owner only, after S4 is green** |
| `VIGIL_FOLD_CACHE_ENABLED` | the verified fold cache (S0: every request-path registry read — §4.2) + the cockpit's boot warm-up / audit thread | owner (production); tests set it |
| `VIGIL_FOLD_CACHE_AUDIT_S` | seconds between the cockpit's rebuild-and-compare audits (default 21600; 0 = warm-up only) | operator |
| `VIGIL_CUSTOMER_CHECKOUT_ENABLED` | hosted top-up checkout (needs `VIGIL_FLW_SECRET_KEY` + `VIGIL_BILLING_WEBHOOK_SECRET`) | owner |
| `VIGIL_CUSTOMER_PLAN_CHECKOUT_ENABLED` | subscription-plan checkout (needs the base flag) | owner, after a sandbox renewal |
| `VIGIL_BILLING_PLAN_ALARM` | quarantine an unaccountable paid plan charge | owner (keep ON while plans can renew) |
| `VIGIL_BILLING_DRAIN_ENABLED` | the money-IN drain unit is watched by the dead-man + doctor | owner / operator |
| `VIGIL_CUSTOMER_PAUSE_RESUME_ENABLED` | customer pause/resume of a launch | owner |
| `VIGIL_CUSTOMER_MONITORING_ENABLED` | AEGIS-SaaS monitoring-authority routes | owner |
| `VIGIL_NET_RECOVERY_ENABLED` | bounded reconnect/retry (OTLP sink, billing drain transient retry) | operator |
| `VIGIL_OTLP_ENDPOINT` / `VIGIL_WITH_OTEL` | loopback OTLP export (opt-in telemetry) | operator |
| `VIGIL_UPGRADE_DRILL_ENABLED` | the on-box upgrade/rollback drill | operator |
| `SIGIL_OIDC_ENABLED`, customer OIDC/passkey flags | operator / customer federated login | owner |

**Pricing / metering flags — on the pricing branch only until M1 / M1c-1 merge (§10):**

| Flag | Enables | Who flips |
|---|---|---|
| `VIGIL_METERED_BILLING` | settle = the run's gateway meter cost / (1 − target margin) (clamped), and the launch mints a model grant | **owner — and NOT before M3 re-budgets the launch products (§10.5)** |
| `VIGIL_MODEL_GATEWAY_ENABLED` / `VIGIL_MODEL_GATEWAY_PORT` (8742) | the cockpit starts the sovereign model gateway (loopback) | owner / operator |
| `VIGIL_BILLING_TARGET_MARGIN` (**no default**: the owner's, set at deploy; unset = metered pricing refused) · `VIGIL_BILLING_CANCEL_SETTLEMENT` (`metered` \| `refund`; unset = `metered`, the owner's decision of 2026-11-13: a cancelled run pays for what it used; an unrecognised value refuses metered launches) · `VIGIL_RUN_FLOOR_CREDITS` (25) · `VIGIL_MODEL_PRICES` (JSON) · `VIGIL_RUN_MODEL` (`claude-opus-4-8`) | the pricing the gateway and settle use | owner (defaults = the owner-delegated design) |
| `VIGIL_GATEWAY_TENANT_CONCURRENCY` (4) · `VIGIL_GATEWAY_GLOBAL_CONCURRENCY` (32) · `VIGIL_GATEWAY_DAILY_LIMIT_USD` (unset) | protecting the one shared API key | owner / operator |

Secrets (never in git): `VIGIL_FLW_SECRET_KEY`, `VIGIL_BILLING_WEBHOOK_SECRET`, `VIGIL_BACKUP_PASSPHRASE`,
`SIGIL_CUSTOMER_SESSION_KEY`, `SIGIL_ANTHROPIC_API_KEY`.

---

## 4. FRONT C — 1,000,000 USERS

### 4.1 Decisions (`docs/decisions/FRONT-C-1M-SCALE-DESIGN.md` §7)
✅ ONE sovereign spine (no per-cell sovereign spines — they would split the EC-5 pool and make money moves
distributed transactions). ✅ The S0 trust model (cache of the signed spine, chain-anchored, never
authoritative, full-fold fallback on any doubt). ✅ S0 first. ⏳ **Scale targets for S4 — owner, still open**
(users, concurrent engagements, p99 login/page latency, appends/s at peak). Do not invent them.

**Measured wall:** every customer request re-folded the signed spine from genesis and re-verified every grant's
Ed25519 signature — ~148–200 µs per record ⇒ ~2.5–3 min per login lookup at 1M customers; `admit_customer` = 2
full folds; the launch gate's `CreditMeter.available` = 3 more. Signed append ≈ 1.1 ms (~900/s/process before
group commit).

### 4.2 S0 — the verified fold cache (S0a–S0d MERGED, default-OFF)
**Files:** `apps/sigil/sigil/spine/fold_cache.py` (generic substrate) · `apps/sigil/sigil/governor/fold_read.py`
(the ONE registry read path) · `key_history.key_resolver_with_horizon` · per registry: a shared one-record step
used by BOTH the full fold and the cache, a seed method, a view, and `_cached(reader)`.

**How it works.** `FoldCache.read(store, key, build=, reader=)` keeps ONE entry per (fold, resolved spine path):
the folded state + the `(seq, entry_hash)` of the last record folded (the **chain anchor**). On each read:
1. the anchor record is re-read; missing or a different `entry_hash` (restore, rollback, rewrite, reset) ⇒
   discard + rebuild from the spine (`entry_hash` links `prev_hash`, so an equal anchor ⇒ an equal prefix for any
   chain `verify()` accepts);
2. records after the anchor are folded with the registry's own step; an **owner-key-history** record ⇒ rebuild
   (rotation can change validity windows retroactively — fork / broken chain deny all);
3. a rebuild whose resolver (built by `key_resolver_with_horizon`) did not see a history record it then folds —
   a concurrent rotation — answers but is **not cached**;
4. any fault while extending ⇒ discard + rebuild; a fault in the rebuild raises exactly as the full fold would;
5. `reader(state)` runs under the entry lock (thread-safe; never a half-extended view).
**Key** (`fold_read.cached_read`): `(trusted_pubkey, genesis_owner_pubkey(), SnapshotState-by-value)` — the
snapshot's boundary moves the live window and its rows ARE the seed (1.8 µs to compare the empty no-prune
identity). A registry view can set `poisoned` (e.g. an owner-signed non-str username no code mints) ⇒ every read
falls back to the full fold.

| Slice | Registry reads now cached | Warm read | Full fold (OFF) | Tests / mutants |
|---|---|---|---|---|
| S0a | `CustomerRegistry.customer / by_email (email index) / customers / set_password` | ~120–135 µs flat 500→30k | 85 ms → 4.45 s | 28 / 22 of 22 |
| S0b | `OrgRegistry.orgs / org / memberships / membership_role` ⇒ `admit_customer` (one entry for both folds) | ~121 µs | 76 ms → 1.5 s (250→5k orgs) | 15 / 18 of 18 |
| S0c | `WalletRegistry`, `PlanCreditLedger` (incl. settle-path `debited_entry`), `SubscriptionRegistry` (one cache per line) ⇒ `CreditMeter.available` | ~355–385 µs | 100 ms → 1.46 s (200→3k tenants) | 11 / 16 of 16 |
| S0d-1 (#1072) | `AccountsRegistry` (every operator request: `resolve`), `CustomerCredentialRegistry` (passkey / TOTP / Google login; by user / credential id / (iss, sub) pairs) | ~120–140 µs | resolve 231 ms, passkey 2.86 s (20k) | 13 / 22 of 22 |
| S0d-2a (#1073) | `InvoiceRegistry`, `CostEnvelopeLedger` (`PairedLedgerView`: O(1) `global_position`), `PostpaidRegistry` + `PostpaidArrearsLedger` | 130 µs pool; ~0.6 ms launch reads | 4.6 s pool; 15.7 s (20k tenants) | 10 / 31 of 31 |
| S0d-2b (#1074) | `PromotionPolicy`, `BudgetLedger.spent` (unsigned, per-(agent, day)), `AssetOwnershipRegistry` (proofs; `KeyedGrantView`), `MonitoringAuthorityRegistry` | ~0.6–0.7 ms launch path | 3.2 s (5k tenants) | 11 / 22 of 22 |
| S0d-2c (#1075) | `KillSwitch` + `CapabilityGate` (no longer re-scanned on every append), assessments (per-slug index), margin settles, `challenge()` (`live_window`) | ~1.1 ms governed action incl. its append | 526 ms (5k tenants) | 13 / 15 of 16 (+1 equivalent) |
| S0d-3 | `SpineStore.tail_after` (fresh store per request: anchor + delta from the active tail; sealed anchor via the manifest boundary hash), `FoldCache.audit` via `fold_read.auditing`, `governor/fold_warm.py`, `sigil verify [--folds]`, `vigil doctor` | 0.21–0.42 ms (fresh store) | 14.8 → 69.6 ms per request before | 20 + 6 / 19 of 19 |
Each slice: full `apps/sigil` suite green with the flag ON and OFF; tests compare the cached public API with the
same API flag-OFF after every randomized op, and fail if a cached read silently fell back.

**Residuals (documented, not hidden):**
- **Cold build O(N) once per process** (~2.5 min at 1M) — removing it needs a persisted signed index, which the
  approved trust model excludes. S0d-3 runs it at boot in the cockpit (`fold_warm.start_background`), off the
  request path.
- ~~Gzip-sealed anchor~~ — fixed in S0d-3 (proven from the manifest boundary hash: 29.6 ms → 0.12 ms).
- **Chain-breaking in-place edits before the anchor are not re-read by a read** — `SpineStore.verify()` and the
  S0d-3 audit (`sigil verify`, the cockpit's periodic audit → `vigil doctor` HARD issue) catch them.
- **The fast path trusts the manifest's `boundary_hash`** for a sealed anchor; a tamper that rewrites a sealed
  segment but leaves the manifest is caught by `verify()` / the audit, not by the read.
- **Audit cost** — one cold build per fold, in the background, every `VIGIL_FOLD_CACHE_AUDIT_S` (default 6 h).
- **Two trust roots in one process** thrash a fold (one entry per fold and spine); production uses one.
- **Kept on their scans by design:** the sovereign `OffenseGate` and the eval capability-grant / offense-
  attestation folds (owner ceremonies, documented "never cached"), `budget.report` (CLI), `revoke_all`, the eval
  `_publish` scans, the cockpit HUD's one-time tip scan.
- **Memory:** one folded state per registry per process — S4 sizes it against the owner's targets.
- **`SnapshotState.load` is O(live window) per read once a prune exists**: the prune cutover IS wired (`sigil spine
  prune -K N --yes`), and on a pruned spine every `load` re-verifies the owner-signed head over the whole live window
  (`verify_checkpoint`) before it trusts the boundary. Memoize the verified boundary on the signed head (S1/S4 note).

### 4.3 S0d — DONE (kept for the record of what it covered)
Follow the S0a–S0c pattern exactly (shared step → seed → view → `_cached` via `fold_read.cached_read`; equivalence
test comparing the cached public API with flag-OFF after every randomized op; O(new) signature-count test; seeded
prune + pubkey bypass + same-boundary different-seed; flag-OFF-never-consulted; mutation-verify each index).
Remaining full folds (all call `_kh.key_resolver` + `SnapshotState.load`, all `iter_records`):
- money/billing: `governor/invoices.py`, `governor/cost_ledger.py` (EC-4/EC-5 — the global pool read on the
  launch path: red-pen hardest), `governor/postpaid.py`, `ui/margin.py` reads;
- identity/authz: `governor/accounts.py` (operator bearer resolve — every operator request),
  `governor/customer_credentials.py` (TOTP / passkeys — on login), `governor/promotion.py`, `governor/capability.py`,
  `governor/eval_capability_grant.py`, `governor/eval_offense_attestation.py`;
- AEGIS: `governor/monitoring_authority.py`, `governor/asset_ownership.py`;
- also scan-only reads: `metering.debited_entry` is done; check `ui/assessments.py`, `ui/server.py` direct scans.
Then the S0 closing items: (a) `sigil verify` / `vigil doctor` **rebuild-and-compare** every cached fold against
its full fold (report, never auto-heal); (b) **warm-up at process start** (cockpit + provisioner), off the request
path; (c) **sealed-anchor fast check** via the manifest boundary hash; (d) `HANDOFF` + design doc status.
⚠️ `doctor.py` is the highest-contention file — serialize edits.

### 4.4 S1 → S4
- **S1 — append-rate instrumentation (read-only).** Count appends/s by signal under production-shaped load. Only
  if the measured peak approaches ~900/s/process: tune group commit (C1a/C1b exist), then consider batch-signing
  (an invariant-touching change → its own owner review). Signed append path: `spine/store.py` (`append`,
  `append_many`, `_write_record_locked`, `spine_lock`).
- **S2a — `ShardAssignment{org_id → shard_id, epoch}`**: an owner-signed spine record (new domain tag in
  `packages/core/vigil_core/vigil_core/spine_domains.py`, signed in the Provisioner, verified keyless at the routing
  edge — mirror the lease / monitoring-authority records). Default: one shard = today, byte-identical.
- **S2b — routing**: the launch path reads the assignment (through the S0 cache) and publishes the lease to that
  shard's seam; missing/mismatched assignment ⇒ fail CLOSED. Edges: `integration/vigil_integration/uiproxy.py`
  (keyless, stdlib-only), `ui/custui.py`, `ui/provision.py`.
- **S2c — per-shard job queue + credit-lease seam**: each shard = worker processes on one host, one
  `CRUCIBLE_ROOT` per tenant (D2: `engine/crucible/framework/v2/common/tenant.py`, `assert_tenant_fleet_isolated`);
  `jobs/{queue,runner,launch_trigger,engage_worker}.py` under the shard's base dir; an org-A job on a shard that
  does not own org A is refused by `jobs/authorize._reconcile_tenant` (isolation only gets stronger).
- **S3 — online tenant migration**: reuse pause/resume — pause → drain (no new reservations; running jobs settle) →
  copy the tenant root + verify → append `ShardAssignment` epoch+1 → resume on the new shard. Reversible until the
  epoch bump; exactly-once by the `(slug, nonce)` settle idempotency; the sovereign spine is untouched. Ship with a
  **kill-mid-migration** test.
- **S4 — scale-acceptance gate (closing slice)**: harness driving N tenants × M concurrent engagements **to the
  owner's targets**, proving: no sovereign-spine fork; isolation during a live migration; EC-5 cap never breached;
  no paid job stranded by migration or node loss; exactly-once across the fleet. Production multi-shard stays
  flag-held until green; the **owner** flips it. The harness can be built before the targets exist; it cannot pass
  or fail without them.

---

## 5. REMAINING PROGRAM (agent), in order
0. **The pricing / metering / Red-Pen program (§10)** — the owner's latest direction. Merge #1076, then M1, then
   M1c-1, then §10.6 in order.
1. **Front C S1, S2a–c, S3, S4** (§4.4) — S0 is complete. Ask the owner for the S4 targets when S4 starts.
2. **Gate 5 — hands-on end-to-end** (personal, adversarial, with evidence; do not rely on per-slice red-pens):
   signup (`custui` → `provision.signup_request` / verify email) → buy credits (`billing_checkout` → Flutterwave
   **sandbox**, never a live secret) → webhook → `vigil billing-drain` credits the wallet → prove domain ownership
   (`target_verify`) → reserve + start a launch (`launch_reserve` / `launch_start`) → the job runs
   (`jobs/runner` → `engage_worker` → `engage`) → an oracle-confirmed FACT → settle (`completion_spool` →
   `LaunchGate.settle_launch`, refund `reserved − consumed`) → `vigil doctor` / `vigil ready` clean. Repeat with
   `VIGIL_FOLD_CACHE_ENABLED=1` and compare. Then the scale harness (S4) at the owner's targets.
3. **CodeQL second pass** (`docs/audit/CODEQL-TRIAGE.md` "Not yet triaged"): `py/path-injection` ×139 in the
   operator console / engine (`console/actions.py` 36, `sessions.py` 13, `oob_collaborator.py` 12,
   `vigil_core/highwater.py` 11, …; the 12 internet-facing sovereign sites are already verified guarded);
   `py/redos` ×3 + `py/polynomial-redos` ×7 on oracle regexes (keep the committed eval baselines byte-identical);
   `py/log-injection` ×7, `py/http-response-splitting` ×6 (medium).
4. **Dependabot** — after DEPS-1: rebase + merge the GitHub Actions bumps (#959, #960, #1038, #1039) if green;
   **#962** huggingface-hub 1.x → 2.2.0 as its own PR with a live `snapshot_download` check; recommend the owner
   close #1040 (superseded by DEPS-1), #963 / #964 (setuptools floors — the hash-locked backend decides), #988
   (Python 3.15 image — conflicts with the W1-7 locked-runtime pin).
5. **Housekeeping** — delete merged `claude/*` branches; remove scratch worktrees; keep this file current.

## 6. OWNER-ONLY (never the agent's)
- Provision the **live Flutterwave secret** and the webhook secret; DNS/TLS cutover (`vigilguard.net`, the
  marketing vhost).
- Flip `VIGIL_CUSTOMER_PROD_EXECUTION`; flip the multi-shard production flag after S4; decide
  `VIGIL_FOLD_CACHE_ENABLED` in production.
- **Money numbers:** the owner SET and DELEGATED the pricing numbers on 2026-11-11 (§10.2–§10.3); the agent
  builds them as env-overridable defaults. Still the owner's: any number NOT in
  `docs/decisions/PRICING-RED-PEN-DESIGN.md`, the **S4 scale targets**, and turning `VIGIL_METERED_BILLING` on.
- **Pricing go-live (§10):** the Anthropic API key in the sovereign secret store (`SIGIL_ANTHROPIC_API_KEY`), a
  dedicated Anthropic **workspace** for customer traffic with a monthly spend limit, Anthropic auto-reload with a
  cap, an Anthropic **admin key** for the daily reconciliation (O1), the calibration spend approval (M5),
  confirming the payment processor's fee schedule (an input to calibration, §10.2 open item c), **choosing the
  cancel-settlement policy** (§10.2 open item d — required before metered billing is enabled), registering the
  customer-facing GitHub App (Red-Pen), and the sub-processor disclosure (Anthropic, GDPR Art. 28) in the privacy
  policy.
- The **AWS KMS key** for evidence-DEK escrow + KEK (#70 tail).
- CodeQL: scope out the deliberately vulnerable benchmark fixtures (proposed `paths-ignore` lines in
  `docs/audit/CODEQL-TRIAGE.md`) and dismiss the by-design alerts with the recorded rationale.
- Close the superseded/declined Dependabot PRs (or tell the agent to).

## 7. DEFINITION OF 100% — the closing gates
1. ✅ Pause/resume chain (PR-1..PR-5) — complete behind its flag.
2. ✅ Front A — #73 network recovery + deploy maturity, #70 backups everywhere (incl. #70c), #69 money gate (+
   MONEY-5). **Open:** evidence-DEK KMS escrow live path — **owner-blocked** on a real KMS key.
3. ✅ Front B surface — billing drain unit, hosted checkout, buy-credits UI + return page, hop budget, alert
   delivery proof; `sigil serve-customer` (`apps/sigil/sigil/cli.py::cmd_serve_customer`) and the customer /
   public vhosts (`apps/sigil/deploy/reverse-proxy/vigil-{customer,public}.{nginx.conf,Caddyfile}`,
   `apps/sigil/deploy/REMOTE-HOSTING.md`) exist — going live needs the owner's DNS/TLS.
4. ⏳ **1M scaling** — design ✅ authorised; S0 (S0a–S0d) ✅ merged; **S1, S2a–c, S3, S4 to build**; S4 needs
   the owner's targets. This is the main remaining distance.
5. ⏳ **Gate 5** — the personal hands-on end-to-end + at-scale verification, with evidence (§5 item 2).
6. **[owner]** the held flips and numbers (§6).

Honest status: the customer-SaaS product, the money loop (in and out), offense breadth, production hardening,
backups and the deploy substrate are **built and merged**; everything new is default-OFF and fail-closed, so
`main` is always safe and shippable at single-node. The distance to "1,000,000 users" is Front C S1 → S4 plus
Gate 5 and the owner's flips.

## 8. KEY ANCHORS (quick map)
- **Signed spine:** `apps/sigil/sigil/spine/store.py` (`append`, `append_many`, `iter_records(since_seq)` seeks
  O(returned), `get(seq)` O(1) via the segment index, `change_token()`, `rotate`/`compact`), `spine/snapshot.py`
  (`SnapshotState.load`, `build`), `spine/prune.py`, `spine/upgrade.py`, `vigil_core/{canonical,chain}.py`.
- **Fold cache:** `spine/fold_cache.py`, `governor/fold_read.py`, `governor/key_history.py`
  (`key_resolver`, `key_resolver_with_horizon`, `rotate`, `re_genesis`).
- **Registries:** `governor/{customers,orgs,wallet,metering,subscription,monitoring_subscription,invoices,
  cost_ledger,postpaid,accounts,customer_credentials,catalog}.py`.
- **Money seam:** `integration/vigil_integration/live/{credit_lease_broker,credit_lease_pause}.py`,
  `ui/launch_gate.py` (reserve / publish / settle / pause), `inbound/{billing_spool,completion_spool}.py`.
- **Customer edge:** `ui/custui.py` (routes, `_SLOW_HOP_TIMEOUTS_S`) → loopback hop → `ui/server.py` dispatch →
  `ui/provision.py` (the only owner-key holder); customer app `ui/customer_app/`.
- **Jobs / offense:** `integration/vigil_integration/jobs/{queue,runner,authorize,launch_trigger,engage_worker}.py`;
  `engine/crucible/framework/v2/{launch_lease,engage}.py`, `common/{paths,tenant}.py`.
- **Hosting:** `sigil serve-customer` (`apps/sigil/sigil/cli.py`), `apps/sigil/deploy/{REMOTE-HOSTING.md,
  customer.env.example,systemd/sigil-public.service,reverse-proxy/*}`.
- **Ops:** `integration/vigil_integration/{doctor,backup,unit_alerts,cli}.py`; `infra/systemd/*`;
  `docs/runbooks/AWS-DEPLOY.md`; `docs/CLI-REFERENCE.md`; `docs/SUPPLY-CHAIN.md`; `docs/audit/CODEQL-TRIAGE.md`.
- **CI:** `.github/workflows/ci.yml` (offense-leg run-list!), `.github/workflows/security-scan.yml` (CodeQL Python
  + JavaScript), `.github/required-status-checks.txt`, `tools/governance/mypy_ratchet.sh`.

## 9. RE-CREATING THE SESSION-LOCAL TOOLING (the scratchpad does not survive)
- **CodeQL CLI 2.27.4** (matches CI): download the `codeql-bundle-linux64` release for 2.27.4, then
  `codeql database create db-py --language=python --source-root .` (same for `javascript`) and
  `codeql database analyze db-py codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest
  --output=py.sarif`; filter results with the workflow's `paths-ignore` to match CI scope.
- **pip-tools 7.6.1** in a throwaway venv for lock regeneration (§0.7).
- **Fold benchmark** (reproduces §4.1/§4.2 numbers): create N customers with `CustomerRegistry(store,
  owner_key=k, trusted_pubkey=k.public_key_b64).create(f"user{i}@example.com", issued_at=100.0+i)`, then time
  `by_email` with `VIGIL_FOLD_CACHE_ENABLED` unset vs `=1` (call it once first: the first point read builds the
  store's offset index).

---

## 10. PRICING, METERING & RED-PEN — the owner's 2026-11-11 program (IN FLIGHT — start here)

### 10.1 Where the work is
| What | Where | State |
|---|---|---|
| Design + every decision, risk and source | `docs/decisions/PRICING-RED-PEN-DESIGN.md` (on `main` with M1) | final for M1; its §4.5 budgets are pre-calibration proposals |
| **M1** — metering core + sovereign model gateway | on `main` (its own PR) | three adversarial review rounds folded; mutation-verified |
| **M1c-1** — sovereign wiring | its own PR after M1 | see §10.5 |
| M1c-2 … A1 | — | §10.6 |

### 10.2 The owner's decisions (2026-11-11; verbatim intent)
- **Credits:** 100 credits per $1 (1 credit = $0.01 at list). **Minimum purchase $5.** Six packs **$5 / $10 / $16 /
  $25 / $50 / $100 → 500 / 1,000 / 1,600 / 2,500 / 5,000 / 10,000 credits, no volume bonus.** Custom amounts =
  whole dollars × 100 with a maximum. Unused credits are kept and never expire.
- **One model only: Claude Opus 4.8 (`claude-opus-4-8`).** Depth → effort: **Quick = high, Deep = xhigh ("extra"),
  Max = max.** **"Ultracode"** (a Claude Code setting that orchestrates multi-agent dynamic workflows) **is the Max
  tier** — used for fixing code AND for deep work on live systems.
- **Customer-facing name: "VIGIL"** (the owner changed it from "VIGIL Agent"). Never name the model to a customer.
- **One VIGIL Anthropic API key.** VIGIL buys the tokens; every tenant's runs draw on that key; **each tenant sees only
  their own bill**, in credits.
- **Tenants must get the work they paid for.**
- **Not everyone tests code**: some customers test live deployed systems, some code, some both. **Not everyone wants
  fixes**: some only want to know their vulnerabilities — Fix is opt-in.
- **Red-Pen** — the owner's "reopen" = this repo's red-pen reviewer (`engine/crucible/.claude/agents/red-pen.md` +
  the dual-review merge bar) — becomes a customer product for PRs and whole systems, finding more vulnerabilities
  and (optionally) fixing them.
- Launch with PAYG credits + per-host AEGIS subscriptions + quoted enterprise contracts; discounted credit
  subscriptions only after costs are measured.
- **Delegation:** "I will leave you to carry out research and answer all the other questions for me; remember we need
  perfection." Every number below is the agent's researched answer, built as an env-overridable default —
  **a proposal, NOT an owner decision** (see the open list below).
- **Owner input since this handoff was first written (2026-11-11, coordinating session):**
  - *Confirmed:* $1 = 100 credits; packs $5 / $10 / $16 / $25 / $50 / $100 → 500 / 1,000 / 1,600 / 2,500 / 5,000 /
    10,000; custom amounts from $5 at dollars × 100; one conversion rate, no volume bonus; unused purchased credits
    are retained.
  - *In the owner's words:* "price scan consumption according to actual operating cost. This is a proposed pricing
    model, not yet a validated profitable rate." Costs to count: AI usage, scan workers, storage, payment processing.
    A credit must not promise a fixed number of raw tokens; deeper scans and more expensive models consume more.
  - *Margin (decided later the same day):* every scan is priced at an **owner-set target margin over its direct
    cost, recorded privately** (outside this public repo), applied via `VIGIL_BILLING_TARGET_MARGIN` at deploy
    (`credits = metered AI cost / (1 − m) × 100`, `0 < m < 1`, **no committed default**: unset ⇒ metered pricing off).
    **Never write the margin value, a markup-to-margin breakdown or any value-based analysis into this repo or a
    commit message.** Doctor must flag metered billing without it (M1c-1). *(2026-11-13, one pricing number:)* `m`
    is the margin over **metered AI cost only** (fees and hosting are outside it) and is the only pricing input; the
    margin dashboard's target line is `cost / (1 − m)`, and `VIGIL_BILLING_MARKUP_K` / `VIGIL_MARGIN_MULTIPLIER_K` are
    refused while present (doctor hard issue; metered launches refuse, metered charges wait).
  - *Seats:* $25 per seat (assume per month; whether a seat includes credits is open) — a public price, may go in
    the catalog (M3).
  - *Free trial:* a real scan with partial results, the full report unlocked once the org buys credits (any pack from
    $5); one trial per verified email AND per verified domain; ownership proof still required. The coordinator is
    designing the unlock (preview rules, leak inventory, unlock record, abuse controls) and the seat SKU — **do not
    start the trial unlock before that spec arrives.**
  - *Audience:* young startups first; no minimums; packs from $5.
  - *Customer experience:* credits shown immediately when an amount is entered; before a scan the estimated
    consumption and a customer-set maximum credit budget; during the scan consumption and remaining budget; at
    completion charge metered usage and release unused reserved credits; optional auto top-up with a spending cap.
  - *Launch offer:* PAYG credits, separate per-host AEGIS monitoring subscriptions, quoted enterprise / on-premise
    contracts; discounted credit subscriptions only after real scan costs are measured.
- **OPEN OWNER DECISIONS — do not ratify any of them** (design doc §1.2):
  (a) the §10.3 numbers (the 25-credit floor, tier budgets 450 / 5,000 / 20,000, top-up limits, concurrency
  4 / 32) are proposed defaults only; (b) the target margin (over metered AI cost; the only pricing input) is set at
  deploy from the owner's private record; (c) the formula meters AI cost only, while the owner's profit target is
  measured after all costs — M5 must report the measured fee and hosting fraction per run so the target margin can
  be set to land the all-in margin on the target; (d)
  **cancellation** (charge a cancelled run for usage vs. today's full refund) is unanswered — it must be a named
  setting, and `vigil doctor` + the go-live notes must say it has to be chosen before metered billing is enabled.
- **This repository is public.** Keep business-sensitive detail (margin rationale, cost structure beyond what a
  default needs to be understood, market or competitor analysis, undecided product ideas) out of committed docs.
### 10.3 The numbers (design §4) — all env-overridable, all PROPOSED (not owner-confirmed; §10.2 open list)
`charge_credits = min(reservation, max(FLOOR, ceil(cost_usd / (1 − target_margin) × 100)))`, where `cost_usd` comes ONLY from the
sovereign gateway's meter.

| Setting | Value | Why / env |
|---|---|---|
| Target margin | **owner-set, private** — no committed default; the margin over metered AI cost only | `VIGIL_BILLING_TARGET_MARGIN`: an exact decimal strictly between 0 and 1, at most 0.99; the markup is derived as 1/(1−m); the only pricing input; no default, so metered paths fail closed while it is unset |
| Floor per run | **25 credits** ($0.25, worker start-up) | `VIGIL_RUN_FLOOR_CREDITS` |
| Price table | Opus 4.8 per MTok: input $5, output $25, cache read $0.50, 5-min write $6.25, 1-h write $10; web search $10 / 1,000 | `VIGIL_MODEL_PRICES` (inline JSON; integer nano-USD; finer than $0.001/MTok is refused) |
| Custom top-up | **$5–$500** per purchase; first purchase ≤ $100 until ≥ $100 settled and ≥ 7 days; ≤ $1,000 / 24 h; ≤ 5 attempts / h; > $500 → invoice | Anthropic's own Tier-1 credit-purchase cap is $500 (M3) |
| Outcomes | completed = metered; **canceled = OPEN OWNER DECISION** — proposed: metered (today a cancel is a full refund — a run cancelled at 95% is free); budget reached = metered (= reservation) + findings delivered + "continue" (resume); **failed on VIGIL's side = 0 + one auto-retry** | `completion_spool._consumed_for` |
| Default budgets (pre-calibration) | Quick **450** (so the $5 pack always buys one), Deep 5,000, Max 20,000, Red-Pen · PR 300 per PR + a monthly cap per repo, Fix 2,000 per finding, Retest 200 per finding | M3 / M5 |
| Fairness | free **preflight** before any reservation; **10% report reserve** (stop testing at 90%, write the report); continue = resume, never restart; only proven findings; an honest coverage map | design §3 (M2 / M4) |
| Account protection | tenant concurrency **4**, global **32**, daily ceiling (unset = none) + an Anthropic workspace spend limit (owner) + daily Admin-API reconciliation | `VIGIL_GATEWAY_*` (§3) |
| Typical prices | from calibration (M5); a budget is only the cap | design §4.5 |

**Two pre-existing defects the program replaces** (do not enable money paths until they are gone):
`vigil_core/credit_lease.ENVELOPE_TOKENS_PER_CREDIT = 100_000` (sells 1M tokens for $0.10 vs ~$2 cost) and
`vendor/strix/strix/report/anthropic_pricing.py` (matches `claude-opus-4-8` to the Opus 4 row $15/$75 = 3× the real
price, so Strix budget caps stop a run at a third of what was paid for).

### 10.4 What M1 built — the architecture
**Why a gateway.** The settle signal deliberately carries NO amount (`vigil_core/engagement_completion.py`): the
keyless offense plane must never set a charge. So metering is sovereign: every model request of a customer run goes
through **`apps/sigil/sigil/model_gateway.py`**, a loopback Anthropic Messages API reverse proxy that holds the ONE
provider key. The offense plane only ever holds a per-run **model grant**.

- **`packages/core/vigil_core/vigil_core/model_metering.py`** — `Usage` (input, output, cache read, 5-min / 1-h
  cache writes, web searches); `usage_from_api` (JSON body) and `StreamMeter` (SSE: `message_delta` counts are
  CUMULATIVE — replace, never add); `PriceRow` / `DEFAULT_PRICES` / `price_table(env)`; `cost_nano_usd` (an
  unpriced model RAISES); `billing_markup` (exact `Fraction`); `run_floor_credits`; `credits_for_cost(cost, markup,
  floor, cap)`; `usd_cap_nano_for_credits(credits, markup)` (the most spend whose charge fits the reservation);
  `format_usd`. Integer nano-USD everywhere; every malformed input raises `MeteringError` (fail closed).
- **`packages/core/vigil_core/vigil_core/model_grant.py`** — owner-signed `ModelGrant{grant_id (128-bit), org_id,
  engagement_slug, nonce, model, effort ∈ {high, xhigh, max}, cap_nano_usd, not_after, issued_at}`; token
  `vmg1.<b64url canonical JSON>.<b64url Ed25519 sig>` over the NEW domain tag `model-grant`
  (`spine_domains.DOMAIN_TAGS`); `decode_token` is total (bad prefix / base64 / length / signature / schema /
  non-canonical body → `(None, reason)`); `meter_id(slug, nonce)` = 32 hex of sha256 — ONE meter per launch, so a
  re-minted grant cannot reset a run's budget and one tenant's spend cannot land on another launch.
- **`apps/sigil/sigil/model_gateway.py`** (as merged, after TWO adversarial rounds — 29 + 23 verified findings, plus
  a parallel 7-lens review, folded; the PR body lists them). The runner is treated as hostile (a scan target can
  prompt-inject it):
  - Endpoints: `POST /v1/messages`; `POST /v1/messages/count_tokens` (free, validated like a message, its own
    concurrency bound, refused for a settled run); `GET /v1/vigil/budget` (cap / spent / pending / remaining /
    `fraction_used` (spent + in flight) / `fraction_spent` (spent only — drives the 90% wrap-up) / closed; an
    expired grant may still read it). Anything else → 404.
  - Auth: the grant in `x-api-key` or `Authorization: Bearer`; bad → 401; expired, settled or an unpriced model →
    403. The provider key is added upstream: https only (http to loopback), **no redirect is ever followed**, key
    with a non-header character refused at start, `repr` hides it.
  - **Allowlist, not denylist.** Top-level fields: `model messages system max_tokens tools tool_choice stream
    stop_sequences metadata thinking output_config cache_control context_management service_tier`; sampling /
    `speed` / `inference_geo` dropped; anything else → 400 by name. Tools: untyped / `custom` / `bash_*` /
    `text_editor_*` by EXACT type (`bash_20250124`, `text_editor_20250124|20250429|20250728`) — every
    server-executed tool (web search / fetch, code execution, advisor, MCP, tool search), computer use, memory and
    any tool with a `model` key → 400. Content blocks: an allowlist (`text image document tool_use tool_result
    thinking redacted_thinking search_result`), checked inside tool results / search results / inline documents;
    images base64 only; documents inline text only; messages carry only `role` + `content`; system = text blocks.
    `context_management`: `clear_*` edits only. Betas: a prefix allowlist, others DROPPED. Query string: only
    `beta=true` is forwarded. **A run cannot use Anthropic web search through the gateway.**
  - Pinning: `output_config.effort` = the grant's; thinking adaptive (dropped under a forced `tool_choice`);
    `service_tier = standard_only`; `inference_geo = global` (the dedicated workspace must allow global inference);
    every `cache_control.ttl` removed (5-minute writes only); no `cache_control` on a tool; a per-tenant text block
    is PREPENDED to `system` (no cross-tenant prompt-cache hits).
  - Budget: the request's worst case is reserved BEFORE forwarding — input (`body bytes + 6,000 per image +
    the Anthropic tool allowances (bash 400, text editor 1,100, +500 preamble) + 1,000` tokens; when that does not
    fit the headroom, the provider's `count_tokens` × 1.05 + 1,000) priced at `max(input, 5m-write)` EXCEPT the
    prompt-cache prefix this launch wrote/read < 270 s ago that the request re-sends unchanged (same tools, system
    and every earlier message, and a cache marker present), which is priced at the cache-read rate; plus output
    (`max_tokens × output price`, `max_tokens` lowered to fit). < 1,024 affordable output tokens of real budget →
    403 "budget is reached"; affordable but held by requests in flight → wait up to `concurrency_wait_s`, then 429
    `retry-after: 5`; the count could not be had and the budget is not spent → 529 retryable.
  - Meter file `$SIGIL_HOME/model_meter/<meter_id>.jsonl` (0600 in 0700; `n` = line number, `h = sha256(prev +
    canonical(line))`). Kinds: `open` (WRITE-AHEAD, fsynced before the request is sent: `rid`, `reserved`,
    `grant_id`), `usage` (`cost_nano`; `held_nano` when cut off), `release`, `orphan`, `close` (always last). A torn
    final line is repaired on the next append. Writes are all-or-nothing.
  - **Confirmed vs unconfirmed spend.** `MeterTotals.cost_nano` = usage Anthropic reported (what the customer's
    charge is computed from). `unconfirmed_nano` = orphans (a crash between the call and its record), the unreported
    rest of a cut-off stream's reservation, a request sent but never answered: counted against the cap and the
    daily ceiling, NEVER billed. An unreadable 200 (or one reporting `usage.iterations` / an unpriced server tool /
    priority tier / fast mode) is charged its reservation.
  - **Close protocol.** `GrantMeter(dir).close(mid)` (the settle step): writes `<mid>.closed` first (admission
    stops, re-checked by the gateway under the file lock), then raises **`MeterBusy`** while the LIVE gateway has an
    `open` of that launch in flight (each `open` carries its gateway process's boot id, written into
    `.gateway.lock`) — the settle must RETRY; opens written by any other (dead) process are recorded as orphans.
    One gateway per meter dir (`.gateway.lock`, an exclusive flock held for the process lifetime, released in a
    forked child; a second gateway refuses to start; the settle probes with a shared lock). A starting gateway
    orphans every dead leftover in the directory. `server.server_close()` cuts connections that have not started a
    request, refuses any that starts after it (529), waits up to `shutdown_drain_s` for the requests in flight and for
    every owed record to be written, then releases the lock (it keeps it, and keeps retrying the records, if either
    is still pending). A stopped meter admits nothing. A forked child closes every meter lock file it inherited.
  - Failure handling: meter unreadable / unwritable before the call → 529, nothing forwarded; a record that fails
    AFTER the call → spend counted in memory at ≥ the reservation, the record kept and retried every 5 s
    (`flush_unwritten`), the launch refused and its settle `MeterBusy` until it is written.
  - Account protection: per-tenant and global slots taken BEFORE the body is read; request bytes in memory bounded
    per tenant (`tenant_body_bytes`, 32 MiB) and overall (`global_body_bytes`, 128 MiB) → 429; `max_connections`
    (256), and when full the oldest connection that has not started a request is cut; `header_deadline_s` (5 s) for
    the request line and headers; `client_timeout_s` (60 s) on every client socket — a stalled reader is treated as
    gone and the upstream is still drained and metered; daily ceiling (day's confirmed + unconfirmed spend +
    pending) → 529.
  - Cached-prefix reservation: the read rate applies only with the same render state (every other request field,
    the forwarded betas, the image count), the unchanged prefix, a breakpoint within 20 blocks of where the entry was
    written, no `context_management` edits, and within 300 s less the worst admission delay (count + budget wait)
    less 10 s. Cache markers are rebuilt as exactly `{"type": "ephemeral"}`; citations are refused.
  - Known limits (documented, accepted): a file cut at a line boundary or deleted is not detectable from the chain
    alone (the `close` line + the owner-signed settle anchor a finished run); the cap is per grant token, not per
    launch (M1c mints one cap per launch); `_states` / tenant semaphores / cached-prefix memory are never evicted;
    concurrency does not bound input tokens per minute; a cache read the provider does not make (early eviction,
    an unmodelled rule) or a provider count below the real bill passes the cap by that difference (VIGIL's cost);
    the startup sweep reads every meter file (fine until Front C scale). A grant lives at most 7 days + 1 h and is refused if issued > 5 min in the future.
  - **For M1c-2 (runner configuration the gateway requires)** — Claude Code: point `ANTHROPIC_BASE_URL` at the
    gateway, pass the grant as `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`), set `ANTHROPIC_MODEL`,
    `ANTHROPIC_DEFAULT_HAIKU_MODEL` / `ANTHROPIC_SMALL_FAST_MODEL` (background requests) and the subagent model to
    the grant's model (any other model → 400), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`,
    `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` (a dropped beta whose fields are still sent → provider 400), and deny
    the WebSearch / WebFetch tools. Requests with `context_management` edits get no cache-read reservation, so a run
    that uses them reaches its cap sooner (it is still charged only what it spent). Strix (LiteLLM `anthropic/…`): no server tools; capture one real request in a
    test and confirm the gateway accepts its shape (fields, tool types, thinking blocks echoed back).
- `vigil_core.model_metering`: also refuses a `usage` with unpriced spend (`iterations` beyond one `message`,
  unpriced `server_tool_use` counters, `service_tier: priority`, `speed: fast`), a zero input / output / cache-write
  price, and a stream whose cache-write total goes down; a bare cache-write total never re-prices the TTL split.
- `vigil_core.model_grant`: canonical base64url only (one grant = one token string); no control characters in
  `engagement_slug` / `nonce`; `not_after > issued_at`.
- Tests: `packages/core/vigil_core/tests/test_model_metering.py`, `test_model_grant.py`,
  `apps/sigil/tests/test_model_gateway.py` (against fake upstreams). The mutation list is in the M1 PR body.

### 10.5 M1c-1 — sovereign wiring (what it does, its interim limits)
All behind `VIGIL_METERED_BILLING` / `VIGIL_MODEL_GATEWAY_ENABLED`, default OFF; with both off nothing changes.
- `sigil/config.py`: `MODEL_METER_DIR`, `metered_billing_enabled`, `model_gateway_enabled/_port/_url`, `run_model`.
- `model_gateway.config_from_env` + `start_from_env` (once per process + port; never raises — any failure is logged
  and the cockpit carries on, metered runs then fail closed; refuses without the owner public key; concurrency settings
  are digits only); `ui/server.py::serve` starts it.
- `ui/launch_gate.py::publish_lease` → `_publish_model_grant`: mints the owner-signed grant from the VERIFIED lease
  (cap = `usd_cap_nano_for_credits(units, markup)`, effort = `run_tier.effort_for(run_tier_for_units(units))`,
  validity = the lease's `not_before`…`not_after`, id derived from (slug, nonce) — re-publishing mints the identical
  grant) and writes it BEFORE the lease, after a per-launch **metered marker** (`MODEL_METER_DIR/<meter_id>.metered`)
  that fixes the launch's billing mode. A pricing setting the core refuses — no target margin, an unrecognised cancel policy, a
  run model (`VIGIL_RUN_MODEL`) with no price — refuses the publish (no lease, no grant); a failed lease write removes
  only a grant that call created (a failed re-publish never removes a live run's grant). The grant is valid from the
  lease's start for the longest grant lifetime (`MAX_GRANT_LIFETIME_S`, past the at-most-a-week lease window), so a
  run armed late in its window, or resumed after it, keeps its model access; the settle closes the meter, after
  which the grant spends nothing.
- **One launch per org+host in flight while metering is involved:** `publish_lease` refuses a new launch while an
  earlier, unsettled one holds the seam's single per-slug lease, when either is metered (a replaced lease would leave
  the earlier run unable to settle, and a customer cancel would read it as never started). Flat-to-flat is unchanged
  (that root cause predates metering; reported). Where metering is involved the check, the grant and the lease
  write run under one per-org+host `flock` (`MODEL_METER_DIR/publish-<hash>.lock`, across threads and the cockpit and
  customer servers), so two concurrent publishes cannot both pass; a flat-only publish takes no lock and writes no
  file.
- `ui/launch_gate.py::settle_launch`: EVERY settle (completion, customer cancel, abandoned-lease sweep) of a launch
  published metered (its marker or meter on disk) first closes the run's meter, so a settled lease can spend nothing
  more, and retires the grant. A request still in flight or a meter not writable right now refuses with `retry`
  (the completion drain defers it); a broken meter refuses without it (quarantined).
- `integration/vigil_integration/live/model_grant_broker.py`: `<base>/model-grants/<slug>.json` (0600 in 0700,
  atomic, nonce-bound via `expect_nonce`, loopback-URL-only, never follows a symlink, never prints the token).
- **The billing mode is the launch's, never the flag's at settle time:** it is decided ONCE, at the launch's first
  publish. A launch published flat settles flat — and a re-publish of it (a double-click after the owner turns
  metering on) stays flat — and one published metered settles metered whatever `VIGIL_METERED_BILLING` says later. So turning metering OFF does not
  change how already-published metered launches settle: keep the target margin and any cancel policy set (in the
  settle drain's environment too) until they have all settled, or their settles defer.
- `inbound/completion_spool.py::_consumed_for`: metered launch → close the meter, then completed = metered (clamped to
  [floor, reservation]); canceled = `VIGIL_BILLING_CANCEL_SETTLEMENT` (`metered` | `refund`; unset = `metered`); failed
  = 0, except a launch the customer held paused through the end of its window (the pause lifted only after it closed,
  so the window refuses its re-drive): charged what it used, like a paused, abandoned launch. Only confirmed spend is
  billed. A request in flight, a transient meter error or an unset pricing setting
  DEFERS the settle (back to `incoming/`, reported as `deferred`); a broken meter is quarantined. A wait on the
  pricing configuration never clears by retrying, so it is also reported as `deferred_config` and `vigil settle-drain`
  exits 1 (the unit FAILS, the dead-man alarms) until it is fixed — set the pricing settings in the drain's own
  environment (`infra/systemd/vigil-settle-drain.env.example`).
- `ops_sweeps.sweep_abandoned_reservations` (owner decision 2026-11-13: a scan paused and never resumed is charged
  for what it used): an abandoned launch published metered that the CUSTOMER paused (a cleanly-read pause marker holds
  its nonce) is charged its confirmed metered use, clamped to [floor, reservation] (`charged_paused`); one NOT paused
  was lost on VIGIL's side and is refunded in full; one whose pause state cannot be read is not settled
  (`pause_unknown`); a flat launch has no meter and is refunded. A paused launch that made no model request and has no
  confirmed spend (it may never have started) is refunded: the floor covers a run's start-up. Lifting a pause after
  the window closed re-admits nothing, so `LaunchGate.resume_launch` first records it
  (`credit_lease_pause.record_paused_past_expiry`, add-only; an unreadable record refuses the resume) and the sweep
  and the drain still charge that launch for what it used. Every metered row reports the meter's confirmed spend
  (`metered_cost_nano`, `metered_requests`).
- `vigil_core/run_tier.effort_for` (quick → high, deep → xhigh; unknown → high, never an escalation).
- `backup.py`: `model_meter` captured (money data), restored functionally (`GrantMeter.verify` totals).
- `integration/vigil_integration/doctor.py::_metering_report` — HARD issues (each blocks metered bring-up): metered
  without the gateway (no run can reach a model); gateway without a provider key (it will not start); gateway not
  answering, or something else answering on its port, while metered (runs fail); a pricing value the core refuses
  (floor, price table, an unpriced run model, gateway limits); with metered billing, no target margin (launches and
  charges refuse) and an unrecognised cancel policy (launches refuse, cancelled-run settles defer; unset = metered).
  Notes: no daily ceiling; the
  gateway down or replaced while billing is flat. The flags read `1/true/yes/on/enabled` exactly as the runtime does.
  The margin value is never printed. Nothing is rendered when neither flag is set. Doctor reads the environment the
  cockpit reads: its own, with `$SIGIL_HOME/sigil.env` layered under it (where the settings UI saves the provider
  key), exactly as `sigil.config` does. A probe that breaks never hides the issues already found. A retired pricing
  setting (`VIGIL_BILLING_MARKUP_K` / `VIGIL_MARGIN_MULTIPLIER_K`) is a hard issue even with both flags off.

**Interim limits (until later slices):**
- **`VIGIL_METERED_BILLING` must NOT be enabled before M3**: today's launch products reserve 3 / 20 units (the
  pre-metering placeholders), so metered caps would be a fraction of a dollar and runs would stop at once.
- The effort is derived from the units band until M3 puts an explicit tier in the owner-signed lease.
- The offense plane does not yet route its model calls through the gateway (M1c-2).

### 10.6 Remaining slices, in order (design §9)
| Slice | What, with anchors |
|---|---|
| **M1c-2 — offense wiring** | (1) `integration/vigil_integration/jobs/engage_worker.py`: read `model_grant_broker.read_model_grant(base, slug, expect_nonce=nonce)`; metered + no grant ⇒ refuse the run (fail closed); scope the run's env the way `_model_routing_scope` does (the worker runs one job at a time): `ANTHROPIC_BASE_URL` = gateway, `ANTHROPIC_API_KEY` = token for in-process engine calls; `LLM_API_BASE` / `LLM_API_KEY` / `STRIX_LLM=anthropic/claude-opus-4-8` for Strix children; restore after. (2) `engine/crucible/framework/v2/kernel/backends/anthropic.py::_client_obj` caches its client and `common/live_keys.refresh_live_anthropic_key()` HOT-RELOADS the persisted key into the env — in metered mode that would replace the token: give an explicit grant env (e.g. `VIGIL_MODEL_GRANT`) precedence and key the cache on it; same for `live/think_claude.py::_resolve_key` / `_build_live_client` (pass `base_url`). (3) **EC-2a model routing must be OFF when metered** (it routes "quick" bindings to cheaper models, which the gateway refuses): `vigil_core/run_tier.routing_enabled_for` + `engage_worker._model_routing_scope`. (4) Fix `vendor/strix/strix/report/anthropic_pricing.py`: rows for `claude-opus-4-5`…`4-8` at $5 / $25 / $0.50 / $6.25. (5) A wire test that `output_config.effort` reaches the API as the grant's effort. (6) Doctor note: in metered mode the offense plane must hold no provider key. |
| **M3 — catalog** | the six packs + custom top-ups ($5–$500 with the §10.3 limits) in `governor/catalog.py` (+ the checkout path `provision.billing_checkout`, amounts always from the catalog); re-budget the launch products (Quick 450 / Deep 5,000 / **Max 20,000** at effort max); an explicit, owner-signed run tier in the lease; retire `ENVELOPE_TOKENS_PER_CREDIT` from the money path. |
| **M2 — engine** | the 90% report-reserve wrap-up (poll `GET /v1/vigil/budget`); continue = resume (Strix `--resume`); runtime caps from the grant as a second line (Strix `max_budget_usd`, Claude Code `--max-budget-usd` — counts subagents, but is a client-side estimate); `max` through Strix. |
| **M4 — customer UX** | the "VIGIL" naming sweep + a test that no model id ever reaches a customer-rendered payload (today `ui/settings.py` and `engine/crucible/framework/v2/console/chat.py` list "Claude Opus 4.8" labels — owner/operator surfaces, keep them there); target / depth / outcome choice; preflight; estimate + budget + live meter; the tenant statement (credits only). |
| **M5 — calibration** | run each tier N times (loopback range + CRUCIBLE corpus), record the gateway meters, publish p10/p50/p90 as estimates and p90 as default budgets. **Needs the owner's API key + a spend approval.** |
| **L1 — live Max** | one rate limit + connection cap per ENGAGEMENT at the scope-gated egress proxy (`gateway/vigil_gateway`), however many agents run (default 10 req/s, 8 connections; charter-tunable); Max agents on VIGIL's governed tools only (no raw shell / network); run-level hard stops (5xx storm / latency → throttle → pause; prior compromise → incident response); stable egress IP + VIGIL User-Agent; kill switch. |
| **R1 — Red-Pen engine** | design §7.2: map → attack (≈12 lenses) → refute-each with a sandbox REPRODUCTION (fails twice on the reviewed commit) → certify via `oracle_adapter.confirm_and_certify(..., provenance="reproduced")` (FACT) → everything else stays a LEAD. Runs as Claude Code dynamic workflows headless through the Agent SDK, on the gateway (`ANTHROPIC_BASE_URL`), inside the S5 sandbox, no network but the gateway, no secrets. |
| **R2 — Red-Pen · PR** | through the existing PR bot (`jobs/pr_bot.py`: diff scan → oracle-verified findings → gated `post_review_comment` → gated fix-PR leg), PR-head checkout `live/pr_checkout.py`; comments marked 🔴 Critical/High (blocking) / 🟠 Medium / 🟡 Low with the reproduction command + evidence ref + a **Fix this** action; LEADs only in the dashboard. |
| **R3 — Red-Pen · System** | the whole repository, on demand or scheduled. |
| **R4 — VIGIL Fix + Retest** | opt-in only: Claude Code `--effort max --settings '{"ultracode": true}'` in the sandbox clone (`live/codefix_runner.py` is the existing remediation runner; its OPEN-PR leg is disabled until LAP-3); re-review (reproduction passes, full suite passes, a Quick Red-Pen of the patch finds no new FACT) → the gated fix PR with the customer's approval; "remediated" only when the reproduction / oracle goes silent. Retest = re-run the proof of each finding the customer says they fixed. Live targets: remediation guidance + Retest + AEGIS virtual patch, never code changes. |
| **R5 — UI** | Red-Pen, Fix, Retest in the customer app. |
| **O1 — owner money view** | per-tenant revenue / gateway AI cost / margin (the EC-6 margin view in `ui/margin.py` still uses the placeholder per-token rate); the daily reconciliation against Anthropic's Usage & Cost Admin API (owner's admin key). |
| **A1 — auto top-up** | off by default; trigger balance + pack + monthly cap; tokenised card; never above the cap; a receipt per charge. |

### 10.7 Research facts the design rests on (verify before relying; sources in the design doc §10)
- **Claude Opus 4.8** `claude-opus-4-8`: $5 / $25 per MTok; cache read ~0.1×, 5-min write 1.25×, 1-h write 2×; Batch
  50% (not for interactive runs); fast mode is a research preview **removed 2026-11-30**; effort `low…max`; adaptive
  thinking must be explicit (`budget_tokens` → 400); sampling parameters rejected; 1M context, 128K output.
- **Opus 5 / 5.5**: same price / 20% cheaper and stronger, but with **elevated cybersecurity safeguards** that can
  refuse security work — the reason to stay on 4.8 until an eval (refusal rate + finding yield on the CRUCIBLE
  corpus) says otherwise.
- **Ultracode** (Claude Code): a SETTING, not an effort level — Claude orchestrates dynamic workflows. `--effort
  ultracode` = ultracode at **xhigh**; for Max use `--effort max --settings '{"ultracode": true}'` (Claude Code ≥
  v2.1.284 keeps ultracode on at levels other than xhigh). The `ultracode` keyword in a `-p` prompt does NOT start a
  workflow. Headless runs need the `Workflow` tool allowed by a permission rule. Workflow limits: 16 concurrent agents
  by default (`CLAUDE_CODE_WORKFLOW_MAX_CONCURRENT_AGENTS`), 1,000 agents per run, `workflowSizeGuideline`.
- **Claude Code CLI**: `--max-budget-usd` counts subagent spend but is a client-side estimate and can be overshot
  (the gateway is the binding cap); `ANTHROPIC_BASE_URL` points it at the gateway — also set the default and
  small/fast model env vars to `claude-opus-4-8` (the gateway refuses other models) and
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.
- **Agent SDK terms**: a product for customers must use **API-key auth** (no claude.ai login / subscription limits);
  keep VIGIL's own branding — never "Claude Code" (or "ultracode") to customers.
- **Anthropic credit tiers**: Tier 1 caps a single credit purchase at $500 and advances on cumulative purchases.

### 10.8 Re-testing and the mutation runner (the scratchpad does not survive)
```bash
R=/home/user/vigil-sovereign
cd $R/packages/core/vigil_core && PYTHONPATH=$R/packages/core/vigil_core $R/.venv-sovereign/bin/python -m pytest \
  -p no:cacheprovider tests                                  # 623 + the M1 files
cd $R && PYTHONPATH=$R/apps/sigil:$R/integration:$R/packages/core/vigil_core:$R/gateway SIGIL_HOME=$(mktemp -d) \
  $R/.venv-sovereign/bin/python -m pytest -p no:cacheprovider apps/sigil/tests/test_model_gateway.py \
  apps/sigil/tests/test_metered_billing.py apps/sigil/tests/test_completion_spool.py apps/sigil/tests/test_launch_gate.py \
  apps/sigil/tests/test_backup*.py integration/tests/test_model_grant_broker.py integration/tests/test_doctor*.py \
  integration/tests/test_two_env_boundary.py integration/tests/test_production_invariants.py
PATH=$R/.venv-sovereign/bin:$PATH bash tools/governance/mypy_ratchet.sh       # ceiling 15
$R/.venv-sovereign/bin/python -m pytest -p no:cacheprovider docs/tests       # ~2.5 min
```
The gateway tests pin their clock to noon UTC today (the daily-ceiling restart seed reads meter-file mtimes).
**Mutation runner** (re-create it, ~40 lines): for each `(file, [(old, new), ...], test-file)` — assert each `old`
occurs once, write the mutant, run `pytest -x -q -p no:cacheprovider <test-file>`, record RED iff the exit code is
non-zero, ALWAYS restore the original. M1's 39 mutants (all RED) covered: forward the client token; skip the effort
pin; stop reading on client disconnect; drop pending from admission; no release on error; ignore the close sentinel;
chain onto a cached hash; keep `speed` / the fast-mode beta / sampling; allow code execution; no `standard_only`; no
model check; no expiry check; an unreadable 200 runs free; `max_tokens` not lowered; replay ignores the chain; keep
thinking under a forced tool; a ticket settles twice; no tenant slot; no account slot; no daily ceiling; the ceiling
ignores the day's spend; a restart does not seed the day; the budget read ignores pending; org not recorded;
stream deltas added; 1-h writes priced at 5-min; credits floor-divided; no reservation clamp; markup below 1;
an unknown model at zero; a price rounded; web search unpriced; no domain on grants; skip the signature; skip the
canonical check; any effort; a meter id that ignores the nonce.
