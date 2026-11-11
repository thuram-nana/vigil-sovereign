# VIGIL — HANDOFF (complete, end-to-end) — 2026-11-11

> Supersedes the 2026-11-09 handoff. Written so a **fresh agent or human can take over cold**: what is on
> `main`, what every shipped slice does and where it lives, every flag and who may flip it, the exact remaining
> program in order, how to work in this repo without tripping its guards, and the definition of done.
>
> **`main` is at `e836b962` (#1070; plus the commit that lands this handoff), all required checks green.** Since the 2026-11-09 handoff 25 PRs have
> merged (#1046–#1070; this handoff written by session `session_01Uzcz55Eva4w7NRFfoQPArA`): Front A is
> complete except the owner-blocked KMS escrow; Front B's pay round-trip is built (default-OFF); the 1M-user design
> was **authorised by the owner** and its first three build slices (S0a–S0c, the verified fold cache over
> customers, orgs/memberships and the money folds) are merged default-OFF. **The next agent's first item is Front C
> S0d (§4.3), then S1→S4, then Gate 5 (§5).**
>
> **Update (same session, 2026-11-11): Front C S0 is COMPLETE** — S0d merged as #1072, #1073, #1074, #1075
> and the S0d-3 PR (which carries this update). Every request-path fold is on the verified cache; per-request
> stores pay O(new records) via the tail fast path; the cache is warmed at boot and audited against the spine
> (`sigil verify`, `vigil doctor`). **The next agent's first item is now S1 (§4.4), then S2–S4, then Gate 5.**

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
| S0d-3 | (this) | **S0d-3** — fresh-store tail fast path, rebuild-and-compare audit, boot warm-up, `sigil verify` / `vigil doctor` |

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
- **`SnapshotState.load` is itself O(snapshot) per read once a prune exists** (today the prune cutover is unwired,
  so it returns the cheap empty identity). When prune goes live, memoize the loaded snapshot on the signed head.

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
- **Money numbers:** margins, $/token, catalog prices, custom credit amounts (rate / min / max / rounding — not
  supported today), and the **S4 scale targets**.
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
