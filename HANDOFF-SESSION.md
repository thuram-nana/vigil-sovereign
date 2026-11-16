# VIGIL — HANDOFF (complete, end-to-end) — 2026-11-16

> Written so a **completely separate agent can take over cold and start implementing at once**. It supersedes the
> 2026-11-11 handoff; every section below §10 was rewritten or added on 2026-11-16.
>
> **START HERE → §11 (the prepaid pay-as-you-go WALLET program).** On 2026-11-16 the owner replaced per-scan budgets,
> estimates and paid calibration with a prepaid, pay-as-you-go credit wallet, and made it a NON-NEGOTIABLE principle
> that VIGIL never estimates, predicts, quotes or displays what an assessment will cost (§11.1). The design is
> `docs/decisions/PRICING-RED-PEN-DESIGN.md` **§0** (it overrides every conflicting line later in that document and in
> §10 of this file). Slice **W1** (published rate card + per-charge usage statement) is built; **W2 → W6** are
> specified in §11.5–§11.9 in enough detail to implement directly.
>
> **⇒ TAKE OVER FROM §15 (the exact take-off point at the end of 2026-11-16), then read §0.**
>
> **Verified state at the end of 2026-11-16 (two local sessions):**
> - `origin/main` = **`198b8f37`** (#1140). Merged on 2026-11-16: #1130 (W1), #1131 (W2a), #1132 (W2b-1), #1133
>   (W2b-2), **#1134 (W2b-3, `02bfcdcf`)**, **#1135 (Dependabot PR A: the z3-solver floor, `9eb4f64a`)**, **#1136
>   (Dependabot PR B: the anthropic SDK 2.8, `a43f8fd3`)**, **#1138 (M1c-2a: the engine guards + the Strix prices,
>   `71610f3b`)**, **#1139 (NYX: the UI-only display name of the Strix engine, `a43b4a31`)**, **#1140 (W2c-1: exact
>   milli-credit settlement + the floor retired, `198b8f37`)**. Dependabot #1121, #1122, #1124, #1125, #1126 are
>   closed as superseded (#1120 was closed earlier).
> - **Open PRs:** **#1137** (this handoff) and **#1141** (the in-app onboarding guide: a skippable first-sign-in tour
>   whose finished/skipped answer is kept SERVER-SIDE per account, the Guide screen covering the whole app, and the
>   VIGIL wordmark loader — behind `VIGIL_CUSTOMER_ONBOARDING`, default OFF). Merge each when its 15 required checks
>   are green (§15.1). **The complete list of what is left to code is §15.11.**
> - Owner decisions of 2026-11-16 (all recorded below — do not re-ask): Stripe is the payment provider (Flutterwave
>   paused); no server / VPS work; NYX is UI-only; the three production flips are delegated to the agent behind their
>   gates (§6); the floor is retired. **W5 dispute timing DECIDED (owner, 2026-11-16):** remove the disputed credits
>   when the dispute OPENS (`charge.dispute.created` / `funds_withdrawn`) and give them back automatically when it is
>   won (`funds_reinstated` / closed `won`). **Red-Pen (D) is built together with the customer app's Code screen.**
> - Every money number the program needs is now **decided by the owner** (§11.2, §12, §13). Nothing in this file is
>   a proposal waiting for a decision except where it says "OPEN".
>
> Order of work (details §5, the full list §15.11): **W2c-2 → W3 → M1c-2b → W4 → W5 → W6 → G1 → Gate-5-lite (wallet
> E2E, simulated) → Red-Pen R1–R5 → Front C S1–S4 → Gate 5 → A1 / O1 / L1**, with the customer-app screens of §15.11 C
> built alongside (each before the onboarding guide can be switched on).

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
1. Do **not** flip `VIGIL_CUSTOMER_PROD_EXECUTION`, the multi-shard production flag or `VIGIL_METERED_BILLING`
   **before its gate is green**. The owner delegated these three flips to the agent on 2026-11-16 (§6): each is
   flipped on the production deployment only when its own gate passes, then reported — never early.
2. Do **not** inject or commit a real payment secret — the Stripe keys (`VIGIL_STRIPE_SECRET_KEY`,
   `VIGIL_STRIPE_WEBHOOK_SECRET`) or the paused Flutterwave ones (`VIGIL_FLW_SECRET_KEY`); all are read from env at
   call time; tests use dummies and Stripe TEST mode only.
3. Do **not** ratify money numbers — margins, $/token, catalog prices, **scale targets**.
4. Do **not** dismiss a security alert. An A14 (supply-chain) red is *handled*, never ignored; the
   GitHub-release-CDN 504 is "transient" only once a clean re-run confirms it.
5. `main` is PR-only — **never `git push origin main`**.
6. **Never estimate a scan's cost** (owner, 2026-11-16, non-negotiable): no scan cost estimator, prediction engine,
   quotation system or calibration procedure; no customer-facing money amount for a scan — credits only (§11.1).
7. **Never run paid calibration scans; never consume production AI credits or charge a real payment method in a
   test** without the owner's explicit authorisation. Validate with simulated provider usage, sandbox payments,
   concurrency tests and failure injection.
8. **The repo is PUBLIC.** Never write the target-margin value, or any sentence tying the published rates to a
   margin percentage, into a file, commit message, branch name or PR text (`tools/governance/money_hygiene.py` and
   `apps/sigil/tests/test_public_repo_money_hygiene.py` enforce the wording patterns; they cannot catch everything).
   The published RATES themselves are public by the owner's choice (§11.2). No secrets, no private plans, no
   description of an unfixed weakness in public text.
9. **Never filter, rewrite or drop CodeQL/SARIF results, and never add `paths-ignore` entries to silence alerts**
   without the owner's explicit, specific OK. (An attempt to filter SARIF before upload was refused by the
   environment's safety classifier as undermining oversight — do not retry it in any form.) By-design alerts are
   DISMISSED BY THE OWNER in the GitHub UI (§13.4); genuine ones are fixed at the source.
10. **Never name the AI model on a customer surface** (any customer-rendered payload, page, email or statement).
Merge authorization (owner, standing): merge once **all required checks are green and the change is tested**.

### 0.4 Merge mechanics (what actually works)
- Live branch protection: **strict = true** (a PR must be up to date with `main`), signed commits required,
  no force pushes. Strict ⇒ **the merge queue is serial**: each PR must be re-based on the previous merge.
- CI wall time ≈ **40 min per PR**; the long pole is `integration two-env boundary (P5)` (~16–37 min), then
  `CRUCIBLE core on vigil_core` (~21 min).
- This session merged with `merge_method="merge"` and `expectedHeadSha` (GitHub signs the merge commit, so
  signed-commit protection is satisfied). Squash also works.
- **Required checks (15)** — canonical list `.github/required-status-checks.txt`: A14 supply-chain gate · CRUCIBLE
  core on vigil_core · CRUCIBLE eval + benchmark corpus · formal (TLA+, F1) · gateway egress gate (P6) ·
  integration two-env boundary (P5) · livefire smoke · loopback engagement · SIGIL governor gates (P7) · SIGIL
  lint (ruff + mypy) · **SIGIL suite with the fold cache ON** · strix Claude-runtime (P8) · the briefing explains
  every agent and capability · vigil_core · WARDEN Rust kernel (A10). A PR shows ~32 check runs in total (the rest
  are advisory or nightly-skipped).
- **The "CodeQL" check run** (the code-scanning summary, separate from the advisory "CodeQL Python" job) goes red
  when the PR introduces NEW alerts in changed files. An alert whose line MOVED because you edited nearby code can
  count as new (its fingerprint changed). Inline annotations only appear for alerts on diff lines; for the others,
  reproduce locally (§9: full-repo scan with the workflow's `paths-ignore`, then diff the per-file rule counts against
  a scan of `main`). Known CodeQL blind spots met this session: it does not treat regex validation as a sanitizer
  (rebuild the value from a dict lookup table instead); it follows `realpath` + `startswith` containment only as two
  separate statements; it does not see `ctx.minimum_version = …` set on an ATTRIBUTE (`self._ctx`) — set it on a
  local variable before storing it; `str.startswith("github.com/")` on a URL is flagged — split on `/` and compare
  the first segment instead. **Advisory** (reported, not required): CodeQL Python, **CodeQL JavaScript** (new,
  CQ-1), gitleaks, semgrep+bandit, pre-commit, perf regression, lint-config, scheduled supply-chain scan.
- A `mergeable_state` of `clean` means every required check passed; `unstable` means something (often an
  advisory or still-running job) is not green — read the check runs before deciding.

### 0.5 Branch / worktree pattern in this cloud environment
- The session branch is pre-assigned (the 2026-11-11/16 sessions: `claude/cool-meitner-v9fq6d`; YOUR session's
  system prompt names yours — use that). **Force-push is denied** except `--force-with-lease` to restart a branch
  whose PR already merged (the branch then holds only merged history).
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
- **Midnight-crossing tests.** `apps/sigil/tests/test_model_gateway.py` pins `NOW` to noon UTC of the day the module
  is IMPORTED, while a restarted gateway stamps the orphans it records with the real clock. A CI run that starts
  before 00:00 UTC and reaches such a test after it fails (#1130 hit it). Assert a day from the record's OWN `ts`, never
  from `NOW`, wherever the gateway wrote it on its own clock; re-check by shifting `NOW` back 86,400 s locally.
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

## 1. STATE OF `main`

**2026-11-16 addendum.** After #1076, other sessions merged the M1 metering core + model gateway and the M1c-1
sovereign wiring (§10.4–§10.5 — both are ON `main`, default-OFF; the `claude/cool-meitner-v9fq6d-pricing` branch is
now historical), the plan/wallet split on leases (`bf243156`), the gateway's AWS SSM key source, and dependency
floors. This session merged **#1128** (PR 2, `a144ada8`) and **#1129** (`7dd30c47`); **#1130 is open** (§ header).
Use `git log --first-parent --oneline origin/main | head -40` for the exact list. The table below is the 2026-11-11
record and is kept as history.

### 1.0 What #1128 (PR 2) and #1129 carried — anchors
- **Nginx-first edge swap** (owner choice): the upstream include file is rewritten, nginx reloads gracefully, the
  old edge drains, then stops. `ui/graceful.py` (per-server `drain_deadline`; `PROVISIONER_DRAIN_DEADLINE_S=65`;
  custui 75 s; an `on_stop` companion stops the model gateway with the cockpit); the BPF listener hold is refused
  with EPERM on GitHub runners, so `HOLD_UNAVAILABLE` records why and the hold test is branch-aware. **Owner action:
  the one-time server setup in `docs/runbooks/EDGE-SWAP.md`.**
- Founder latch (`governor/customer_latch.py`; `find_repo_root` falls back to the checkout when `sys.prefix` is a
  venv), held-cancel marker, OD-4, doctor fixes; the iPhone app keeps Google sign-in with the email-code / Face ID
  fallback (owner choice).
- `engine/crucible/framework/v2/console/safeinput.py`: `token`, `slug_chars`, `contained`, `resolved_under` —
  allowlist re-derivation and realpath containment; use these for any new console input that reaches a path or a
  subprocess.
- #1129: approval broker / eval attestation / live instructions / OOB collaborator / host-command run ids rebuilt from
  fixed tables; clone URL rebuilt after the host allowlist; `spine/upgrade.py` extracts with `filter="data"` only;
  `github_client._owner_repo` parses the host; `ownership_fetch` pins TLS ≥ 1.2 on any context; four ReDoS regexes
  in `verify/oracles.py` + `verify/version.py` replaced by linear scanners (fuzz- and exhaustively-checked equal);
  `api/server.py::_log_safe` strips CR/LF; posture bundle writes `verify_offline.py` 0600.

### 1.1 The 2026-11-11 record (history)

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
- **Payment provider = STRIPE (owner, 2026-11-16): "we won't be using Flutterwave so leave its development paused,
  focus on Stripe."** The Flutterwave code stays on `main` but nothing new is built on it. Stripe lane:
  `VIGIL_BILLING_PROVIDER=stripe`, `VIGIL_BILLING_ENABLE_STRIPE`, `VIGIL_STRIPE_SECRET_KEY`,
  `VIGIL_STRIPE_WEBHOOK_SECRET`, `VIGIL_STRIPE_API_VERSION`, `VIGIL_STRIPE_BILLING_DRAIN_ENABLED`
  (`governor/billing.py::StripeBillingProvider` — acts on `checkout.session.completed`,
  `checkout.session.async_payment_succeeded`, `invoice.paid`, `invoice.payment_failed`, re-fetching each object from
  Stripe; `governor/stripe_egress.py`). The code still DEFAULTS to Flutterwave when `VIGIL_BILLING_PROVIDER` is unset
  (fails closed without its secrets); making Stripe the default is its own small slice (or part of W5).
- **Hosted checkout** (#1056) — `provision.billing_checkout`; hosted payment (Stripe; the paused Flutterwave lane is
  `VIGIL_FLW_SECRET_KEY`, `VIGIL_FLW_API_BASE`), amounts always from the **owner catalog**
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
| `VIGIL_CUSTOMER_ONBOARDING` | the customer app's onboarding guide: the first-sign-in tour (finished/skipped kept server-side per account: edge `GET/POST api/customer/onboarding` → provision `onboarding_get` / `onboarding_set` → `ui/onboarding_store.py`, `SIGIL_HOME/customer/onboarding/`; all three absent while OFF), the Guide screen and the wordmark loader (#1141) | owner, once the flows it walks through are live (§15.11 C) |
| `VIGIL_FOLD_CACHE_ENABLED` | the verified fold cache (S0: every request-path registry read — §4.2) + the cockpit's boot warm-up / audit thread | owner (production); tests set it |
| `VIGIL_FOLD_CACHE_AUDIT_S` | seconds between the cockpit's rebuild-and-compare audits (default 21600; 0 = warm-up only) | operator |
| `VIGIL_CUSTOMER_CHECKOUT_ENABLED` | hosted top-up checkout (Stripe: `VIGIL_BILLING_PROVIDER=stripe` + `VIGIL_BILLING_ENABLE_STRIPE` + `VIGIL_STRIPE_SECRET_KEY` + `VIGIL_STRIPE_WEBHOOK_SECRET` + `VIGIL_STRIPE_API_VERSION`) | owner |
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

Secrets (never in git): `VIGIL_STRIPE_SECRET_KEY`, `VIGIL_STRIPE_WEBHOOK_SECRET`, (paused) `VIGIL_FLW_SECRET_KEY` /
`VIGIL_BILLING_WEBHOOK_SECRET`, `VIGIL_BACKUP_PASSPHRASE`, `SIGIL_CUSTOMER_SESSION_KEY`, `SIGIL_ANTHROPIC_API_KEY`.

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
  `_publish` scans, the cockpit HUD's one-time tip scan. Reviewed 2026-11-11 (S0 retroactive review, lens 8): sound
  — none is on a per-request customer path and no cached read feeds a decision they gate. Still full scans per
  request with the flag ON, to move in a later slice: the cockpit `/api/snapshot` (polled every 4 s), `/metrics`
  (at most once per `METRICS_PROJECTION_TTL_S`), and the customer monitoring-events bell
  (`inbound/monitoring_spool.py`, polled every 45 s per customer).
- **The audit's final compare runs under the fold's entry lock** (O(state), seconds at 1M customers, once per fold
  per audit); an incremental per-view digest would make it O(1).
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

## 5. REMAINING PROGRAM (agent), in order — 2026-11-16

Every item is one or more PRs, each built per §0.2 (default-OFF, fail-closed, mutation-verified, red-penned).

0. ~~Merge #1130~~ — **merged 2026-11-16** (`503e06af`).
1. **W2 — wallet-backed rolling reservations + rate-card charging + exact milli-credit settlement** (§11.5). The
   hardest money slice; read §11.3–§11.4 first. **W2a is merged (§11.17, #1131); W2b-1 is merged (§11.18,
   #1132, `cc227ccc`); W2b-2 is merged (§11.19, #1133, `454d9ac3`); W2b-3 is merged (§11.20, #1134, `02bfcdcf`)**;
   **W2c-1** (f + g: exact settlement with the per-org remainder, the floor retired) is **merged (#1140,
   `198b8f37`, §11.21 / §15.2)**; **W2c-2** (j + k: balance-after on the statement, the envelope constant off every
   metered path, the exact customer-visible balance) is NEXT (§15.6, §15.11).
2. **W3 — pause on insufficient credit, resume after top-up** (§11.6).
3. **M1c-2 — offense wiring through the gateway** (§10.6 row M1c-2, unchanged, plus §11.10 notes). Until W2 + W3 +
   M1c-2 are merged, `VIGIL_METERED_BILLING` stays OFF (and it is the owner's flip, never the agent's).
4. **W4 — worker-time and premium-API metering** (§11.7).
5. **W5 — chargebacks / payment reversals / refunds + the low-balance alert** (§11.8).
6. **W6 — the customer billing dashboard** (§11.9).
7. **G1 — gateway at scale** (§11.11): capacity from the provider's rate-limit headers, a per-tenant fair share,
   a provider-account pool, the loss alarm.
8. **Wallet E2E (simulated)** (§11.12) — the whole customer journey of §11.1 driven in a test, no real money.
9. **Red-Pen R1 → R5** (§12; design §7).
10. **Front C S1, S2a–c, S3, S4** (§4.4) with the owner's targets (§13.1).
11. **Gate 5** — hands-on end-to-end, updated for the wallet (§13.2).
12. **A1 — auto top-up** (§11.13), **O1 — owner money view** (§10.6 row O1, now "rate-card revenue vs gateway
    cost"), **L1 — live Max** (§10.6 row L1).
13. ~~**Dependabot** (§13.3)~~ — **done 2026-11-16** (#1135, #1136). **NYX** (§15.4) — the UI-only display name,
    built; merge its PR. **Housekeeping** — delete merged `claude/*` branches; keep this file current at the end of
    every session.

**Removed from the program (owner, 2026-11-16):** M5 calibration (never build it, never run paid calibration
scans); every estimate / quote / tier-budget screen in M4; the run floor (`VIGIL_RUN_FLOOR_CREDITS`, retire it in
W2); the tier budgets 450 / 5,000 / 20,000 as charging caps (M3's "re-budget the launch products" is replaced by W2's
allowance chunks).

## 6. OWNER-ONLY (never the agent's)
- **No server work is in scope (owner, 2026-11-16):** the program builds the customer app — code, tests, CI. No agent
  deploys to or changes any server until the owner brings a deployment back into scope.
- **Flips the owner DELEGATED to the agent (2026-11-16, pick-one answers)**, for when the customer app has a
  deployment — the agent flips each one only when its gate is green, verifies the service is healthy, and reports it:
  - `VIGIL_CUSTOMER_PROD_EXECUTION` — after **Gate 5** passes (§13.2), with its evidence;
  - **`VIGIL_METERED_BILLING`** (with `VIGIL_MODEL_GATEWAY_ENABLED`, which it requires) — after W2 + W3 + M1c-2 are
    merged and the wallet E2E (§11.12) is green, and only once the owner has set the target margin and the
    Anthropic key on the server (`vigil doctor` must report no hard issue);
  - the multi-shard production flag — after S4 is green (§13.1; the flag arrives with S2–S4).
- **Flips that stay the owner's:** `VIGIL_FOLD_CACHE_ENABLED` in production; `VIGIL_MODEL_GATEWAY_ENABLED` in production
  other than as part of the metered flip above.
- **Secrets / accounts:** the live Stripe secret key + webhook signing secret; the Anthropic API key in the sovereign secret
  store (or SSM) for the gateway; a dedicated Anthropic workspace (or several, for G1) with Console spend limits;
  Anthropic auto-reload with a cap; an Anthropic admin key (O1 reconciliation); Bedrock / Vertex accounts if G1's
  overflow is wanted; the customer-facing GitHub App registration (Red-Pen, with `checks:write`); the AWS KMS key for
  evidence-DEK escrow (#70 tail); DNS/TLS cutover (`vigilguard.net`).
- **Deploy-time settings the owner sets privately:** `VIGIL_BILLING_TARGET_MARGIN` (the value is the owner's, recorded
  privately; never in the repo); `VIGIL_TRIAL_CREDITS` (decided: 450 — §11.2); optionally `VIGIL_RATE_CARD` to change
  the published rates without a release.
- **One-time server setup** for the nginx-first edge swap: `docs/runbooks/EDGE-SWAP.md`.
- **CodeQL:** dismiss the by-design alerts in the GitHub UI with the recorded rationale (§13.4); decide whether the
  deliberately vulnerable benchmark fixtures get `paths-ignore` (OPEN — the agent must not add it unasked).
- **Dependabot:** the agent closes the Dependabot PRs its two replacement PRs supersede (owner-approved 2026-11-16,
  §13.3); any other closure is the owner's.
- Any money number NOT recorded in `docs/decisions/PRICING-RED-PEN-DESIGN.md` §0 / §1.1b / §1.1c or in §11.2 here.

## 7. DEFINITION OF 100% — the closing gates
1. ✅ Pause/resume chain (PR-1..PR-5). ✅ Front A (except the owner-blocked KMS escrow). ✅ Front B surface.
2. ⏳ **The wallet** — W1 ✅ (#1130); W2a ✅, W2b-1 ✅, W2b-2 ✅, W2b-3 ✅ (#1131–#1134); W2c-1 ✅ (#1140); W2c-2,
   W3–W6 to build; the simulated wallet E2E (§11.12) green.
3. ⏳ **Metered offense** — M1 ✅, M1c-1 ✅, M1c-2 in progress (part 1 of 6, §15.5); G1 to build.
4. ⏳ **Red-Pen** — R1–R5 to build.
5. ⏳ **1M scaling** — S0 ✅; S1, S2a–c, S3, S4 to build; S4 passes at 100,000 then 1,000,000 users (§13.1).
6. ⏳ **Gate 5** — the personal hands-on end-to-end + at-scale verification, with evidence (§13.2).
7. **[owner]** the flips, secrets and setup of §6.

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

## 10. PRICING, METERING & RED-PEN — the owner's 2026-11-11 program (architecture reference)

> **Superseded in part on 2026-11-16 — read §11 first.** The billing MODEL changed to a prepaid pay-as-you-go wallet
> with a published rate card and no estimates. Still valid and authoritative here: the gateway architecture (§10.4),
> the M1c-1 wiring (§10.5), the M1c-2 / L1 / R1–R5 / O1 / A1 row specs (§10.6) and the research facts (§10.7).
> **No longer valid:** the "proposed numbers" of §10.3 (floor, tier budgets — retired; purchase limits — now
> confirmed, §11.2), the M3 re-budgeting, every estimate / budget screen in M4, and M5 calibration (removed).

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
- **`VIGIL_METERED_BILLING` must NOT be enabled before W2 + W3 + M1c-2** (§11): today a launch reserves a small fixed
  number of units (`VIGIL_LAUNCH_UNITS`, default 10, or a catalog product's 3 / 20), so a metered run would stop at
  once. W2 replaces this with wallet-backed extendable allowances. (Was: "not before M3".) The flip is the owner's.
- The effort is derived from the units band for a lease that names no depth; a metered launch's lease names its
  depth explicitly since W2b-3 (§11.20).
- The offense plane does not yet route its model calls through the gateway (M1c-2).

### 10.6 Remaining slices, in order (design §9)
| Slice | What, with anchors |
|---|---|
| **M1c-2 — offense wiring** | (1) `integration/vigil_integration/jobs/engage_worker.py`: read `model_grant_broker.read_model_grant(base, slug, expect_nonce=nonce)`; metered + no grant ⇒ refuse the run (fail closed); scope the run's env the way `_model_routing_scope` does (the worker runs one job at a time): `ANTHROPIC_BASE_URL` = gateway, `ANTHROPIC_API_KEY` = token for in-process engine calls; `LLM_API_BASE` / `LLM_API_KEY` / `STRIX_LLM=anthropic/claude-opus-4-8` for Strix children; restore after. (2) `engine/crucible/framework/v2/kernel/backends/anthropic.py::_client_obj` caches its client and `common/live_keys.refresh_live_anthropic_key()` HOT-RELOADS the persisted key into the env — in metered mode that would replace the token: give an explicit grant env (e.g. `VIGIL_MODEL_GRANT`) precedence and key the cache on it; same for `live/think_claude.py::_resolve_key` / `_build_live_client` (pass `base_url`). (3) **EC-2a model routing must be OFF when metered** (it routes "quick" bindings to cheaper models, which the gateway refuses): `vigil_core/run_tier.routing_enabled_for` + `engage_worker._model_routing_scope`. (4) Fix `vendor/strix/strix/report/anthropic_pricing.py`: rows for `claude-opus-4-5`…`4-8` at $5 / $25 / $0.50 / $6.25. (5) A wire test that `output_config.effort` reaches the API as the grant's effort. (6) Doctor note: in metered mode the offense plane must hold no provider key. |
| **M3 — catalog** | **Partly superseded (§11).** Still to do: the six packs + custom top-ups ($5–$500 with the §11.2 purchase limits, now owner-CONFIRMED) in `governor/catalog.py` (+ `provision.billing_checkout`, amounts always from the catalog). **Retired:** re-budgeting the launch products to tier budgets — W2 makes a launch product select a DEPTH only and reserve allowance chunks; the explicit owner-signed run tier in the lease moves into W2 (§11.5 h); retiring `ENVELOPE_TOKENS_PER_CREDIT` from the money path moves into W2 (§11.5 k). |
| **M2 — engine** | the 90% report-reserve wrap-up (poll `GET /v1/vigil/budget`); continue = resume (Strix `--resume`); runtime caps from the grant as a second line (Strix `max_budget_usd`, Claude Code `--max-budget-usd` — counts subagents, but is a client-side estimate); `max` through Strix. |
| **M4 — customer UX** | the "VIGIL" naming sweep + a test that no model id ever reaches a customer-rendered payload (today `ui/settings.py` and `engine/crucible/framework/v2/console/chat.py` list "Claude Opus 4.8" labels — owner/operator surfaces, keep them there); target / depth / outcome choice; preflight; ~~estimate + budget~~ (removed 2026-11-16: never show an estimate) + the live meter + the tenant statement (credits only) — the billing parts are W1/W6 (§11). |
| ~~**M5 — calibration**~~ | **REMOVED by the owner (2026-11-16).** Never build it; never run paid calibration scans; no p10/p50/p90 estimates anywhere. |
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

---

## 11. THE PREPAID PAY-AS-YOU-GO WALLET — the owner's 2026-11-16 program (START HERE)

Design of record: `docs/decisions/PRICING-RED-PEN-DESIGN.md` **§0** (+ §1.1b, §1.1c). Where §0 and anything later in
that document (or §10 here) disagree, **§0 wins**. This section is the implementation plan for it.

### 11.1 The non-negotiable principle (owner's words, 2026-11-16 — verbatim intent)
VIGIL must NEVER calculate, predict, estimate, quote or display the expected total cost of a Quick, Deep, Max or any
other assessment. The customer experience is exactly:
1. The customer purchases prepaid credits. 2. The credits appear in their wallet. 3. They launch any authorised
assessment **without** a scan price estimate. 4. VIGIL deducts credits automatically from actual metered
consumption. 5. The dashboard continuously shows credits consumed and credits remaining. 6. When credits are
insufficient, VIGIL safely pauses billable operations and preserves completed work. 7. The customer buys more credits
and resumes from the checkpoint.

All customer-facing usage amounts are **credits**, never a computed money cost of a scan. Quick / Deep / Max are
assessment DEPTHS, not pricing tiers. Do not build scan cost estimators, cost-prediction engines, quotation systems
or calibration procedures. Internal provider-cost accounting is allowed strictly for SIGIL's own financial
management and must never produce a customer-facing estimate. Keep: transparent deduction rates, transaction
history, prepaid balance enforcement, auditability. "Proceed with the implementation; avoid unrelated changes to
VIGIL's cybersecurity functionality."

### 11.2 Every owner decision the wallet needs (all DECIDED — do not re-ask)
| Topic | Decision |
|---|---|
| Model | Prepaid pay-as-you-go wallet; billing = measured consumption × published rates. M5 calibration REMOVED; no estimates; the per-run **floor is dropped** (worker time is metered instead). |
| Credit rate | $1 = 100 credits. Packs $5 / $10 / $16 / $25 / $50 / $100 → 500 / 1,000 / 1,600 / 2,500 / 5,000 / 10,000 credits. Custom amounts from $5, whole dollars × 100. No volume bonus. Purchased credits never expire. |
| Purchase limits (CONFIRMED) | $5–$500 per purchase; first purchase ≤ $100 until the account has ≥ $100 of settled purchases and is ≥ 7 days old; ≤ $1,000 per account per 24 h; ≤ 5 purchase attempts per hour per account; above $500 → invoice. |
| **Published rate card** (public, committed — owner chose "in the code repo") | AI input **1,250** · AI output **6,250** · cache read **125** · cache write 5-min **1,563** · cache write 1-hour **2,500** credits per million tokens; web search **2.5** credits per search; scan-worker time **1 credit per minute** (billed per second); premium external APIs/tools: each its own line, priced from its provider cost on the same basis as the AI rates. Implemented: `vigil_core/rate_card.py` (W1). Owner override without a release: `VIGIL_RATE_CARD`. |
| Precision | Exact to **0.001 credit** (milli-credit, "mc"). Statement lines show 3 decimals; the balance shows 2 decimals (display rounds DOWN — never show more than the customer has). No charge is ever rounded up to a whole credit. |
| Low-balance alert | Email + dashboard when the balance falls below **max(100 credits, 20% of the last top-up)**. |
| Optional per-scan limit | Off by default (the wallet is the limit). If set: a warning at 90%, the scan pauses at the limit with findings saved, one tap raises the limit and resumes. |
| Paused for credit | Waits **7 days** for a top-up; then it closes, results stay in the report, it is charged what it used. |
| Chargeback / reversal | Remove the disputed credits; any part already spent is recorded as **owed**; the org cannot start billable work until the next top-up repays it; the owner is alerted. Balances never go negative through spending. |
| Trial | **450** one-time trial credits; one per verified email AND per verified domain; ownership proof still required; the full report unlocks on the first purchase. (`VIGIL_TRIAL_CREDITS=450` at deploy.) |
| Auto top-up (A1) | Off by default; customer sets a trigger, a pack and a **monthly cap**; paused scans resume on their own after the payment is confirmed. |
| Enterprise | A signed contract or a paid invoice **credits the same wallet**; an optional contract credit line (postpaid limit) for trusted customers. |
| Seat | $25 per seat per month, platform access only — **includes no credits**. |
| Target margin | Decided; recorded privately; set at deploy via `VIGIL_BILLING_TARGET_MARGIN`; never in the repo (§0.3 #8). With rate-card billing it no longer drives customer charges — it is the target line of the owner's money view (O1). |
| Cancellation (2026-11-13, still in force) | A cancelled scan pays for what it used (`VIGIL_BILLING_CANCEL_SETTLEMENT=metered`, the default). |
| Scale & spend guard (2026-11-15) | Gateway capacity sized automatically from the provider's live rate limits, a fair share per tenant, a pool of provider accounts (several Anthropic workspaces; Bedrock / Vertex overflow). No fixed daily dollar ceiling: spend is prepaid-backed. **Loss alarm:** new runs pause + owner alert when the day's unbillable provider spend passes 2% of the day's billed AI spend. (G1, §11.11.) |
| Model / depth | One model (`claude-opus-4-8`) for every run, never named to customers. Depth → effort: Quick = high, Deep = xhigh, Max = max (+ ultracode, design §6). |

### 11.3 What is ALREADY built — reuse it, do not rebuild
| Need | Built (on `main` unless noted) | Changed by |
|---|---|---|
| Wallet per org, signed, append-only | `apps/sigil/sigil/governor/wallet.py` — `WalletRegistry.grant / debit / balance / available / has_*_entry`; integer `credits`; idempotent by signed `entry_id`; snapshot-seeded; prune-durable | W2 (remainder), W5 (reversal) |
| Credits only after verified payment | `governor/billing.py` (webhook EVIDENCE → owner-signed FACT), `governor/catalog.py` (amounts from the owner catalog, never the wire), `inbound/billing_spool.py`, `vigil billing-drain`, `ui/pending_checkout.py`, CHK-1/CHK-2 checkout (`customer_checkout_enabled`) | W5, M3 |
| Plan credits / subscriptions / invoices / credit lines | `governor/metering.py` (`CreditMeter`, `PlanCreditLedger` — plan tranches + wallet burn-down order), `governor/subscription.py`, `governor/invoices.py`, `governor/postpaid.py` (credit line + arrears) | W5 (arrears for chargebacks) |
| Launch reservation / lease | `ui/launch_gate.py` (`reserve_launch` — the fail-closed chokepoint: membership + ownership proof + EngagementAuthority + credits; `publish_lease`; `settle_launch` / `_settle_once` with the K4-1 invariant "net spend == metered consumption, neither bucket over-refunded"; `pause_launch` / `resume_launch`), `governor/launch_reservations.py` (`scan_reservations`, `ReservationIndex`, `Reservation.units` = bucket → credits, **first wins**), `governor/launch_settlement.py` (cross-process settle lock + signed settle decision), `settle_checkpoint.py`, `paused_expiry_settle.py`, `governor/settle_hold.py`, `ops_sweeps.py` | **W2** (extensions), W3 |
| Units a launch reserves | `provision.py::launch_reserve` — `config.LAUNCH_UNITS` (`VIGIL_LAUNCH_UNITS`, default 10) or a catalog launch product's units (EC-7b); run tier DERIVED from units (`vigil_core/run_tier.py`) | **W2** (allowance chunks; explicit depth) |
| AI metering | `apps/sigil/sigil/model_gateway.py` (§10.4) — per-request worst-case reservation BEFORE forwarding, `GrantMeter` hash-chained per-launch meter (`open / usage / release / orphan / close`), confirmed vs unconfirmed spend, close protocol (`MeterBusy`), daily ceiling, tenant/global slots; `vigil_core/model_metering.py` (Usage, prices, `cost_nano_usd`); `vigil_core/model_grant.py` (owner-signed per-launch grant token, `meter_id(slug, nonce)`) | **W2** (rate-card mc on each line), W4, G1 |
| Metered settle | `inbound/completion_spool.py::_consumed_for` (close meter → completed = metered; canceled per policy; failed = 0), `ops_sweeps.sweep_abandoned_reservations` | **W2** |
| Pause / resume | `integration/vigil_integration/live/credit_lease_pause.py` (reversible nonce-scoped marker), `LaunchGate.pause_launch / resume_launch`, `credit_lease_pause.record_paused_past_expiry`; engine checkpoints every phase (`engine/crucible/framework/v2/engage.py` + `phase_ledger.PhaseLedger`, `resume=True`); Strix `--resume` | **W3** |
| Internal cost (separate from billing) | `governor/cost_ledger.py` (EC-4 per-tenant cost envelope), `ui/margin.py` (EC-6 owner margin view — still on a placeholder per-token rate), `governor/ledger_view.py` | O1 |
| Customer billing reads | `ui/billing.py` (`billing_overview`, `billing_invoices`, **W1** `billing_rates`, `billing_usage`), routes in `ui/custui.py::_READS` → `ui/server.py` dispatch → `ui/provision.py::customer_*` (`_customer_read` = `admit_customer(view_billing)` on the SESSION org) | W2 (balance-after), W6 |
| Customer app | `ui/customer_app/app.js` (a wallet card ~line 503: available / persistent / plan), `components.css`, `tokens.css` | **W6** |
| Notifications / email | `notifications` read (`provision.customer_notifications`), `ui/email_channel.py` (NTF-4 delivery proof) | W3, W5 |
| Trial / report unlock | `governor/trial_policy.py` (`VIGIL_TRIAL_CREDITS`), `governor/report_unlock.py` (`ReportUnlockRegistry`), `ui/finding_preview.py` | check §11.14 |
| No estimates today | The customer app shows no estimate and no money amount for a scan (verified 2026-11-16: no `estimat`/`$`/`usd` in `customer_app/app.js`); M5 was never built | keep it so (test in W6) |

### 11.4 Invariants every W-slice must keep (each needs a test; each guard a mutation)
- **I1** No billable operation starts without enough balance or a valid reserved allowance (reserve BEFORE forward /
  start; the worst case of an indivisible operation is reserved, the actual reconciled after).
- **I2** No customer balance ever goes negative through spending. An owed amount exists only from a chargeback /
  reversal and is recorded separately (arrears), never as a negative wallet.
- **I3** Exactly-once: every charge counted once (signed `entry_id`s / per-request `rid`), every settle once per
  `(slug, nonce)`, every webhook once.
- **I4** Reconciliation: for a settled scan, Σ its statement lines (mc) == its settled consumption (mc) == the
  wallet + remainder movement it caused. The latest statement balance-after == the exact remaining balance.
- **I5** Credits only on customer surfaces; no estimate; no model name; no money amount for a scan.
- **I6** Tenant isolation: every read and every meter is org-scoped; one tenant's usage never appears for another.
- **I7** Default-OFF and byte-identical when off: with `VIGIL_METERED_BILLING` unset, flat launches settle exactly as
  today (the existing flat tests must stay green untouched).
- **I8** Fail closed on ambiguity: an unreadable / broken meter, a malformed rate card, an unknown pause state →
  no charge on a guess; defer (retry) or quarantine, and surface it in `vigil doctor`.
- **I9** Limits are enforced in CODE (gateway, scheduler, LaunchGate) — never by agent instructions. Concurrency,
  late usage reports or uncontrolled external calls cannot push usage past prepaid authorization; spend that cannot be
  confirmed is VIGIL's cost, never the customer's. **One deliberate exception (M1, §10.4, kept by W2a):** a 200
  response whose usage the gateway cannot read (malformed, unpriceable) is charged its reservation, so it never runs
  free; the meter flags it (`charged_reservation`) and the statement shows it as its own line.
- **I10** Internal provider cost (nano-USD) stays in the cost ledger / meter's `cost_nano`; it never feeds a
  customer amount (customer amounts come only from the rate card).

### 11.5 W2 — wallet-backed rolling reservations, rate-card charging, exact settlement (the core slice)
**Goal.** Replace "reserve a fixed chunk at launch; charge = AI cost × markup clamped to [floor, reservation]" with
"charge = Σ rate-card lines in milli-credits, drawn progressively from the live wallet through extendable
allowances, settled exactly to the milli-credit". Behind `VIGIL_METERED_BILLING` (still OFF); flat unchanged (I7).
Expect 2–3 PRs (W2a gateway mc + allowance read; W2b extensions + index/settle; W2c remainder + balance-after).

(a) **Customer charge on every meter line.** In `model_gateway.py`, when a response is committed
(`GrantMeter.commit` → `_settle`), compute `lines = rate_card().ai_lines(usage)` and record `amount_mc = Σ` on the
`usage` line, plus `rate_card_sha` (sha256 of the canonical published card) so a later card change never re-prices
recorded usage; record the worst-case `reserved_mc` on the `open` line. Keep `cost_nano` (internal, I10).
`_replay_records` gains `charged_mc` / `pending_mc` totals; `MeterTotals` gains them. A meter written before W2
(no `amount_mc`) is priced from its `usage` with the card at settle time — deterministic; test it. Load the card once
per gateway start (a malformed `VIGIL_RATE_CARD` → the gateway refuses to start, doctor hard issue).
(b) **Worst case in mc.** Mirror the gateway's existing nano-USD worst case (input estimate priced at
max(input, 5-min write) except the cached prefix at the cache-read rate, + `max_tokens × output`), but with the rate
card's mc rates. Keep the nano-USD reservation as well (internal ceiling / G1).
(c) **Allowance.** A launch's allowance (mc) = 1000 × Σ its owner-signed reservation records. At `reserve_launch`
reserve `min(available, CHUNK)` with `CHUNK = VIGIL_ALLOWANCE_CHUNK_CREDITS` (an engineering holding granularity, not
a price — default 100; document it). Refuse to start when the available balance cannot cover one request's worst
case at the minimum useful `max_tokens` (the gateway already refuses < 1,024 affordable output tokens).
(d) **Extension.** When `charged_mc + pending_mc + worst_mc > allowance_mc`, the gateway asks for one more chunk:
`LaunchGate.extend_reservation(org, slug, nonce, chunk)` — in-process if the gateway runs in the cockpit process
(`ui/server.py::serve` calls `model_gateway.start_from_env()`; the Provisioner/LaunchGate live in the same process —
**verify**; if not, add an owner-authenticated loopback call, never a keyless one). An extension = new owner-signed
reserve record(s) per bucket with `entry_id = reserve-<bucket>:{slug}:{nonce}:x{k}` (k = 1, 2, … computed under the
per-launch lock from the extensions already on the spine, so a retried extension is idempotent). Bucket draw order =
what `reserve_launch` / `CreditMeter` does today (read it; do not change it). Refuse (→ W3 pause) when the balance
cannot cover the request's worst case; refuse when the lease is settled, customer-paused, or the org is on a billing
hold (W5). Extension never re-runs the ownership/authority checks (the launch was authorised at reserve).
(e) **Index + settle for multiple reserve records per lease.** `governor/launch_reservations.py`: `Reservation.units`
must SUM the base record and every extension per bucket (dedup by `entry_id`), keeping "first wins" only per
`entry_id`. Then audit every consumer: `ui/launch_gate.py::_settle_once` (K4-1 invariant), `launch_settlement.py`,
`settle_hold.py` (`PLAN_DEBIT_PRUNED`), `ops_sweeps.sweep_abandoned_reservations`, `paused_expiry_settle.py`,
`settle_checkpoint.py`, the plan/wallet split that must survive a hard prune (`8a26cf65`: leases record their split —
extensions must record their own split in their signed records, and the snapshot must carry it:
`spine/snapshot.py`, `spine/prune.py`), and the fold-cache ledger views (`governor/ledger_view.py`,
`spine/fold_cache.py`). Write the failing tests first.
(f) **Exact settlement (milli-credits).** The wallet stores whole credits (`_DEBIT_CORE` integer `credits`).
Recommended, additive design — a per-org **usage remainder**: at each metered settle, under a per-org lock (follow the
existing cross-process lock pattern of `launch_settlement.py` / the publish `flock` in `MODEL_METER_DIR`), read the
org's remainder `r` (0–999 mc; from its last owner-signed remainder record, snapshot-durable), compute
`t = r + consumed_mc`, `debit_credits = t // 1000`, `r' = t % 1000`, and sign it INTO the settle decision
(`{consumed_mc, debit_credits, remainder_before, remainder_after}`, idempotent per `(slug, nonce)`). Refund per bucket
= reserved − debited (existing split logic). The exact remaining balance = `1000 × wallet.available − r'` mc.
Enforcement and display use the exact value. (Alternative only if this fails review: a versioned milli-credit debit
record in the wallet ledger — touches every money fold, the snapshot and the fold cache.) Never round a charge up to
a whole credit; never let the exact balance go below zero (I2).
(g) **Retire the floor** (owner): remove `run_floor_credits` / the `floor` from the metered settle path
(`credits_for_cost` stays for flat/legacy and its tests); `vigil doctor` reports a set `VIGIL_RUN_FLOOR_CREDITS` as
retired (pattern: `model_metering.obsolete_pricing_settings`). Update the tests that pinned the floor, citing the
owner decision of 2026-11-16.
(h) **Explicit depth.** Today the run tier is derived from the reserved units (`vigil_core/run_tier.py`, EC-7b
products). Add the depth (`quick | deep | max`) as an explicit owner-signed lease field (bump the lease document
version; `engine/crucible/framework/v2/launch_lease.py` verifies; old leases stay valid and keep the derived tier);
`catalog.launch_product` selects a depth, not a credit amount; the grant's effort comes from the depth.
(i) **Grant cap.** `ModelGrant.cap_nano_usd` stays as a hard per-token ceiling (a leaked token is still bounded): set
it from `VIGIL_GRANT_CEILING_CREDITS` (or the customer's per-scan limit when set, W3) converted to provider cost;
the binding customer limit is the allowance, enforced per request.
(j) **Balance-after on the statement** (requirement "each charge shows … remaining balance"): extend
`ui/billing.py::billing_usage` with `balance_after_mc` per line = purchased-to-date − consumed-to-date (all the org's
scans, in timestamp order). Define and show two numbers: **remaining** (bought − consumed) and **available to start
work** (remaining − allowances held by running scans). Test I4: the latest `balance_after_mc` == the exact remaining.
(k) **Retire the envelope defect** — `vigil_core/credit_lease.ENVELOPE_TOKENS_PER_CREDIT` (100,000 tokens per credit;
sells AI at ~5% of cost, design §4.2): find every use (`grep -rn ENVELOPE_TOKENS_PER_CREDIT`) and make sure no
metered path reads it.
**Tests (minimum, name them):** extension race (two gateway threads + a concurrent settle) never double-reserves or
over-reserves; extension idempotent on retry; extension refused at zero balance (→ W3 hook called); settle with N
extensions refunds exactly per bucket; settle after a hard prune with extensions; remainder exact across 3+ settles
(e.g. 2.502 + 0.499 + 0.001 → 3 credits debited, remainder 2 mc); two orgs settling in parallel; pre-W2 meter priced
at settle; malformed card refuses gateway start; flat mode byte-identical; **failure injection:** crash between an
extension record and the gateway's allowance cache (restart re-reads the spine), crash between the settle debit and
the remainder record (exactly-once on re-drive), duplicate completion signal.
**Mutation targets:** sum → first-wins in `Reservation.units`; skip the extension lock; ignore `pending_mc` in the
admission check; round the debit up; drop the remainder; price with the wrong card version; let the exact balance go
negative; keep the floor.

### 11.6 W3 — pause on insufficient credit, resume after top-up
**Triggers:** an extension refused for balance (W2 d); the customer's per-scan limit reached; an org billing hold
(W5).
- **Gateway response:** an Anthropic-shaped, NON-retryable error — HTTP 403
  `{"type":"error","error":{"type":"permission_error","message":"VIGIL: credits exhausted — the scan is paused"}}`.
  Verify with fakes that Strix (LiteLLM) and Claude Code treat it as terminal (no retry storm). Never forward a request
  past the refusal.
- **Pause:** the sovereign records a pause marker with reason `insufficient_credits` (extend
  `credit_lease_pause` with a reason field, add-only, old markers still read) and appends a customer notification +
  email (`notifications`, `ui/email_channel.py`). The offense side already honours the pause marker between phases
  (the PR-1..PR-5 pause/resume chain); `engage.py` checkpoints every phase (`PhaseLedger`), Strix `--resume`. Confirm
  FACTs/evidence are already persisted (signed at confirmation) before the stop. Worker time (W4) stops being billed.
- **Per-scan limit:** the customer may set `limit_credits` at launch (custui `launch/reserve` body → provisioner
  validates an int ≥ 1 → an owner-signed lease field). At 90% of it: one notification (the gateway's
  `GET /v1/vigil/budget` already exposes `fraction_used`). At 100%: pause. "Raise limit + resume" = a new owner-signed
  limit record + resume.
- **Resume:** the customer clicks Resume after topping up → provisioner `launch_resume` → `LaunchGate.resume_launch`
  (exists) must now: re-check the exact balance, take an extension (W2), clear the pause marker, re-trigger the job
  with resume (`jobs/launch_trigger.py`). Completed phases are not re-run; no request is re-charged (per-`rid`
  meter lines). Auto-resume only when A1 auto top-up is on and its payment is confirmed (billing-drain hook).
- **7-day close:** a scan paused for credit and not resumed within `VIGIL_CREDIT_PAUSE_TTL_S` (default 604800) is
  settled by the drain / sweep as "charged what it used" (the owner's paused-abandoned rule); results remain.
  **Lease-window caveat:** a lease window is at most a week and a resume after it refuses re-drive
  (`record_paused_past_expiry`, §10.5). Read `framework/v2/launch_lease.py` + `resume_launch` and choose: an
  owner-signed window continuation for credit pauses, or a continuation lease bound to the SAME meter. Keep one meter
  per scan so the statement stays continuous. **VERIFIED 2026-11-16 (check-don't-assume #4):** the Provisioner reserves
  with the DEFAULT window — `_DEFAULT_LEASE_HOURS = 8.0` (max a week) — and a grant lives at most 7 days + 1 h from the
  lease's start (`MAX_GRANT_LIFETIME_S`); a run armed in the window keeps running past `not_after`, but a RE-ARM (the
  resume re-drive) after it is refused by the seam poller, the pickup gate and the arm, and `paused_expiry_settle`
  settles a paused launch whose window closed. So a credit pause can outlive its lease (8 h) and its grant, and the
  continuation is REQUIRED, not optional: `CreditLaunchLease.continue_of` (a signed v2 field nothing uses yet) is the
  hook; count the 7-day TTL from the pause, not from the lease.
- **Tests:** E2E with a fake upstream: run → balance hits zero → 403 → marker → phases stop → notification →
  sandbox top-up (signed webhook fixture → `billing-drain`) → Resume → completes; no duplicate charge; evidence intact;
  statement continuous; 7-day close; 90% warning once; limit pause + raise; two scans of one org racing for the last
  credits (one pauses, the balance never goes negative).

### 11.7 W4 — worker-time and premium-API metering
- **Worker time** (1 credit/min, billed per second: `rate_card.worker_line(seconds)`). Measure it on the SOVEREIGN
  side — the offense worker is keyless and must not self-report. Add `POST /v1/vigil/worker/heartbeat` to the gateway,
  authenticated by the run's grant: each heartbeat commits the seconds since the previous one (bounded by the slot it
  had reserved) and reserves the next slot (default 60 s) from the allowance (W2); no heartbeat → the slot lapses and
  only time up to the last heartbeat is billed (the unconfirmed slot is VIGIL's cost, I9). Meter line kinds
  `worker_open` / `worker` in the same hash-chained file (extend `_replay_records`; generalise W1's `usage_records`
  into `charge_records`). `jobs/engage_worker.py` heartbeats every ~30 s while running, stops on a refusal (→ W3).
  Paused or idle = no heartbeat = no charge.
- **Premium APIs:** inventory first — no paid third-party API is billed today (a 2026-11-16 grep for common paid
  intel APIs in `framework/v2` found none). Each paid API must go through a SOVEREIGN proxy that holds its key
  (the model-gateway pattern), reserves the call's rate before forwarding (`rate_card.premium_line`) and writes a
  `premium` meter line. No published rate → refused (`RateCardError`), never free and never unmetered. Rate = the
  API's provider cost × the AI card's credits-per-provider-dollar; compute it privately, commit only the resulting
  credit rate (never the multiple — §0.3 #8), and confirm each new rate with the owner in a popup.
- Statement operations: "Scan-worker time", and the API's label.

### 11.8 W5 — chargebacks, reversals, refunds; the low-balance alert
- **Stripe** (the payment provider since 2026-11-16). Event names VERIFIED from docs.stripe.com/api/events/types
  (2026-11-16): disputes (`data.object` = Dispute) `charge.dispute.created`, `charge.dispute.funds_withdrawn` (funds
  removed from the account), `charge.dispute.updated`, `charge.dispute.closed` (status `won` | `lost` |
  `warning_closed`), `charge.dispute.funds_reinstated` (funds returned after the dispute closes); refunds
  `charge.refunded` (`data.object` = Charge, incl. partial refunds) and `refund.created` / `refund.updated` /
  `refund.failed` (`data.object` = Refund); early fraud warnings `radar.early_fraud_warning.created` / `.updated`.
  Re-fetch every object from Stripe before acting (the existing provider never trusts a body). **OPEN (owner, ask with
  a popup before building):** remove the disputed credits when the dispute opens / funds are withdrawn, or only when
  it closes `lost` (and re-grant on `funds_reinstated`)? Extend `governor/billing.py` (EVIDENCE → owner-signed FACT; `billing_spool`,
  `vigil billing-drain`): a verified reversal → an owner-signed reversal record that debits `min(disputed,
  available)` from the wallet; the rest goes to the arrears ledger (`governor/postpaid.py`, `postpaid_debit`) as
  owed; an owner-signed **billing hold** on the org that `LaunchGate.reserve_launch` and W2 extensions refuse
  (running scans pause at their next extension). The next top-up grant first repays the arrears (drain-side,
  idempotent), then lifts the hold. Alert the owner (`integration/vigil_integration/unit_alerts.py`, a `vigil doctor`
  hard issue, a notification). Balances never negative (I2).
- Owner-initiated refunds of unused credits use the same path (reason `refund`). Failed / interrupted operations are
  already handled by the settle rules (failed = 0; a VIGIL-side loss = full refund).
- **Low-balance alert:** threshold `max(100, 20% × last top-up)` credits; fires once per crossing (idempotency key =
  org + the last top-up's entry id); email + dashboard notification; re-arms after the next top-up.
- Tests: signed / unsigned / replayed reversal; a reversal larger than the balance → arrears + hold; the hold blocks
  reserve and extension; the next top-up repays then lifts; the alert fires once and re-arms.

### 11.9 W6 — the customer billing dashboard
- `apps/sigil/sigil/ui/customer_app/app.js` (+ `components.css`, `tokens.css`). Reads `/api/customer/billing`,
  `/api/customer/billing/rates`, `/api/customer/billing/usage` (W1) and new reads for live consumption of running
  scans (charged + held per scan, from the meter + allowances) and paused scans; actions: Resume (W3) and one-click
  Top up (the CHK-2 offers `/api/customer/billing/offers` + `billing_checkout`, behind `customer_checkout_enabled`).
- Show, in plain language: available credits (2 decimals, rounded down); on hold for running scans; credits bought;
  credits used; live consumption per running scan; spending history by project / scan / operation; the published
  rates; the low-balance notice; Top up; paused scans awaiting credit with Resume. No estimate, no money amount for a
  scan, no model name — add a test that scans every billing payload and the rendered page strings for model ids,
  `$`, `usd` (outside the rate-conversion constant) and `estimat`.
- Every new customer read route joins the leak-scan census (`apps/sigil/tests/test_finding_preview_edge.py::_SCANNED`
  — the census test REDs otherwise) and the live-route assertion there. The CodeQL JavaScript advisory job scans
  the JS.

### 11.10 M1c-2 deltas
As §10.6 row M1c-2, plus: runners treat the W3 403 as a terminal pause (no retries); `engage_worker` sends the W4
heartbeat; in metered mode the offense plane holds no provider key (doctor note). M1c-2 can be built in parallel with
W2/W3 but `VIGIL_METERED_BILLING` stays off until all three are merged.

### 11.11 G1 — gateway at scale
Stand-ins today: `VIGIL_GATEWAY_TENANT_CONCURRENCY` (4), `VIGIL_GATEWAY_GLOBAL_CONCURRENCY` (32),
`VIGIL_GATEWAY_DAILY_LIMIT_USD` (unset = none) in `model_gateway.py`. Build: (1) capacity sized from the provider's
rate-limit response headers — **VERIFIED 2026-11-16 (check-don't-assume #3) from platform.claude.com/docs/en/api/
rate-limits:** `retry-after` (seconds; not on every 429 — the spend-cap 429 `rate_limit_error` never carries it),
`anthropic-ratelimit-{requests,tokens,input-tokens,output-tokens}-{limit,remaining,reset}` (`*-reset` RFC 3339; token
`*-remaining` rounded to the nearest thousand; `tokens-*` show the most restrictive limit in effect) and
`anthropic-workspace-id`; limits are RPM, ITPM (cache-aware) and OTPM per model class. The gateway passes through only
`request-id`, `retry-after`, `x-should-retry` today (`_PASS_RESPONSE_HEADERS`) — G1 must READ these; (2) a per-tenant fair share
in requests AND tokens per minute; (3) a pool of provider accounts — several Anthropic workspace keys, Bedrock and/or
Vertex as overflow (different request APIs: re-validate the allowlist and pinning per provider; the prompt cache does
not cross providers), with health checks and failover; (4) the loss alarm: day's unconfirmed provider spend >
2% of the day's confirmed provider spend → new reservations refused + owner alert (doctor hard issue + unit alert).
Load-test with fake upstreams only.

### 11.12 Wallet E2E (simulated) — the acceptance test of the program
One test module drives the §11.1 journey end to end with a fake model upstream and a signed sandbox-payment webhook
fixture: two orgs concurrently; buy → wallet shows credits → launch with no estimate → live consumption → exhaustion
→ pause → top-up → resume → completion → exact settle → statement reconciles with the ledger (I4). Failure
injection: kill the gateway mid-request, kill the settle mid-way, duplicate webhook, duplicate completion signal.
Assert I1–I10. No real payment, no production AI call.

### 11.13 A1 — auto top-up
Off by default; customer-set trigger balance, pack and monthly cap; needs a saved card — on STRIPE: a saved
PaymentMethod on the org's Customer and an off-session PaymentIntent (verify the API and its webhooks at A1); never
above the cap; a receipt per charge; after a confirmed payment, auto-resume
the org's credit-paused scans (W3 hook).

### 11.14 Trial
`VIGIL_TRIAL_CREDITS=450` (owner, at deploy). Check `governor/trial_policy.py` enforces one trial per verified email
AND per verified domain (add the domain dedup if missing) and that the full report unlocks on the first purchase
(`governor/report_unlock.py`, `ui/finding_preview.py`). Ownership proof is still required to scan.

### 11.15 Enterprise and seats
A signed contract or a paid invoice credits the same wallet (`governor/invoices.py`; verify the paid-invoice → grant
path exists, add it if not); trusted customers may get a credit line (`governor/postpaid.py`). The $25 seat includes
no credits — check `governor/catalog.py` / `governor/subscription.py` grant none by default.

### 11.21 W2c-1 — MERGED (#1140 → `198b8f37`, 2026-11-16): exact settlement, the floor retired
Implements §11.5 (f) and (g). The decided design, everything built, the tests, the mutants and the risks are in §15.2;
when its PR merges, move that text here. In one line: the owner-signed `governor.launch_settled` v3 decision is the only
place an org's sub-credit remainder moves; the wallet fold derives the remainder from the lifetime Σ `consumed_mc`
(snapshot schema 11 carries it across a hard prune); a metered settle keeps ⌊(r + used)/1000⌋ whole credits; metered
reserves (under the settle lock) and extensions draw from the exact balance; `VIGIL_RUN_FLOOR_CREDITS` is a retired
setting; no settle reads the target margin.

### 11.20 W2b-3 — DONE (merged in #1134, `02bfcdcf`): the explicit depth in the lease + the first allowance
Implements §11.5 (c) and (h). Behind `VIGIL_METERED_BILLING` (OFF); a flat launch passes, reserves, signs and settles
exactly as before (I7).
- **Depths** (`vigil_core/run_tier.py`): `DEPTHS = ("quick", "deep", "max")` — a superset of the units band's
  `RUN_TIERS`, which never derives `max`. Effort Quick = high, Deep = xhigh, Max = max; Max runs the full roster with
  model routing off. `depth_of(named, units)` / `lease_depth(doc)`: the depth the lease names, else the tier its units
  derive; a value that is not a depth resolves to Quick (never an escalation).
- **The lease** (`vigil_core/credit_lease.py`): the prepared v2 field `run_tier` carries the depth (now any `DEPTHS`
  value), and a new optional field `version` = `LEASE_DEPTH_VERSION` (3) marks a lease that names one — the "bump the
  lease document version" of §11.5 (h). Every older reader is `extra="forbid"` without that field, so it REFUSES a
  depth lease instead of re-deriving a tier from its allowance chunk; a version-3 lease must name its depth; a reader
  refuses a version it does not know. Leases that name no depth carry neither field and keep their exact bytes (the
  golden v1 fixture is unchanged). Every depth lease the gate mints carries the version; a v2-format lease naming a
  `run_tier` without one (the prepared format of `8a26cf65`, never minted by any release) is still read.
- **The first allowance** (`ui/launch_gate.py::reserve_launch(..., depth=)`): a metered launch holds
  `min(max(chunk, one useful request), live balance)` — plan credits count and are drawn plan-first; a postpaid
  launch draws from its credit line's live headroom instead — sized under the spine lock. It is refused, nothing
  debited and no amount quoted, when that cannot cover ONE useful model request: `model_gateway.min_request_mc` =
  the least the gateway ever reserves for one (one token of content + the 1,000-token framing margin, at the dearest
  input rate, which is what a prepaid reservation always uses, + 1,024 output tokens) = **7.965 credits** at the
  published card. The floor of one request matters because a postpaid or plan-funded launch cannot be extended.
  The bound is a SOUND lower bound (it never refuses a launch that could make a request): between it and about 8.1
  credits a launch may start yet see its first request refused, depending on the provider's count of the shaped
  prompt (the gateway's per-tenant system block is in it) — such a run has no admitted request and is never charged
  (pre-W3 it fails and is refunded; W3 pauses it for a top-up).
- **The chunk** is read by ONE function, `vigil_core.model_metering.allowance_chunk_credits()` (1 to 1,000,000,
  default 100 — a holding size, not a price), used by the launch path, the gateway (`config_from_env`) and doctor.
- **The product selects a depth** (`ui/provision.py::launch_reserve`, both the ordinary and the locked-trial branch):
  metered → the product's depth (Quick when none is chosen) and the chunk, never the product's units. No Max product
  is offered yet: Max on live systems needs L1's controls first (design §6).
- **The grant's effort** comes from `lease_depth(doc)` (`_publish_model_grant`); re-publishing still mints the
  identical grant.
- **Fail-closed edges:** a lease that names a depth is never published flat (metering resolved off after it was
  reserved → refused; the customer cancels it for a full refund); a completed launch whose lease names a depth but
  whose meter and metered marker are gone is quarantined by the completion drain, never charged its whole chunk.
- **Engine / worker:** `framework/v2/launch_lease.read_verified_launch_depth` (verify-only, same owner-pinned
  verify + bind); `jobs/engage_worker.py` runs the depth the lease names for the EC-7 roster / routing (an injected
  `read_depth` outranks `read_units`; every value passes through `depth_of`).
- **Interim limits, for W2c and later:** (1) the metered settle still prices with `credits_for_cost` and the per-run
  floor, clamped to lease + extensions — with the chunk as the reservation the 25-credit floor now binds in full on a
  tiny run; W2c (f, g) settles the recorded `charge_mc` exactly and retires the floor. (2) `ENVELOPE_TOKENS_PER_CREDIT`
  (the EC-3 engine hard budget, the EC-5 cost ledger — both default-OFF) still multiplies the lease units, which are
  now only the first chunk: W2c (k) must take it off every metered path before the metered flip. (3) Postpaid
  launches are still not extended (§11.18). (4) Reserves and the gateway's extensions run in the one cockpit process
  (the spine RLock serialises them); a multi-process layout (Front C S2+) must take the cross-process settle lock in
  the reserve too.
- **Tests:** `apps/sigil/tests/test_launch_depth.py` (new), `test_trial_launch.py` (+1),
  `packages/core/vigil_core/tests/test_run_tier.py` (+4), `test_credit_lease.py` (+4), `test_model_metering.py`
  (+2), `engine/crucible/framework/v2/tests/test_launch_lease.py` (+2), `test_run_tier_conformance.py` (+1),
  `integration/tests/test_engage_runner.py` (+2). **37 mutants, all RED** (sizing, the lock, the one-request floor
  and start check for prepaid and postpaid, the input margin, the depth and version stamps, version refusals, the
  flat-publish refusal, the meterless quarantine, product → depth, the trial branch, the chunk reader + its bound,
  the gateway / doctor readers, the engine and worker depth reads, the depth vocabulary).
- **Red-pen:** three lenses (money / lease + planes / spec + tests) and a verifier (10 findings CONFIRMED, 4 merged
  as duplicates, none refuted on substance — every one folded, each with a test and a mutant); folded: the start check ignored the
  gateway's input margin (7–8 credit wallets admitted but never servable); a first allowance could be below one
  request (postpaid / plan-only launches stuck); no upper bound on the chunk; no lease version (an older plane would
  misread a quick / deep depth lease); a meterless depth lease could settle flat for its whole chunk; unpinned
  branches (postpaid threshold, trial branch, plan funding, worker injection, the invalid-chunk audit); docstrings
  that claimed W2c's exact pay-for-use settle.
- **Local evidence:** the slice's suites pass locally except failures that are identical on `main` and come from
  this machine (an onnxruntime older than the lock; a UI socket timeout under load). Tests that spawn an isolated
  verifier need a venv whose editable installs point at the slice (the shared `.venv-sovereign` resolves to another
  checkout); with one, they pass.
- **Next — W2c-1:** exact settlement with the per-org milli-credit remainder (§11.5 f) — snapshot-durable, signed into
  a v3 settle decision, enforcement and display on the exact balance (reserve and extension must draw from
  `1000 × available − r`, or the exact balance can go below zero by up to the remainder) — and the floor retired from
  the metered settle (g). Then **W2c-2:** balance-after per statement line (j) and `ENVELOPE_TOKENS_PER_CREDIT` off
  every metered path (k).

### 11.19 W2b-2 — DONE (merged in #1133, `454d9ac3`): gateway admission against the prepaid allowance
- `model_gateway.GrantMeter.reserve(..., allowance_mc=)`: a request is admitted only if its worst-case CUSTOMER charge
  fits beside the launch's confirmed charges and the requests in flight (output lowered to fit, like the cap); when
  not even the smallest useful request (1,024 output tokens) fits beside the confirmed charges → refused
  `allowance`. Unconfirmed spend never counts (I9). `_fit_tokens` = binary search on the monotone worst case.
- `ModelGateway.ensure_allowance(grant, need_mc)`: one decision per launch at a time (per-meter lock); caches the
  allowance; when short, takes ONE extension of `max(VIGIL_ALLOWANCE_CHUNK_CREDITS (default 100), shortfall)`
  credits, capped at the wallet balance, through the in-process source. A busy settle lock → retryable 429; an
  unreadable allowance → retryable 529; a wallet that cannot cover it → the request is lowered or refused with a
  NON-retryable **403 `permission_error` `CREDITS_EXHAUSTED`** (W3 turns that into a pause).
- `GatewayConfig.allowance` / `allowance_required` / `allowance_chunk_credits`; `config_from_env(allowance)` sets
  `allowance_required = metered_billing_enabled()`; **`start_from_env(allowance=)` refuses to start while metered
  billing is on and no source is given** (logged; metered runs fail closed; doctor reports the gateway not answering).
  A gateway with `allowance_required` and no source admits nothing (529).
- `ui/launch_gate.py::LaunchAllowance(gate)` — the source: `allowance_mc(grant)` = 1000 × (the OWNER-SIGNED seam
  lease's `units_reserved` + extensions), verified under the owner key and bound to the grant's (org, slug, nonce);
  None on any mismatch, unverifiable lease or pruned extension. `available_credits`, `extend` →
  `LaunchGate.extend_reservation`. `ui/server.py::serve` passes `LaunchAllowance(LaunchGate(srv.store()))`.
- The published grant's `cap_nano_usd` is now a technical CEILING: `usd_cap(max(units, VIGIL_GRANT_CEILING_CREDITS))`
  (`vigil_core.model_metering.grant_ceiling_credits`, default 1,000,000 credits — an engineering bound on a leaked
  token, not a price; the owner may change it). `vigil doctor` validates both new settings.
- Tests: `test_model_gateway.py` (+11: admitted inside; extends first; exhausted 403 with nothing upstream; max_tokens
  lowered to fit; confirmed charges count; busy/unreadable retryable; required-without-source admits nothing;
  concurrent requests extend once; `_fit_tokens`; no metered start without a source); `test_allowance_extensions.py`
  (+3: the real source reads the signed lease + extensions and refuses another launch / org; never reads a pruned
  extension; grant capped at the ceiling); `test_doctor_metering.py` (+1); `test_graceful_stop.py` now pins that the
  cockpit passes a `LaunchAllowance`; `test_metered_billing.py` pins the ceiling cap. 13 mutants, all RED.
- **Takeover review, 2026-11-16:** cockpit wiring now supplies the actual `SpineStore`; the test exercises a
  wallet read through it. Extensions refuse a paused or unreadable launch under the existing settle lock. Admission
  requires a readable signed allowance after extending, invalidates its cache before a possibly committed debit,
  and refuses non-insufficient extension errors. Interrupted extensions recover the signed debit before retrying.
  Prepaid reservations cover an early provider cache eviction; actual cache-hit charges retain the recorded rate.
- **Local evidence:** 329 gateway, extension, cockpit shutdown, metered billing, customer charge, usage statement,
  and doctor tests passed. Sixteen takeover guard mutants went RED against named tests: in-flight/confirmed charges,
  cache eviction, debit cache invalidation, paused/unreadable pause state, real store wiring, extension refusal,
  signed allowance reread, interrupted debit, allowance enforcement, required source at admission/startup,
  busy extension, extension shortfall, and grant ceiling. Restored-source verification passed (920 tests, 7 skipped, including documentation and CI-policy tests);
  updated-head CI remains required; the prior session's 13-mutant report above is historical evidence, not a new run.
- **Takeover tooling:** pinned ruff passed; money hygiene and staged gitleaks passed. Local mypy 2.3.1 completed
  but its ratchet failed because `sigil/voice/components.py` appeared type-clean (stale ratchet entry). No ratchet
  exemption was changed; the updated-head CI lint result is still required before merge.
- **Note for the next agent:** running `mypy` on `packages/core/vigil_core` from a worktree OUTSIDE the repo path
  reports 7 pre-existing errors in `run_budget` / `install_manifest` / `highwater` / `signed_build_manifest` that do not
  appear from the repo path (same files) — an environment artefact; CI and the in-repo run are clean.
- **Next — W2b-3:** the explicit depth in the owner-signed lease (§11.5 h) and the first reservation sized
  `min(available, CHUNK)` at `launch_reserve`; then **W2c**; then **W3** (the 403 becomes a pause + resume).

### 11.18 W2b-1 — DONE (merged in #1132, `cc227ccc`): allowance extensions in the launch's own settle unit
**Design decisions (read before W2b-2):**
- **An extension is part of the SAME launch**, not a new reservation: one more owner-signed WALLET debit with
  `entry_id = reserve-wallet:{slug}:{nonce}:x{k}` (k = 1, 2, … consecutive; canonical decimal). The launch's ONE
  exactly-once settle (`_settle_once`, keyed `(slug, nonce)`) refunds or keeps it with the rest. (A separate nonce per
  extension was rejected: the superseded sweep / E7 would see a live run's extension as a superseded launch and refund
  it mid-run.)
- **Prepaid WALLET only.** Consumption eats the lease's expiring plan share first and the rest is refunded to the
  wallet — so settling on `reserved = lease units + Σ extensions` keeps K4-1 and the plan/wallet split unchanged.
  A **postpaid** credit-line launch is NOT extended yet (`extend_reservation` refuses with `insufficient` → the run
  pauses at its reservation); postpaid extensions are a follow-up (they need `postpaid.in_flight_reserved` to fold
  `…:x{k}` keys under their launch).
- **Prune durability.** The wallet fold now also keeps each `reserve-wallet:` debit's AMOUNT for the live window
  (`WalletRegistry.reserve_debit`; `_WalletView.reserve_amounts`, maintained by the shared `_apply_wallet_record`, so
  the S0 audit still matches). An extension in the prune-durable seen-set whose amount left the live window HOLDS a
  fresh settle (`PLAN_DEBIT_PRUNED`, the existing owner alarm) — never guessed.
- **No race with settle.** `extend_reservation` runs under `self._lock` + the cross-process `settle_lock` and refuses
  once the launch's meter is closed; every fresh settle of a metered launch closes the meter inside the same critical
  section, then RE-READS the extension total (`allowance_check`) and retries with nothing written if it changed since
  the decision was built.
- **Verified (handoff "check, don't assume" #1):** the gateway runs IN the cockpit process (`ui/server.py::serve` →
  `model_gateway.start_from_env()`), the same process as the Provisioner / `LaunchGate` — W2b-2 can call
  `extend_reservation` in-process (no keyless hop).
**What changed:** `governor/wallet.py` (`reserve_debit`, `reserve_amounts`); `governor/launch_reservations.py`
(`extension_entry_id`, `_extension_of`, `Reservation.extensions`, `reserved` sums both); `ui/launch_gate.py`
(`extension_total`, `reserved_with_extensions`, `extend_reservation`, `_held_for`; `settle_launch` settles on lease +
extensions — only for a launch published metered, so a flat settle reads nothing more; `_settle_once(allowance_check=)`;
E7 `_release_refusal` → `metered` for any extended launch); `inbound/completion_spool.py` and `ops_sweeps.py` /
`paused_expiry_settle.py` (`_paused_metered_charge(..., org_id=)`) clamp the metered charge to lease + extensions.
**Tests:** `apps/sigil/tests/test_allowance_extensions.py` (15). 11 mutants, all RED (drain clamps to the lease; extend
a closed meter; skip the balance check; drop the in-lock re-check; settle on a pruned extension; settle ignores
extensions; index ignores extensions; E7 may release; paused charge clamps to the lease; fold forgets amounts;
non-consecutive k).
**Next — W2b-2 (gateway admission against the allowance):** the gateway gets an in-process allowance source from
`serve()` (`LaunchGate(srv.store)`): before forwarding, `charged_mc + pending_mc + worst_mc > 1000 × (lease units +
extensions)` → `extend_reservation(credits=CHUNK)` (`VIGIL_ALLOWANCE_CHUNK_CREDITS`, an engineering holding size,
default 100 — not a price) → refused `insufficient` → a NON-retryable 403 "credits exhausted" (W3 then pauses the run).
`start_from_env` must refuse to start without the allowance source while `VIGIL_METERED_BILLING` is on (fail closed).
The grant's `cap_nano_usd` becomes a high technical ceiling (a leaked token is still bounded by the wallet). Settle
stays on `credits_for_cost` until W2c switches it to the recorded `charge_mc` with the per-org remainder.
**Then — W2b-3:** the explicit depth in the lease (§11.5 h) and the first reservation sized `min(available, CHUNK)`.

### 11.17 W2a — DONE (merged in #1131, `9164ec92`): what it is
Implements §11.5 (a) + (b). No admission or settlement change: admission still runs on the grant's provider-cost cap
until W2b; settle still uses `cost_nano` until W2c.
- `vigil_core/rate_card.py`: `RateCard.charge(usage) -> (amount_mc, {unit: [mc, per]})` and
  `RateCard.request_worst_mc(input_tokens, cached_tokens, output_tokens)` (cached prefix at cache-read, the rest at
  max(input, 5-min write, cache-read), + output; one ceil — mirrors `_admit`'s provider-cost worst case).
- `model_gateway.GrantMeter(..., rate_card=)`: with a card, every `open` line carries `reserved_mc` and every `usage`
  line `charge_mc` + `rates` (+ `charged_reservation: true` for an unreadable 200, charged `max(lines, reserved_mc)`).
  A hold, a release, an orphan and a cut-off response's held part are never charged. `_LaunchState` / `MeterTotals`
  gain `charged_mc`, `pending_mc`, `unpriced_usage` (usage recorded without a charge — a pre-W2a meter or a meter
  with no card); `_replay_records` rebuilds them; `usage_records` returns the recorded charge + rates.
- `GatewayConfig.rate_card` (default `DEFAULT_RATE_CARD`; `config_from_env` loads `rate_card()` — a malformed
  `VIGIL_RATE_CARD` raises a `ValueError`, so `start_from_env` logs and does not start: metered runs fail closed).
- `_admit` passes `worst_mc=lambda out: card.request_worst_mc(tokens_in, cached, out)` to `reserve`.
- `ui/billing.py::_priced_lines`: the statement shows the RECORDED charge and rates (a later card change never
  re-prices past usage); a pre-W2a record is priced with the card in force; the lines always sum to the charge.
- `vigil doctor` (`_metering_report`): validates the card; a malformed override is a hard issue; reports
  `rate_card: published defaults | owner override`.
- Tests: `apps/sigil/tests/test_meter_customer_charge.py` (10), two end-to-end in `test_model_gateway.py`
  (hand-worked 22.189 credits for the fixture's usage; an unreadable response charged its reservation),
  `packages/core/vigil_core/tests/test_rate_card.py` (+2), `integration/tests/test_doctor_metering.py` (+1).
  9 mutants, all RED (held part charged; orphan charged; no max on unreadable; pending not dropped; replay ignores
  the recorded charge; statement re-prices; worst case ignores the 5-min write rate; no `reserved_mc`; doctor skips
  the card).
- **Next (W2b):** admission against the ALLOWANCE in mc (`charged_mc + pending_mc + worst_mc > allowance_mc` →
  extend, else refuse → W3), using these fields.

### 11.16 W1 — DONE (merged in #1130): what it is
- `packages/core/vigil_core/vigil_core/rate_card.py` — `MC_PER_CREDIT=1000`; `Rate(unit, mc, per, label).amount(q)
  = ceil(q × mc / per)`; `RateCard.ai_lines(usage)`, `.worker_line(seconds)` (per-minute rate charged per second),
  `.premium_line(name, calls)` (unpriced → `RateCardError`), `.published()` (credits only); `DEFAULT_RATE_CARD` = the
  owner's rates; `rate_card(env)` = default or the whole-card `VIGIL_RATE_CARD` override (a malformed one is refused
  whole; free AI tokens / worker time refused; finer than 0.001 credit refused); `format_credits(mc)`.
  Tests: `packages/core/vigil_core/tests/test_rate_card.py` (15).
- `model_gateway.GrantMeter.usage_records(mid)` — verified (hash-chain-checked) read of a launch's `usage` lines.
- `ui/billing.py::billing_rates()` and `billing_usage(store, org_id, *, trusted_pubkey, meter_dir)` — per-charge
  statement from the org's owner-signed reservations → each scan's meter → rate-card lines (operation, ts, quantity,
  unit rate, credits); a chain-broken meter → `status: unavailable`, never priced; never names the model.
- Routes `GET /api/customer/billing/rates` and `/api/customer/billing/usage` (`custui._READS` → `server.py` dispatch
  `billing_rates` / `billing_usage` → `provision.customer_billing_rates / customer_billing_usage`, `view_billing`).
- Tests: `apps/sigil/tests/test_billing_usage_statement.py` (5); census + live-route check in
  `apps/sigil/tests/test_finding_preview_edge.py`.
- Limits (by design, for later slices): AI lines only (W4 adds worker / premium); no balance-after yet (W2 j); the
  statement prices with the CURRENT card (W2 a records the card digest per line).

---

## 12. RED-PEN — owner decisions (2026-11-16) and build notes
Design: `PRICING-RED-PEN-DESIGN.md` §7 (pipeline: map → attack lenses → refute each with a sandbox reproduction that
fails twice on the reviewed commit → certify via `oracle_adapter.confirm_and_certify(..., provenance="reproduced")`
→ FACT; everything else stays a LEAD). Row specs R1–R5: §10.6. Decisions:
- **Trigger (R2):** every pull request on a connected repository, automatically (GitHub `pull_request` opened /
  synchronize webhooks through the existing route + job queue), billed by usage like any scan (no estimate), with an
  **optional per-repository monthly spending limit** set by the customer (owner-signed per-repo setting; refuse new
  reviews once the month's charged credits reach it; notify).
- **Blocking:** reproduced **Critical and High** findings block the merge via a GitHub **check run** ("VIGIL
  Red-Pen", conclusion `failure`; needs `checks:write` on the customer-facing GitHub App — owner registers it);
  Medium and Low are review comments only (`post_review_comment`, gated). Each customer can change the threshold per
  repository (none | critical+high | medium and up). Only FACTs are posted; LEADs live in the dashboard.
- **VIGIL Fix (R4):** a fix PR opens **only when the customer clicks "Fix this"**; the patch is re-reviewed (the
  reproduction now passes, the full suite passes, a Quick Red-Pen of the patch finds no new FACT) before its PR opens;
  never auto-merged. Existing anchors: `jobs/pr_bot.py`, `live/pr_checkout.py`, `live/codefix_runner.py` (its open-PR
  leg is disabled until LAP-3).
- **Platforms:** **GitHub only** at launch (GitLab / Bitbucket later).
- **Red-Pen · System (R3):** on demand, or on an optional weekly / monthly schedule the customer sets (owner-signed
  schedule record + a scheduler unit in the `vigil-billing-drain` systemd-timer pattern that enqueues the jobs).
- Everything runs through the metered gateway (M1c-2 first), in the S5 sandbox, with no network but the gateway and
  no secrets; "Claude Code" / "ultracode" never appear to customers.

## 13. SCALE TARGETS, GATE 5, DEPENDABOT, CODEQL
### 13.1 Front C S4 targets (owner, 2026-11-16 — recorded in `FRONT-C-1M-SCALE-DESIGN.md` §7)
A first acceptance run at **100,000** registered users, then **1,000,000**; **10,000** concurrent engagements; p99
login and page latency **under 500 ms**; the appends/s target follows from S1's measurement at that load. S1–S4 specs:
§4.4. The multi-shard production flag stays the owner's flip after S4 is green.

### 13.2 Gate 5 (updated for the wallet)
Signup → buy credits (Stripe **test mode**, never a live key or a real card) → webhook → the Stripe billing drain credits the
wallet → prove domain ownership → launch with **no estimate** → live consumption on the dashboard → exhaust credits →
pause with work preserved → sandbox top-up → Resume → an oracle-confirmed FACT → exact settle → the statement
reconciles with the ledger → `vigil doctor` / `vigil ready` clean. Repeat with `VIGIL_FOLD_CACHE_ENABLED=1`. Then the
S4 harness at §13.1's targets. Any real AI spend needs the owner's explicit authorisation; otherwise use the fake
upstream.

### 13.3 Dependabot (owner-approved plan, 2026-11-16) — DONE
**Done on 2026-11-16:** PR A = #1135 (`9eb4f64a`, the z3-solver floor `>=5.4.1.0,<6` in both engine `smt` extras;
pydantic ≥ 2.14.3 was already on `main` since `d2ba73f0`, #1120 was already closed) — #1121, #1124, #1126 closed with a
comment linking it; PR B = #1136 (`a43f8fd3`, the anthropic SDK 2.8, §15.3) — #1122, #1125 closed with a comment
linking it. Note on z3 5.4.1.0: its wheels are `manylinux_2_27_x86_64` / `manylinux_2_38_aarch64` only, so a
binary-only install on an older glibc cannot take the `smt` extra (recorded in #1135). The plan as it stood:
Open (then): **#1120** pytest-httpserver 1.2.0 → 1.2.1 (`engine/crucible/framework/v2`; `main` already carries 1.2.1 via
`d2ba73f0` — check, likely superseded), **#1121** z3-solver floor ≥ 5.4.1.0 (`engine/crucible`), **#1124** pydantic
≥ 2.14.3 (`engine/crucible`), **#1126** pydantic ≥ 2.14.3 (`packages/core/vigil_core`), **#1122** anthropic
`<1` → `>=2.8.0,<3` (`engine/crucible` dev), **#1125** anthropic `>=0.40,<3` (`engine/crucible/framework/v2` dev).
- **PR A — the minor bumps batched** (#1120 if still needed, #1121, #1124, #1126) through the hash-lock tooling
  (§0.7: pip-tools 7.6.1 under Python 3.13 from each lock's canonical CWD; the shared-pin guard needs pydantic /
  pydantic-core / cryptography to agree across the sovereign and engine locks; regenerate the offense SBOM; run
  `bin/verify-supply-chain.sh` for all three locks). Then close the Dependabot PRs it replaces, with a comment linking
  PR A (owner-approved).
- **PR B — the Anthropic SDK major upgrade** (#1122 + #1125) on its own: read the SDK's CHANGELOG / migration guide
  (the `claude-api` skill's `upgrade` subcommand covers the Python 0.x → 1.x+ path), update the call sites
  (`engine/crucible/framework/v2/kernel/backends/anthropic.py`, `live/think_claude.py`, any other `import anthropic`),
  run the offense legs + loopback engagement + strix P8; never call the real API in tests. Close #1122 / #1125 after.

### 13.4 CodeQL state after #1129 — the owner's dismiss list
#1129 fixed every genuine alert in the files it touched (a full-repo local scan showed it removing 33 alerts in
changed files and adding none). The remaining alerts are BY DESIGN; the **owner** dismisses them in GitHub (Security →
Code scanning → Dismiss) — the agent never does, never filters SARIF, never adds `paths-ignore` (§0.3 #9):
| Where | Dismiss as | Why |
|---|---|---|
| `executor.py`, `sandbox_exec.py`, console terminal | Won't fix | Running commands is the feature; owner-gated and sandboxed |
| uiproxy, aegis gateway, `ownership_fetch` (SSRF) | Won't fix | Fetching the operator's chosen, allowlisted target is the purpose |
| Scanner TLS probes (`quantum_era`, `verify/tls`, `websocket`, `egress_floor`), scripts/api cert-less requests | Won't fix | A scanner must connect to broken / self-signed TLS to report it |
| Operator target paths (codebase, sast, aegis), chat target, `verify_fix` root | Won't fix | The owner chooses these paths on their own machine |
| Clear-text logging (sigil cli, integration cli, `billing_spool`, `tools/livefire`, memory sync) | False positive | A name / status / redacted value is logged, never a secret |
| Escrow sha256 of the sealed blob; cleartext-storage cases | False positive | Integrity fingerprint of already-encrypted data, not password storage |
| `sigil/ui/settings.py` sha256 "password hashing" | False positive | A short display fingerprint of a high-entropy API key |
| `scanner/sso.py` XML bomb | False positive | Any DTD / ENTITY is rejected before parsing; no expansion possible |
| Benchmark / demo targets (`eval/benchmark_app.py`, `scanner/benchmark.py`, `analysis/benchmark/python/*`, `range/codebase-demo/*`) | Used in tests | Deliberately vulnerable practice targets (whether to `paths-ignore` them is OPEN — owner) |
`docs/audit/CODEQL-TRIAGE.md` holds the older triage record.

## 14. SESSION-LOCAL TOOLING ADDED 2026-11-16 (re-create; the scratchpad does not survive)
- **Find a "CodeQL" PR-check alert that has no inline annotation:** build the full-repo Python DB with the workflow's
  config (`paths-ignore: **/tests/**, **/test_*.py, **/conftest.py, docs/tests/**, **/eval/corpus/**,
  **/corpus_apps/**` via `--codescanning-config`), analyze with `python-security-extended.qls` to SARIF, do the same
  for `origin/main`, and diff the per-(rule, file) counts restricted to the PR's changed files. A single-file DB can
  miss an alert that needs its callers (the TLS-version query did) — include the package.
- **Targeted query:** `codeql database analyze <db> codeql/python-queries:Security/CWE-327/InsecureProtocol.ql
  --format=csv --output=x.csv` (any single `.ql` path under `Security/`).
- **gitleaks 8.28.0:** `gitleaks git --log-opts="origin/main..HEAD" --no-banner .` before every push.
- **Money hygiene:** `python3 tools/governance/money_hygiene.py ci --base origin/main --head HEAD` (after
  committing — it scans commit messages) and `... tree` for the working tree.
- The vigil_core suite: `cd packages/core/vigil_core && ../../../.venv-sovereign/bin/python -m pytest
  -p no:cacheprovider tests` (769 + 1 skip after W1).

---

## 15. TAKE-OFF POINT — end of the 2026-11-16 local session (READ THIS FIRST, then §0)

This section is the exact place to pick up. Everything in it was verified against GitHub at the time of writing;
re-verify with §15.10 before acting (another session may have moved things since).

### 15.1 Exact state
| Item | State | Anchor |
|---|---|---|
| `origin/main` | **`198b8f37`** (merge of #1140) | `git log --first-parent --oneline origin/main` |
| W2b-3 (explicit depth in the lease + the first allowance) | **MERGED** #1134 → `02bfcdcf` | §11.20 |
| Dependabot **PR A** — z3-solver floor `>=5.4.1.0,<6` in both engine `smt` extras | **MERGED** #1135 → `9eb4f64a`; closed #1121, #1124, #1126 (pydantic ≥ 2.14.3 was already on `main` since `d2ba73f0`); #1120 had been closed earlier | §13.3 |
| Dependabot **PR B** — the anthropic SDK 2.8 | **MERGED** #1136 → `a43f8fd3`; closed #1122, #1125 | §15.3 |
| **W2c-1** — exact milli-credit settlement + the floor retired | **MERGED #1140** → `198b8f37` (squashed `793cd477` + the mypy / wording fix `cb6645d7`; 23 mutants red; all 15 required checks green) | §11.21, §15.2 (the build record) |
| **NYX** — the agentic engine shown as "NYX" in the UI only | **MERGED #1139** → `a43b4a31` (8 mutants red) | §15.4 |
| **M1c-2a** — the engine guards + the Strix prices | **MERGED #1138** → `71610f3b` (17 mutants red) | §15.5 — next: **M1c-2b** |
| **Onboarding guide** — first-time users, end to end | **PR #1141** (`claude/customer-onboarding-guide`): `customer_app/guide.js` + app.js / app.css / index.html wiring, plus the SERVER-SIDE tour state (`ui/onboarding_store.py`, provision `onboarding_get` / `onboarding_set`, edge `api/customer/onboarding`), behind `VIGIL_CUSTOMER_ONBOARDING` (default OFF); 42 mutants red. (An earlier stand-alone design page the owner holds privately is superseded by it.) | §15.6 item 0 — merge when green; the flag waits for the screens of §15.11 C |
| Everything after (W2c-2, W3, W4, W5, W6, G1, wallet E2E, R1–R5, Front C S1–S4, Gate 5, A1/O1/L1) | not started | §15.6, §5 |

Strict branch protection ⇒ each open PR must be brought up to date with `main` after every merge (rebase, re-run CI).
**Two sessions worked in parallel at the end of 2026-11-16** (§15.8); the second one (W2c-1 / NYX) ended at about
15:00 EST, and everything it had — committed or not — was committed and pushed by the remaining session (NYX as
#1139, W2c-1 as `638bf8e9`). Whatever happened after this was written is on GitHub — run §15.10 first.
**Merge checks:** the classic branch-protection API answers "Branch not protected" and the rulesets list was empty on
2026-11-16, so `mergeStateStatus` is not a reliable gate: before merging, confirm each of the 15 names in
`.github/required-status-checks.txt` is green on the PR head yourself.

### 15.2 W2c-1 — MERGED (#1140 → `198b8f37`); kept as the build record
**What it is.** §11.5 (f) exact settlement and (g) the floor retired. The design was chosen on 2026-11-16 from three
independent designs (a v3 decision record / a separate remainder ledger / "minimal"); the winner is "minimal": no new
record type, fold, registry or lock.

**The design (decided — implement exactly this):**
1. **The settle decision record is the ONLY commit point of the remainder.** `governor.launch_settled` v3 = the v2 core
   + `consumed_mc`, `remainder_before`, `remainder_after`, all signed together (`launch_settlement._SETTLED_CORE_V3`,
   `EXACT_RECORD_VERSION = 3`). `consumed` keeps its v2 meaning — the WHOLE credits the settle keeps of the
   reservation; refunds = reserved − consumed, split by the unchanged K4-1 logic. `SettlementDecision.validate()`
   enforces `remainder_before + consumed_mc == 1000·consumed + remainder_after` (forces consumed = ⌊t/1000⌋: never
   rounded up, no remainder dropped), both remainders < 1000, `consumed_mc ≤ 1000·reserved`, and the three fields
   all-or-none. A separate remainder record written after the decision is NOT atomic (another settle of the same org
   could decide on a stale r in between) — that is why the decision carries it.
2. **The remainder is DERIVED, not stored:** r = C mod 1000 with C = Σ `consumed_mc` of the org's first verified,
   well-formed v3 decision per lease. A count-add is order-independent and associative (needed by multi-prune
   fold-of-fold). ONE step function, `launch_settlement.fold_exact_settle(p, key_at_seq, seen, usage)`, is used by the
   wallet fold, the fold-cache view, `SnapshotState.build` and the prune tripwire, so they cannot diverge. It keys
   `(signal, org, "slug:nonce")` in the wallet's own prune-durable seen-set (a malformed v3 is consumed but counts
   nothing, so a later copy never counts).
3. **Snapshot schema 10 → 11**, one additive row `wallet_usage_mc` (`wallet_usage_map()`); a v10 snapshot loads with
   empty usage (correct: no older build wrote v3). The prune tripwire (`spine/prune.py::stranded_active_wallets`)
   refuses a prune whose round-tripped seed drops the usage total.
4. **Enforcement uses the EXACT balance.** `Balance.usage_mc`, `.remainder_mc`, `.exact_available_mc` (1000·available
   − r), `.spendable` (max(0, exact) // 1000); `WalletRegistry.remainder_mc(org)`. A METERED reserve holds the
   cross-process settle lock (new `LaunchGate._settle_lock_into`; E7's `_one_launch_locked` already takes it) and
   sizes `u = min(max(chunk, ⌈min_mc/1000⌉), _exact_room(org, balance))` where `_exact_room = max(0, 1000·balance −
   r)//1000` with balance = plan + wallet (prepaid) or credit_limit − accrued (postpaid), then re-checks the start
   (`u ≥ 1 and 1000·u ≥ min_mc`) because a settle can land between `_gated()` and the lock. An allowance extension
   (wallet only) needs `wallet.balance(org).spendable ≥ credits`. `LaunchAllowance.available_credits` = spendable
   (unlocked hint). Flat reserves ignore r (I7; owner-accepted).
   *Why plan + wallet for reserves (owner-accepted deviation from this file's earlier wallet-only formula):*
   `1000·wallet − r ≥ 0` is not maintainable once a launch is plan-funded (a d = 0 settle refunds the plan in full
   while r rises). *Why the reserve must hold the settle lock:* `CreditMeter.position` reads the wallet then the plan;
   a plan-funded settle in another process between the two reads made a model run end negative in 4,996 of 5,000
   seeds unlocked, 0 locked.
5. **Settle** (`ui/launch_gate.py`): `metered_use_mc(slug, nonce)` = Σ over `GrantMeter.usage_records` of the recorded
   `charge_mc` (W2a; never re-priced) else `card.charge(usage)[0]` priced PER LINE with the card in force (equals the
   statement's `ui/billing._priced_lines`; pricing the aggregate would break I4). It raises `MeteringError` while a
   retired pricing setting is present and `RateCardError` on a malformed card (both ⇒ the caller DEFERS as
   `deferred_config`; both are `ValueError`s, so catch them before the broken-meter `ValueError`).
   `settle_launch(..., consumed_units=0, consumed_mc=N)`: refused unless the launch was published metered; clamps to
   `1000·(lease units + extensions)`; `_settle_reservation` builds `exact(r)` closures (prepaid via the shared
   `_split(kept)` helper, postpaid `refund = reserved − d`); `_settle_once(exact=...)` reads r INSIDE spine_lock +
   settle_lock on a FRESH settle only (after `refuse_if` → meter close → allowance re-check), replaces the
   provisional decision with `exact(r)`, and records it **whatever `VIGIL_SETTLE_SPINE_RECORD` says** (record
   condition `decision.exact or config.settle_spine_record_enabled()`). The result adds `consumed_mc` and
   `remainder_mc`. A not-fresh settle never reads r and finishes the RECORDED decision (ignores its own consumed_mc).
   Zero use never takes the exact path (callers pass None ⇒ the byte-identical v2 refund).
6. **Callers:** `completion_spool._settle_inputs` → `(units, consumed_mc, guard)`; `ops_sweeps._paused_metered_use_mc`
   (renamed from `_paused_metered_charge`) and `paused_expiry_settle` pass `consumed_mc` (basis `sweep:paused`) or
   None (`sweep:refund`); their `charged` row field = the settle's `net_spend`, plus `charged_mc`. The callers no
   longer clamp (`settle_launch` does) and no longer read the margin.
7. **Floor retired:** `VIGIL_RUN_FLOOR_CREDITS` (`FLOOR_ENV`) joins `OBSOLETE_PRICING_ENVS` (doctor: HARD issue
   whether or not metering is on; metered publishes refuse and metered settles defer while it is set);
   `run_floor_credits` / `DEFAULT_FLOOR_CREDITS` deleted; `obsolete_setting_refusal` reworded (no longer "the only
   pricing input is the margin"); `credits_for_cost` kept (legacy + its tests, no production caller). Doctor drops
   `floor_credits` and adds a HARD issue for metered billing with the settle record off (the finish passes need it).
   `deploy_checks.MUST_MATCH`: the floor row became `VIGIL_RATE_CARD`; the margin row was DROPPED (no settler reads the
   margin any more — it is read only where a metered launch is published).
8. **Crash / re-drive:** (a) crash before the v3 append ⇒ nothing recorded; the re-drive is fresh and decides on the r
   of THEN (correct: this lease moved nothing). (b) crash after the v3 append ⇒ r moved exactly once; every later
   settle is not fresh and finishes only the recorded refunds (`has_grant_entry` / `has_credit_entry` guards).
   (c) duplicate completion ⇒ tombstoned, no-op. (d) the flag-gated finish passes still need
   `VIGIL_SETTLE_SPINE_RECORD` (hence the doctor issue).
9. **Invariant sketch (I2):** E = 1000(A+P) − r only decreases through reserve/extend, both sized to keep E ≥ 0
   under settle_lock; a settle changes E by 1000·U − c ≥ 0. Caveats (owner-accepted): a plan tranche expiring can
   take E to −r (< 1 credit) with no spending; a flat reserve after an owner rollback ignores r (≤ 999 mc).
10. **Owner-decided open questions (2026-11-16):** v3 written regardless of the flag (+ the doctor issue); the plan +
    wallet reserve form; the exact customer-visible balance lands in W2c-2 / W6 (metered stays OFF until then);
    retired settings keep deferring settles; reword the refusal; keep `credits_for_cost`; `VIGIL_RATE_CARD` in
    MUST_MATCH; flat reserves ignore r; no rate-card digest in the decision; the remainder is per ORG (not per org +
    mode — a postpaid ↔ prepaid switch carries r across).

**Built on the branch (`9c747e19`) — production code is complete per the design above:**
`governor/launch_settlement.py` (v3, `with_exact`, `exact`, validate, `record_launch_settled` v3, `_decision_from`
v2/v3, `verified_settle_core` — tries the claimed core, then the others, then v1: ANY owner-signed record settles —
`decision_of(p, core)` — a decision is read only from the core its `v` claims —, `fold_exact_settle`, the scans,
evidence JSON), `governor/launch_reservations.py` (verifies v3 too), `governor/wallet.py` (usage slot, Balance
props, `_seed`/`_fold` 4-tuples, `remainder_mc`), `spine/snapshot.py` (schema 11), `spine/prune.py` (tripwire),
`ui/launch_gate.py`, `inbound/completion_spool.py`, `ops_sweeps.py`, `paused_expiry_settle.py`,
`vigil_core/model_metering.py`, `integration/.../doctor.py`, `deploy_checks.py`, `config.py` (docstring),
`docs/runbooks/GO-LIVE-quickstart.md`, `infra/systemd/vigil-settle-drain.env.example`, and
`apps/sigil/tests/test_metered_billing.py` updated (78 pass: fixture usage = 8,640 output tokens = exactly 54 credits
at the default card; floor tests rewritten; `test_a_metered_settle_reads_no_target_margin` added).

**Status at `862a2640` (end of 2026-11-16):** steps 1–3 below are DONE — the regression set passes (977 sovereign
settle / wallet / launch / gateway / statement tests + 100 doctor tests + 784 vigil_core + 496 docs), the three new
test modules exist (`test_exact_settle.py` 25, `test_exact_settle_xproc.py` 1, `test_exact_settle_prune.py` 2 × 3
fixtures), and 23 mutants are red (the list in step 3, minus "metered reserve skips the settle lock", "price the
meter's aggregate", "evidence_from_json drops the exact fields" — still worth adding). An inline red-pen (step 4) found
one wrong comment (the in-lock start check guards against a draw — another process's flat reserve — not a settle: a
settle only ever adds room; fixed). **Left:** the whole sovereign suite with the fold cache off and on (a run was in
progress at hand-off; locally `test_capability_ui.py::test_typed_ask_survives_a_voice_disable` and
`test_aegis_multi_gateway.py::test_real_gateway_self_registers` fail identically on `main`), §11.21, then the PR.

**The steps (kept for the record):**
1. **Update the existing tests that pin the old behaviour.** These were red at `9c747e19`; `638bf8e9` updated all of
   them plus `test_doctor_metering`, `test_doctor_deploy_units` and `test_model_metering`:
   - `apps/sigil/tests/test_allowance_extensions.py`: `test_the_settle_charges_extension_usage_and_refunds_the_rest`,
     `test_the_paused_abandoned_charge_clamps_to_lease_and_extensions` — charge = exact rate-card use (make the big
     usage 240,000 output tokens = exactly 1,500 credits).
   - `apps/sigil/tests/test_paused_expiry_settle.py`: `test_a_metered_launch_paused_until_its_window_closed_is_charged_
     for_what_it_used[record_off|record_on]`, `test_a_a_halted_run_resumed_after_its_window_closed_settles_once_the_
     grace_from_the_resume_passed[*-metered]`.
   - `apps/sigil/tests/test_settle_fold_main.py`: `test_a_meter_retry_writes_no_decision[flag_off|flag_on]`,
     `test_a_pause_landing_after_the_sweeps_pause_read_is_honoured`, `test_a_sweep_refusal_of_a_paused_metered_launch_
     leaves_it_unsettled_and_the_next_pass_charges`, `test_a_failed_completion_whose_past_expiry_record_flips_in_lock_
     is_deferred_then_charged_under_d4`, `test_flag_on_a_d3_metered_cancel_charge_survives_seam_loss`,
     `test_flag_on_a_d4_paused_charge_survives_seam_loss`, `test_flag_on_a_failed_paused_past_expiry_charge_is_
     recorded`; ADD a `v=4` "unknown version" case to the malformed/legacy-record test (it must still SETTLE).
   - `apps/sigil/tests/test_settle_flag_off_golden.py`: the four metered scenarios (`metered_completed`,
     `metered_d3_canceled`, `metered_failed_past_expiry`, `metered_d4_paused`) in both tests. Keep the golden literal =
     `main`'s capture; add an `EXACT_SCENARIOS` set whose assertion is "main's records with the exact refund amount,
     plus exactly ONE v3 `governor.launch_settled` record first" (flag off AND on). Every flat / cancel / refund /
     postpaid scenario must stay byte-identical (I7).
   - `apps/sigil/tests/test_pricing_ledgers.py::test_schema_is_v10_and_an_older_snapshot_loads_with_empty_fields` →
     schema 11, an older snapshot loads with empty `wallet_usage_mc`.
   - Not yet run on the branch: `integration/tests/test_doctor_metering.py` (no `floor_credits` key / render
     fragment; retired-setting count 2 → 3; the floor out of the refused-value loop; the new metered + settle-record-
     off HARD issue), `integration/tests/test_doctor_deploy_units.py` (MUST_MATCH rows), `packages/core/vigil_core/
     tests/test_model_metering.py` (the retired tuple; `run_floor_credits` gone; the refusal wording is pinned in
     ~3 places), `docs/tests` (runbook text pins), `apps/sigil/tests/test_public_repo_money_hygiene.py`, then the
     whole sovereign suite, the suite with `VIGIL_FOLD_CACHE_ENABLED=1`, and the integration sovereign leg (§0.6).
2. **New test modules** (write them; names are the contract the mutants point at):
   - `apps/sigil/tests/test_exact_settle.py`: `test_the_remainder_is_exact_across_three_settles[cache off|on]`
     (2,502 + 499 + 1 mc → debits 2, 1, 0; remainder 2 mc; 97 credits available = 96,998 mc; pin each v3 row's
     consumed_mc / consumed / remainder_before / remainder_after) · `test_a_settle_never_keeps_more_than_the_allowance`
     · `test_a_pre_w2a_meter_is_priced_per_line_like_the_statement` (two 1-token lines = 14 mc = `billing_usage`'s
     `amount_mc`; the aggregate would be 13) · `test_a_recorded_charge_is_never_repriced_and_a_pre_w2a_line_is_priced_
     now` (recorded 6,250 kept; pre-W2a line priced with an owner `VIGIL_RATE_CARD` override in force) ·
     `test_a_reserve_draws_from_the_exact_balance` (30 credits with r = 500 → reserves 29) ·
     `test_the_start_check_uses_the_whole_credits_the_exact_balance_can_hold` (8 credits with r = 500 → refused:
     7 < 7.965) · `test_an_extension_draws_from_the_exact_balance` (20 refused, 19 granted) ·
     `test_the_exact_decision_is_recorded_with_the_settle_record_off` · `test_a_crash_after_the_decision_finishes_it_
     exactly_once` (inject `OSError` on the `settle-wallet:` grant after the v3; the re-drive passes 12,345 mc yet the
     recorded decision stands; r moved once) · `test_a_crash_before_the_decision_decides_afresh` (inject `OSError` on
     `record_launch_settled`) · `test_a_duplicate_completion_is_settled_once` · `test_a_flat_settle_records_nothing_
     new` (and an exact settle of a flat launch is refused) · `test_two_orgs_settle_in_parallel_threads` ·
     `test_the_fold_cache_reads_the_remainder_like_the_full_fold[5 seeds, replays, forged records]` ·
     `test_the_snapshot_carries_the_usage_total` (schema 11; v10 loads empty; a captured v3 replayed above K counts
     once) · `test_an_exact_decision_that_does_not_reconcile_is_never_recorded_or_counted` ·
     `test_a_forged_exact_decision_moves_no_remainder[cache off|on]` · `test_a_settle_landing_before_the_reserve_takes_
     the_settle_lock_is_seen_by_the_sizing` · `test_a_postpaid_metered_launch_settles_exactly_and_its_line_counts_the_
     remainder` (accrued 20 → 2, r 502, the next reserve gets 37 not 38) · `test_the_floor_is_retired` (a no-usage run
     is charged 0; doctor HARD issue; no `floor_credits` key) · `test_a_metered_reserve_holds_the_settle_lock` ·
     a `settle_checkpoint` round-trip of an exact decision · pins `wallet._SETTLED_SIGNAL ==
     launch_settlement.LAUNCH_SETTLED_SIGNAL` and every `MC_PER_CREDIT` copy == `vigil_core.rate_card.MC_PER_CREDIT`.
   - `apps/sigil/tests/test_exact_settle_xproc.py`: `test_two_processes_settling_one_org_chain_their_remainders` (REAL
     child processes; widen the r-read → v3-append window, e.g. 0.6 s, via the `SETTLE_RACE_WIDEN_AT` harness of
     `test_settle_cross_process_race.py` at `sigil.governor.launch_settlement:record_launch_settled`; the two decisions
     must chain 0→600→300 or 0→700→300 and debit exactly 1 credit in total).
   - `apps/sigil/tests/test_exact_settle_prune.py`: `test_a_settle_after_a_hard_prune_collects_the_carried_remainder
     [cache_off|cache_on|settle_record_on]` (a REAL `commit_prune` archives a v3; `wallet_usage_map() == {org: 2502}`;
     the next 499 mc settle debits 1, carries 1) · `test_the_prune_tripwire_refuses_a_seed_that_drops_the_usage_total`;
     add the wallet remainder to `test_real_prune_registries.py`'s registry.
3. **Mutation-verify** (`mutate.py`, §15.9; each must turn a NAMED test red, then restore): round the debit up
   (prepaid builder; postpaid builder) · decide on r = 0 · `validate()` without the identity · the wallet fold
   ignores v3 · counts a replayed v3 twice · counts a forged v3 · the reserve ignores r · no in-lock start check ·
   the extension ignores r · record the exact decision only with the flag · re-decide a recorded settle on the
   current r · no clamp of consumed_mc · exact settle allowed on a flat launch · price a recorded charge with the
   card in force · price pre-W2a lines with `DEFAULT_RATE_CARD` instead of the card in force · the snapshot drops
   the usage total · the wallet seed ignores the carried usage · keep the floor (not retired) · decision readers
   verify only the claimed core · the prune tripwire ignores the usage · read r outside the settle lock (the xproc
   test: debit 0 instead of 1) · the metered reserve skips the settle lock · price the meter's aggregate · the fold
   counts a malformed v3 · `evidence_from_json` drops the exact fields · `decision_of` ignores the core.
4. **Red-pen** (adversarial; each "finding" is a claim to verify). Focus: lock order (`_publish_lock` → spine_lock →
   settle_lock → leaves; the metered reserve's new settle-lock acquisition must never nest), every place a v2-only
   reader could still exist (grep `_SETTLED_CORE_V2`), version skew (a pre-W2c-1 build ignores v3 and sees a
   v3-settled lease as settled only through its seam marker; an OLDER build that prunes after v3 records exist
   writes a v10 snapshot without the usage — deploy forward-only, upgrade every settling process together, never
   prune with an older build), the plan-expiry caveat, postpaid remainder, fold cache == full fold, I4 statement ==
   settle, the "charged" sweep row, doctor/deploy messages, and that NOTHING changed for flat launches.
5. **Write §11.21** (the W2c-1 record: what it is, its anchors, the invariants, the risks above) and update the header
   and §5 of this file in the same PR; then PR → CI (15 required checks) → merge (§0.4).

**Known follow-ups surfaced while building:** `LaunchGate.reserved_with_extensions` no longer has a production
caller (keep it only if a test or the gateway needs it; else delete with its tests under the dead-code rule);
`completion_spool._consumed_for` still returns units only; `Balance`/`balances()` list only orgs with wallet activity
(a postpaid-only org's usage is reachable through `balance(org)`).

### 15.3 What PR B (#1136, the anthropic SDK 2.8) changed — for anyone touching an SDK client
- `packages/core/vigil_core/vigil_core/sdk_retry.py`: SDK 2.x honours ANY positive `Retry-After` (0.x capped it at
  60 s), so `bounded_http_client()` adds `cap_retry_after` (drops a `retry-after(-ms)` outside (0, 60] s or
  unreadable) to an `anthropic.DefaultHttpxClient`. **Every SDK client VIGIL builds must pass
  `http_client=bounded_http_client(...)` or `max_retries=0`** — enforced by the AST guard
  `engine/crucible/framework/v2/kernel/tests/test_sdk_client_retry_guard.py` (a new client site fails CI until it
  complies). The helper returns None when the installed `anthropic` has no `DefaultHttpxClient` (test doubles).
- `kernel/llm.py::sampling_create_kwargs(model, temperature, effort, *, platform="anthropic")`: older models keep
  `temperature` through the legacy API version (anthropic: header `2023-06-01`; bedrock: body
  `bedrock-2023-05-31`; vertex: body `vertex-2023-10-16`); current models send `output_config.effort` and no sampling
  params; the Claude 5 family (incl. `claude-haiku-5`) is "current".
- The extra is pinned `anthropic>=2.8.0,<2.9` on purpose (the legacy-route preparation was verified on 2.8 only —
  widen after re-verifying). SDK 2.x sends the key as `Authorization: Bearer` (the gateway accepts it) and uses the
  OS trust store (httpx2).

### 15.4 NYX — built; open its PR
Owner (2026-11-16): **"nyx will be only in ui, nothing changes in backend."** The vendored Strix engine is shown as
"NYX" in every UI; backend ids, routes, `STRIX_*` settings, signed `strix.*` ids, CI check names and `vendor/strix`
(with its Apache-2.0 NOTICE credit) are untouched.
- `packages/vigil-ui/ui.js`: `DISPLAY_RENAMES` (`\bStrix\b` / `\bSTRIX\b` → `NYX`), `displayText()` applied by `h()`
  to `text` props, text children and the visible attributes `title` / `aria-label` / `placeholder` / `alt` only;
  `RAW_TEXT_TAGS` (`pre`, `code`, `kbd`, `samp`, `textarea`, `script`, `style`) keep evidence exactly as recorded;
  ids, classes, option values, URLs and `data-*` are never renamed; `VUI.displayText` exported.
- `packages/vigil-ui/app.js`: the drawer title and the two graph-label writers go through `V.displayText`; the
  kill-switch reason it POSTs stays backend data.
- `apps/sigil/tests/test_ui_display_names.py` (5 tests, run under node with a minimal DOM; 6 mutants all red; the
  131 UI tests and the console S10 suite pass).
- Two more suites must stay green on it (the parallel session was fixing both when this was written):
  `test_ci_suite_legs` (the new test's node lookup must go through the shared failing gate) and
  `test_customer_kit_copies` (the customer `ui.js` fork must match outside its customer regions).
- **PR #1139.** Both copies of the kit carry the rule (`test_customer_kit_copies`), the node test goes through the
  shared `_need_node` gate (`test_ci_suite_legs`); 8 mutants red; checked that the app's direct label writers and the
  `Strix …` strings in `app.js` all render through `h()` / `displayText`. To do: CI green → merge (update with `main`
  first if another PR merged).

### 15.5 M1c-2 — offense wiring through the gateway (the full map, 2026-11-16)
**M1c-2a = PR #1138** (branch `claude/billing-m1c2-strix-prices`) — DONE pending CI:
- item (4): `vendor/strix/strix/report/anthropic_pricing.py` rows for `claude-opus-4-5` … `4-8` at $5 / $25 / $0.50 /
  $6.25 (without them `claude-opus-4` matched by substring and Strix's runtime cap stopped a run at a third of what it
  was allowed);
- `engine/crucible/framework/v2/kernel/metered.py` (`model_grant()`, `metered_mode()`, `gateway_base()`,
  `stop_reason()`); `AnthropicBackend` builds a metered client for the grant + the LOOPBACK gateway only (rule:
  `vigil_core.model_grant.gateway_url`, now shared with the grant seam), keyed on (grant, gateway), no client without a
  gateway, no key hot-reload under a grant, and **no ambient proxy** (`trust_env=False` AND the proxy patterns mounted
  to no proxy — SDK 2.x mounts the environment's proxies whatever `trust_env` says; verified on 2.8.0 and 0.120.2);
- the gateway's credit refusal carries `x-vigil-stop: credits_exhausted` (`vigil_core.model_grant.STOP_HEADER` /
  `STOP_CREDITS_EXHAUSTED`) and the backend raises it as a terminal `CreditsExhausted(BackendError)` (never retried,
  never failed over);
- `kernel/llm.py`: under a grant only `anthropic` / `anthropic-zdr` are constructed (`_refuse_unmetered`), selected
  (`_metered_backend`, cached per grant, never touching the unmetered selection), pinned (`complete_with_backend`) —
  no failover; `kernel/routing.py`: routing off under a grant.
- Tests: `kernel/tests/test_metered_engine.py` (29 + a real-SDK wire test, skipped where the SDK is absent),
  `test_model_gateway.py::test_only_the_credit_stop_names_itself_to_the_run`, vigil_core `gateway_url` cases; 17
  mutants red.

**CI note for #1138:** its first P5 run failed in `integration/tests/test_strix_patch_series.py` — any change under
`vendor/strix` must be recorded with `python3 tools/vendoring/regen_strix_series.py` (fixed in `696707bf`). On this
machine git renders a UTC author date as `Z` where the committed series (and CI) have `+00:00`, so the script also
rewrites patches 037 / 038: keep only the NEW patch file and its `series.json` entry (+ the changed file hash), and
re-run the test. A rebase changes the commit hash the patch names: regenerate after any rebase of that commit.

**Remaining = M1c-2b** (nothing sets `VIGIL_MODEL_GRANT` until this lands; from the read-only map of every place a
customer run's model call leaves the engine — the items M1c-2a already did are marked DONE):
- DONE (M1c-2a): the metered helper, the grant-only client, the key-reload guard, the distinguishable terminal
  credit stop, the no-failover / gateway-only selection, routing off.
- **Map `CreditsExhausted` at the engage seam to a pause** (the worker holds the lease for resume — no refund, no
  re-drive), or leave that mapping to W3; decide and record it. Note: the engine's reasoning phases run inside
  PhaseLedger swallow-wrappers, so a `CreditsExhausted` raised there must be re-raised past them (as the customer-pause
  `EngagementPaused` already is at a clean point), or a credit stop silently degrades the run.
- **The worker forces `routing_override=False`** for a metered run (the engine guard is in; the worker scope is not).
- **`jobs/engage_worker.py`:** read `model_grant_broker.read_model_grant(base, slug, expect_nonce=nonce)`; metered and
  no grant ⇒ refuse BEFORE the arm (never burn the single-use floor); a `_model_grant_scope` around the runner sets
  and restores EXACTLY: `ANTHROPIC_BASE_URL` / `ANTHROPIC_API_KEY` = gateway / grant, `VIGIL_MODEL_GRANT`,
  `CRUCIBLE_LLM_BACKEND=anthropic`, `CRUCIBLE_MODEL_ROUTING=0`, `CRUCIBLE_ANTHROPIC_MODEL` = the grant model,
  `CRUCIBLE_EFFORT` = the depth's effort, `STRIX_LLM=anthropic/<grant model>`, `LLM_API_BASE` / `LLM_API_KEY` =
  gateway / grant; unset `SIGIL_ANTHROPIC_API_KEY`, `VIGIL_LIVE_KEY_RELOAD` and the api-base siblings. (Safe only
  because `JobRunner.run_one` serialises jobs.)
- **`live/think_claude.py`:** `_resolve_key` prefers the grant; `_build_live_client` passes `base_url`; its error
  path must recognise the credit 403 (today it degrades to ASK_USER — a metered live run would never pause).
  **`live/codefix_runner.py`:** in metered mode use the grant's model (its default differs ⇒ a gateway 400).
- **Strix children** (`strix_runtime.strix_child_env`, `console/actions._strix_session_llm_env`, the sovereignty
  gates): permit `anthropic/<model>` pinned at the LOOPBACK gateway without widening the cloud allowlist; confirm that
  LiteLLM's `anthropic/` provider honours `LLM_API_BASE` / `LLM_API_KEY` (read the vendored call site).
- **`uiproxy._child_env`:** in metered mode exclude `SIGIL_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY` from offense
  children and do not set `VIGIL_LIVE_KEY_RELOAD=1`; **doctor**: a HARD issue when the offense plane would inherit a
  provider key in metered mode.
- **Wire test (item 5)**: with a fake gateway (`httpx2.MockTransport`, importorskip the SDK), assert base_url, the
  Bearer grant, the grant model, `output_config.effort` = the grant's effort and NO temperature.
- Tests + one mutant per guard as listed; FATAL-2 (`integration/tests/test_two_env_boundary.py`) stays green.
- Open engineering questions to settle while building (NOT money — decide and record): the authoritative KEYLESS
  "this run is metered" signal (the grant file is written before the lease at publish — recommended); grant model /
  effort source in the worker (decode the grant token with the owner public key the worker already loads vs derive
  from the lease depth); claude-code refused in metered mode for M1c-2 (route it through the gateway later, M2);
  whether `anthropic-zdr` counts as the grant backend.

### 15.6 After W2c-1, NYX and M1c-2 — the rest of the program (unchanged order, §5)
0. **The onboarding guide** (owner request, 2026-11-16) = **#1141**, in the customer app itself, behind
   `VIGIL_CUSTOMER_ONBOARDING` (default OFF; all of it — the tour, the Guide tab, the loader, the server route and
   the cockpit actions — is absent while OFF):
   - **The tour** opens after a person's first sign-in and at each sign-in after it, **on any device, until they
     finish or skip it**. The answer is kept SERVER-SIDE per account: the app asks `GET api/customer/onboarding`
     (once per page load; `pending` / `done` / `skipped`) and records the outcome with `POST {state}`. The edge relays
     for the SESSION's account only (never a body field) → provision `onboarding_get` / `onboarding_set` (flag-gated
     in `_provision_dispatch` too) → `Provisioner.onboarding_state` / `onboarding_record` (ACTIVE customers only,
     `done` / `skipped` only; the same answer again writes nothing and only the FIRST close is audited as
     `provision.audit` `onboarding_record`, so a customer cannot grow the signed spine by re-posting) →
     `ui/onboarding_store.py`: one sha256-named 0600 JSON file per account in `SIGIL_HOME/customer/onboarding/`
     (0700; O_NOFOLLOW; anything odd reads `pending`; outside backups like the rest of `customer/` — a restore shows
     the tour once more). The browser also remembers the answer (`vigil.guide.v1.<username>`): it decides only when
     the server cannot be asked, and a tour closed here whose record did not land is re-sent, not re-shown. Skip /
     Esc / Finish all record; the top-bar tab of each step is lit.
   - **The Guide screen** (`#/guide`) covers the whole app: 8 chapters — Get started (account, sign-in incl. Google
     and passkey, account security, install, password reset, sign-out), Your workspace (Overview, Team + roles,
     notifications), Credits and plans (buy, plans, trial, how credits are spent, rates, low balance + auto top-up),
     Prove you control a host, Test a host (launch, follow / pause / resume / cancel, findings, retest), Red-Pen and
     GitHub (connect the App step by step, PR reviews, merge-blocking settings, whole-repo review, Fix this,
     disconnect), AEGIS monitoring (plans, turn on, events, change / stop), Statement and invoices — plus a
     Questions tab (9 answers). Each step: where, the clicks in order, why, "Go to <screen>", "Mark as done".
     The Team step offers only the roles a customer can grant (`provision._CUSTOMER_GRANTABLE_ROLES`: Admin, Analyst,
     Viewer — test-pinned; Operator is granted only by VIGIL); the launch step offers Quick and Deep only — **add
     Max to the guide when L1 lands** (there is no Max launch product before it).
   - **Tests:** `test_customer_onboarding.py` (the tour, the Guide, the loader, the copy rules — no model / engine
     names, no price or credit amount, an estimate only to rule it out — the server-decides scenarios, and a
     **screen census**: every route in app.js `ROUTES` must be covered, so a new screen fails CI until the guide
     covers it) and `test_customer_onboarding_state.py` (store, provisioner, cockpit dispatch, edge stub + real hop).
   - **Before the flag goes on:** the screens the guide already describes must exist — §15.11 C. Keep the copy in
     step as each lands (the census + the chapter / step ids are test-pinned).
1. **W2c-2** (§11.5 j + k): `balance_after_mc` per statement line, "remaining" vs "available to start work"; take
   `ENVELOPE_TOKENS_PER_CREDIT` off every metered path (the EC-5 cost settle still multiplies the exact debit by it);
   show the customer the EXACT balance (floor of `exact_available_mc`) on `billing_overview` / the wallet card.
2. **W3** (§11.6) pause on insufficient credit / resume after top-up. VERIFIED: a credit pause can outlive the 8-hour
   lease and the grant (7 days + 1 h), so the continuation lease (`CreditLaunchLease.continue_of`, bound to the SAME
   meter) is REQUIRED; count the 7-day TTL from the pause.
3. **M1c-2** finished (§15.5). Then `VIGIL_METERED_BILLING` may be flipped by the agent only per §6.
4. **W4** (§11.7), **W5** (§11.8 — Stripe; **ask the owner the dispute-timing question with a pick-one pop-up BEFORE
   building**: remove disputed credits when the dispute opens / funds are withdrawn, or only when it closes `lost`
   and re-grant on `funds_reinstated`?), **W6** (§11.9), **G1** (§11.11, headers verified), the **wallet E2E**
   (§11.12), **Red-Pen R1–R5** (§12), **Front C S1–S4** (§4.4, §13.1), **Gate 5** (§13.2, Stripe TEST mode),
   **A1 / O1 / L1**.
5. Optional cleanup noted: split `test_smt_unknown_region_is_a_noop_without_z3` into its two cases (after PR A it
   covers both the with-z3 and without-z3 paths in one test).

### 15.7 Owner decisions recorded on 2026-11-16 (do not re-ask)
- **Flips delegated** to the agent, each only when its gate is green and only once a deployment exists (§6):
  production execution after Gate 5; metered billing after W2 + W3 + M1c-2 are merged and the wallet E2E is green
  (and the owner has set the target margin and the Anthropic key); multi-shard after S4.
- **No server / VPS work** — the program builds the customer app (code, tests, CI) only.
- **Payment provider = Stripe**; Flutterwave development paused (its code stays; build nothing new on it).
- **NYX** is the UI-only display name of the Strix engine (§15.4).
- **The floor is retired** (W2c-1) and the rate card is the customer price (§11.2).
- **W5 disputes** (pick-one, 2026-11-16): remove the disputed credits when the dispute OPENS / funds are withdrawn;
  re-grant automatically when it is won. **Red-Pen R1–R5 is built together with the Code screen** (tests use a fake
  GitHub; the owner registers the real GitHub App). The owner asked for ALL of §15.11 B + C (+ D) to be built by
  parallel agents and strictly tested (2026-11-16).
- The owner asked what "the margin value" means: `VIGIL_BILLING_TARGET_MARGIN` is the owner's private target margin
  over the METERED AI cost, set at deploy and never in the repo. Since W2c-1 no settle reads it: customers are charged
  from the published rate card; the margin sets the USD ceiling of a run's model grant (`billing_markup()` at publish)
  and feeds the owner's money view (O1). It must be set (with the Anthropic key) before the metered flip.

### 15.8 Lessons from this session (they will bite again)
- **Two sessions, one worktree.** On 2026-11-16 two Claude processes of the SAME session worked the same local
  worktrees at the same time (one merged #1136 while the other committed W2c-1). Before editing, check for a peer
  (`ListAgents`, `ps -ef | grep claude`), give each session its own worktree, and message the peer before touching
  shared state.
- **Never `git stash` in a worktree.** The stash list is shared by every worktree of the repo: a `git stash` on a
  clean tree saves nothing, and the `git stash pop` after it pops someone else's entry. On 2026-11-16 that applied the
  main checkout's old `salvage-main-dirty-327behind-2026-09-30` stash into the W2c-1 worktree (conflicts); the worktree
  was reset to its commit and the stash entry is still there, untouched (`git stash list`). To compare with the base,
  use `git show origin/main:<path>` or a second worktree.
- **`CRUCIBLE_ROOT`.** A test run without `CRUCIBLE_ROOT` set writes into the LIVE engine root (one run appended 3
  lines to `/home/kali/Music/PENTEST/crucible/framework/v2/.crucible-v2.log`; removing them was refused as log
  tampering, so they stay). Always `CRUCIBLE_ROOT=<worktree>/engine/crucible CRUCIBLE_ROOT_STRICT=1`.
- **Stage by path, never `git add -A`:** tests regenerate `engine/crucible/targets/127-0-0-1/charter.md` (a stray copy
  nearly shipped in PR B).
- **Run the mypy ratchet on every slice before its PR** (`PATH=<venv>/bin:$PATH bash tools/governance/mypy_ratchet.sh`):
  #1140's first CI run failed on new type errors in three modules. Locally the ratchet also prints a STALE line for
  `sigil/voice/components.py` (identical on `main`, an environment difference): read the module list it names, not
  just the exit status.
- **Fake `anthropic` modules in tests** have no `DefaultHttpxClient` — that is why `bounded_http_client()` returns
  None for them (43 console tests went red before that).
- **`git fetch` over SSH can hang** — wrap it in `timeout 60`.
- **Commit messages via `git commit -F <file>`** — backticks inside `-m "…"` are executed by the shell.
- Failing identically on `main` locally (not regressions): `test_aegis_multi_gateway.py::test_real_gateway_self_
  registers`, UI socket timeouts, an old onnxruntime; the shared `.venv-sovereign`'s editable installs point at
  `/home/kali/vigil`, whose checkout carries an unrelated uncommitted change — test a worktree with the worktree first
  on `PYTHONPATH` (or a venv copy whose editable installs point at the worktree).
- The Workflow tool and subagents may be unavailable or rate-limited ("5-hour limit"); every step here can be done
  inline.
- Attribution used locally (no session URL available): commit trailer `Co-Authored-By: …` only; PR bodies end with
  the "Generated with Claude Code" line (§0.8).

### 15.9 Local tooling recipes (this machine; re-create in a scratch dir)
- The second session kept its own copies under `<scratchpad>/e0/` (`t.sh`, `mutate.py`, `ciwait.sh`, a venv copy whose
  editable installs point at `e0/slice`, and the mutant specs `m1c2a_mutants.py`, `w2c1_mutants.py`,
  `w2c1_xproc_mutant.py`, `w2c1_prune_mutants.py`). The scratchpad does not survive; the recipes below re-create
  them. `t.sh` re-points `slice` to the worktree it is given — never run two worktrees' tests through one slice at
  once.
- **Test helper** `t.sh <worktree> <leg> <pytest args…>`: legs `sov` (PYTHONPATH = `apps/sigil:integration:
  packages/core/vigil_core`), `int` (+ `gateway`), `core` (`packages/core/vigil_core`), `off` / `eng` (offense venv
  `/home/kali/vigil/.venv-offense`, PYTHONPATH with `engine/crucible`); always a fresh `SIGIL_HOME=$(mktemp -d)`,
  `CRUCIBLE_ROOT=<worktree>/engine/crucible`, `CRUCIBLE_ROOT_STRICT=1`, `-p no:cacheprovider`, no extra `-q`.
- **Mutation runner** `mutate.py <worktree> <spec.py>`: the spec lists `(file, old, new, test-node-ids)`; for each it
  applies the one edit, runs the named tests (they must FAIL), restores the file byte-for-byte, and reports
  RED/SURVIVED. Restore is verified with `git diff --quiet`.
- **CI wait** `ciwait.sh <pr>`: polls `gh pr view <pr> --json statusCheckRollup` every 60 s, prints
  `pending=N fail=M`, exits when nothing is pending. Merge with
  `gh pr merge <pr> --merge --match-head-commit <headRefOid>` only when every required check is green.
- Hygiene before every push: `python3 tools/governance/money_hygiene.py ci --base origin/main --head HEAD` and
  `gitleaks git --log-opts="origin/main..HEAD" --no-banner .`.

### 15.10 Verify before acting
```bash
git fetch origin && git log --first-parent --oneline -5 origin/main
gh pr list --repo thuram-nana/vigil-sovereign --state open
for b in claude/billing-w2c1-exact-settle claude/ui-nyx-display-name claude/billing-m1c2-strix-prices; do
  echo "== $b"; git log --oneline origin/main..origin/$b; done
```

### 15.11 EVERYTHING LEFT TO CODE — the complete list (end of 2026-11-16)
Everything the program still needs, in build order. Each line is one or more PRs built per §0.2. "Owner" marks what
only the owner can do. Nothing here is server work (§6).

**A. Open PRs.** #1141 (onboarding guide + server-side tour state) and #1137 (this file) — merge when their 15
required checks are green, bringing the other up to date with `main` after each merge.

**B. Money and metering (the wallet program, §11).**
1. **W2c-2** — `balance_after_mc` on every statement line; "remaining" vs "available to start work"; take
   `ENVELOPE_TOKENS_PER_CREDIT` off every metered path; show the EXACT balance (floor of `exact_available_mc`) on
   `billing_overview` and the wallet card (§15.6 item 1).
2. **W3** — pause on insufficient credit, resume after a top-up (continuation lease bound to the SAME meter; the 7-day
   grant TTL counted from the pause) (§11.6).
3. **M1c-2b** — the offense wiring through the gateway: `CreditsExhausted` → pause at the engage seam (past the
   PhaseLedger swallow-wrappers); `routing_override=False` in the worker; `engage_worker` grant scope;
   `think_claude` / `codefix_runner` grant use; Strix children via the loopback gateway; `uiproxy._child_env` key
   exclusion + the doctor HARD issue; the wire test (§15.5).
4. **W4** — worker-time and premium-API metering (§11.7).
5. **W5** — chargebacks / reversals / refunds + the low-balance alert, on Stripe. **Decided (owner, 2026-11-16):**
   remove the disputed credits when the dispute opens / funds are withdrawn; re-grant automatically when it is won
   (`funds_reinstated` / closed `won`) (§11.8).
6. **W6** — the customer billing dashboard (§11.9; see C5 below for its screens).
7. **G1** — the gateway at scale: capacity from the provider's rate-limit headers, per-tenant fair share, a
   provider-account pool, the loss alarm (§11.11).
8. **Wallet E2E (simulated)** — the whole §11.1 journey in one test, fake upstream + sandbox payments (§11.12).
9. **A1** auto top-up (§11.13), **O1** the owner money view, **L1** live Max (§10.6).

**C. Customer-app screens the onboarding guide already describes but that do not exist yet** (the API mostly does;
each is a UI slice with its own tests; the guide flag stays OFF until all of C is in):
1. **Assessments: launch and control** — depth picker (Quick / Deep; Max only with L1) → `launch/reserve` → `launch/start`;
   Pause / Resume / Cancel (`launch/pause|resume|cancel`, PR-4b flag); live state and what a run has used so far;
   **Retest** on a finding. The app still says "Launching a new assessment arrives with the run driver."
2. **Team** — list members, Add member (email + role), change role, Remove (the member-management provision actions
   exist; `#/team` is still `viewSoon`).
3. **Account security** — TOTP enrolment (`mfa/totp/enroll`, `mfa/verify`) and passkey enrolment
   (`passkey/enroll/*`), plus **passkey sign-in** on the sign-in screen (`passkey/login/*`); the step-up prompt for a
   sensitive action (today a purchase only shows an error asking for a fresh check).
4. **Monitoring (AEGIS)** — the screen: choose a verified host, Observe / Respond, step-up, events list, Turn off
   (`api/customer/monitoring*` exists behind `VIGIL_CUSTOMER_MONITORING_ENABLED`); and on **Billing**, the AEGIS plan
   offers rendered as plans for 1 / 5 hosts (today `offerLine` would print an AEGIS plan as "Plan: 0 credits").
5. **Billing (W6)** — Rates view (`billing/rates` read exists), the statement with balance-after (`billing/usage`
   read exists), credits on hold for running assessments, live consumption per run, the low-balance notice (W5),
   Auto top-up settings (A1).
6. **Code (Red-Pen)** — Connect GitHub (the App install round-trip), the repository list, per-repo merge-blocking
   threshold + monthly spending limit, Red-Pen System (now / schedule), Fix this → re-checked fix PR (never merged by
   VIGIL), disconnect — this is Red-Pen R1–R5 (D below) seen from the app.
7. **Overview** — bring credits, hosts, assessments and monitoring together (today: account + workspace only).

**D. Red-Pen R1 → R5** (§12; design §7) — the GitHub App (owner registers it, with `checks:write`), PR reviews that
post only reproduced FACTs, the "VIGIL Red-Pen" check blocking Critical / High, per-repo threshold + monthly
spending limit, System reviews on demand / on a schedule, Fix this.

**E. Scale and the closing gates.** Front C **S1, S2a–c, S3, S4** (§4.4, §13.1: 100,000 then 1,000,000 users);
**Gate 5** — the hands-on end-to-end with evidence, Stripe TEST mode (§13.2).

**F. Owner-only (never the agent's, §6).** The GitHub App registration; the live Stripe secret + webhook secret; the
Anthropic key + workspace + spend limits; the target margin and trial credits at deploy; the AWS KMS key for
evidence-DEK escrow; DNS / TLS; the CodeQL by-design dismissals. The three production flips
are delegated to the agent behind their gates (§6) once a deployment exists.

**G. Housekeeping.** Delete merged `claude/*` branches; split `test_smt_unknown_region_is_a_noop_without_z3` into its
two cases; keep this file current at the end of every session.

