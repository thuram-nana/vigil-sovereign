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

## Blockers / open questions to owner

- (a) Can the GitHub **Actions** read tool be enabled? Otherwise #3 = "paste me the job logs".
- (b) Confirm **Flutterwave sandbox/test mode** only for #25 (no production payment target).

## Exact next step

Stand up the live stack and drive one real end-to-end customer journey over HTTP against the running custui
edge, capturing evidence; then run the loopback-engagement harness. Record results here and checkpoint.

## Conventions reminder

- Branch fresh off main per unit of work; one reviewable slice per PR; drive every PR to green.
- Never merge / approve / dismiss-alert / enable-production without explicit owner instruction.
- Preserve invariants: FATAL-2 two-plane boundary, money doctrine, FACT doctrine, billing-authz≠testing-authz,
  owner-key isolation, egress floor + kill-switch, default-OFF + fail-closed.
