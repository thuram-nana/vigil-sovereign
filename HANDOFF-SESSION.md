# VIGIL — End-to-End Handover (read this first)

Repo: thuram-nana/vigil-sovereign. Default branch: main. No credentials in this file.
Rule: verify live repo state with GitHub tools before trusting anything here.

## 0. Owner rules (non-negotiable)
- Merge, approve, dismiss alerts, or run against production ONLY with explicit owner approval.
- Standing approvals: merge PR #996 when ALL checks green; merge #993/#994/#995 only if ALL checks green.
- Never weaken a guard or disable a test to get green. Never force-push. No model names in commits/PRs/code.
- Every change: build -> tests -> mutation-verify (break guard, test fails, restore) -> review -> fold -> PR.
- Invariants: two-plane boundary (sovereign imports no framework), owner key only in sovereign provisioner,
  owner catalog decides money, billing != testing, tenant isolation, default-OFF and fail-closed.

## 1. Open pull requests

### PR #996 — AEGIS-SaaS AE-0..AE-7 (branch claude/aegis-saas-ph9x2k)
- State: OPEN. Approved to merge once every check is green.
- Last known: all blocking checks green except P5, which was re-running.
- P5 fix pushed (c9b2138): acceptance test child process now has integration/ on PYTHONPATH.
- Later commit d313c4a (handoff note) restarted CI.
- CodeQL (advisory default setup) still red. Local CodeQL 2.27.4 and 2.26.3 (default + security-extended,
  tests in/out, threat model local, actions): 0 new alerts, 0 on changed lines. 11 real alerts already fixed.
  To finish: get the text of the CodeQL check details (or code-scanning read access) and fix what it lists.
- Note: one commit in branch history contains merge conflict markers (fixed in the next commit). Prefer
  squash merge so main history stays clean.

### PR #993 — billing-drain CLI (branch claude/billing-drain-ph9x2k)
- State: OPEN, NOT merged. Its run failed "SIGIL governor gates (P7)" (run predates #992 merge).
- To do: reproduce P7 locally (PYTHONPATH=apps/sigil:integration pytest apps/sigil/tests), fix at source,
  update branch from main, re-run, merge only if all green.

### PR #994 — ops sweeps (branch claude/ops-sweeps-ph9x2k)
- State: OPEN. Review found + fixed: --apply could refund a lease whose completion was still pending.
- To do: confirm all checks green after main moved; merge only if green. May conflict with #993 in cli.py.

### PR #995 — ops runbooks (branch claude/ops-docs-ph9x2k)
- State: OPEN. Was all green. To do: update from main, confirm green, merge.

### PR #991 — offboarding cascade (branch claude/offboarding-cascade-ph9x2k)
- State: OPEN, CI was green. NOT pre-approved; ask owner before merging.

### Merged this session
- PR #992 livefire nikto hardening -> main (squash 74d5c86).

### Dependabot PRs
- 8 open (#959,#960,#962,#963,#964,#988,#989 and others). Not triaged. Some are security bumps
  (pydantic 2.14.2). Lock regeneration rules in section 5.

## 2. What AEGIS-SaaS contains (on PR #996, not yet on main)
- AE-0 governor/monitoring_authority.py: owner-signed per-(org,host) grants; snapshot schema bump; prune tripwire.
- AE-1 ui/provision.py monitor_authorize/revoke/list; rbac perm manage_monitoring; custui routes.
  Flag VIGIL_CUSTOMER_MONITORING_ENABLED (default OFF).
- AE-2 aegis/monitoring_authority_check.py: keyless verify against pinned owner root.
- AE-3 aegis/gateway.py: tenant gateway needs saas_host; flag VIGIL_AEGIS_SAAS_ENFORCE (default OFF).
- AE-4 aegis/monitoring_report.py + inbound/monitoring_spool.py: sealed metadata-only reports, drainer,
  tenant events route.
- AE-5 governor/monitoring_subscription.py + catalog/billing changes: separate subscription line, period clamp,
  cancel/past-due cascade, plan enforcement, 72h renewal grace, reconcile sweep.
- AE-6 gateway CLI flags, docker-compose profile aegis-saas, infra/systemd unit, governor/monitoring_secrets.py,
  CLI verbs monitoring-secret (--export-to), monitoring-drain, monitoring-reconcile.
- AE-7 integration/tests/test_aegis_saas_acceptance.py (8 tests) + docs/runbooks/aegis-saas-flag-hold.md.
- Runbooks: docs/runbooks/aegis-saas-onboarding.md, aegis-saas-flag-hold.md.

## 3. Work left to complete (in order)
1. PR #996 to all-green, then squash-merge.
2. PR #993 P7 failure -> fix -> merge if green. Then #994, #995 if green.
3. Real prices, no placeholders (owner request). File: apps/sigil/sigil/governor/catalog.py is marked
   PLACEHOLDER (AEGIS per-host 49/99 USD and whole list). Do: set final prices in code, remove placeholder
   wording; move provider plan ids into owner config mapping catalog price_id -> Flutterwave plan id; refuse
   to start in production if an offered subscription is unmapped. Owner must create real Flutterwave plans.
   Then grep the repo for other placeholder markers (PLACEHOLDER, TODO, FIXME, XXX) in shipped code and resolve.
4. After #996 and #991 are both on main: add a test that decommission_org also revokes and unpublishes
   that org's monitoring grants (hook exists via orgs.revoke_org).
5. #14 Enterprise postpaid invoicing on the existing billing spine:
   PP-1 owner-signed postpaid account mode (credit limit, net terms; usage accrues a balance).
   PP-2 periodic owner-signed arrears invoices (extend governor/invoices.py; org-scoped reads).
   PP-3 overdue/over-limit -> reduce access via the credit gate; reversible; replay cannot advance a period.
   PP-4 reconciliation, acceptance test, review. Build on top of AEGIS billing code.
6. #7 polish: customer Monitoring UI screens in custui SPA (APIs exist); marketing-domain reverse-proxy vhost
   (follow apps/sigil/deploy/reverse-proxy/vigil.nginx.conf); NVD/EPSS enrichment for CVE catalog.
7. #4 leftover: kill-switch default decision (owner decides).
8. #3 livefire cron: fix merged in #992; confirm the next nightly run is green.
9. Dependabot triage.

## 4. Owner decisions pending
- Real AEGIS prices and the full price list; create Flutterwave plans and supply their ids.
- Flag flips per docs/runbooks/aegis-saas-flag-hold.md (all default OFF).
- Merge PR #991. Kill-switch default.

## 5. Environment and how to resume
- Python 3.13 (python3.13); venvs .venv-sovereign and .venv-offense (bootstrap.sh --yes builds them).
- Sovereign tests: SIGIL_HOME=$(mktemp -d) PYTHONPATH=apps/sigil:integration .venv-sovereign/bin/python -m pytest apps/sigil/tests -q
- Engine tests: PYTHONPATH=engine/crucible:packages/core/vigil_core .venv-offense/bin/python -m pytest <path> -q
- CI-faithful lint: venv from engine/crucible/framework/v2/requirements.lock.txt + vigil_core + infra/supply-chain/ci-tooling.lock.txt;
  then (cd apps/sigil && ruff check sigil) and bash tools/governance/mypy_ratchet.sh. Do not run the ratchet
  in the full sovereign venv (false STALE).
- Known env-only failures: test_golden_vectors_match, test_live_server_registers_eight_tools,
  test_gitleaks_negative_control_real_catch.
- Any change under vendor/strix/ needs uv==0.11.29 lock regen in a temp copy and
  python3 tools/vendoring/regen_strix_series.py.
- Trivy DB: use --db-repository public.ecr.aws/aquasecurity/trivy-db:2.
- CodeQL can be run locally (bundle from github/codeql-action releases) to find PR alerts.
- Tool limits seen: no Actions-log or code-scanning API tools; long chat messages about security specifics get
  truncated, so keep chat short and put detail in files.

## 6. Verified results this session
- Full SIGIL suite green except the 3 known env-only tests.
- AEGIS engine suite 0 failures; AEGIS acceptance 8/8; ruff + mypy ratchet green.
- Loopback engagement harness: positive, offline re-verify, tamper rejected, sound negative.
- make gate PASS (precision/recall/f1 1.000).
