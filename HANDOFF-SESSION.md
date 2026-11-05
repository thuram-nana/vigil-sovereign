# VIGIL — Session Handoff (continuous delivery)

Repo: thuram-nana/vigil-sovereign. No credentials in this file.

## 1. Where things stand

| Item | State |
|---|---|
| main | includes merged PR #992 (livefire nikto hardening), squash 74d5c86 |
| PR #996 AEGIS-SaaS (AE-0..AE-7) | OPEN, branch claude/aegis-saas-ph9x2k, head c9b2138. Owner authorized merge once ALL checks green |
| PR #993 billing-drain CLI | OPEN. P7 "SIGIL governor gates" FAILED on its last run (before #992 merged). NOT merged. Needs investigation + rebase on main |
| PR #994 ops sweeps | OPEN. Not yet checked for merge. Review caught + fixed a refund-of-completed-work bug |
| PR #995 ops runbooks | OPEN. Was all green. Not yet merged |
| PR #991 offboarding cascade | OPEN, green earlier. Not authorized to merge |

Owner authorization: merge #992-#995 only if ALL checks green. #996 merge also only when all green.

## 2. PR #996 check status at handoff
- All blocking checks green except P5 (integration two-env boundary), re-running on c9b2138.
- P5 root cause found and fixed in c9b2138: acceptance test's sovereign child lacked integration/ on PYTHONPATH.
- CodeQL (advisory) still red on GitHub. Locally, CodeQL 2.27.4 and 2.26.3, default and security-extended
  suites, tests in/out, threat-model local, actions: 0 new alerts and 0 alerts on changed lines.
  11 real alerts were fixed. Cause of GitHub's red is not visible from this toolset (no code-scanning access).
  Next: owner pastes the CodeQL check detail text, or grants code-scanning read.

## 3. AEGIS-SaaS delivered on claude/aegis-saas-ph9x2k (not yet on main)
- AE-0 sovereign monitoring-authority registry (snapshot schema bump, prune tripwire).
- AE-1 mint path + customer routes (flag VIGIL_CUSTOMER_MONITORING_ENABLED, default OFF).
- AE-2 keyless per-request authority check in the gateway.
- AE-3 enforcement gating (flag VIGIL_AEGIS_SAAS_ENFORCE, default OFF). Fixed a HIGH Host-header bypass.
- AE-4 metadata-only sealed reports + sovereign drainer + tenant events route.
- AE-5 monitoring billing on a separate subscription line; period clamp; cancel/past-due cascade;
  plan-change enforcement; renewal grace (72h); reconcile sweep. Fixed 3 HIGH + 4 MED lifecycle bugs.
- AE-6 managed deploy: gateway CLI flags, compose + systemd, report secrets, drain/reconcile CLI verbs.
  monitoring-secret CLI prints no secret and no location; --export-to added.
- AE-7 cross-plane acceptance test (8/8) + flag-hold runbook.
Verified locally: full SIGIL suite green except 2 known env-only tests; aegis suite 0 failures;
ruff + mypy ratchet green.

## 4. Open request from owner: real prices, no placeholders
- apps/sigil/sigil/governor/catalog.py is marked PLACEHOLDER: AEGIS per-host prices (49/99 USD) and the
  whole price list, plus provider plan ids.
- Plan: set final prices in code and remove placeholder wording; move provider plan ids to owner config
  (internal price_id -> provider plan id), fail-closed at startup in production if unmapped. Real
  Flutterwave plan ids cannot be invented here; the owner must create them in the merchant dashboard.
- Not started at handoff.

## 5. Remaining work (in order)
1. Get PR #996 all green (P5 re-run, CodeQL detail) then merge.
2. Investigate PR #993 P7 failure, rebase on main, re-check; merge #993/#994/#995 only if all green.
3. Prices + no-placeholder slice (section 4).
4. After #996 and #991 are on main: test that decommissioning an org revokes/unpublishes its monitoring.
5. #14 enterprise postpaid invoicing (PP-1..PP-4), on top of the AEGIS billing code.
6. #7 polish: customer Monitoring UI screens; marketing-domain vhost; NVD/EPSS CVE enrichment.
7. #4 leftovers: kill-switch default decision (owner).
8. Triage 8 open Dependabot PRs (some security bumps, e.g. pydantic).

## 6. Environment notes
- Use python3.13; venvs .venv-sovereign / .venv-offense. CI-faithful lint env at /tmp/lintenv.
- Known env-only failures: test_golden_vectors_match, test_live_server_registers_eight_tools,
  test_gitleaks_negative_control_real_catch.
- Git push works over HTTPS. No Actions-log or code-scanning tools available.
- Long text about security specifics gets cut off mid-output; keep briefs short and put detail in files.
