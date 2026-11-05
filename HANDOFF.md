
### Milestone 10 — AEGIS-SaaS (#42) on branch claude/aegis-saas-ph9x2k (NOT merged)
- AE-0 (ac4cee5, +fold 02d2e42): sovereign MonitoringAuthorityRegistry; snapshot v6; prune tripwire;
  grant bound to its minted-against ownership proof. 16 tests, 10/10 mutants; red-pen 0 HIGH/0 MED.
- AE-1 (bcdaa8d, +fold e895574): Provisioner.monitor_authorize/revoke/list; new rbac perm `manage_monitoring`
  (org_admin+owner only; != run_engagement/offense_authority); owner-signed SignedMonitoringAuthority published
  verify-only (0600/0700, sha256 filename, atomic); feature flag VIGIL_CUSTOMER_MONITORING_ENABLED default-OFF;
  custui routes /api/customer/monitoring[/authorize|/revoke]; config.MONITORING_WINDOW_SECONDS (default 30d,
  client may only shorten). Red-pen: 2 MED confirmed 3/3 and FIXED — revoke_proof + orgs.revoke_org now cascade
  to unpublish the artifact (retire), and publish-failure-revokes-grant is tested. Verified here: provision
  +registry+asset_ownership+orgs suites pass; FATAL-2 clean; ruff + ratchet green.
- TODO: AE-2 keyless gateway per-request authority verify (no key); AE-3 enforcement gating (BLOCK + fired
  oracle+cert + AEGIS_RESPOND + prod flag OFF); AE-4 verdict->tenant Monitoring surface; AE-5 catalog plan;
  AE-6 managed gateway deploy; AE-7 acceptance + flag-hold.
- AE-2 (6695aac, +fold d5c120c): aegis/monitoring_authority_check.py — keyless verify-only per-request check
  (pinned owner authority root, exact tenant + normalized host + half-open window, fail-closed, never raises,
  FATAL-2 lockstep filename test). 44 tests, 12/12 mutants. Red-pen: 0 HIGH/0 MED, 1 LOW folded.
- AE-3 (9edee32, +fold dfc66b6): gateway enforcement gating. Tenant gateway REQUIRES saas_host (fixed protected
  host); no valid authority => uninspected pass-through; OBSERVE never blocks; hard block needs BLOCK grant +
  VIGIL_AEGIS_SAAS_ENFORCE (default OFF) + enforce + AEGIS_RESPOND + kill-switch untripped, on a confirmed
  certificate verdict (request AND response side). Red-pen found a real HIGH (auth keyed on client Host header
  => bypass / cross-host) — FIXED + regression-tested; MED (response-side untested) FIXED. Full aegis suite 0 fail.
- NEXT: AE-4 verdict crossing -> tenant Monitoring surface; AE-5 catalog plan; AE-6 deploy; AE-7 acceptance.
- AE-4..AE-7 + billing folds: AE-4a a6d871c (gateway sealed metadata-only reports); AE-4b/5/6/7 built in parallel
  worktrees, merged at 826d2ef; AE-5 fold acff3e0 (separate monitoring subscription line, period clamp, down-path
  cascade, plan enforcement + renewal re-mint, reconcile sweep, flag-off catalog hiding, slot predicate) and fold 2
  6cc5a04 (down-event routing by full catalog, 72h renewal grace). Reviews: AE-5/7 4+1 lenses x 3 skeptics found
  3 HIGH + 4 MED (all fixed); re-reviews clean. Verified here: monitoring/billing suites green, acceptance 8/8,
  ruff + ratchet green; full SIGIL suite 2426 pass (2 known env-only fails).
- PR #996 (AEGIS-SaaS -> main) OPEN. Owner authorized merge once ALL checks green. Status at checkpoint: all
  blocking checks green so far; RED: "pre-commit hooks (advisory)" — every hook + full-tree gitleaks 8.28.0 +
  negative controls PASS on a clean checkout of this branch (likely transient hook-env build), re-running on this
  commit; "CodeQL" (default setup, advisory) reports new alerts that this toolset cannot read (no code-scanning
  access) — needs owner: grant access to fix/triage, or decide dismissal (dismissal requires owner approval).
- Parallel close-out PRs open (NOT authorized to merge): #992 livefire nikto, #993 billing-drain CLI,
  #994 ops sweeps (review caught + fixed a refund-of-completed-work money bug), #995 ops runbooks.
