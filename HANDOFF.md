
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
