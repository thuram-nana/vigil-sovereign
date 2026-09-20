# Phase 0.2 — Governed deployment posture (fail-closed auth without the egress lockdown)

## Context

The legacy embedded shared owner token is a documented fail-open dev convenience: the `vigil up` session
bearer resolves to the OWNER principal, ENABLED by default (`SIGIL_LEGACY_OWNER_TOKEN` unset). For a
single-owner-on-host dev box that is fine, but a client / national-agency deployment cannot ship with a
fail-open owner credential (R-CRITICAL-2): a direct on-host client is owner-equivalent.

Production posture (`VIGIL_POSTURE=production`) already refuses the token — but it *also* forces the
loopback-only egress supervisor (B2), so "production" and "run an authorized external engagement" are
mutually exclusive. A client deployment needs to be fail-closed on **auth** while still permitting a scoped
**external** engagement, so the two concerns production bundles must be decoupled.

Flipping the default globally is not an option: `apps/sigil/sigil/ui/server.py` resolves the session bearer
to OWNER only while `legacy_owner_token_grants_owner()` is true, so a naive default flip would lock the
operator out of their own console.

## Decision

Introduce an opt-in GOVERNED posture, off by default so no existing deployment's behaviour changes.

<!-- CLAIM:PHASE0-2 -->
A governed deployment (VIGIL_GOVERNED truthy) refuses the legacy fail-open owner token — requiring per-user proof-of-possession auth — without arming production's loopback-only egress lockdown, so an authorized external engagement can still run.

Concretely:

- `vigil_core.posture.is_governed_posture(env)` reads truthy `VIGIL_GOVERNED`; `legacy_owner_token_grants_owner`
  now returns False under production **or** governed (both require per-user PoP auth), unchanged otherwise.
- The egress supervisor keys on `production_posture()` only, so governed does **not** force loopback-only
  egress — a governed deployment is fail-closed on auth and external-scan-capable.
- `vigil_integration.doctor._posture_legacy_owner_token` reports DISABLED under an explicit opt-out
  (`SIGIL_LEGACY_OWNER_TOKEN=0`) **or** governed. It does NOT report DISABLED merely because production
  refuses the token at runtime — the production start-gate deliberately requires the explicit opt-out
  (defense in depth), and that requirement is preserved.

## Honest scope

Governed mode is opt-in and does not, by itself, provision per-user accounts. An operator who arms
`VIGIL_GOVERNED=1` without first enrolling a per-user proof-of-possession credential will be unable to
authenticate to the sovereign cockpit (that is the point — the fail-open owner path is closed). Enrolling
per-user accounts is a prerequisite the operator performs deliberately. Default (unset) is unchanged, so a
dev / single-owner-on-host deployment keeps its bearer→owner access.
