# VIGIL — sovereign, provable, autonomous security + personal-AI (monorepo)

> Working name. Fuses SIGIL (sovereign signed-spine + WARDEN governance), CRUCIBLE/AEGIS
> (oracle-authority offensive/defensive engine), and Strix (Claude-powered agentic Kali sandbox)
> into one Claude-powered tool. See the approved plan for architecture + phases.

## Layout (product fusion, isolated cores)
- `packages/core/vigil_core/` — shared signed-chain + canonical + crypto + trust-root (imports NO framework.*/strix.*)
- `apps/sigil/`     — SIGIL personal orchestrator (offense-free by construction) + Rust WARDEN kernel
- `engine/crucible/`— CRUCIBLE offensive engine + AEGIS defensive dual (framework.v2)
- `vendor/strix/`   — Strix autonomous AI-hacker (Apache-2.0, Claude-migrated)
- `gateway/`        — host-side deny-default egress firewall + scope_gate forward-proxy (FATAL-1 fix)
- `integration/`    — OracleConfirmationAdapter, WardenGateHooks, the inert signed-data seam

Two isolated build environments share `vigil_core`: env-sovereign (vigil_core+sigil) and
env-offense (vigil_core+crucible+strix). Offense runs as a separate no-owner-key process; findings
cross to the personal spine as inert signed data only.
