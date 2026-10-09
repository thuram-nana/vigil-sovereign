# VIGIL — Unified-UI End-to-End Certification

**Date:** 2026-10-09 · **Branch:** `prod/ui-cert` (off `origin/main` `cfb59c13`) · **Target:** bundled MERIDIAN loopback range (`127.0.0.1:19010`)

## Scope
Bring the whole system up in production posture and drive the **entire unified Command UI end-to-end through a real browser** — every screen, every control — then prove the deterministic pipeline. All work is on the operator's own loopback system against an authorized range; no third party is touched.

## Method
- Tree fast-forwarded to `origin/main` (`cfb59c13`); sovereign spine crash-safe-migrated (`sigil upgrade`, 93 records preserved, backup verified).
- Production posture: vault **TPM-SEALED**; **7 of 8** refuse-to-start controls green (sovereignty TRUSTED_CLOUD+ZDR, entitlement ACTIVE, charter PRESENT, legacy-token DISABLED, egress-supervisor ARMED, witness DISTINCT-QUORUM). The 8th (`backups`) is gated on a one-time re-login — see residuals. The refuse-to-start gate itself was **proven** (it correctly blocked on `backups`).
- Stack live under `sg tss` (so the sealed vault unseals): unified UI `:8770` + sovereign `:8733` + offense console `:8787` + gated-api `:8799` + MERIDIAN `:19010/:19011`.
- Harness: **Python Playwright** in an isolated `.venv-e2e` (FATAL-2 clean — no `framework`/`strix` import), vendored Chromium, **network-level** assertions (`assert_calls` via CDP) proving each button fires its real backend call — not just a DOM change.

## Results
- **UI wiring guard** (durable CI drift-test): 187 routes — **160 UI-driven, 27 intentionally-headless, 0 pending, 0 ORPHAN**; 43 action-funnel verbs, 0 orphan. Every button maps to a live route; every route is UI-driven or documented-headless. Closed-set dispatch namespaces (ceremonies/hostcmd) are enumerated so a fake button is caught.
- **Full UI E2E: 115/115 PASS live** (125 s) across all 35 screens / ~116 controls. Detection/proof flows run **for real** against MERIDIAN (engage→FACT, codescan, AEGIS); destructive/offense controls (panic, kill-switch, destruction-quorum, live-target, weaponized) are **asserted-to-gate and never fired**.
- **Deep-pipeline proof (`vigil deploy-acceptance`): HANDOVER-READY — 6/6 checks PASS**: Anthropic reachability + oracle-gating · engage→signed FACT→offline re-verify (tamper rejected) · LEAD-stays-LEAD · codescan static FACT · AEGIS `enforce` 403 + re-runnable certificate · HexStrike `nmap`→SERVICE_REACHABILITY FACT.
- The **eval button** (EvalCapabilityGrant) is surfaced in the UI: owner-gated, override set locked to the closed enum {witness_quorum, blast_veto, containment_preview}, confirm-gated, keys never in the browser.

## Defects found by the E2E, and fixed (all verified live)
1. **[Functional]** Defense "Destruction quorum (m-of-n)" card did a `GET /api/destruction/status` but the route is POST-only → card stuck on its error fallback. **Fixed** (GET→POST).
2. **[UI]** Screen-head `<h2>` title destroyed on data load on 6 screens (compliance, assurance, charter, proof, strix, report). **Fixed** (mount head once + redraw a child `#…-body` container).
3. **[UI]** Plane segmented toggle didn't re-highlight the active plane after a click. **Fixed** (`refreshTopbar`).
4. **[UX / defense-in-depth]** Genuinely-destructive controls lacked a client-side confirm (Users revoke/assign-role; Knowledge memory-reset / feed-pull). **Fixed** (confirms added). Safety kill-switch left as its by-design no-confirm.
- Two **test-quality** issues the red-pen caught (a green-washed Live-screen assertion satisfied by a background poller; a missed assert-gate on 3 danger-zone ceremonies) — **fixed**; the suite is now sound.

## Honest residuals (named, never faked)
1. **Full-production START** (`backups=ON`) needs a one-time **logout + login** (or reboot): the `tss` group only reaches the systemd `--user` manager on a fresh login, and a sealed vault requires TPM access to unseal at runtime. After re-login, `tools/oneshot-bringup/vigil-oneshot.sh` (idempotent) goes fully green and systemd manages the stack persistently. The refuse-to-start gate is already proven correct.
2. **`ANTHROPIC_API_KEY` is invalid/expired** on this host (server-rejected). The deterministic pipeline (FACTs/oracles) is unaffected and fully proven; AI-reasoning features (engage think, chat) need a valid key.
3. A historical commit body (ops cluster) overclaimed coverage; the suite's own docs are corrected (past commit messages are immutable).

## Deliverables (branch `prod/ui-cert`, no AI attribution — ready to PR/push)
- `tools/oneshot-bringup/vigil-oneshot.sh` + README — one-command fail-closed production bring-up + prove.
- `tests/e2e/` — Python-Playwright harness + 5 cluster suites (115 live tests) + smoke + FATAL-2 guard.
- `integration/tests/test_ui_wiring_matrix.py` + `docs/capability-matrix/ui-wiring-matrix.json` — the living wiring guard.
- The eval-button surface + the product fixes in `packages/vigil-ui/app.js`.
