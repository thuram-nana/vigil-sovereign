---
name: vigil-government-complete-program
description: "The 2026-07 \"make VIGIL government-complete + research-grade\" program — Phases A/B/L/P/C, what merged, and the honest remaining scope."
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-30T09:27:15.166Z
---

Program to "fully implement the gated/scaffolded parts" so VIGIL is complete enough for a government
(ANTIC-class assurance) and compelling for global research. Re-baselined against ~80% already-merged prior
work; executed as phases, each build → adversarial red-pen → 6-job CI green → squash-merge. Repo
`thuram-nana/vigil-sovereign` @ /home/kali/vigil. **NO `Co-Authored-By: Claude`** (see [[vigil-authorship-contributors]]).

MERGED to main (all CI-green):
- **#178 Phase A** — per-action owner-signed approval is the DEFAULT offense authority (`vigil approve` + broker + engine defaults to `build_approval_gate`); the Strix arbitrary shell (`exec_command`/`write_stdin`) is GATED BY DEFAULT (opt-out `VIGIL_WARDEN_STRIX_GATE`), queue→approval not hard-block. Red-pen BLOCK caught+fixed: the hook read args from the static `tool` def, not `ToolContext.tool_arguments` → the token bound a CONSTANT command (owner signed blind). Fix: read the ToolContext.
- **#179 Phase B** — how-to-verify on ALL surfaces (report/SARIF/cert/bundle/drawer), embedded per-session GraphStore as the default backend, `dossier --session` handoff, Inbox/assurance/feed UI, orphan-route removal. Red-pen BLOCK: `dossier --session` shipped operator secrets in the clear (URL basic-auth, chat tokens) under NON-secret keys while claiming to scrub — the scrubbers were KEY-NAME only → added a VALUE-level redactor (URL userinfo + bearer/JWT/api tokens) across every artifact + the index. +3 MED (graph partition-key aliasing `abc`vs`abc.`; feed double-spawn; zombie=alive).
- **#180 Phase L** — the one honesty defect closed. Loopback `error_signature` FACT reproduced + re-verified 3/3 offline (SQLite `unrecognized token`; the AS-BUILT claim had wrongly said MySQL). External testasp RE-corroborated live: `engage --spine` minted 4 cert-backed FACTs (boolean_sqli 0.99, open_redirect 0.90, 2× request_smuggling) onto `.blackboard/store.sqlite`; docs reconciled (the earlier per-run telemetry.json refusal-view vs the spine's confirmed FACTs).
- **#181 Phase P w1** — P6 proof-carrying-finding OPEN STANDARD (`docs/proof-carrying-finding/`: SPEC + 6 JSON Schemas + a STANDALONE VIGIL-free `verify_pcf.py` — stdlib+cryptography only, canonical-bytes parity PROVEN, 10 conformance tests incl. clean-env tamper rejection) + P4 attack-path/chokepoint (`spine_projector.project_spine` → worldmodel; `vigil attack-paths` = shortest paths + ranked chokepoints + blast-radius + what-if).
- **#182 Phase P/P1** — signed, tamper-evident, independently-verifiable benchmark scorecard (`benchmark --sign`, `make bench`; crucible 9/9 bugs, 0 FP, precision 1.000; m-of-n Ed25519 over canonical bytes + fingerprint pin).
- **#183 Phase P w2** — P2 calibration report (`framework.v2 calibration report`: ECE/Brier/reliability bins; invariant: re-scores DISPLAYED confidence only, never promotes) + P3 coverage-guided oracle-gated discovery (`scanner/coverage.py`: response-behavior buckets + a bandit scheduler; asserted never-gate-out, oracle-only FACT, deterministic injected-rng, explicitly NON-EVASIVE).
- **Phase C1** — the 6 CI jobs are now REQUIRED status checks on protected main (enforce-admins, no lockout — review-count 0). Nothing merges without green CI.

- **#185 P5 + docs** — closed the `engage --learn` cross-run AUTO-loop: the OutcomeLedger→calibrator half already auto-closed; now `--learn` also auto-persists+warm-starts a per-target Thompson bandit (`engage.py:_resolve_bandit_path` → `targets/<slug>/bandit.json`; non-circular, re-rank only). Refreshed README + FEATURES.md §7 to reflect every pending/scaffolded SOFTWARE feature as done (corrected the stale "Strix gate opt-in" README claim → default-on).

ALL software-completable work MERGED. HONEST REMAINING SCOPE (small refinement, capability present): the P2 Assurance reliability-diagram panel + `/api/calibration` provider surface once the OODA loop writes a per-engagement outcome ledger (the `calibration report` verb works today). Genuinely gated (unchanged, honestly labelled scaffold+fallback+runbook — never claimed active): real TEE (hardware), the live Claude call at runtime (needs a valid key — the box's is 401), full binary CRS patch synthesis (research).

LESSONS: background agents STALL on the stream watchdog ~60-70% here — salvage substantial partial work from the worktree (P4/P3 salvaged + finished by hand) or redo (P1/P2/P5). New tests importing `vigil_integration` at module scope break the framework-only "CRUCIBLE core" CI job → `pytest.importorskip` or move to `integration/tests` + the framework-inclusive sub-job. CI can lag on PR-open → re-trigger with an empty commit. `git add -A` grabbed `.claude/` worktrees → gitignored `.claude/` + `/scratch-demo/`. Egress (loopback + external) needs `dangerouslyDisableSandbox` (Bash sandbox drops TCP). Substrate recon saved at scratchpad/phase-p-substrate.md.
