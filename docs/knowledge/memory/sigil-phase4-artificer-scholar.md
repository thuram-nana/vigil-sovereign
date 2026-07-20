---
name: sigil-phase4-artificer-scholar
description: "SIGIL Phase 4 — ARTIFICER (background coding, PRs-not-pushes) + SCHOLAR (sourced research)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

**SIGIL Phase 4 (ARTIFICER + SCHOLAR) — BUILT** at **`/home/kali/sigil/sigil/agents/`** (extends the [[sigil-phase3-agent-mesh]] framework). SIGIL §4.4/§4.5. Both acceptance deliverables **PROVEN with real `claude -p`**.

**ARTIFICER (§4.4, `artificer.py`, ceiling A2):** owns a background coding task via headless Claude Code. `run(task, repo, test_cmd, coder)`: checkout a fresh branch → `coder.code()` (ClaudeCoder = `claude -p --permission-mode acceptEdits` in the repo, or a test double) → **run test_cmd — a PR is proposed ONLY if it PASSES** (red test → a `finding`, PR withheld = correctness discipline) → commit locally + propose a `pr` record (A2, QUEUED). **NEVER pushes** (git push/deploy = A3, no such method exists). **DEMO: fixed a real slugify bug (`s.strip().lower().replace(" ","-")`), tests passed, PR proposed on branch `artificer/task` awaiting approval.**

**SCHOLAR (§4.5, `scholar.py`+`sources.py`, ceiling A1):** sourced research. `run(question, sources, synthesizer)`: read each source (`read_source`: http(s) fetch + HTML-strip, or local path; '' on failure) → `synthesizer.synthesize` (ClaudeSynthesizer = `claude -p` → JSON claims{claim,source,quote,confidence}, or a double) → **VERACITY (reuses the consolidation serve-the-quote gate `grounds_in_source`): a claim is GROUNDED only if its quote is VERBATIM in the cited source AND ≥2 salient tokens** → report grounded claims (cited+confidence) + FLAG unverified separately (never asserted as fact) → `report` record (A1). **DEMO: researched WARDEN over SIGIL.md + kernel README → 3/3 claims source-verified (Ed25519, A0-A3 tiers, hash-chain), each with a verbatim quote.**

CLI: `sigil agents artifice --repo --task --test` / `sigil agents research --question --source ...`. New KINDS: report, pr. **Tests: 6/6 (`tests/test_agents_phase4.py`)**. Full system **73/73** (48 Python + 25 Rust).

**RED-PEN REVIEW DONE — 7 findings, all fixed** (adversarial workflow, attack→verify):
- **CRITICAL — SCHOLAR served the model's CLAIM, not the verbatim QUOTE.** A fabricated claim paired with a *real* quote would have been presented as a source-verified fact. This is the EXACT [[sigil-phase0-memory-loop]] consolidation defect recurring. **Fix:** `compose_report` now serves the verbatim source span as the authoritative content under "Source-verified spans"; the model's claim is printed on a "model's reading (ADVISORY, not verified)" line only. Proven by `test_scholar_serves_quote_not_claim_and_flags_unbacked` (claim="stores keys in PLAINTEXT" + the real Ed25519 quote → the fabrication appears ONLY on ADVISORY lines).
- **HIGH — no filesystem isolation.** ARTIFICER edited the real working tree (isolated only by branch), so pre-existing/unrelated edits could get bundled and a failure dirtied the repo. **Fix:** the coder now works in a dedicated **git worktree** (`worktree add -B <branch> <tmp> <base>`, removed in `finally`); the main tree is never touched.
- **HIGH — trivial-test greenwash.** CLI default `--test true` (and no `--test`) would trivially "pass" → a PR stamped "tests passing". **Fix:** `_TRIVIAL_TEST` frozenset + `real_test` guard: no real test cmd → emit an **UNVERIFIED finding, withhold the PR** (never claim tests passing). cli.py now passes `test_cmd=None` (not `"true"`) when `--test` absent.
- **LOW — fixed branch name** collided across tasks → **Fix:** `_slug(task)` = sanitized-prefix + `sha256(task)[:6]`, unique & stable per task.
- **2 test-honesty findings (HIGH/MED):** the never-pushes test asserted on method NAMES (`dir()`), and no test proved the fabrication-with-real-quote case. **Fix:** `test_artificer_never_invokes_git_push` now **spies every git argv** (behavioral — asserts `push` never appears, `commit` does); added the CRITICAL serve-the-quote test above + `test_artificer_withholds_pr_without_a_real_test`.

**RECURRING LESSON (3rd time now — consolidation, then here):** token-analysis of a model's *paraphrase* is NOT entailment. **Always serve the byte-verbatim source span as the authoritative fact; the model's free-text is advisory-only.** A gate that verifies a quote but then *serves the claim* is a padding attack waiting to happen. Same discipline as CRUCIBLE's serve-the-quote / oracle-authority rule.

**STILL-OPEN HONEST NOTE:** SCHOLAR `read_source` fetches arbitrary URLs (SSRF-shaped) / reads arbitrary local paths — acceptable for A1 owner-directed research but not yet scope-gated; revisit in Phase 6 hardening.

**NEXT:** Phase 5 (perception: camera/screen VLM + BASTION defensive posture on OWN infra only); then Phase 6 (hardening: budgets, kill switch, mobile bridge, dashboard, + SCHOLAR source scope-gate). Wire ARTIFICER/SCHOLAR actions through the Rust WARDEN signed log. Roadmap SIGIL.md §11.
