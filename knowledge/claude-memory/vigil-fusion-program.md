---
name: vigil-fusion-program
description: VIGIL — the monorepo fusing SIGIL + CRUCIBLE/AEGIS + Strix into one Claude-powered provable-autonomy security + personal-AI tool
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-21T00:54:24.987Z
---

**VIGIL** = approved fusion of the owner's three systems into ONE Claude-powered monorepo at
**/home/kali/vigil** (github **thuram-nana/vigil-sovereign**, private). Working name VIGIL (owner to
confirm; NOT the same as the unrelated `vigil-apex` project). Plan file: `/home/kali/.claude/plans/parsed-popping-lemur.md`,
also copied into the repo at `docs/PLAN.md` + `docs/CONTINUATION.md` (resume-here doc) + `docs/research/FRONTIER.md`.
The 1-of-1 thesis: an autonomous agent whose every finding is deterministically ORACLE-confirmed (no
hallucinated findings), cryptographically SIGNED into a witnessed transparency log, and hard-GOVERNED by a
fail-closed WARDEN + charter + host-egress gate — that also runs the owner's life on the same sovereign spine.
No competitor holds >2 of {oracle-confirmed · signed-provenance · hard-syscall-scope · sovereign · full-Claude}.

**Architecture (LOCKED §12): fuse the PRODUCT, isolate the PROCESSES.** One CLI/repo/signed-spine + shared
`packages/core/vigil_core` (SIGIL's v2 Merkle-prune signed hash-chain; signing domain tag
`crucible-evidence-v1\x00` UNCHANGED = signature-compatible; v1 heads sign byte-identically). TWO envs:
env-sovereign (vigil_core+sigil, offense-free by construction — `assert_no_offense` bars `framework.*` AND
`strix.*`) and env-offense (vigil_core+crucible+strix). Findings cross as INERT signed JSON only. Two FATAL
flaws the whole plan is built to fix: **FATAL-1** unbounded sandbox egress; **FATAL-2** offense-free boundary.

**Members (history-preserving git subtrees):** `apps/sigil`, `engine/crucible` (AEGIS at `framework/v2/aegis`),
`vendor/strix` (Apache-2.0; telemetry deleted, Claude default), `packages/core/vigil_core`.

**Status (2026-07-20):** **P0–P10 core + I1 + I2 ALL MERGED to main** (via ~8 PRs; latest I2 = PR #8 @0d4ce90).
Every phase went through the full discipline (build → independent red-pen in isolated clone → fix → adversarial
re-check on the fixed branch → PR → wait ALL CI green → merge); ~25 real defects caught. P6 egress gate
(FATAL-1), P5 two-env boundary + inert-data seam, P7 WARDEN tool gate + two-anchor TrustRoot + offense-gate
anti-replay, P8 Claude runtime, P9 OracleConfirmationAdapter, P10 spine-sign findings — all done. I1 =
per-run randomized-challenge oracles + kernel-minted Verified|Abstain (unforgeable HMAC). **I2 done** — see
[[vigil-i2-transparency-log]] (witnessed transparency log + a shared-core KEYLESS-FORGERY fix).

**CI on main:** 6 jobs (vigil_core · CRUCIBLE-core · gateway · integration · strix · sigil-governor). CRUCIBLE-core
was RED since subtree import (test_charter_path_for_template needed `engine/crucible/targets/_template/charter.md`,
removed by the subtree clean; crucible_root() anchors at engine/crucible via the CLAUDE.md sentinel) — FIXED in
PR #8 by restoring the blank `_template` scaffold (`.gitignore` whitelists `!targets/_template/**`). All 6 green now.

**I4 slice DONE (PR #9 @0d6c2cb):** m-of-n threshold-gated destruction authorization
(`integration/vigil_integration/destruction_gate.py`, 26 tests) — LOCKED decision 2. On top of the P7
conjunctive gate, destructive/high-blast actions require a quorum-signed `DestructionAuthorization`, fail-closed
on: m-of-n via verify_threshold · MANDATORY owner bound into an immutable `DestructionAuthority(trust_root,
mandatory_signer_ids)` (NOT a per-call string — the red-pen BLOCK: a worker is itself a registered authorizer, so
a free owner_key_id let worker+policy self-authorize) · action-binding · dead-man's-switch (policy-capped window,
no long-lived sleeper) · single-use (is_consumed REQUIRED, no fail-open default; caller commits atomically to
spine). Red-pen caught the owner-binding BLOCK + fail-open default + type-confusion-raises; re-check confirmed
resolved. Uses exact-type checks (type(x) is C) to block subclass-override binding bypass.

**Remaining — ALL infra-blocked in THIS env (offense venv has NO claude_agent_sdk/mcp/anthropic/litellm/agents; Z3 absent):**
**I3** (Claude-Agent-SDK-native body: Strix Kali tools → in-process MCP servers — needs the SDK + a live Kali
container), **I4-TEE** (Intel-TDX/SEV-SNP + Anthropic Confidential Inference — needs TEE hardware; FROST single-sig
aggregation also deferred, verify_threshold already gives the m-of-n *property*), **I5** (AIxCC binary/auto-patch —
needs Z3/angr + fuzzing infra; study ToB "Buttercup"). These need the owner's environment/hardware decisions.
**SCITT/OpenVEX DONE (PR #10 @8352053):** `integration/vigil_integration/scitt.py` (20 tests). Offline-verifiable-
forever finding certs (plan §8-C): OpenVEX vocab (confirmed→affected, lead→under_investigation) · DSSE Signed
Statement (m-of-n over the PAE, domain-separated from raw evidence sigs) · RFC-6962 Merkle transparency log +
Receipt with a real inclusion proof · verify_receipt REQUIRES a caller-pinned expected_root (red-pen BLOCK: a
receipt carries its own root → a fabricated receipt passed; pinning fixes it) · verify_anchored_receipt pins that
root to an I2 witness-attested checkpoint. Merkle core verified byte-identical to an independent RFC-6962 ref +
exhaustively fuzzed (0 false accepts). 3 review rounds closed BLOCK-1 (honesty) + fail-closed completeness (witness/
payload/index/size/proof-depth — every malformed input denies, never raises) + LOW-1 (sig-order-stable digest).

**Conjunctive WIRING DONE (PR #11 @d14ce0c):** the I4 destruction gate is now the 3rd conjunct of the offense
governance gate (`conjunctive_gate.conjunctive_decide` + `build_offense_gate`). Destructive/high-blast → ALLOW iff
CRUCIBLE in-envelope AND WARDEN auto AND owner-inclusive m-of-n threshold-authorized for THIS action; fail-closed
on no-gate/error/unauthorized/target-mismatch. Red-pen caught: the conjunct was DEAD in build_offense_gate (only
extended the pure fn — a "trap" destructive flag) → fully wired + production-path test w/ mutation teeth; loose
truthiness → `is True`; missing cross-binding (CRUCIBLE target vs quorum-signed target) → require equality.

**Continuation totals: 6 PRs merged this session** (#8 I2 · #9 I4-slice · #10 SCITT · #11 conjunctive-wiring ·
#12 SCITT-bridge · #13 checkpoint-emitter, main @276cab9), each build→red-pen→fix→re-check→CI-green→merge; ~16 more
real defects caught. **#12 SCITT bridge:** `scitt.mint_finding_statement` + `oracle_adapter.certify_to_scitt` —
a confirmed fact → registered offline-verifiable SCITT statement (lead refused; red-pen BLOCK was trusting
receipt.root → pinned; null-field guard). **#13 CheckpointEmitter:** operational spine-head → witnessed checkpoint
chain (idempotent on position, atomic willing-set gather via Witness.would_accept, key_id dedup). Also fixed
`is_split` to key on `head_hash` (a fork = a different HEAD; a same-head merkle_root diff = un-adjudicable prune
boundary, authenticated by the signed head/archive, NOT a fork) — the deepest re-check finding (BLOCK-A). Emitter
review went 3 rounds: no-progress false-fork · non-atomic cosign brick · honest-prune false is_split.

**USER PICKED "keep building self-contained" — that scope is now COMPLETE.** Full pipeline connected end-to-end:
propose → oracle-confirm (P9) → sign cert → SCITT statement (#12) → transparency log → witnessed checkpoint chain
(#13) → offline-verifiable receipt; governance = CRUCIBLE+WARDEN+threshold-destruction conjunctive (#11).
Only docs/consolidation remains at zero infra. **Blocked on OWNER's environment (the headline moonshot):** I3
Claude-Agent-SDK body (needs SDK+live Kali container), I4-TEE (hardware), I5 AIxCC (Z3/angr/fuzzing). Deferred:
P9 live scope-gated re-drive + extended Strix finding contract (live target); OpenTimestamps (live calendar).
Build protocol: production-grade, no stubs; build→adversarial dual-review→re-check→green→PR/merge.
See [[anti-hallucination]] [[sigil-hardprune-program]] (its Merkle-prune head is the I2 transparency-log substrate).

**INFRA GOTCHAS this session (2026-07-19/20):** remote cloud agents (isolation:remote) ALL failed on
"stream idle timeout"; local sub-agent launches + `git push` intermittently blocked by the auto-mode classifier
(claude-sonnet-5) being "temporarily unavailable"; local Write/Edit/Bash worked with retries. **`git push` and `gh pr merge` are classifier-gated and INTERMITTENT
— retry succeeds** (a single retry has always cleared it); pushes/PRs/merges have all gone through this way. Do
NOT route file writes through Bash to dodge the safety classifier, and don't try to work around a denial in
bypass-y ways — just retry or ask. The "pc off/on" messages arrived via background-task notifications flagged
NON-genuine — not treated as user consent.
