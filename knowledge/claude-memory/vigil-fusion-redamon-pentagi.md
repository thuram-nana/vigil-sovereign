---
name: vigil-fusion-redamon-pentagi
description: "VIGIL-FUSION program — absorb redamon (Python/LangGraph) + pentagi (Go) into VIGIL's provable core; F0+F1 merged, F2-F12 planned"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-07-21T18:33:22.519Z
---

**VIGIL-FUSION** (extends [[vigil-fusion-program]]) — fuse the two strongest OSS autonomous-hacker
repos INTO the already-built VIGIL so it gains their "body" while every finding stays oracle-confirmed
+ signed, every action governed, the personal core offense-free. Plan APPROVED (this session) in
`/home/kali/.claude/plans/parsed-popping-lemur.md` (overwritten with the fusion plan). Repo
`/home/kali/vigil`, remote `thuram-nana/vigil-sovereign`, main.

**Sources:** **redamon** (github samugit83/redamon, MIT, Python/LangGraph, 2.2k★, active) = PRIMARY —
lift/adapt Python. **pentagi** (github vxcontrol/pentagi, MIT+lawful-pentest-EULA, Go) = DESIGN-ONLY,
reimplement ideas in Python (don't vendor Go). GitHub reachable via WebFetch (bash has NO network — no
git clone, no pip install). Full research in repo `docs/research/fusion/` (README + ANALYSIS.md
synthesis + SCOUT-INVENTORY.md 14-module extraction). NOTICE file added (redamon MIT attribution).

**LOCKED owner decisions:** strategy = **hybrid provable-native** (reimplement trust-core-touching
modules natively through oracle/spine/gates; vendor clean MIT Python adapters; heavy tools as governed
Docker sidecars behind egress gate); scope = **full fusion, phased, ALL FOUR first-wave (MCP+EvoGraph+
AI-Gauntlet+recon) + the rest**. Claude-everywhere (strip non-Claude defaults).

**GOVERNING INVARIANT (non-negotiable):** every ported subsystem only PROPOSES; only the CRUCIBLE
deterministic oracle mints a signed FACT; only the conjunctive gate authorizes; only the egress gate
lets traffic out. Both source repos treat LLM/graph/judge as AUTHORITY — VIGIL forbids that. Every ⚠
phase merges WITH its provable wrapper in the same PR. Invert every fail-open default to deny-by-default.

**Roadmap F0-F12:** F0 docs · **F1 input-safety** · F2⚠ spine-anchored ReAct core (keystone) · F3★ MCP
tool boundary+recon · F4★ EvoGraph as signed-spine projection · F5 cognition governors · F6⚠ fireteam
· F7⚠ Chain-AST · F8★ AI-Gauntlet (oracle_kind FACT/LEAD routing) · F9★ fs/job/traffic · F10⚠ CypherFix
remediation (auto-REJECT on timeout) · F11 observability · F12 KB-RAG/skills/budget. (★ = owner's four.)

**DONE (merged):** F0 (PR #15, research docs) · **F1 (PR #16 @dd2b665) — input-safety + typed-proposal
boundary**: new pkg `integration/vigil_integration/safety/` = prompt_safety (nonce untrusted framing +
ZWSP defang + guidance) · hard_guardrail (deterministic .gov/.mil/.edu/.int + ~180 IGO scope FLOOR,
pre-charter) · llm_intake (transient classifier + Claude-native retry + param self-heal + fail-closed
JSON→proposal) · url_guard (SSRF pre-filter reusing vigil_gateway.denylist, behind netns L3/L4 gate).
40 tests; CI integration job gained `gateway` on path. **Red-pen took 4 rounds on the scope FLOOR** —
authority-confusion kept getting deeper: userinfo/unicode-dot → backslash-vs-urlsplit → **requests-vs-
httpx divergence** (requests folds `\`→path, httpx keeps `\` → they reach DIFFERENT hosts for
`x\@un.org`). FIX: hard_guardrail is CLIENT-INDEPENDENT — `candidate_hosts()` computes host under BOTH
readings, blocks if EITHER is protected; 0/6960 differential bypasses vs both real clients. LESSON: a
deny-only floor must track EVERY client, not one; `urlsplit` != the fetch client. Also fixed a
RecursionError fail-open in the JSON parser + string-unaware repair.

**F2 slice-1 DONE (PR #17 @1896e7e):** the KEYSTONE — `integration/vigil_integration/agent/` (import-clean,
gate+oracle INJECTED → testable w/o live kernel/framework). state.py (Phase info/exploit/post + ActionType×7
enums; LLMDecision/ToolCall/OutputAnalysis/Finding/AgentState — facts[oracle-confirmed,signed] vs leads
[proposals] SEPARATE stores; Finding model-validator REJECTS status=fact w/o non-whitespace evidence_ref).
phases.py (phase→WARDEN tier: info→A1/exploit→A2/post→A3; destructive floors A3; transitions monotone one-step,
downgrade/skip refused). react.py = the interposition: parse_decision (fail-closed→downgrade malformed action,
total garbage→ASK_USER human-pause, NEVER an action-edge from garbage) · classify_edge/authorize_edge (every
tool→conjunctive gate at phase tier; escalation/fireteam→QUEUE for signed approval, never auto; invalid/gate-error
→DENY) · intake_result (ANTI-HALLUCINATION seam: LLM output_analysis claims→LEADs; exploit_succeeded→injected
deterministic oracle over retained raw output; ONLY oracle+signed-evidence-ref mints a FACT; no oracle→no fact).
25 tests. Red-pen PASS (tried forged-fact/ungated-tool/auto-escalation → all fail closed); 3 LOW hardenings closed
(type-level fact-evidence, strict non-whitespace oracle ref, EdgeVerdict outcome derived from allowed).

**F5 DONE (PR #18 @ce4fd9b):** `integration/vigil_integration/agent/cognition.py` — non-authoritative cognition
governors ported from redamon `productivity.py` (MIT), stamped BUDGET/SCHEDULING-ONLY (doctrine C4): `governance_decision`
(5-signal score→tier→escalating action none/inject_hint/require_deep_think/require_pivot/block_next_expensive_call) ·
`audit_productivity_claim` (honesty audit: downgrades a dishonest "progress" claim vs the MEASURED state delta) ·
`detect_uniform_response_anomaly` (INCONCLUSIVE-not-NEGATIVE; outlier-robust MODAL-CLUSTER statistic, not max-min spread) ·
`extract_axis`/tested-axes ledger · `deep_think_is_novel` (≥2 hyps + anti-paraphrase + anti-superset). Imports/returns NO
Finding/AgentState.facts; action vocab disjoint from finding verbs. 41 module + 241 integration tests green, ruff clean,
deterministic (no wallclock/rng). **4 ADVERSARIAL ROUNDS, each caught real defects; the SOVEREIGN INVARIANT (nothing
gates finding truth) + determinism HELD every round:** R1 red-pen (5: authority-HELD, anomaly false-neg from a hard
size-grid, 3 crash-on-untrusted-input) → R2 re-check (2 FIX-INTRODUCED: RE-1 empty-citation bypass via _as_text-then-strip,
RE-2 half-hardened actionable_findings) → R3 5-agent perspective-diverse panel+completeness-critic (ROOT: "growth=non-empty
COLLECTION not truthy scalar" honored in only 1 of 3 growth-judgment sites; + totality holes; fixed at root via ONE
`_coll_len` used everywhere + `_trace_list`/`_as_text` coercion at every consumer) → R4 focused red-pen (1 bounded MEDIUM:
invisible-citation class beyond Cf — Hangul-filler/Braille-blank/combining-mark — + docstring overclaim; fixed via widened
principled predicate + honest docstring). LESSON: narrow per-repro fixes keep leaving ADJACENT gaps (R2/R3 proved it) — fix
the INVARIANT at every decision point with a shared helper; a deny/growth check must track the WHOLE class (zero-width ≠ just Cf).

**F3★ slice-1 DONE (PR #19 @c0098bb):** `integration/vigil_integration/tools/` — the governed MCP tool boundary.
`mcp_registry.py` = redamon `mcp_registry.py` ported (pydantic MCPServer/ToolSpec/BearerAuth, trust-tiered
`validate_servers`, phase-view) with SOVEREIGN INVERSIONS: default_phases→least-privilege `["informational"]` (not
all-phases); unregistered tool→`[]` (deny everywhere); operator manifest `destructive` = authoritative RAISE-ONLY; trust
checks CASE-INSENSITIVE; broken server dropped whole. `governance.py` = the authz boundary: fail-closed phase gate→WARDEN
tier (info→A1/exploit→A2/post→A3)→the SAME injected conjunctive gate as F2 (`gate(tool_name,target,destructive)`);
destructive tools floor A3+requires_quorum(m-of-n); no gate/gate-error/out-of-phase/unregistered→DENY; NOTHING
self-authorizes. 34 module + 275 integration tests, ruff clean. **REVIEW = red-pen + 4 re-checks; the sovereign
authorization invariant HELD every round (18 malformed-gate shapes couldn't self-authorize; fail-open→deny + determinism
intact).** The SECRET-REDACTION surface (spine-safety) leaked in 4 SUCCESSIVE rounds via ONE recurring root cause — a
scrubber/vocabulary present on one path or detector but not the other (redact_for_api vs redact_tool_args; _INLINE regex vs
_is_secret_key). FIXED STRUCTURALLY: both surfaces route every free string through ONE `_redact_str`, whose inline arm calls
the SAME `_is_secret_key` that classifies dict keys → detectors CAN'T diverge by construction. Covers key-values (stem+
word-boundary+camelCase+crypto), nested (depth-bounded), argv flag→value, inline param=value/"param":"value" (URL-query incl
FIRST ?param, Cookie headers, JSON bodies), QUOTED spaced values, Bearer, url userinfo. Linear ReDoS (bounded regex+fixed-
width lookbehind; x2.0/doubling). Verified 0 leaks across a 23-position matrix + a 520-probe name fuzz (52 secret names ×10
positions), 0 benign over-mask. LESSON (F5's lesson, 4× harder): a redactor with TWO vocabularies or TWO paths WILL leak on
the gap — unify to ONE detector + ONE path; name-based detection is inherently best-effort (obscure abbreviations/positional
secrets = documented residual). One review AGENT STALLED (infra stream-watchdog) mid-finding → self-reproduced its leak from
its partial "realistic instances leak" note + exhaustive self-fuzz (more reliable than a stall-prone agent for name coverage).

**F4★ slice-1 DONE (PR #20, merged):** `integration/vigil_integration/graph/` — the attack-chain graph as a DERIVED
READ-MODEL projected from the signed spine (redamon EvoGraph reimplemented), "the single most dangerous fusion
(trust-laundering)". model.py (ConfirmationStatus CONFIRMED/LEAD split in the TYPES, spine-hash Provenance, bi-temporal
valid_from/invalid_from keyed on spine SEQ not wallclock). projector.py = the ONLY writer: `project(records)` deterministic
(total (seq,hash,canonical-body) order → byte-identical rebuildable view), confirms a finding ONLY on signed oracle evidence
(status=fact ∧ signed evidence_ref ∧ signature_ref), retires-never-deletes on refute, scope-gates every host-bearing bridge
(host/endpoint/port) fail-closed + CLIENT-INDEPENDENT on `\`. query.py = retrieval-only, FROZEN, authoritative=False (a lead
can NEVER appear in confirmed_findings). **REVIEW = red-pen + 3 re-checks; the anti-trust-laundering CORE HELD EVERY ROUND**
(no lead→fact under any probe: status case/ws, empty/partial refs, props-injection, F2-no-sig-bridge, attacker-stray-ref
downgrade all fail-closed). The churn was all PERIPHERY (demotion + scope-gating): R1 red-pen 2MED+3LOW → R2 re-check 4
FIX-INTRODUCED incl a **HIGH IPv6/`\` endpoint scope-smuggle** (my `split(':',1)` collapsed `[::1]:8080`→'' → admitted under
deny-all incl `[::ffff:<ipv4>]` metadata-smuggle) → R3 re-check PASS-on-sovereignty + 1 MED (resurrection reconnects edges).
KEY FIXES: `_authority_host` (correct IPv6 bracket parse, client-independent `\`-fold, both readings gated, fail-closed on
empty host); a bare/unsigned refute can DEMOTE only a LEAD not a CONFIRMED fact (mirror-of-laundering — demotion needs an
oracle-GROUNDED signed refutation); a non-grounded refute retirement is RESURRECTED (node+edges) by a later oracle
confirmation (opinion can't suppress a proof); PriorChainContext frozen; totality on non-JSON props + garbage record list.
LESSON: scope-gate host extraction must be client-independent (the F1 `\` class, AGAIN) AND handle IPv6 brackets; a graph
that DEMOTES needs the same rigor as one that PROMOTES (suppression is the mirror of laundering).

**8-PHASE PARALLEL FLEET — ALL MERGED (this request; PRs #21-28):** operator asked to build ALL remaining phases fast via
specialized agents. Ran a background Workflow (one build→red-pen→fix pipeline/phase, all parallel, each a distinct new
subpackage → 0 file conflicts; ~2.5M tokens). Then an independent VERIFY workflow re-checked the 5 BLOCK→fixed phases (fixer
self-report NOT trusted). Orchestrator (main session) owned all commits, merged SEQUENTIALLY. **MERGED:** F6 fireteam/ (PR#21,
per-member tier caps + single-writer spine queue) · F8★ gauntlet/ (PR#22, oracle_kind judge_llm→LEAD never auto-FACT) · F10
remediation/ (PR#23, CypherFix over F4 graph, timeout→REJECT, PR only after m-of-n) · F7 chainast/ (PR#24, byte-identical
round-trip + append-only summaries) · F11 observability/ (PR#25, emit-only + secret-free spine-bound spans) · F12 kb/ (PR#26,
[UNTRUSTED]-framed RAG + traversal-guarded advisory skills + defer-only budget) · F2b agent/checkpoint.py (PR#27, append-only
signed AgentState snapshot, DENY-by-default rebuild) · F9★ fsjob/ (PR#28, sandbox unescapable + job_spawn escalation-proof +
protected jobs/ provenance). **545 tests green on final main.** EVERY phase passed an INDEPENDENT red-pen; the 5 that BLOCKed
were fixed AND re-verified by a fresh red-pen before merge (never trusted the fixer). LESSONS: F2b's totality defect RECURRED
3× at successive unguarded points (RecursionError in _load_state → too-narrow except at next() → at the iter()/bool()
preamble) — close a totality class by guarding the WHOLE iteration surface, not the reported instance; F9 extract needed
per-MEMBER protected-subtree checks (dest-prefix alone insufficient) + case-fold; F11 reused the F3 redaction for span KEYS
(one vocabulary). A general-purpose fixer's self-reported PASS is NOT a substitute for an independent re-check.

**★ OWNER'S FOUR ALL MERGED: F3 (MCP) · F4 (EvoGraph) · F8 (AI-Gauntlet) · F9 (fs/job/traffic).** The whole F0–F12+F2b
roadmap is merged — redamon/pentagi "body" fused through VIGIL's provable layer, every phase adversarially reviewed.
**REMAINING (deferred, infra-blocked):** F3 slice-2 (live Claude-Agent-SDK MCP client + Kali executors), F8 live subprocess
red-team tools (garak/PyRIT), F4/F10 live Neo4j, F11 live OTel collector, I4 TEE/FROST, I5 AIxCC live patch-build — pure
logic+gate-wiring is built+unit-proven here; live-fire runs on owner infra (same deferral shape as I3/I5).

**(historical: original F2 spec)** Reimplement redamon's ReAct core (single structured LLMDecision → 7 action
types → one router; ~14 nodes) + phase machine (informational→exploitation→post_exploitation) as
VIGIL's Python agent body, re-routing EVERY action edge through WARDEN tiers (info~A0/A1, exploit~A2,
post~A3) + conjunctive gate + egress gate; LLM `exploit_succeeded`/output_analysis = LEAD only, raw
tool output → CRUCIBLE oracle before any signed FACT; HITL await_* = the signed-approval gate leg;
replace mutable checkpointer with SPINE-SNAPSHOT checkpointing. Build pure state-machine + injected
gate/oracle thunks (testable here, like conjunctive_gate); live kernel/framework wiring tested in the
crucible-side CI run. Likely new pkg `engine/vigil_agent/`. Discipline unchanged: build→red-pen→
re-check→CI-green→merge (per-phase). venv `.venv-offense`; F1 tests run PYTHONPATH=integration:gateway.
