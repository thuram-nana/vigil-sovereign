# VIGIL Fusion Analysis — redamon (Python/LangGraph) + pentagi (Go) → VIGIL sovereign provable core

Scope note: this is a design synthesis over the supplied scout findings and VIGIL's stated architecture. The governing invariant throughout: **the LLM and every ported subsystem only PROPOSE; only a CRUCIBLE deterministic oracle mints a signed FACT; only the conjunctive gate (authority ∧ WARDEN-tier ∧ m-of-n) authorizes an action; only the netns/nftables egress gate lets traffic out.** Any fusion that lets an LLM self-report, a graph node, or a tool result become "truth" or an authorization is a sovereignty breach and is called out as such.

---

## A. Feature inventory (grouped; one line each)

### Agent orchestration
- **redamon LangGraph ReAct core** — StateGraph over ~80-field AgentState, ~14 nodes, single structured `LLMDecision` routing 7 ActionTypes through one router (`_route_after_think`).
- **redamon phase state machine** — informational→exploitation→post_exploitation with `PhaseAwareToolExecutor` per-phase tool gating and auto-downgrade-free / escalation-needs-approval policy.
- **redamon human-in-the-loop interrupt/resume** — graph suspends to END at `await_approval`/`await_tool_confirmation`, resumes from checkpoint via `resume_after_*_with_streaming()`.
- **redamon checkpointer** — MemorySaver / AsyncPostgresSaver persisting mutable AgentState across turns.
- **redamon agent_context ContextVars** — tenant+phase identity propagated to tools without arg-threading, kept import-light.
- **redamon redamon_ctx signed tags** — HMAC-SHA256 canonical-JSON capability tokens, source-selected key (recon vs agent), constant-time, fail-closed.
- **redamon fireteam** — 1–8 parallel specialist sub-agents (own StateGraph), bounded recursion via router, forbidden-action stripping, mutex groups, credit-based deadline, confirmation registry, snapshot partial-recovery.
- **pentagi worker tree** — FlowController→FlowWorker→TaskWorker→SubtaskWorker; Generator decomposes ≤15 subtasks; Primary/Orchestrator loops to a `done` barrier.
- **pentagi role taxonomy** — Primary, Generator, Refiner, Reporter + specialists (Pentester/Coder/Installer/Searcher/Memorist) + meta (Adviser/Enricher/Reflector).
- **pentagi dual-role Adviser** — one agent is Planner in planning-mode, Mentor in supervision-mode.
- **pentagi in-band mentor loop** — `performMentor()` wraps real tool output with `<mentor_analysis>` critique the acting agent reads next turn; never halts.
- **pentagi living-plan Refiner** — re-derives remaining subtasks after every step against a fixed budget (15 − completed); empty = objective met.
- **pentagi structural repair** — Reflector (prose→toolcall, max 3), ToolCallFixer (bad-JSON repair), Chain-AST consistency repair on interruption.
- **pentagi execution monitor** — same-tool≥5 / total≥10 → Mentor; ≥3 identical → free block; general≥100 → graceful exit; done/ask barriers bind to status transitions.

### Meta-cognition / loop detection
- **redamon productivity scoring v2** — 5-signal dynamic-weight score → tier (green/yellow/orange/red/critical) → escalating governance (hint→deep-think→pivot→block-next-expensive).
- **redamon honesty audit** — `audit_productivity_claim`→`downgrade_verdict_to_no_progress` overrides the LLM's self-reported "progress" against measured state delta.
- **redamon tested_axes ledger** — semantic (family,dials) dedup catching slow session-wide loops outside the rolling window.
- **redamon deep-think** — mandates ≥2 `CompetingHypothesis` + Jaccard novelty guard so a re-plan can't paraphrase the prior plan.
- **redamon uniform-response anomaly** — same error-class + size + sub-50ms latency across N probes ⇒ INCONCLUSIVE not NEGATIVE (prevents false "SQLi tested, safe").
- **redamon embedded-error detection** — flips MCP `success=True` bodies that carry a real Playwright/timeout error to failure so a ChainFailure is learned.
- **redamon error-class taxonomy** — duration-aware split of shell-quoting glitch vs real 4xx vs 5xx-that-crashed-in-3ms.
- **redamon recon-budget commit gate** — after N informational iters, discovery tools hard-disabled to break "scan forever."

### Tools / recon
- **redamon tool_registry** — single-source-of-truth dict of ~70 tools ({purpose,when_to_use,args_format,description}), renders prompt tables + tool-name enum, thread-safe runtime MCP injection.
- **redamon MCP registry** — pydantic manifest layer (sse/http/stdio), trust-tiered `validate_servers(is_user_supplied)`, reserved SYSTEM ids, builtin-collision reject, round-trip-safe secret redaction, phase-view.
- **redamon PhaseAwareToolExecutor** — central dispatch: phase gate, in-process fs_/job_ short-circuit, server-side secret injection, signed context tags, coalesced reconnect, offload.
- **redamon recon/exploit breadth** — nuclei/nmap/naabu/httpx/ffuf/arjun/katana/hydra/wpscan/subfinder/gau/amass/metasploit/kali_shell + Shodan/GoogleDork/WebSearch.
- **redamon traffic tools** — 10 tools over `captured_http_transactions` (search/sitemap/params/grep/diff/to_curl/query passive; replay/fuzz active), allowlist SQL builder, origin pinning.
- **redamon workspace_fs** — 24 async fs tools, 4-layer path-escape defense, per-file byte-snapshot undo, tree-sitter symbols, tar-slip/zip-bomb-hardened archive.
- **redamon job_runner** — asyncio JobRegistry: UUID jobs, on-disk meta+log, RAM-budgeted concurrency, crash recovery, `asyncio.shield` wait.

### LLM-safety guards
- **redamon prompt_safety** — nonce-delimited (`token_hex(8)`) untrusted framing + forged-marker defang (ZWSP splice) + standing "treat as data" directive = a prepared-statement for LLM context.
- **redamon hard_guardrail** — deterministic non-disableable scope block: ~200 IGO domains + .gov/.mil/.edu/.int TLD regex, no LLM/net/toggle.
- **redamon guardrail** — soft LLM target judge (deliberately lenient, raises on exhaustion so caller sets fail-open/closed).
- **redamon llm_url_guard / fetch_guard** — SSRF: block IMDS IPs/metadata hosts/link-local/CGNAT/IPv4-mapped-IPv6, resolve-first, TLS-off-on-public forbidden.
- **redamon llm_guard** — FastAPI dep: constant-time internal-key auth, per-(user,ip) token bucket, 24h rolling spend cap.
- **redamon startup_guard** — refuse boot if WORKERS>1 (in-process registry not multi-worker-safe).
- **pentagi untrusted framing** — memory-first + summarization-awareness ("summaries are historical records, NOT examples to copy"); system-authored mentor text only.

### Memory / graph
- **redamon EvoGraph** (`chain_graph_writer`) — Neo4j AttackChain→ChainStep→{Finding|Failure|Decision} bridged into recon graph (STEP_EXPLOITED→CVE, FOUND_ON→IP); fire-and-forget + dead-letter, tenant-scoped.
- **redamon query_prior_chains** — synchronous cross-session retrieval of prior wins AND failure lessons for the same target.
- **redamon tradecraft KB/RAG** — @tool over HackTricks/PAYLOADSALLTHETHINGS/CVE-PoC, 6 resource-type sitemaps, lexical+LLM-tiebreak ranking, TTL cache, SSRF-per-hop, `[UNTRUSTED]` envelope, bounded agentic crawler.
- **redamon Neo4jToolManager** — text-to-Cypher graph query, write-rejection, mandatory tenant-filter injection.
- **pentagi Graphiti** — bi-temporal KG (valid_at/invalid_at vs created_at/expired_at), 7 specialized queries (temporal/entity-rel/MMR-diverse/episode/**successful-tools**/recent/by-label), group_id namespacing, communities.
- **pentagi 4-type vector KB** — guide/answer/code/memory doc-types, retrieve-before-action, threshold 0.2.

### Conversation context management
- **pentagi Chain-AST** — typed reversible AST (ChainAST→Section→{Header,BodyPair}), lossless round-trip, tool-call↔response pairing first-class, force-repair mode, provider reasoning-signature awareness.
- **pentagi Chain-Summary** — idempotent multi-phase byte-budget compaction, summary as a first-class typed node, hard-preserves last body pair + last KeepQASections (reasoning signatures), goroutine-parallel.
- **pentagi provider portability** — `NormalizeToolCallIDs` + `ClearReasoning` migrate a live chain across providers.

### Offensive-LLM (AI Gauntlet)
- **redamon adapters** — garak/PyRIT/Giskard/promptfoo behind one `run(...)->list[Finding]` contract, shared `_severity` bands + `proc.run_streamed`.
- **redamon owasp_map** — `(owasp_llm_id, chip, oracle_kind)` 3-tuple co-locating WHAT with HOW-to-confirm (classifier/contains/judge_llm).
- **redamon ASR metric** — Attack Success Rate = hits/trials, severity-banded, normalized cross-tool Finding.
- **redamon zero-egress harness** — `_OFFLINE_ENV` + OPENAI_API_KEY strip + local-Ollama judge, refuse-rather-than-degrade, local encoding-strategy re-impl.

### Remediation
- **redamon CypherFix triage** — 9 fixed Cypher queries (zero LLM) gather ground truth, LLM scoped to correlate/dedup/prioritize → RemediationDraft.
- **redamon CypherFix codefix** — clone→branch, 11 tree-sitter AST code tools, edit/build in disposable sandbox container, commit only edited files (never `git add -A`), open PR; per-block approval gate.
- **pentagi Coder/Installer specialists** — code-writing + environment maintenance agents inside the delegation tree.

### Knowledge / skills / prompts
- **redamon base.py** — dynamic REACT_SYSTEM_PROMPT, cache-prefix static/dynamic split, output_analysis anti-hallucination schema, RoE-as-option-pruning, TEXT_TO_CYPHER schema.
- **redamon classification.py** — intent/vuln-class router (9 builtin skills) with RoE-pruned menu.
- **redamon stealth_rules / skill_loader / nuclei.md** — per-decision stealth-risk tag; markdown skills (YAML frontmatter, path-traversal-guarded, MAX_SKILLS=5); exemplar tooling skill.
- **pentagi prompt template hierarchy** — memory-first, self-critique/steelman, `<task_assignment>` planner wrapper, standardized across roles.

### Providers
- **redamon llm_setup/llm_retry/parsing/key_rotation/model_providers** — multi-provider dispatch, 3-tier transient classifier + once-only param self-heal, defensive JSON-repair→typed proposal with fail-closed action downgrade, round-robin keys, discovery with fallback lists.
- **pentagi LangChainGo abstraction** — Claude/Gemini/OpenAI behind one `llms.Model`, ChainAST tool-ID/reasoning normalization, per-provider caching/thinking.

### Observability / deployment
- **pentagi OTel pipeline** — Collector → Jaeger/VictoriaMetrics/Loki/ClickHouse/Grafana; Logrus→OTel span-correlation hook.
- **pentagi Langfuse plane** — LLM-native observation taxonomy (Generation/Agent/Tool/Chain/Retriever/**Evaluator/Guardrail**/Embedding).
- **pentagi Observation{ID,TraceID,Time}** — one identity threaded through KG writes AND telemetry.
- **redamon startup_guard / two-container isolation** — deployment invariants (single-worker refuse; secret-holding agent vs disposable build sandbox).

---

## B. Gap analysis

Verdict legend: **LACKS** = VIGIL should acquire it; **BETTER** = VIGIL already stronger (preserve, don't regress); **COMPL** = complementary, adopt as defense-in-depth/refinement.

| Capability | redamon | pentagi | VIGIL today | Verdict |
|---|---|---|---|---|
| Provable oracle-confirmed signed FACT | ✗ (LLM self-report `exploit_succeeded`) | ✗ ("evidence" claimed, not re-executed) | ✓ kernel (CRUCIBLE oracle) | **VIGIL BETTER — the differentiator** |
| Ed25519 append-only spine | ✗ (mutable Postgres/Neo4j) | ✗ (Postgres) | ✓ | **VIGIL BETTER** |
| Kernel-enforced tier governance | soft Python phase gate | prompt-level + counters | ✓ Rust WARDEN A0–A3 | **VIGIL BETTER** |
| Conjunctive m-of-n destruction gate | ✗ | ✗ | ✓ | **VIGIL BETTER** |
| Host egress gate (netns/nftables) | app-layer SSRF filters | container isolation | ✓ kernel deny-default | **VIGIL BETTER + COMPL** (adopt SSRF pre-filters behind it) |
| Transparency log / SCITT / OpenVEX | ✗ | ✗ | ✓ (I2) | **VIGIL BETTER** |
| LangGraph/typed ReAct loop, single-decision dispatch | ✓ mature | ✓ (Go) | ✗ | **LACKS** |
| Explicit offensive phase machine | ✓ | task/subtask tree | ✗ | **LACKS** |
| HITL interrupt/resume | ✓ suspend-to-END | `ask` barrier | partial (gate is the approval leg) | **COMPL** |
| Parallel specialist sub-agents (fireteam) | ✓ governed | ✓ delegation tree | ✗ | **LACKS** |
| Role taxonomy + self-supervising mentor loop | fireteam only | ✓ rich (Mentor/Reflector/Refiner) | ✗ (has metacog critics) | **LACKS + COMPL** |
| Loop/stall detection + honesty audit | ✓ productivity v2 | ✓ ExecutionMonitor | ✗ | **LACKS** (port as non-authoritative critics) |
| Attack-chain GRAPH memory | ✓ EvoGraph (Neo4j) | ✓ Graphiti | ✗ (linear spine only) | **LACKS (graph view)** |
| Cross-session learning ("what worked/failed before") | ✓ query_prior_chains | ✓ successful-tools query | ✗ (cold start) | **LACKS** |
| Bi-temporal fact invalidation (refute≠delete) | ✗ | ✓ | append-only (kin) | **COMPL — excellent fit** |
| Conversation context compaction (typed, signature-safe) | prompt-cache split | ✓ Chain-AST/Summary | ✗ | **LACKS** |
| MCP registry / governed tool boundary | ✓ mature blueprint | — | in progress (I3) | **LACKS (this is the blueprint)** |
| Tool breadth (~70 recon/exploit) | ✓ | specialists+containers | thin | **LACKS** |
| Captured-traffic proxy toolset | ✓ | — | ✗ | **LACKS** |
| Sandboxed workspace fs (undo/symbols/archive) | ✓ 24 tools | container fs | ✗ | **LACKS** |
| Background job runner | ✓ | worker tree | ✗ | **LACKS** |
| KB-RAG offensive corpus | ✓ tradecraft | ✓ 4-type vector KB | ✗ | **LACKS** |
| Markdown skills / playbook-RAG | ✓ | prompt templates | ✓ prose playbooks | **COMPL** |
| Offensive-LLM harness (garak/PyRIT/Giskard/promptfoo) | ✓ | — | playbook prose only | **LACKS** |
| OWASP-LLM taxonomy + `oracle_kind` FACT/LEAD seam | ✓ | — | ✗ | **LACKS — perfect provable fit** |
| ASR metric + normalized cross-tool finding | ✓ | — | ✗ | **LACKS** |
| Autonomous remediation (triage→codefix→PR) | ✓ CypherFix | Coder agent | ✗ (I5 moonshot) | **LACKS** |
| Prompt-injection structural boundary | ✓ nonce | untrusted framing | ✗ | **LACKS** |
| Deterministic non-disableable scope denylist | ✓ hard_guardrail | — | charter (not hardcoded) | **COMPL** |
| LLM proposal-intake hardening (retry/parse/self-heal) | ✓ | ToolCallFixer/Chain-repair | ✗ | **LACKS** |
| Budget/rate/spend metering | ✓ llm_guard | — | deferred | **LACKS** |
| Observability (OTel + Langfuse Guardrail/Evaluator) | — | ✓ full | ✗ | **LACKS** |
| Multi-provider abstraction | ✓ 8+ | ✓ 3 | Claude-everywhere (deliberate) | **VIGIL BETTER posture** (adopt only ChainAST Claude normalization) |

Honest summary: **VIGIL wins decisively on provability/governance/sovereignty and loses across the board on agent cognition, memory-as-graph, tool breadth, context management, offensive-LLM testing, remediation, and observability.** These two repos are almost pure "body" to VIGIL's "spine + conscience." The fusion is high-leverage precisely because there is minimal overlap — but the seam is dangerous: both source repos treat the LLM (or an LLM judge, or a graph node) as an authority, which is exactly what VIGIL forbids.

---

## C. What to fuse, and HOW it flows through VIGIL's provable layer

The recurring pattern (state it once, apply everywhere): **redamon/pentagi produce a candidate → VIGIL re-frames it as a typed PROPOSAL/LEAD → a deterministic oracle re-executes to confirm → confirmed becomes a signed FACT on the spine (+ transparency-log entry + SCITT/OpenVEX cert) → unconfirmed stays a labelled LEAD → any resulting ACTION additionally clears the conjunctive gate + egress gate.** No subsystem is an authority; the spine and oracle are.

### C1. ReAct core + phase machine → spine-anchored, WARDEN-tiered
- **Source:** redamon orchestrator (14 nodes, single `LLMDecision`, phase machine, `PhaseAwareToolExecutor`, checkpointer); pentagi worker tree + living-plan Refiner.
- **Flow:** Keep the SHAPE. `think` = propose, `execute_tool`/`execute_plan` = act. Re-route **every action-bearing edge** (`execute_tool`, `execute_plan`, `transition_phase`, `switch_skill`, `deploy_fireteam`) through: (1) WARDEN tier gate — map informational→A0/A1, exploitation→A2, post_exploitation→A3; the phase gate is enforced **inside the Rust kernel, fail-closed**, not the soft Python check; (2) the conjunctive gate for anything A2/A3 or destructive; (3) egress gate on any traffic. `await_approval`/`await_tool_confirmation` interrupts become the **human leg of the conjunctive gate** — resume requires a signed Ed25519 operator approval, not a bare `ApprovalDecision`. **KEYSTONE:** `LLMDecision.output_analysis.exploit_succeeded` and every `OutputAnalysisInline` field are LLM CLAIMS → LEAD only; feed raw tool output to the CRUCIBLE oracle for re-execution before any FACT is signed. **Checkpointer:** MemorySaver/Postgres is mutable/un-provable → snapshot `AgentState` + `execution_trace` into the append-only signed spine each turn; keep Postgres only as a rebuildable cache. The whole run becomes offline-verifiable and can mint a run-level SCITT/OpenVEX cert.

### C2. MCP registry → the governed tool-call boundary
- **Source:** redamon `mcp_registry.py` + `PhaseAwareToolExecutor` + `tool_registry.py`; VIGIL's in-progress I3.
- **Flow:** Lift `mcp_registry.py` near-verbatim (pydantic models, `validate_servers(is_user_supplied)`, `parse_user_servers`, `to_mcp_servers_dict`, `redact_for_api` — zero LangChain deps). Re-bind the client from LangChain `MultiServerMCPClient` to the **Claude-Agent-SDK MCP client** (the one real seam). Then **subordinate the tool plane**: `ToolSpec.default_phases` map onto WARDEN tiers and `is_tool_allowed_in_phase` is enforced **inside the WARDEN gate** (replacing redamon's fail-open shared-bearer MCP auth). Every tool invocation is an action clearing the conjunctive gate (m-of-n for metasploit/nuclei/hydra/DoS). Every call + its **full pre-offload output** is a signed spine record; the head/tail offload stub is for the LLM only — the oracle re-executes against the whole persisted artifact. Generalize redamon's `X-Redamon-Ctx` signed tag into spine provenance (upgrade recon→agent trust to Ed25519; the no-owner-key offense worker holds no signing key). Keep the trust-tiered manifest split, secret-redaction, server-side secret injection, and prompt-injection framing wholesale.

### C3. EvoGraph / Graphiti → typed VIEW projected from the signed spine (never a parallel truth)
- **Source:** redamon `chain_graph_writer` (Neo4j attack-chain graph, `query_prior_chains`); pentagi Graphiti (bi-temporal facts, successful-tools query, MMR).
- **Flow:** Run Neo4j/Graphiti as an **internal, egress-gated, secret-free, rebuildable read-model**. A one-way projector subscribes to the spine and mirrors **only oracle-confirmed signed FACT records** into the graph; each node/edge carries provenance = spine record hash + Ed25519 signature ref + confirmation-status label. Unconfirmed items enter as a **DISTINCT `lead` node/edge class** so the LLM can never launder a hypothesis into "known." Adopt pentagi's **bi-temporal edges**: when the oracle refutes a lead, set `invalid_at` — never delete — inheriting the provable audit trail. `group_id` = per-engagement namespace bound to the charter/target; `CHAIN_TARGETS` bridges respect the scope gate (only in-scope hosts become nodes). `query_prior_chains` / `successful-tools` feed the reasoning core as **retrieval context only** — any action they suggest still clears the conjunctive gate. Keep fire-and-forget + dead-letter so projection never blocks the loop. **This is the single most dangerous fusion for trust-laundering; projection-only writes keyed on spine hashes + the confirmed/lead split are mandatory, and no gate may ever read authority out of the graph.**

### C4. Loop-detection / honesty audit / mentor → non-authoritative critics
- **Source:** redamon productivity v2 (`compute_productivity_score`, `audit_productivity_claim`, `detect_uniform_response_anomaly`, tested_axes, deep-think Jaccard, embedded-error, error-class); pentagi Mentor/Reflector/Refiner.
- **Flow:** Wire all of these as **budget/scheduling governors only**, exactly like VIGIL's existing RL/metacog layer (re-rank/defer/hint/block-next-expensive). **Hard constraint: a productivity verdict must NEVER gate a finding's truth — that is the oracle's sole job.** The honesty audit and `detect_uniform_response_anomaly` ("INCONCLUSIVE not NEGATIVE") are kin to VIGIL's veracity firewall and port cleanly as critic modules. Deep-think's ≥2 competing hypotheses maps onto CRUCIBLE self-consistency critics. pentagi's mentor `<mentor_analysis>` maps onto VIGIL's metacognition doctrine injected into reasoning calls — **but the mentor text must be system-authored, never derived from untrusted tool output** (else it is a prompt-injection channel). Mentor/Reflector/Refiner are structurally forbidden from authorizing A2/A3 or widening scope — meta agents re-rank/critique/re-plan only.

### C5. Fireteam → per-member tier-scoped sub-agents, single-writer spine
- **Source:** redamon fireteam subsystem (deploy/collect/registry, credit accounting, forbidden-action stripping, mutex groups).
- **Flow:** Each member runs under its own **capped WARDEN tier** and is structurally unable to `deploy_fireteam`/`transition_phase`/cross the egress gate (keep `_strip_forbidden_actions`, back it with tiers). Dangerous-tool escalation becomes an A2/A3 conjunctive-gate request; `confirmation_registry.resolve()` is driven only by a signed operator approval; register/resolve/reject/drop_wave are spine events. Member findings are LEADs; `fireteam_collect` only rolls up **oracle-reconfirmed** findings as FACTs. **Critical engineering risk:** parallel members contend with the single-writer append-only signed hash-chain — **serialize all spine writes behind one writer/queue** or signatures break. Neo4j stays working-memory-only. Adopt as-is (pure Python, low risk): credit-based deadline extension, snapshot partial-recovery, mutex validation, honesty auditor.

### C6. Chain-AST / Chain-Summary → append-only signed summaries + context assembly
- **Source:** pentagi `pkg/cast` (typed reversible AST, idempotent compaction, reasoning-signature preservation). Reimplement in Python (Go + license).
- **Flow:** Chain-AST becomes a **pure, re-executable typed projection over a contiguous span of signed spine records** (each spine event already has a kind). Because derivation is pure, anyone re-derives a byte-identical AST — matching VIGIL's re-execution veracity rule. Extend `BodyPairType` with a veracity tag: FACT / LEAD / SUMMARY, so leads/summaries never masquerade as facts inside the agent's own context. Compaction is **append-only**: a summary is a NEW signed spine record of kind `Summarization` citing the Merkle range it covers (RFC-6962 witnessed); originals are never deleted. Preserve the "never summarize last body pair / last KeepQASections" invariant to protect Claude extended-thinking signatures (a hard API requirement). Route the summarizer LLM call through the egress gate as an A1 transform; the summary stays non-authoritative.

### C7. AI Gauntlet → a CRUCIBLE offensive-LLM sensor family with `oracle_kind` FACT/LEAD routing
- **Source:** redamon garak/PyRIT/Giskard/promptfoo adapters + `owasp_map` 3-tuple + ASR + zero-egress harness.
- **Flow:** Port the uniform `run(...)->list[Finding]` contract + `proc.run_streamed` subprocess launcher, but emit **native spine records** (seed + tool version + config hash → reproducible). Adopt the `(owasp_llm_id, chip, oracle_kind)` 3-tuple as VIGIL's LLM taxonomy and **route on `oracle_kind`**: `contains`/`classifier`/regex kinds (sysprompt leak, apikey leak, encoding decode) are DETERMINISTIC → a VIGIL randomized-challenge oracle re-executes → signed FACT; `judge_llm` kinds (malwaregen, LLM-judge ASR) are NON-deterministic → **stay LEAD** until a deterministic oracle reconfirms. This maps redamon's own "depends on LLM judge" reality onto VIGIL's honesty gate exactly. Firing adversarial prompts at a live model = A2/A3 action through the gate; the harness's OPENAI_API_KEY-strip + `_OFFLINE_ENV` + local-Ollama judge become **defense-in-depth behind** the netns egress drop, not a substitute. Confirmed findings → RFC-6962 log + SCITT/OpenVEX cert. **garak-first** (deterministic oracles, best FACT yield). **Main risk: piping an LLM-judge ASR straight to a signed FACT launders a guess into the transparency log — forbidden.**

### C8. CypherFix remediation → gated pipeline, PRs as signed evidence
- **Source:** redamon CypherFix triage (9 Cypher queries + LLM correlate) + codefix (AST tools, sandbox build, PR).
- **Flow:** Keep the 9 deterministic Cypher queries (oracle-friendly). Every `TriageFinding` must be re-run through a CRUCIBLE oracle → signed FACT **before it may spawn a remediation**; the LLM's correlate/dedup/prioritize is a proposal the gate re-ranks. Persist `RemediationDraft` as signed spine records, not a plaintext `POST /batch`. The codefix agent is a **destructive action under the conjunctive gate**: clone/branch = A1, edit/write = A2, `github_bash`/build = A3 inside the egress-gated sandbox; opening the PR = threshold-destruction m-of-n. **CRITICAL FLIP: CypherFix auto-ACCEPTS a block on the 300s approval timeout — for VIGIL this must become auto-REJECT / fail-closed;** `add_guidance` and spawn-fail paths all fail closed. Verify the fix with a randomized-challenge oracle that re-executes the original exploit against the patched build, then sign "remediated" and mint a SCITT/OpenVEX cert linking fix→oracle-confirmed-finding→transparency-log entry on the PR. Keep the two-container isolation and "never `git add -A`" commit hygiene verbatim.

### C9. LLM-safety guards → compose with WARDEN/charter, never replace them; invert fail-open defaults
- **Source:** redamon prompt_safety, hard_guardrail, guardrail, llm_url_guard, fetch_guard, llm_guard, startup_guard.
- **Flow:** prompt_safety nonce boundary wraps **all** untrusted tool/scan/KB output entering any Claude call (structural, provider-agnostic — highest value, S effort). hard_guardrail runs as a deterministic pre-block **before** the charter/gate (defense-in-depth, not a replacement). SSRF denylists (llm_url_guard/fetch_guard) become a fast app-layer pre-filter **behind** the netns egress gate. llm_guard supplies the deferred budget/rate/spend metering for the MCP layer. **Every lenient/fail-open default must be INVERTED to deny-by-default** (guardrail's "when in doubt ALLOW", the fail-open no-secret auth) or it silently erodes VIGIL's fail-closed sovereignty. The soft LLM allow-verdict is demoted to a non-authoritative LEAD — the gate decides.

### C10. Providers → keep Claude-everywhere, adopt only the hardening
- **Source:** redamon `llm_retry.py` + `parsing.py` + `llm_url_guard`; pentagi ChainAST normalization.
- **Flow:** Port `llm_retry` (3-tier transient classifier, word-boundary status regex, once-only param self-heal via `model_copy`) and `parsing` (JSON-repair → typed Pydantic proposal with **fail-closed action downgrade**) as VIGIL's single Claude call-site + deterministic proposal-intake boundary. **Do NOT adopt the multi-provider dispatcher** — it violates Claude-everywhere; strip every non-Claude default. Wire `validate_llm_base_url` into the egress gate. Log every self-heal param-strip + endpoint/TLS choice to the spine. Adopt pentagi ChainAST tool-ID/reasoning normalization only for Claude robustness.

### C11. Observability → OTel + Langfuse Guardrail/Evaluator bound to spine identity
- **Source:** pentagi OTel pipeline + Langfuse taxonomy + `Observation{ID,TraceID,Time}`.
- **Flow:** Standard OTel wiring (S/M). Thread the **spine record hash / OTel trace id** through spine writes, KG writes, and traces so the transparency log, signed corpus, and Grafana/Jaeger share one identity (offline-verifiable AND debuggable). Emit a Langfuse **Guardrail** observation on every WARDEN gate block and an **Evaluator** observation on every oracle confirm/refute — an off-the-shelf telemetry shape for exactly the events a provable engine produces.

---

## D. Prioritized integration roadmap (F1…F12)

Ordering doctrine: **governance/safety-preserving substrate FIRST; anything that could let an LLM output become an unsigned FACT or bypass a gate REQUIRES its provable wrapper in the same PR (never before).** Phases flagged ⚠ must land the oracle/gate/spine wrapper as an atomic part of the merge.

| Phase | Name | Adds | Source modules | VIGIL modules touched | Effort | Depends on |
|---|---|---|---|---|---|---|
| **F1** | Input-safety + proposal-intake boundary | Nonce untrusted framing, deterministic scope denylist, typed fail-closed proposal intake, transient/param self-heal | prompt_safety, hard_guardrail, parsing, llm_retry, llm_url_guard | reasoning call-site, egress gate, charter | **S** | — |
| **F2 ⚠** | Spine-anchored ReAct core + WARDEN-tiered phase machine | Single-decision ReAct loop, phase→tier gating, HITL as signed-approval gate leg, spine-snapshot checkpointing | redamon orchestrator, state.py, agent_context, redamon_ctx; pentagi Refiner | WARDEN kernel, conjunctive gate, spine, CRUCIBLE oracle adapter | **L** | F1 |
| **F3 ⚠** | MCP governed tool boundary + first tool breadth | Pluggable MCP registry, phase→tier tool gating in-kernel, spine-logged calls, offload | mcp_registry, tools.py, tool_registry, tool_offload_policy, output_offload | I3 MCP layer, WARDEN, egress gate, spine | **M** (registry) / **L** (full executor) | F1, F2 |
| **F4 ⚠** | Attack-chain graph as signed-spine projection + cross-session learning | Bi-temporal KG view, confirmed/lead node split, prior-chains + successful-tools retrieval | chain_graph_writer, query_prior_chains; Graphiti + graphiti-go-client (reimpl) | spine projector, reasoning core, charter scope | **M** | F2 |
| **F5** | Non-authoritative cognition governors | Productivity v2, honesty audit, uniform-response anomaly, tested_axes, deep-think, mentor/reflector | redamon productivity, phase; pentagi mentor/reflector | metacog/RL layer (re-rank/defer only) | **S** | F2 |
| **F6 ⚠** | Fireteam under per-member tiers | Bounded parallel specialists, forbidden-action stripping, credit-deadline, confirmation registry | fireteam_member_graph, deploy/collect/think, confirmation_registry | WARDEN per-member context, conjunctive gate, single-writer spine queue | **L** | F2, F3, F5 |
| **F7 ⚠** | Chain-AST context management + append-only signed summaries | Typed reversible AST view, signature-safe idempotent compaction | pentagi chain_ast, chain_summary (reimpl) | spine projection, reasoning context assembly, egress gate | **M–L** | F2 |
| **F8 ⚠** | AI Gauntlet offensive-LLM sensor family | garak/PyRIT/Giskard/promptfoo, OWASP-LLM taxonomy, ASR, `oracle_kind` FACT/LEAD routing | AI Gauntlet adapters + owasp_map | CRUCIBLE/AEGIS oracle, gate, egress, transparency log | **M** (garak) / **L** (all four) | F1, F2, F3 |
| **F9 ⚠** | Agent fs/job/traffic tooling | Sandboxed workspace fs (signed rollback), job runner (witnessed provenance), captured-traffic proxy tools | workspace_fs, job_runner, traffic_tools | WARDEN, spine, egress gate | **M–L** | F2, F3 |
| **F10 ⚠** | Autonomous remediation (gated) | Deterministic triage → oracle-confirmed findings → gated codefix → signed PR + fix-verification oracle | CypherFix triage + codefix + system.py | conjunctive gate, egress sandbox, oracle, SCITT/OpenVEX | **L** | F2, F3, F4 |
| **F11** | Observability | OTel (Jaeger/VM/Loki/Grafana) + Langfuse Guardrail/Evaluator bound to spine identity | pentagi observability | telemetry layer, spine identity, gate/oracle emit points | **S–M** | F2 |
| **F12** | KB-RAG tradecraft + markdown skills + budget metering | Offensive corpus RAG (untrusted envelope), markdown skills loader, spend caps | tradecraft_lookup/crawl, skill_loader, llm_guard | MCP tool, egress gate, budget metering | **M** | F3 |

Rationale for the front of the queue: **F1 hardens every Claude call and inverts fail-open defaults with zero infra and zero risk of bypass — it can ship alone and only strengthens sovereignty.** F2 is the keystone: until every action edge routes through the gate + oracle + spine, no later "body" is safe to attach. F3 makes the tool boundary itself governed. F4/F5 add memory and cognition without touching authority. Everything ⚠ carries the same non-negotiable: it merges only with its provable wrapper.

---

## E. Risks + licensing

### Licensing
- **redamon = MIT** — Python code may be lifted/adapted with attribution and license retention. F1's pure modules (prompt_safety, hard_guardrail, parsing, llm_retry, fetch_guard, mcp_registry, workspace_fs, job_runner, owasp_map) port near-verbatim. Keep the MIT NOTICE.
- **pentagi = verify before ANY reuse** — the scout flags an EULA/custom license and the code is Go. **Treat pentagi strictly as design-only: reimplement ideas (Chain-AST, mentor loop, bi-temporal projection, worker taxonomy, Observation identity) in Python; do NOT vendor Go source, config, or docs prose.** Confirm the exact license text before writing a line that mirrors its structure.
- **Transitive backends** — Graphiti server (getzep) and `graphiti-go-client` (vxcontrol) are separate projects with their own licenses; if VIGIL uses a Neo4j KG, prefer the upstream getzep Graphiti (check its license) over the Go client, or build a minimal Python projector. garak (Apache-2.0), PyRIT (MIT), Giskard, promptfoo each carry their own license — they run as **subprocesses**, not imports, which keeps their deps and licenses out of VIGIL's process (also the right isolation posture).

### Sovereignty / architecture risks (ranked)
1. **Trust-laundering via the graph (highest).** A KG the LLM treats as ground truth reintroduces hallucination through the back door — the exact failure the veracity firewall exists to prevent. Mitigation: projection-only writes keyed on signed spine hashes, a distinct `lead` class, per-edge provenance + confirmation-status, and a hard rule that **no gate reads authority from the graph**.
2. **LLM-as-oracle imports.** redamon's `exploit_succeeded`/productivity verdicts and pentagi's "evidence at every stage" are self-report; an LLM-judge ASR is non-deterministic. Piping any of these to a signed FACT breaks oracle-sole-authority. Mitigation: everything is a LEAD until a deterministic oracle re-executes; `oracle_kind` routing is mandatory; `judge_llm` never auto-promotes.
3. **Gate bypass on naive action ports.** redamon's `think` can transition phase and fire dangerous tools on LLM+optional-human approval; CypherFix auto-accepts on timeout; MCP auth is fail-open. Mitigation: every action edge re-plumbed through WARDEN + conjunctive + egress gate; **invert every fail-open/lenient default to deny-by-default**; auto-accept→auto-reject.
4. **Offense-free-core boundary.** The agent scaffolding, fireteam, tools, and remediation all belong in the **no-owner-key offense worker**, never the sovereign personal core. The signing key never crosses into the offense env; the worker holds only HMAC inner tags. Preserve the two-env boundary and P5 inert-signed-data seam.
5. **Claude-everywhere erosion.** redamon's 8-provider dispatcher and pentagi's 3-provider abstraction must NOT bring multi-provider defaults. Strip every non-Claude path; keep only the retry/parse/self-heal and ChainAST-for-Claude hardening. Log any endpoint/TLS/param choice to the spine.
6. **Single-writer spine vs parallelism.** Fireteam and parallel tool waves contend on append-only chain ordering → serialize all spine writes behind one writer/queue or signatures break.
7. **New stateful attack surface.** Neo4j/Graphiti, Postgres cache, sandbox containers, job runner are new surfaces. Keep them internal, egress-gated, secret-free, and rebuildable from the spine.
8. **Prompt-injection channels.** Crawled KB pages, tool output, and mentor-injected critique are attacker-influenceable. Mitigation: nonce untrusted framing everywhere (F1), system-authored-only mentor text, `[UNTRUSTED]` envelopes on all RAG, SSRF-per-hop + egress gate.
9. **TOCTOU/symlink races.** workspace_fs `_resolve_safe` uses `.resolve()` (follows symlinks) — needs a symlink-race review under VIGIL's threat model before F9.

---

## F. Recommended FIRST fusion phase — **F1: the Untrusted-Input + Typed-Proposal Boundary**

**Why this first:** it is the single increment that is highest-value, lowest-risk, fully self-contained, and — uniquely — **strengthens the sovereign core instead of risking a bypass.** It requires no LangGraph, no Neo4j, no MCP client, no infra, no gate rewiring. It is pure Python that hardens every Claude call VIGIL already makes today, and it establishes the two load-bearing invariants every later phase depends on: *everything the LLM reads is framed as untrusted data; everything the LLM emits is a typed, non-authoritative proposal.* All source modules are redamon (MIT) — no pentagi/Go/EULA exposure.

**Crisp scope (one PR-sized slice):**
1. **prompt_safety** — port `wrap_untrusted`/`wrap_untrusted_inline` (nonce `token_hex(8)` delimiters), `_neutralize_markers` (ZWSP defang of forged markers), and the standing `UNTRUSTED_OUTPUT_GUIDANCE` directive. Wire it so **all** tool/scan/KB/target output entering any Claude reasoning call is nonce-framed. Provider-agnostic, zero cost.
2. **hard_guardrail** — port the deterministic, non-disableable scope pre-block (`_normalize_domain` → `is_hard_blocked`: ~200 IGO domains + `.gov/.mil/.edu/.int` TLD regex). Runs as defense-in-depth **before** the charter/gate; no LLM, no network, no toggle.
3. **parsing** — port `try_parse_llm_decision`/`parse_analysis_response`: JSON extraction + repair → Pydantic validation → **fail-closed action downgrade** (malformed `deploy_fireteam`/`plan_tools` → `use_tool`; empty `phase_transition`/`user_question` → None). Every parsed `LLMDecision` is stamped a **non-authoritative PROPOSAL**; nothing here can become a FACT.
4. **llm_retry** — port the 3-tier transient classifier (MRO name / keyword / word-boundary status regex) + once-only `model_copy` param self-heal, as VIGIL's single Claude call-site wrapper.
5. **llm_url_guard / fetch_guard SSRF denylist** — wire the IMDS/metadata/link-local/CGNAT/IPv4-mapped-IPv6 pre-filter into the existing egress gate as an app-layer fast-path (behind, not replacing, the netns drop).

**Invert on port (non-negotiable):** every lenient/fail-open default becomes deny-by-default. The soft LLM target judge is **explicitly excluded from F1** (it's LEAD-only, deferred to a later phase) so nothing in F1 ever trusts an LLM verdict.

**Spine touch:** log each param self-heal strip and each hard-guardrail block as a signed spine record — so even the safety layer's decisions are provable.

**Definition of done:** every Claude call in VIGIL's offense worker receives only nonce-framed untrusted context and returns only a typed, validated, fail-closed proposal; a sensitive-TLD target is refused deterministically before the charter is even consulted; transient/param errors self-heal without a multi-provider path; SSRF pre-filter is live behind the egress gate. No new stateful surface, no gate rewiring, no cross-env key movement — pure hardening of what exists, and the substrate F2–F12 stand on.