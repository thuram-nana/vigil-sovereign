# PROJECT VIGIL — a sovereign, provable, autonomous security + personal-AI system (1-of-1)

> Working name **VIGIL** (owner to confirm). Fuse the owner's three systems into ONE Claude-powered monorepo
> and push each layer past the state of the art. **This is a PLAN — nothing is built yet.**
> Grounded in: 6 code deep-dives (SIGIL, CRUCIBLE/AEGIS, Strix ×3, overlap), 4 frontier-research sweeps
> (autonomous-AI-offense SOTA · provable-AI/formal-methods · crypto-transparency/sovereign · agentic/Claude),
> and a 5-agent adversarial design panel (2 FATAL flaws found, both fixable; every fusion thesis corrected).
> **Four strategic decisions LOCKED by owner (§12): product-fusion/isolated-cores · staging-default gated-LIVE
> autonomy · two-anchor trust roots · full-moonshot-phased ambition.**

---

## 1. Context / why (owner's mandate)
- Merge **SIGIL** (sovereign signed-spine + Rust WARDEN governance; offense-free today) + **CRUCIBLE + AEGIS**
  (offensive engine + defensive dual; oracle-authority + veracity firewall + charter/ROE + PCF certs) and fold
  in **Strix**'s core ideas + infra (autonomous AI-hacker: agent loop + hardened Kali Docker sandbox + Caido
  proxy + 57-skill playbooks + SARIF) into **one Claude-powered tool**. Preserve both owned git histories (subtree).
- **True capability fusion** (one tool does offense AND personal orchestration). **Claude everywhere** (models
  and agents). **Peak innovation — a tool the world hasn't seen.** Not limited to these four; deepen anything.

## 2. The validated 1-of-1 thesis (what makes it unique)
Two independent research streams converged: the winning architecture (DARPA AIxCC victors, Google Big Sleep, the
2025-26 Antiproof/ExploitBench/EG-VAR line) is **LLM proposes → deterministic ORACLE confirms → signed,
re-runnable certificate** — and **most commercial "AI hackers" skip the rigorous middle step** (even XBOW ships
only light "validators"; CAI/PentAGI trust the LLM; PyRIT/Garak's LLM-as-judge has 35-90% false positives). No
existing system holds more than **two** of these five properties; **fusing all five is unclaimed ground:**
1. **Oracle-confirmed validation, generalized to live web/API/net/cloud** (AIxCC only did sandboxed OSS memory bugs).
2. **Cryptographically-signed evidence/provenance** — the single biggest open gap; *nobody* signs findings.
3. **Hard-governed scope at the syscall/egress layer** (everyone is prompt-level → injection-breakable).
4. **Sovereign / air-gappable** (all the leaders are cloud/closed).
5. **Claude reasoning across the full lifecycle** (discover → prove → patch → re-verify → sign → report),
   *while never trusting Claude for the verdict.*
These five map **exactly** onto SIGIL (spine + WARDEN + sovereign) + CRUCIBLE (oracle + firewall + PCF + charter)
+ Strix (Claude agentic body + Kali sandbox). Market tailwinds: the "AI-slop" trust crisis (curl ended its bounty
program Jan-2026; ~20% slop) that signed+oracle-confirmed findings directly solve; **EU AI Act Art. 12** mandates
tamper-evident logging for high-risk AI; **OWASP APTS** codifies hard autonomous-pentest scope no product enforces.

## 3. The unified architecture — *fuse the PRODUCT, isolate the PROCESSES*
The panel's load-bearing correction: a naive one-interpreter fusion is **unsafe and won't boot** (FATAL-2 below).
The correct shape is ONE monorepo / one CLI / one shared core / one signed spine, but **TWO isolated trust
domains / environments / processes** joined only by an **inert, signed, no-code data seam.** This *is* "true
capability fusion" at the product level while preserving SIGIL's offense-free-by-construction personal core.

```
                    ┌──────────────────── ONE CLI / one product / one signed spine ────────────────────┐
  ENV-SOVEREIGN  ───┤  SIGIL personal orchestrator (offense-free BY CONSTRUCTION: imports neither        │
  (owner key,       │  framework.* nor strix.*; assert_no_offense() still structurally holds)            │
   personal spine)  │        ▲ receives inert SignedEvidence JSON (kind="finding"), never code           │
                    └────────┼──────────────────────────────────────────────────────────────────────────┘
                             │  narrow, gated, data-only channel (existing WG bridge/queue)
  ENV-OFFENSE  ──────────────┼──────────────────────────────────────────────────────────────────────────┐
  (no owner key,   AGENTIC BODY (Strix, Claude-powered): agent loop · multi-agent graph · Caido capture   │
   engagement-      TRUTH+AUTHZ (CRUCIBLE): oracle authority · veracity firewall · PCF certs · world-model │
   scoped store)    GOVERNANCE (SIGIL WARDEN tier gate + CRUCIBLE charter/scope, conjunctive, fail-closed) │
                    └──────────────────────────────────────────────────────────────────────────────────┘
  SHARED CORE  packages/core/vigil_core = SIGIL's reuse/{canonical,chain,crypto,models} v2 (Merkle-prune,
               the source of truth) — pure-Python, imports NO framework.* and NO strix.*  (this purity is
               what keeps assert_no_offense() sound). Deps: cryptography + pydantic only.
  NETWORK      the Strix Kali sandbox sits on an internal-only docker net; its ONLY route out is a host-side
   BOUNDARY    deny-default charter-derived L3/L4 egress gateway (nftables) + a scope_gate forward-proxy.
```
Verified facts underpinning this: SIGIL's `reuse/*` are byte-identical vendored copies of CRUCIBLE's
`evidence/`+`entitlement/crypto` (same `crucible-evidence-v1\x00` domain tag); SIGIL's v2 `SignedChainHead` is a
backward-compatible **superset** of CRUCIBLE v1 (`base_count=0` reduces v2 verify to v1 exactly) → adopt v2 as the
one core with zero signature breakage. `kind="finding"` already exists in `sigil/spine/models.py`.

## 4. The two FATAL flaws (must be fixed before any fused offense run)
- **FATAL-1 — Unbounded sandbox egress.** Strix's Kali container holds `NET_ADMIN`/`NET_RAW` + `host.docker.internal`
  → host-gateway with **no host-side egress firewall**, and scope is **prompt-level only** (the exec wrapper is
  cosmetic). An autonomous, prompt-injectable offense agent could reach the operator's LAN, cloud metadata
  (169.254.169.254), or third parties — from a box that also (in a naive fuse) holds the personal spine. **Fix:**
  host-side deny-default, charter-derived L3/L4 egress gateway keyed to `common/ethics.py:parse_scope`, on the
  sandbox's own docker network; **drop `NET_ADMIN`** (keep `NET_RAW` only if SYN scans are needed); Caido stays as
  *capture*, never a boundary. Gates everything; ships alone.
- **FATAL-2 — The offense-free boundary is removed/defeated.** `assert_no_offense()` (bans importing `framework.*`)
  IS SIGIL's entire guarantee; collapsing into one venv either won't boot or silently destroys it, and Strix adds a
  *second* offense namespace (`strix.*`) the guard doesn't bar; a single dep-lock is unsatisfiable (SIGIL's exact
  pins vs `openai-agents[litellm]`). **Fix:** two environments/processes (env-sovereign vs env-offense), both
  path-depending on `vigil_core`; widen the guard to bar BOTH `framework.*` and `strix.*` in the sovereign process;
  the offense worker is a SIGIL agent with a ceiling and **no owner key** (it cannot forge governance events, exactly
  like today's mesh agents). Entering offense mode = `assert_offense_gated()`: an explicit **A3, owner-signed,
  spine-logged, auto-expiring** transition bound to one verified charter (mirrors killswitch release semantics).

## 5. The no-hallucinated-findings pipeline (honest — the panel corrected the thesis)
CRUCIBLE's oracle does **not** re-execute a PoC string or a raw Caido request; `verify/reverify.py` re-runs a *pure
deterministic oracle* over a retained, bug-class-bound `FindingContext` (baseline/mutated state, probe rounds,
timing samples, OOB hits). So the fusion needs an **`OracleConfirmationAdapter`** (modeled on
`agents/oracle_probe_executor.py`): re-drive a scope-gated baseline+probe pair → build `FindingContext` → call
`OracleVerifier.confirm` → on confirm, `evidence/certify.py:build/sign_certificate`. And the Strix finding contract
(`tools/reporting/tool.py:create_vulnerability_report`) is extended to carry `{bug_class|cwe, injection_point,
baseline_request_id, probe_request_id}` + a CWE→canonical-bug_class map.

**Honesty invariant (owner decision, recommend ACCEPT):** *only* oracle-mappable classes (sqli/xss/idor/ssrf/rce/lfi
… in `BUG_CLASS_ORACLES`) become **signed FACTS**; everything else is honestly demoted to a **labelled lead** per
`veracity/firewall.py`. Claiming every Strix finding becomes a signed fact *would itself be the hallucination the
system exists to kill.* Deterministic dedup by `oracle_context_digest`/`cert_digest` replaces the LLM-judge for
CONFIRMED findings; keep Strix's LLM-judge dedup for unconfirmed leads only.

Full flow: **proposer** (Claude agent + Strix tools, recall-optimized) → **cheap cull** (CRUCIBLE benign-alternative/
refute-or-promote + conformal abstention) → **deterministic ORACLE** mints `Verified` → **PCF certificate** → inert
JSON → **SIGIL signs it into the spine.** Findings that don't survive stay `Abstain` with a replayable audit trail.

## 6. Governance of capability fusion (non-waivable)
Two **orthogonal, conjunctive** gates over one signed spine, backstopped by a network the agent can't see past:
- **CRUCIBLE** answers *"is THIS target/action inside the signed engagement envelope right now?"* (`authority/gate.py`
  order: killswitch→window→scope→destructive→live_destructive→budget; fail-closed).
- **SIGIL WARDEN** answers *"what TIER is this action-class and must the owner approve it now?"* (`kernel/tiers.rs` +
  `governor/core.py`). Every target-touching action passes BOTH; first failure wins; any error fails closed.
- **WARDEN impedance fix:** `classify("exec_command")` → `exec ∈ A3_TOKENS` → A3, and the registry is raise-only, so
  naive by-name gating halts ALL shell. Resolution — three complementary layers: (1) the **egress gateway** = wire
  enforcement of the TARGET; (2) **WARDEN** = tool-CLASS authorization + signed audit (floor: offense exec ≥ A2, never
  auto-A0) via a `WardenGateHooks(RunHooks)` on the SDK `on_tool_start/end` seam, routing A2/A3 semantic tools
  (`repeat_request`→A2, `scope_rules`→A2/A3) to the owner-signed approval queue; (3) **`scope_gate.validate_action`**
  = exact per-URL refuse for host-side tools.
- **Threshold-gated destruction** (research add): high-blast-radius actions require **FROST m-of-n** (RFC 9591:
  offense-worker key + owner YubiKey/HSM + policy key), the authorization itself written to the spine; a
  dormant-authorization dead-man's-switch bounds autonomy. SIGIL already has `verify_threshold` m-of-n.
- **Agentic-misalignment mitigations** (Anthropic research: all 16 frontier models took harmful self-directed action
  under autonomy-threat): "permission is infrastructure, not prompt" — deny→ask→hook→allow; **default TWIN/STAGING**
  target env, LIVE requires a charter flag + per-action second-ack; per-engagement `max_actions` + daily budgets;
  always-available killswitch; owner-watched A3 queue.

## 7. Claude everywhere (models now, Claude-native agents next)
- **Models (fast, Phase-0/1):** Strix already lists `anthropic/claude-opus-4-8` in `RECOMMENDED_MODEL_NAMES` and
  routes non-openai prefixes via `StrixProvider(MultiProvider)→LiteLLM` (agent `model=None`). Set the default to
  Claude; map `reasoning_effort`→Anthropic adaptive/extended thinking; **live-fire ONE real Claude turn** (tests
  can't substitute) to resolve three runtime-only seams: (a) whether `Reasoning(effort=)` 400s or is silently
  dropped, (b) whether prompt-cache `cache_read` fires, (c) whether `dedupe.py`'s Responses-shaped
  `ResponseOutputMessage` text extraction returns empty on Claude (needs a fallback).
- **Budget-meter-disarm fix (HIGH):** the governor raises `BudgetExceededError` off LiteLLM's cost total, which is
  **$0 without an Anthropic price table** → the budget silently disarms on Claude. Add Anthropic prices + assert at
  startup that cost increments after turn 1.
- **Claude-native agents (committed later phase):** the *research* favors the **Claude Agent SDK** (native prompt
  caching, compaction, memory tool, subagents-with-isolated-context+resume, PreToolUse hooks). The *code reality*
  (migration designer): Strix's Kali execution is welded to `openai-agents` `SandboxAgent`/`Shell`/`Filesystem`/
  `SandboxRunConfig`; a native port is a multi-week rebuild of the sandbox layer (Kali tools re-exposed as in-process
  **MCP servers** driving the container). Recommendation: **ship Claude-via-LiteLLM first**; port the agent body to
  the Claude Agent SDK as a dedicated later phase (true "Claude agents") — owner decision on timing (§12).
- **Telemetry (HIGH):** DELETE the network calls outright (`posthog.py`, `scarf.py`, OpenRouter attribution header,
  gate `web_search`/Perplexity) — not merely flip the config default (which leaves them one env-var from firing).
- **Sovereignty trade (owner-accept):** Claude-everywhere transits engagement context (captured requests, discovered
  creds, target source) to `api.anthropic.com` — SIGIL's local-only guarantee is gone for offense runs. Mitigate with
  a redaction pass; the near-term sovereign path is **Anthropic Confidential Inference (TEE-attested)** (§8).

## 8. Peak-innovation extensions (the moonshot — beyond the three-way fuse)
Each maps to a mature-or-emerging standard and is *incremental on what SIGIL already has* (signed hash-chain +
Merkle-prune head = an MMR; m-of-n threshold crypto). Scope decision in §12.
- **A. Provable-findings differentiators** (from the formal-methods research): (1) **per-run randomized-challenge
  oracle for every finding class** (generalize DARPA CGC Type-1/2: code-exec→random PC+reg, info-leak→random canary,
  SQLi→random nonce, SSRF/RCE→per-run OOB token) so replay/hallucination are *structurally* impossible; (2)
  **kernel-minted `Verified|Abstain` epistemics** (EG-VAR) — the oracle is the only minter of "Verified"; (3)
  **sanitizer (ASAN/UBSAN) + patch-neutrality gate** (AIxCC ground-truth: PoC fires pre-patch, silent post-patch,
  tests still pass); (4) **SPRT + conformal** finite-sample error bounds for noisy blind/timing channels (CRUCIBLE
  already has SPRT); (5) **proof-carrying vulnerability certificates.**
- **B. Witnessed transparency log of confirmed findings** (world-first): re-express the signed spine as a tile-based
  log (**Trillian Tessera / C2SP tlog-tiles**), emit signed checkpoints, **witness-quorum countersign** (`tlog-witness`,
  optional **Armored-Witness** hardware held by clients), **anchor to Bitcoin via OpenTimestamps** → split-view
  resistance + third-party auditability + trustless timestamping.
- **C. Standards-native PCF certs** = IETF **SCITT** Signed Statements (COSE/DSSE + **OpenVEX** finding vocabulary)
  with offline-verifiable Receipts — verifiable forever by client/regulator/court.
- **D. TEE-attested sovereign agent** (Intel TDX / AMD SEV-SNP, + H100 confidential-compute; **Anthropic Confidential
  Inference** as the Claude path) with attestation-gated key release; honest caveat (TEE.Fail) → the witnessed log is
  the ultimate arbiter. **Proof-of-inference receipts** on the gating classifier (attested now; DeepProve zkML later).
- **E. AIxCC binary/memory-safety tier + autonomous auto-patching:** LLM-guided fuzzing (OSS-Fuzz-Gen style) + concolic/
  SMT (angr/Z3) + sanitizer-oracle + patch re-verification — extends beyond web pentesting into the Cyber-Reasoning-
  System space. Study **Trail of Bits "Buttercup"** (open-source AIxCC 2nd place) as a reference to fold in.

## 9. Monorepo structure (uv workspace; two envs; subtree-preserved history)
```
vigil/  (owner names it)
  packages/core/vigil_core/     ← SIGIL reuse/* v2 verbatim; deps cryptography+pydantic; NO framework.*/strix.*
  apps/sigil/                   ← git subtree add from thuram-nana/sigil (keeps setuptools-rust + kernel/ Rust wheel)
  engine/crucible/              ← git subtree add from thuram-nana/PENTEST (framework.v2 + aegis; setuptools)
  vendor/strix/                 ← git subtree add from usestrix/strix (Apache-2.0: retain LICENSE + add NOTICE)
  gateway/                      ← NEW: host-side egress firewall + scope_gate forward-proxy (FATAL-1 fix)
  integration/                  ← NEW: OracleConfirmationAdapter, WardenGateHooks, the inert-data seam
  uv.workspace + TWO locks: env-sovereign(vigil_core+sigil) · env-offense(vigil_core+crucible+strix+openai-agents)
```
Build reconciliation: each member keeps its own backend (SIGIL setuptools-rust, CRUCIBLE setuptools, Strix
hatchling, vigil_core hatchling). Python floors: env-offense ≥3.12 (Strix), env-sovereign can stay 3.11; bump
CRUCIBLE mypy to 3.12. Pin the Kali sandbox image by **digest**, checksum the Caido tarball, treat the sandbox
image as a signed release artifact. Clean `graphify-out/`, `.coverage`, `targets/` before `git subtree add`.

## 10. Staged sequencing (each phase independently green; safety before capability)
- **P0 — Pure subtraction + Claude default** (day one, ships alone): delete Strix telemetry calls; strip OpenRouter
  header; gate `web_search` off; set `STRIX_LLM=anthropic/claude-opus-4-8` + valid `reasoning_effort`; force telemetry off.
- **P1 — Monorepo scaffold** (`git subtree add` all three at HEAD; uv workspace; no code change). GATE: each member's
  existing suite passes unchanged (SIGIL ~490 py + 26 Rust; CRUCIBLE full; Strix pytest).
- **P2 — Extract `vigil_core`** (SIGIL reuse/* v2 verbatim). GATE: union of SIGIL + CRUCIBLE crypto/chain tests +
  a **v1-head→byte-identical-signing regression**.
- **P3 — SIGIL adopts core + widen the guard** (`assert_no_offense` bars `framework.*` AND `strix.*`). GATE: SIGIL full suite green.
- **P4 — CRUCIBLE adopts core** (make-or-break: rewire ~25 modules to `vigil_core`; upgrade `evidence` to v2 form
  WITHOUT changing signing bytes; `EntitlementError = IntegrityError`). GATE: **every existing v1 signed head re-verifies** + CRUCIBLE suite green.
- **P5 — Two-environment build boundary + inert-data channel** (two locks; offense-worker trust domain, no owner key).
- **P6 — HARD EGRESS GATE (FATAL-1)** — parallelizable (Docker/netfilter, not Python). Highest security ROI; ships alone.
- **P7 — Unified spine/killswitch/TrustRoot + WARDEN tool gate + offense-worker domain (FATAL-2 + confused-deputy).**
- **P8 — Claude runtime hardening** (gated by the one-turn live-fire; budget price table; reasoning/cache/dedup seams).
- **P9 — Oracle confirmation pipeline (§5), ONE bug class at a time** (extend the finding contract + CWE map + the adapter).
- **P10 — Spine-sign confirmed findings + chosen trust-anchor model.** Confirmed `SignedEvidence` → inert JSON →
  `spine.append(kind="finding")` without importing `framework.*`.
- **INNOVATION PHASES (post-core, scope per §12):** I1 randomized-challenge oracles + kernel-minted epistemics;
  I2 witnessed transparency log + SCITT/OpenVEX certs + OpenTimestamps; I3 Claude-Agent-SDK-native agent body
  (Kali tools → MCP); I4 TEE attestation + threshold-gated destruction; I5 AIxCC binary/auto-patch tier (study Buttercup).
- **ONGOING:** budgets, TWIN/STAGING default, owner-watched A3 queue, killswitch, pinned/checksummed sandbox, CI
  eval harness (XBEN/Cybench/CVE-Bench, variance-aware reliability + FP-rate).

## 11. Risk register (panel synthesis, ranked)
- **FATAL** sandbox egress (P6) · **FATAL** offense-free boundary (P3/P5/P7).
- **HIGH** oracle pipeline no-op vs raw findings (P9 adapter) · confused-deputy across trust boundary (offense worker
  no owner key) · WARDEN by-name halts shell (three-layer gate) · telemetry leaks offensive activity (P0 delete) ·
  budget meter disarms on Claude (P8 price table) · Claude-via-LiteLLM 3 runtime seams (P8 live-fire).
- **MED** v1↔v2 core migration ordering · two trust roots collide (owner decision) · EntitlementError→IntegrityError ·
  autonomy×offense in-scope blast radius (TWIN/STAGING default) · Claude sends context to Anthropic (sovereignty
  trade) · sandbox supply-chain pinning.
- **LOW** Python-floor mismatch · subtree cruft.

## 12. Decisions — LOCKED by owner (2026-07-19)
1. **Fusion topology = Product fusion, isolated cores.** ONE tool/CLI/repo/signed spine + shared `vigil_core`, but
   offense runs as a separate **no-owner-key** process; the personal core stays **offense-free-by-construction**
   (bars `framework.*` AND `strix.*`); findings cross as **inert signed data**. (This is the safe form — the plan
   is built entirely around it.)
2. **Autonomy = Staging-default, gated LIVE.** Default target env is TWIN/STAGING; a LIVE target needs a charter
   flag + per-action second-ack; destructive/high-blast actions need the **m-of-n threshold**. Conservative + reversible.
3. **Trust roots = Two anchors.** CRUCIBLE's m-of-n governance root signs the finding **EvidenceCertificate**; the
   owner's Ed25519 key signs the **spine head** that chains it. Separation of engagement-authority vs owner-custody.
4. **Ambition = Full moonshot, phased.** All innovation phases (I1 randomized-challenge oracles + kernel-minted
   epistemics · I2 witnessed transparency log + SCITT/OpenVEX certs + OpenTimestamps · I3 Claude-Agent-SDK-native
   agent body · I4 TEE attestation + threshold destruction · I5 AIxCC binary/auto-patch tier) are **committed**,
   sequenced after the core fusion (P0-P10), each always-green.
Accepted (recommendations, non-blocking): oracle-mappable-only signed facts (YES — everything else a labelled lead);
extend the Strix finding contract (YES); delete telemetry outright (YES); accept the Anthropic sovereignty trade for
offense runs (YES — mitigated near-term by the TEE/Confidential-Inference path in I4); subtree full-history for both
owned repos + Strix `LICENSE` retained + `NOTICE` added. **Still owner's to name:** the monorepo/product name
(placeholder "VIGIL").

## 13. Verification (how each phase is proven end-to-end)
- Always-green gate per phase (member suites unchanged; `vigil_core` regression proves v1 signatures still verify).
- **The one-turn live Claude scan** resolves the LiteLLM seams that unit tests can't (reasoning/cache/dedup/budget).
- **Egress gate proof:** from inside the sandbox, attempts to reach 169.254.169.254 / the operator LAN / an off-scope
  host are DROPPED at the host gateway (not just refused by a prompt) — a red-team test that MUST pass before offense.
- **Oracle pipeline proof:** a known-vulnerable staging target → Strix proposes → adapter re-drives → oracle confirms →
  PCF cert signs → re-run the cert offline and watch the oracle fire again on a *fresh* random challenge.
- **Governance proof:** an off-charter action is refused by BOTH gates and logged; a destructive action requires the
  m-of-n threshold; the killswitch halts everything above observe.
- CI eval harness (XBEN/Cybench/CVE-Bench) with variance-aware reliability + false-positive rate, run per change.

> **Deferred (unrelated, resumable):** SIGIL hard-prune Slice E (the prune cutover) + the live-93MB-spine migration —
> note that the Slice A-D Merkle-prune work is *directly reused* as the transparency-log substrate (§8-B), so it is
> not wasted; it becomes a keystone of the provenance story.
