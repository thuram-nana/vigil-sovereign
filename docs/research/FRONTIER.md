# VIGIL — Frontier Research Digest (the 1-of-1 case, with sources)

> Distilled from 4 structured internet-research sweeps + a 5-agent adversarial design panel (2026-07).
> This is the *why VIGIL is unclaimed ground* argument and the *exact techniques + reference systems* for the
> moonshot phases. Pair with [`../PLAN.md`](../PLAN.md) (architecture) and [`../CONTINUATION.md`](../CONTINUATION.md)
> (build state). When a phase says "generalize CGC Type-1/2" or "study Buttercup", the specifics are here.

## 1. The market gap (what everyone else ships, and doesn't)
The winning architecture across the 2024-26 research frontier is unanimous: **LLM proposes → deterministic
ORACLE confirms → signed, re-runnable certificate.** The DARPA **AIxCC** finals (Aug 2025) proved autonomous
find-AND-patch at scale, but *only* over sandboxed open-source memory-safety bugs with a build/PoV/sanitizer
oracle. Google **Big Sleep** / Project Zero's agent found real 0-days by reasoning + a reproduction oracle.
The academic line (**EG-VAR** exploit-generation-as-verification, **ExploitBench**, **Antiproof**, the SPRT/
conformal-abstention work) formalizes "a finding is only Verified when a program re-derives it."

**Most commercial "AI hackers" skip the rigorous middle step:**
- **XBOW** (topped HackerOne US) ships only light "validators", not a general oracle; cloud/closed.
- **CAI**, **PentAGI**, **Strix** itself, **Nebula** — trust the LLM's judgment for the verdict.
- **PyRIT / Garak** — LLM-as-judge, measured at **35–90% false-positive** rates.
- The trust crisis this creates is now material: **curl ended its bug-bounty program (Jan 2026)** over ~20%
  AI "slop"; HackerOne/Bugcrowd triage is drowning. **Signed + oracle-confirmed findings are the direct fix.**

**No existing system holds more than two** of the five properties below. VIGIL's whole thesis is that its three
source systems already implement all five — fusing them is the unclaimed ground:

| # | Property | Who has it | VIGIL source |
|---|---|---|---|
| 1 | **Oracle-confirmed validation, generalized to live web/API/net/cloud** | AIxCC (sandboxed OSS memory bugs only) | CRUCIBLE oracle authority + veracity firewall |
| 2 | **Cryptographically-signed evidence/provenance** — *the single biggest open gap; nobody signs findings* | ~nobody | SIGIL signed spine + CRUCIBLE PCF certs |
| 3 | **Hard-governed scope at the syscall/egress layer** (not prompt-level → injection-breakable) | ~nobody (all prompt-level) | SIGIL WARDEN + the P6 egress gateway |
| 4 | **Sovereign / air-gappable** | ~nobody (all cloud/closed) | SIGIL local-first |
| 5 | **Claude reasoning across the full lifecycle** (discover→prove→patch→re-verify→sign→report), *never trusted for the verdict* | partial | Strix agentic body + Claude |

**Regulatory tailwinds:** EU AI Act **Art. 12** mandates tamper-evident logging for high-risk AI (VIGIL's signed
spine is native compliance); **OWASP APTS** (Agentic Pentest Testing Standard) codifies hard autonomous-pentest
scope no product enforces; SLSA/SCITT/in-toto make signed provenance a procurement checkbox that's coming.

## 2. The no-hallucinated-findings pipeline (the honest version)
The design panel's load-bearing correction: CRUCIBLE's oracle does **not** re-execute a PoC string or replay a
raw Caido request. `verify/reverify.py` re-runs a **pure deterministic oracle** over a retained, bug-class-bound
`FindingContext` (baseline vs mutated state, probe rounds, timing samples, OOB hits). So the fusion needs an
**`OracleConfirmationAdapter`** (model it on `agents/oracle_probe_executor.py`):
```
Strix proposes finding  →  adapter re-drives a scope-gated baseline+probe pair  →  builds FindingContext
   →  OracleVerifier.confirm  →  on confirm: evidence/certify.py build+sign_certificate  →  inert JSON  →  spine
   →  on no-fire: stays Abstain with a replayable audit trail (NOT discarded, NOT asserted-false)
```
**Honesty invariant (LOCKED):** only oracle-mappable classes (`BUG_CLASS_ORACLES`: sqli/xss/idor/ssrf/rce/lfi…)
become **signed FACTS**; everything else is a **labelled lead** per `veracity/firewall.py`. *Claiming every Strix
finding becomes a signed fact would itself be the hallucination the system exists to kill.* Deterministic dedup by
`oracle_context_digest`/`cert_digest` replaces the LLM-judge for CONFIRMED findings; keep Strix's LLM-judge dedup
for unconfirmed leads only.

## 3. The moonshot techniques (I1–I5), each mapped to a standard + reference
### I1 — Provable-findings differentiators (formal-methods research)
1. **Per-run randomized-challenge oracle for EVERY finding class** — generalize DARPA CGC's Type-1 (register/PC
   control) & Type-2 (secret-region read) proofs so replay/hallucination are *structurally* impossible:
   code-exec → random PC+register target; info-leak → random canary; SQLi → random nonce the DB must echo;
   SSRF/RCE → a unique per-run OOB token. A recorded PoC can't be replayed because the challenge changes each run.
2. **Kernel-minted `Verified|Abstain` epistemics (EG-VAR):** the deterministic oracle is the *only* minter of
   "Verified" — no LLM/critic/confidence path can produce that token. Mirror SIGIL's WARDEN token-minting.
3. **Sanitizer + patch-neutrality gate (AIxCC ground-truth):** a real finding fires pre-patch (ASAN/UBSAN or the
   web oracle), goes silent post-patch, and the target's own tests still pass — the triad that killed AIxCC false
   positives.
4. **SPRT + conformal finite-sample error bounds** for noisy blind/timing channels (CRUCIBLE already has SPRT in
   `verify/`) — bound the false-positive probability instead of eyeballing a timing delta.
5. **Proof-carrying vulnerability certificates** — the cert *contains* everything needed to re-derive the verdict
   offline; verification needs no network and no trust in VIGIL.

### I2 — Witnessed transparency log (world-first for findings)
Re-express the signed spine as a **tile-based log** (Trillian **Tessera** / C2SP **tlog-tiles**), emit signed
checkpoints, get a **witness quorum to countersign** (C2SP **tlog-witness**; optionally **Armored-Witness**
hardware held by clients) → **split-view resistance** + third-party auditability. **Anchor checkpoints to Bitcoin
via OpenTimestamps** → trustless timestamping, no CA. **The Slice A–D Merkle-prune head SIGIL already built is an
MMR — it is the substrate for this**; the hard-prune work is not wasted, it's the keystone of the provenance story.

### I3 — Standards-native certs (SCITT/OpenVEX)
Express PCF certs as IETF **SCITT** Signed Statements (COSE/DSSE) with **OpenVEX** as the finding vocabulary and
offline-verifiable **Receipts** — verifiable forever by a client, regulator, or court. in-toto/Sigstore/Rekor as
the ecosystem VIGIL slots into.

### I4 — TEE-attested sovereign agent + threshold destruction
Run the gating classifier + agent in **Intel TDX / AMD SEV-SNP** (+ H100 confidential compute); **Anthropic
Confidential Inference** is the sovereign Claude path (recovers the local-only guarantee lost when offense context
transits to `api.anthropic.com`). Attestation-gated key release. Honest caveat (**TEE.Fail** and the side-channel
line) → the *witnessed log* remains the ultimate arbiter, not the TEE. **Proof-of-inference receipts** on the
classifier (attested now; **DeepProve**-style zkML later). High-blast-radius/destructive actions require **FROST
m-of-n threshold signatures (RFC 9591)**: offense-worker key + owner YubiKey/HSM + policy key, the authorization
itself written to the spine; a dormant-authorization dead-man's-switch bounds autonomy. SIGIL already has
`verify_threshold`.

### I5 — AIxCC binary/memory-safety tier + autonomous auto-patching
Extend beyond web pentesting into the Cyber-Reasoning-System space: LLM-guided fuzzing (**OSS-Fuzz-Gen** style) +
concolic/SMT (**angr** / **Z3**) + sanitizer oracle + **patch re-verification** (fires pre-patch, silent post-,
tests pass). **Reference to fold in: Trail of Bits "Buttercup"** — open-source, AIxCC 2nd place — a complete
CRS pipeline to study for the fuzzing↔SMT↔patch loop.

## 4. Claude-everywhere decision (models now, native agents later)
- **Models (done, P0):** Strix routes non-openai model prefixes through `StrixProvider(MultiProvider)→LiteLLM`;
  `anthropic/claude-opus-4-8` is set as default. Map `reasoning_effort`→Anthropic extended thinking.
- **3 runtime-only seams (P8, need ONE live Claude turn — unit tests can't substitute):** (a) does
  `Reasoning(effort=)` 400 or silently drop on the Anthropic route; (b) does prompt-cache `cache_read` fire;
  (c) does `report/dedupe.py`'s Responses-shaped `ResponseOutputMessage` text extraction return empty on Claude
  (needs a fallback). Plus the **budget-meter disarm (HIGH):** LiteLLM cost total is **$0 without an Anthropic
  price table** → the budget governor silently disarms → add prices + assert cost increments after turn 1.
- **Claude-native agents (I3-adjacent, later):** research favors the **Claude Agent SDK** (native prompt caching,
  compaction, memory tool, subagents-with-isolated-context+resume, PreToolUse hooks). But Strix's Kali execution
  is welded to `openai-agents` `SandboxAgent`/`Shell`/`Filesystem`/`SandboxRunConfig`; a native port is a
  multi-week sandbox rebuild (Kali tools re-exposed as in-process **MCP servers**). Ship Claude-via-LiteLLM first;
  port the agent body as a dedicated phase.
- **Telemetry (done, P0):** the network calls were **deleted outright** (`posthog.py`, `scarf.py`, OpenRouter
  attribution header) — not merely config-flipped, which would leave them one env-var from firing.

## 5. Agentic-safety research that shaped the governance (§6 of the plan)
Anthropic's agentic-misalignment work (all 16 frontier models took harmful self-directed action under an
autonomy-threat scenario) drove the non-negotiables: **"permission is infrastructure, not prompt"** —
deny→ask→hook→allow; **default TWIN/STAGING** target env (LIVE needs a charter flag + per-action second-ack);
per-engagement `max_actions` + daily budgets; an always-available killswitch; an owner-watched A3 approval queue.
This is *why* the two FATAL flaws (prompt-level egress scope, and a collapsed offense-free boundary) are treated
as ship-blockers rather than hardening niceties.

## 6. Reference systems to study (open-source, when building each phase)
- **Trail of Bits Buttercup** — full open AIxCC CRS (I5).
- **Trillian Tessera + C2SP tlog-tiles / tlog-witness** — the transparency-log substrate (I2).
- **OpenTimestamps** — Bitcoin anchoring (I2). **SCITT / OpenVEX / in-toto / Sigstore-Rekor** — cert standards (I3).
- **angr + Z3, OSS-Fuzz-Gen** — the binary tier (I5). **FROST / RFC 9591** — threshold destruction (I4).
- **DARPA CGC** Type-1/Type-2 PoV format — the randomized-challenge generalization (I1).
