---
name: crucible
description: >
  How to operate CRUCIBLE — the authorized, prove-don't-guess offensive-security engine
  in framework/v2. Read this BEFORE running an engagement/scan, re-verifying a finding,
  inspecting the event spine, reasoning about the veracity/anti-hallucination layer, the
  learning/metacognition core, or the safety stack. Use it when a task names CRUCIBLE,
  OBSIDIAN, `python3 -m framework.v2 <subcommand>`, findings/oracles/evidence certificates,
  the blackboard event spine, critics, reflection, or the reward/calibration loop.
---

# CRUCIBLE — operating the engine

CRUCIBLE turns an authorized seed URL into **oracle-confirmed** findings, reasons over them,
and produces auditable reports — inside a fail-closed safety stack. Its whole value is one
rule; internalize it before anything else:

> **A claim is a FACT only when a deterministic oracle fires over data a real target
> produced.** You (the LLM) ADVISE where to look and what a result might mean; the oracle
> CONFIRMS. Nothing else — not your confidence, not a critic's endorsement, not a plausible
> story — promotes a claim to a fact.

The standing doctrine every reasoning call operates under is
[framework/cognitive/metacognition.md](../../../framework/cognitive/metacognition.md) (it is
injected into every LLM system prompt). The full architecture — agents, event spine, veracity
layer, learning/metacognition core, safety stack — is
[framework/v2/docs/CRUCIBLE-AI.md](../../../framework/v2/docs/CRUCIBLE-AI.md). The binding
constitution is [CLAUDE.md](../../../CLAUDE.md); never relax scope, destruction, evidence, or
honesty rules.

## The invariants (never violate these)

1. **Oracle authority.** Only a fired oracle confirms. Critics/RL/reflection/self-consistency
   may only *advise, re-rank, defer, or abstain* — never promote a finding or override the oracle.
2. **Coverage.** Never silently skip an authorized attack surface. Learning and reflection
   *deprioritise* (re-rank / defer); they never gate a surface out.
3. **Prove by re-execution.** A finding is a fact only if its retained `oracle_context`
   re-fires. The veracity firewall (`framework/v2/veracity/`) re-runs proofs; it can only demote.
4. **Non-circular learning.** An EXPLOITABLE label needs ≥2 independent corroborating oracle
   kinds; a silent oracle is never auto-labelled a false positive.
5. **Refuse honestly, fail closed.** Decline to conclude what you cannot ground; record every
   refusal as evidence. Hard limits (scope, authorization, destruction, real user data) are
   inviolable — when unsure, stop and ask.
6. **Determinism + append-only.** No wallclock/global-rng in learning/reward math; the event
   spine is append-only (supersede, never edit).

## Structured workflows

### Run an authorized engagement (end-to-end, gated)
1. Confirm the active target's `targets/<slug>/charter.md` authorizes it (constitution §II).
2. `python3 -m framework.v2 engage <slug> <seed-url> [--recon] [--spine]`
   — crawls, audits, confirms via oracles, chains attack paths, scores confidence, and
   (with `--spine`) mirrors the whole run onto the immutable blackboard event stream.
   (`--strict-evidence` is a **`scan`**-only flag, below — not an `engage` flag.)
3. Every request passes the full gate chain; an out-of-scope seed or tripped kill-switch
   refuses *before* traffic and is recorded as a `refusal` event.

### Loopback-only quick scan
`python3 -m framework.v2 scan http://127.0.0.1:<port>/ --format json|sarif|html [--strict-evidence]`
— the export states each finding's **live grounding** (fact / ungrounded / contradicted);
`--strict-evidence` withholds non-fact findings from the rendered doc but keeps them in
`--reverifiable-out`.

### Re-verify a report (prove-don't-guess, offline)
`python3 -m framework.v2 verify <report.json>` re-runs each finding's retained `oracle_context`.
`python3 -m framework.v2 evidence ...` builds/verifies signed, hash-linked evidence certificates
(and, with report claims bound in, fails closed when a report sentence has no backing evidence).

### Inspect / audit the event spine
The blackboard (`framework/v2/agents/blackboard.py`) is the one append-only, typed, provenance-
linked event stream. Replay it with `Blackboard.replay(engagement=..., since_id=...)`.
Cryptographic tamper-evidence: `framework/v2/agents/spine_chain.py`
(`build_spine_chain` / `sign_spine_head` / `verify_spine_head`).

### Recon / intel, memory, self-improvement
`python3 -m framework.v2 intel ...` (OSINT into the shared world-model; gated egress),
`memory ...` (cross-engagement priors — never fabricate a score), `improve ...`
(authorise-not-apply — it never self-applies a change).

### Read-only operator console
`python3 -m framework.v2 console` — loopback, read-only, zero-impact operator UI over the run.

## What NOT to do
- Do not build detection-evasion / identity-rotation / stay-hidden-from-defenders capability —
  CRUCIBLE is correlatable and authorized by doctrine (constitution §VI).
- Do not let any learned/critic/LLM signal enter the deterministic oracle/SCE/calibration inputs
  or promote a finding.
- Do not attack third parties (payment/IdP/CDN) — test only the operator's integration with them.
