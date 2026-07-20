# ROADMAP — FLAGSHIP

The path from CRUCIBLE v2 (an autonomous, learning offensive-intelligence
platform that runs against operator-authorised targets) to the
international flagship for professional red teaming.

This document states the target, the audience, the three pillars of
work, the non-proliferation posture, and a sequenced set of milestones.
It is written to the same standard as `V2-LIMITATIONS.md`: it does not
claim capability the code does not have, and it names the boundaries it
will not cross.

It supersedes the school/training framing entirely. There is exactly
one audience.

---

## 0. The target, in one paragraph

A capability so strong, so well-governed, and so tightly held that
*access to it is itself a control*. It is operated only by vetted,
highly-authorised professional red teams, under signed engagement
authority, against systems those teams are lawfully permitted to test.
It is not sold broadly, not open-sourced, and not deployable by an
arbitrary actor. Its power is matched by the rigour of who is allowed
to run it and the completeness of the record it leaves behind.

The defining property is not a single offensive feature. It is the
combination of frontier autonomous reasoning, deep program analysis,
defender-aware operation, a self-improvement engine that never stops
proposing, and a distribution-control system that makes unauthorised
use cryptographically infeasible and unauthorised possession useless.

---

## 1. Audience and non-goals

**Audience.** Vetted national / institutional red teams operating under
explicit, signed authority. Single tier of user. No student tier, no
community edition, no self-service.

**Non-goals (explicit).**

- No training/education shell. Legibility-for-learning is not a design
  driver. The only audience for the reasoning trace is the operator's
  after-action review and the audit record.
- No broad distribution. There is no "download and run" path. A
  deployment exists only after a governance decision binds an
  entitlement to attested infrastructure (Pillar 2).
- No unattended self-modifying offence. The framework proposes its own
  improvements continuously; it never merges or deploys them to itself
  without a human (or threshold) gate (Pillar 3).
- No working evasion-of-real-defenders library shipped in the open tree.
  Defender *awareness* (knowing what telemetry an action trips) is
  built; *defeat* of a specific production defender stack is an
  entitlement-gated, human-authored capability, not a turnkey module.

---

## 2. Where the framework is today (honest baseline)

Five subsystems ship and are live-path verified to varying degrees
(`V2-MANIFEST.md`): **URK** (reasoning kernel), **UTI** (target
intake), **MLS** (memory/learning), **MAO** (multi-agent
orchestration), **ACP** (autonomous campaign planner). The full loop
has run end-to-end against exactly one real, operator-owned target
under a deliberately conservative shape.

Three subsystems are designed but absent: **DAA** (deep analysis),
**DEL** (defender emulation), **SIL** (self-improvement). These are the
capability frontier and one of them — SIL — is the never-stop engine
this roadmap is named for.

The sovereignty substrate (`kernel/sovereignty.py`) already implements
a four-tier backend-trust ladder and a fail-closed egress guard. That
ladder is the foundation Pillar 2 extends from a *substrate* policy
into a *capability-entitlement* policy.

---

## 3. The three pillars

### Pillar 1 — Capability (the "most advanced" ceiling)

Built for depth, not explicability.

- **DAA — Deep Analysis Arsenal.** The single biggest lever. Today the
  framework reasons well over *thin* sensing (passive fingerprint, ~120
  signatures). DAA gives it rich sensing: orchestrated static analysis
  (Semgrep / CodeQL / Joern), coverage-guided fuzzing, differential
  testing, and an AST/symbol index the reasoning kernel can query.
  Reasoning over deep analysis is the difference between a clever
  scanner and a Big-Sleep-class system.
- **DEL — Defender Emulation Layer (defensive subset first).** A model
  of what telemetry each action emits, scored against detection rules,
  so the operator knows their own footprint and can choose TEST vs
  EMULATE posture deliberately. This is the purple-team capability that
  makes the tool worth deploying against a hardened adversary. The
  evasion-generation half is gated (see §4).
- **SIL — Self-Improvement Loop.** Pillar 3.

### Pillar 2 — Controlled distribution (the defining work)

"Not every actor gets it" is enforced in code, not just policy. The
**Entitlement & Capability-Gating layer** (`framework/v2/entitlement/`)
is the first subsystem built under this roadmap because the dangerous
subsystems hang off it.

- **Cryptographic entitlement, not a license file.** Capability tiers
  unlock only against a valid, threshold-signed entitlement document
  bound to a specific deploying institution. m-of-n Ed25519 — no single
  authoriser can authorise a deployment. (Forward-compatible with a
  single aggregated FROST-Ed25519 group signature.)
- **Capability ladder.** The most dangerous modules (DEL evasion,
  autonomous full-chain exploitation) are entitlement-locked, not
  config-flagged. A deployment's signed grant declares which
  capabilities unlock.
- **Hardware / identity binding + attestation.** A deployment binds to
  attested infrastructure; the framework verifies it is running where
  it was authorised to run. Unauthorised possession of the code is
  useless without a matching, bound, signed entitlement.
- **Revocation.** Entitlements expire and can be revoked; the gate
  checks a signed revocation list and fails closed.
- **Tamper-evident audit.** Every entitlement decision is logged to the
  engagement audit trail.

This composes with the ANTIC platform's threshold-crypto and
append-only chain-anchored audit log: ANTIC is the institutional trust
backbone; CRUCIBLE is the capability that backbone authorises.

### Pillar 3 — The never-stop improvement engine

Continuous *discovery and authoring*; gated *deployment*. This is the
only version of "never stops" a serious institution can field.

- **Eval harness first.** Self-improvement is unfalsifiable without
  measurement. A benchmark corpus with ground-truth findings scores
  every proposed change: detection rate up? false-positives down?
  anything regressed? Built before SIL (it is SIL's blocker).
- **SIL reviewer agent.** Runs at engagement end. Mines the blackboard
  and MLS for missed hypotheses, refuted threads, unreached surface,
  and the gap between what the playbooks say and what executed.
  Produces structured capability-gap records.
- **Patch-generator agent.** Turns the highest-value gaps into concrete
  reviewable diffs (new detector, signature, playbook step, code fix)
  as proposals — never direct commits.
- **Adversarial self-test (DAA turned inward).** Continuously fuzzes and
  threat-models the framework itself, since the framework is a
  top-tier target. This is "agents find weak points in the system"
  pointed safely at the tool's own code.
- **Horizon-scanner.** Ingests new CVEs/techniques and proposes
  corresponding playbooks/signatures, keeping the flagship current
  indefinitely.
- **The merge gate.** eval-harness-green **and** threshold human
  approval (reusing Pillar 2's crypto). The same signing that
  authorises *distribution* authorises *self-improvement merges*.

---

## 4. Non-proliferation posture

The capability is dual-use and dangerous if widely held. The controls
that make it exclusive are the same controls that make it safe.

1. **Possession is insufficient.** The code without a bound, signed,
   unexpired, unrevoked entitlement runs only the safe, low-capability
   core. Dangerous capabilities are dark.
2. **Authorisation is plural.** No single key holder can stand up a new
   deployment or unlock a high capability. Threshold signing by a
   governance panel is required.
3. **Operation is attributable.** Every engagement and every capability
   unlock is chain-anchorable to a specific institution and operator.
   Unattributed use is not a supported mode.
4. **Self-improvement is bounded.** The framework never evolves and
   self-deploys evasion or new offence unattended. An uncertifiable,
   unattributable, self-mutating offensive tool is precisely what the
   governance model exists to prevent.
5. **Evasion is human-authored and gated.** Defender *awareness* ships;
   turnkey *defeat* of a named production defender does not. That line
   is deliberate and load-bearing.

---

## 5. Milestones (sequenced)

| # | Milestone | Pillar | Blocks |
|---|-----------|--------|--------|
| M1 | **Entitlement & capability-gating layer** — crypto, threshold verify, registry, binding, revocation, fail-closed gate, audit. | 2 | M5, M6, M7 |
| M2 | **Eval harness** — benchmark corpus contract, ground-truth model, scoring, regression detection. | 3 | M3 |
| M3 | **SIL** — reviewer + patch-generator + threshold merge gate + horizon-scanner. | 3 | — |
| M4 | **DEL (defensive subset)** — telemetry model, self-detection scoring, posture annotation. | 1 | — |
| M5 | **DAA** — static-analysis orchestration, fuzzing harness, differential testing, symbol index. | 1 | — |
| M6 | **DEL (gated evasion interface)** — human-authored, entitlement-locked. | 1 | M1 |
| M7 | **Full-chain autonomous exploitation under ROE** — entitlement-locked. | 1 | M1, M5 |
| M8 | **External assurance** — third-party audit, reproducible builds, supply-chain attestation made real. | all | — |

Sequencing rationale: distribution control (M1) precedes every
dangerous capability so nothing dangerous ships ungated. Measurement
(M2) precedes self-improvement (M3) so improvement is falsifiable. The
defensive half of DEL (M4) and DAA (M5) precede their offensive,
entitlement-locked counterparts (M6, M7).

---

## 6. Definition of done (per milestone)

Every milestone ships to the same bar — no exceptions, no demo code:

- Production code only. No stubs, no `TODO` in load-bearing paths, no
  fabricated data presented as real.
- `mypy --strict` (per `pyproject.toml`) clean.
- A real test suite registered in `pyproject.toml`'s `testpaths`,
  passing offline and deterministically.
- Fail-closed behaviour on every authorisation/scope/entitlement
  boundary, with typed `EthicsViolation` errors that propagate.
- A limitations entry in `V2-LIMITATIONS.md` for anything not yet
  verified live. The framework does not lie about its own completeness.

---

## 7. The standing question

This roadmap has no terminal state. After every milestone the operator
and the framework ask: *what would make this better, what does it still
lack, what would a more advanced version do that this one cannot yet?*
The answers become the next entries in the backlog. SIL automates the
asking; the human gate governs the answering.
