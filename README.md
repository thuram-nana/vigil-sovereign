# CRUCIBLE

**An authorized, prove‑don't‑guess offensive‑security platform.** CRUCIBLE takes a web target you
own, and — instead of "asking an AI to hack it and trusting whatever it says" — it *crawls the
target, attacks each input with real payloads, and only calls something a vulnerability when a
deterministic proof program (an "oracle") fires over data the real target actually produced.* It
then reasons over those proven facts to build attack paths, scores its own confidence, and emits
tamper‑evident evidence anyone can re‑verify offline — all inside a fail‑closed safety cage that
cannot touch anything outside the authorized scope.

This README is the **complete, self‑contained explanation of the entire system.** You do not need to
open any other file to understand it. It explains *why* CRUCIBLE exists, *how it works
mechanistically* end‑to‑end, and *what every subsystem does, how it works internally, and how it
wires into the others* — followed by an honest account of what ships today versus what is still
being built. Jargon is defined the first time it appears.

---

## Table of contents

- [1. Why CRUCIBLE exists (from first principles)](#1-why-crucible-exists-from-first-principles)
- [2. The two faces: the OBSIDIAN agent and the engine](#2-the-two-faces-the-obsidian-agent-and-the-engine)
- [3. The one rule that everything is built around](#3-the-one-rule-that-everything-is-built-around)
- [4. Architecture at a glance](#4-architecture-at-a-glance)
- [5. How it works end‑to‑end (the runtime, mechanistically)](#5-how-it-works-endtoend-the-runtime-mechanistically)
  - [5.1 The engagement as a concrete data‑flow](#51-the-engagement-as-a-concrete-dataflow)
  - [5.2 Worked example: one request from insertion to confirmed finding](#52-worked-example-one-request-from-insertion-to-confirmed-finding)
  - [5.3 The OODA reasoning loop: how the agent decides what to do next](#53-the-ooda-reasoning-loop-how-the-agent-decides-what-to-do-next)
- [6. Repository layout](#6-repository-layout)
- [7. Quick start](#7-quick-start)
- [8. The CLI surface](#8-the-cli-surface)
- [9. Subsystem reference (what · why · how · data · wiring)](#9-subsystem-reference-what--why--how--data--wiring)
  - [9.1 The event spine](#91-the-event-spine--the-shared-nervous-system-agentsblackboardpy)
  - [9.2 The oracle / verification layer](#92-the-oracle--verification-layer--the-confirmation-authority-verify)
  - [9.3 The unified Bayesian world‑model](#93-the-unified-bayesian-worldmodel-worldmodel)
  - [9.4 The veracity (anti‑hallucination) firewall](#94-the-veracity-antihallucination-firewall-veracity)
  - [9.5 The scanner / audit engine and the intruder](#95-the-scanner--audit-engine-and-the-intruder-scanner--intruder)
  - [9.6 The Scientific Confidence Engine (SCE)](#96-the-scientific-confidence-engine-sce-confidence)
  - [9.7 The learning / calibration core](#97-the-learning--calibration-core-calibration)
  - [9.8 The nervous system: critics, reflection, refusal, credit](#98-the-nervous-system-critics-reflection-refusal-credit-agents)
  - [9.9 Memory and priors (MLS)](#99-memory-and-priors-mls-memory)
  - [9.10 The intelligence / OSINT engine](#910-the-intelligence--osint-engine-intel)
  - [9.11 The reasoning kernel (URK)](#911-the-reasoning-kernel-urk-kernel)
  - [9.12 Knowledge: attack‑graph operators](#912-knowledge-attackgraph-operators-knowledge)
  - [9.13 Signed evidence bundles](#913-signed-evidence-bundles-evidence)
  - [9.14 The fail‑closed safety stack](#914-the-failclosed-safety-stack-the-6-gate-chain--authority--entitlement--sovereignty)
  - [9.15 Intake, analysis, defender, improve, socialdefense, console, eval, common](#915-the-remaining-subsystems)
  - [9.16 The universal sensor / producer framework and live fusion](#916-the-universal-sensor--producer-framework-and-live-fusion-sensors)
  - [9.17 The opt-in autonomous OODA loop and the reasoning hook](#917-the-opt-in-autonomous-ooda-loop-and-the-reasoning-hook-engage_autonomouspy)
  - [9.18 AEGIS — the defensive dual](#918-aegis--the-defensive-dual-aegis)
  - [9.19 Reporting, export, and the platform seams](#919-reporting-export-and-the-platform-seams-report-mcp-api-plugins-imports)
- [10. The doctrine and posture, in depth](#10-the-doctrine-and-posture-in-depth)
- [11. Testing and verification](#11-testing-and-verification)
- [12. Roadmap / in progress](#12-roadmap--in-progress)
- [13. Status and honesty](#13-status-and-honesty)
- [14. Where this lives in the repo](#14-where-this-lives-in-the-repo)

---

## 1. Why CRUCIBLE exists (from first principles)

**The problem.** A large language model (LLM) can read a web application, reason about it, and
propose vulnerabilities fluently. That makes it tempting to point an LLM at a target and let it
"pentest autonomously." But an LLM is a *plausibility engine*, not a *truth engine*. It produces
text that is likely given its training — which means it will, with total confidence:

- **Hallucinate findings that do not exist** ("this endpoint is vulnerable to SQL injection")
  because that sentence is plausible, not because it tested anything.
- **Mislabel severity and impact**, inventing CVSS scores and blast‑radius claims it never measured.
- **Fabricate corroboration** ("I confirmed this with three payloads") that never ran.
- **Silently skip** whole classes of attack it simply didn't think to generate.

For most tasks a wrong answer is an inconvenience. For an **autonomous offensive‑security tool** it
is dangerous twice over. First, a *false positive* wastes an engineering team's time chasing a bug
that isn't there — and, worse, erodes trust until real findings get ignored too. Second, an
*unconstrained* tool that acts on its hallucinations can hammer production, touch systems it was
never authorized to touch, exfiltrate real user data "to prove impact," or pivot into a third‑party
provider. An offensive tool that is both *autonomous* and *untrustworthy* is a liability, not an
asset.

**The naive approaches don't fix it.** Asking the model to "be careful," to "only report confirmed
bugs," or to "double‑check itself" does not work: the self‑check is produced by the same
plausibility engine and hallucinates its own confidence. Bolting on a second LLM "judge" just moves
the hallucination one layer up. You cannot make a guess trustworthy by asking it more nicely.

**The answer: separate proposing from proving, and make proving mechanical.** CRUCIBLE's founding
decision is that **the LLM never decides what is true.** The LLM (and the search machinery around it)
*proposes* where to look and what a result might mean. A separate layer of **deterministic oracles**
— small, pure verification programs with no network, no clock, and no randomness — *decides* whether
a real signal fired, by examining data a real target actually produced. If no oracle fires, there is
no finding, full stop. This is the **prove‑don't‑guess** invariant, and it is the reason every other
design choice exists:

- Because a claim must be *provable by re‑execution*, every confirmed finding carries a **re‑runnable
  certificate** — the exact observed data plus the oracle that judged it — so *anyone* can re‑verify
  it offline, with no target, months later. Findings become receipts, not assertions.
- Because facts must *compose* into attack paths without laundering a guess into a fact, CRUCIBLE
  keeps a single **Bayesian world‑model**: a graph where every node and edge carries a probability
  *and* a provenance pointer back to what made the system believe it. A path is only as strong as its
  weakest, least‑evidenced hop, and the whole chain is explainable.
- Because an LLM can quietly hallucinate a "fact" into a report, a **veracity firewall** sits at
  every boundary and *re‑executes the cited proof* before letting a claim through — it can only ever
  demote a claim, never promote one.
- Because an autonomous tool must never exceed its authorization, every single action passes a
  **fail‑closed safety stack** (kill‑switch → scope → destructive‑confirm → budget → rate‑limit →
  egress) that refuses by default and records refusals as evidence.
- Because trustworthiness includes *not lying about your own limits*, CRUCIBLE's own rule is **never
  overclaim what the deterministic layer enforces** — this README flags every place a mechanism is a
  built primitive that is not yet wired into the live loop.

The result is an autonomous tool whose findings you can trust the way you trust a compiler error:
not because a model felt confident, but because a deterministic program re‑ran the proof.

---

## 2. The two faces: the OBSIDIAN agent and the engine

CRUCIBLE is used in two complementary ways.

**OBSIDIAN — the reasoning agent.** You open the repository in Claude Code (Anthropic's coding agent)
and it reads `CLAUDE.md`, an operating "constitution" that turns it into **OBSIDIAN**, a senior
offensive‑security operator. OBSIDIAN is not a script runner — it reasons in a disciplined loop
(observe → orient → hypothesize → test → update → critique → pivot), driven by a library of
**playbooks** (what to test per domain), a **cognitive framework** (how to think), **checklists**
(coverage receipts), **templates** (charter, findings, reports), and a **knowledge base** (deep
per‑technique references). This is the human‑driven, judgment‑heavy face: you and OBSIDIAN work a
target together, and OBSIDIAN documents everything with discipline.

**The engine (`framework/v2/`) — executable, deterministic machinery.** Roughly 380 Python source
modules (with ~270 test files) that make the discipline mechanical: the oracles, the event spine, the
world‑model, the veracity firewall, the calibrated learning core, the OSINT engine, and the safety
stack. Where OBSIDIAN *reasons about* whether something is a bug, the engine *proves* it. You invoke
the engine through one CLI: `python3 -m framework.v2 <subcommand>`.

There is also a **defensive dual — AEGIS** (`framework/v2/aegis/`, the `aegis` subcommand): the same
prove‑don't‑guess core pointed *inward* at the operator's own app as an embeddable AI‑attack‑detection
library. It is deliberately isolated (lazily imported, never touched by `scan`/`engage`/`benchmark`),
defensive‑only, and covered in §9.15 and §13.

The two faces share the same doctrine. The exact same prove‑don't‑guess rules that bind OBSIDIAN's
reasoning are the rules the engine enforces in code — and, as we'll see, the engine quotes that
doctrine *verbatim* into every LLM prompt it issues, so the reasoning layer can never drift from it.

---

## 3. The one rule that everything is built around

> **A finding is `confirmed` for exactly one reason: a deterministic oracle fired at or above
> threshold over data a real target actually produced.** The LLM proposes; the oracle disposes.

An **oracle** here is a small, pure function that takes already‑collected observations (HTTP
responses, captured state, an out‑of‑band callback log, sanitizer output) and returns a verdict:
*did a real signal fire, and with what calibrated confidence?* "Pure" means no I/O, no network, no
wall‑clock, no randomness — the *same inputs always produce the same verdict*. That purity is what
makes a finding re‑verifiable offline.

Every other subsystem in CRUCIBLE is **subordinate** to this rule. Any AI addition — the critics,
the reinforcement learning, the reflection engine, self‑consistency voting, the planner — may only
**advise, re‑rank, defer, or abstain.** None may promote a claim the oracle refused, and none may
silently skip an authorized attack surface. This is not merely a convention; it is enforced at the
type level and at report time:

- The blackboard event stream defines a "critic verdict" whose only possible values are
  `endorse | object | abstain` — there is *no* `confirm` value a critic could emit. An LLM's opinion
  literally cannot be encoded as a confirmation.
- A finding's status reserves `confirmed` for a fired oracle; an LLM‑only verdict is stored as
  `llm_advisory`.
- At report time, each finding's stored certificate is **re‑executed**; a finding whose proof no
  longer reproduces is demoted before it is ever rendered as a fact.

The runtime expression of this discipline is a document (`framework/cognitive/metacognition.md`) that
is injected verbatim into every LLM system prompt: *prove don't guess (the oracle is the sole
authority), reflect in the loop, submit to the critics, refuse honestly, vote against yourself, learn
without fabricating.* So the model is *told*, on every call, that it advises and the oracle confirms
— and the code makes that true regardless of what the model says.

---

## 4. Architecture at a glance

CRUCIBLE is a **reasoning operating system**: every tool is a *sensor* (a fact producer), every
observation — regardless of origin — is normalized into **one** evidence model, reasoned over
consistently, and backed by verifiable proof.

```
                         AI REASONING CORE  (the moat — built from scratch)
     multi-critic panel · reflection · cognitive-refusal · scientific confidence ·
     reinforcement-learning + calibration + conformal bands · self-consistency ·
     governance preamble in every prompt · goal-tree planner · autonomous chaining ·
     cross-engagement memory
                         ▲                                   │
          reasons over / │ correlates                        │ drives (gated) sensors
                         │                                   ▼
                 BAYESIAN WORLD-MODEL  ◄───────────  ORACLE / PROOF ENGINE
                 (typed graph; every node/edge         (15 offensive oracle KINDS;
                  carries a Beta probability +          re-verifies every claim → mints a
                  a provenance pointer; a               re-runnable certificate; only a
                  refutation channel lowers             fired oracle CONFIRMS)
                  belief)                                       ▲
                         ▲                                      │ sign
                         │ project (normalize)                 │
                 UNIFIED EVIDENCE + EVENT SPINE  ──────►  SIGNED, TAMPER-EVIDENT EVIDENCE
                 (append-only, hash-linked, seq-clocked,       (m-of-n Ed25519; verify offline;
                  governance-signed head)                       fail-closed on any tampering)
                         ▲
                         │  every observation → one model (provenance + confidence)
   ┌─────────────────────┴──────────────────────────────────────────────────────────────┐
   │  SENSORS / PRODUCERS  (each is a GATED action through the fail-closed safety stack)   │
   │  native web scanner+intruder · OSINT collectors (DNS / CT / RDAP / ASN) · static      │
   │  analysis (Semgrep/Joern) · cloud-IAM & SBOM file-ingest · third-party tool adapters  │
   │  (Nuclei / ZAP / Burp / sqlmap output parsed as attestations, then re-verified)       │
   └────────────────────────────────────────────────────────────────────────────────────────┘

  ── every target-touching action passes, IN THIS ORDER, none bypassable without a code change ──
  authority/kill-switch → scope → destructive-confirm → per-engagement budget → rate-limit → egress
```

Read the diagram top to bottom as *"reason over proven facts,"* and bottom to top as *"turn raw
sensor output into proven facts."* Two design commitments hold it together:

1. **Instrumentation is not the moat; intelligence is.** Discovering ports, capturing packets,
   crawling HTML, inventorying a cloud account — these are *solved* engineering problems with mature
   engines. CRUCIBLE integrates those as interchangeable, gated **sensors** rather than reinventing
   them. What it builds from scratch is Layer 2: the oracle engine, the world‑model, the veracity
   firewall, the confidence/calibration math, the memory, and the signed spine.
2. **Provability survives integration.** A third‑party tool's claim (say, a Nuclei "SQLi") enters as
   a *provenance‑tagged attestation* — never a rubber‑stamped fact — and becomes a `fact` only when a
   CRUCIBLE oracle **re‑verifies** it over the retained evidence. Otherwise it stays a labelled lead.

---

## 5. How it works end‑to‑end (the runtime, mechanistically)

### 5.1 The engagement as a concrete data‑flow

An **engagement** is one authorized assessment of one target. Here is the actual sequence of what
happens when you run `python3 -m framework.v2 engage <slug> <seed-url> --recon --spine`, with the
data that flows between stages. (`<slug>` names the engagement and directs its charter, scope,
evidence, and logs; the seed URL is where crawling starts.)

```
 (0) AUTHORIZATION        targets/<slug>/charter.md must exist and be signed; the seed host must be
      │                   in its in-scope list. Unsigned charter or out-of-scope host → REFUSED here,
      │                   before a single byte leaves the box. (common/ethics.py)
      ▼
 (1) PREFLIGHT            engage.preflight(): re-read the kill-switch file (tripped → refuse); run the
      │                   scope gate on the seed URL; if an out-of-band relay is configured, its host
      │                   must ALSO be on the charter allowlist. Any refusal is recorded as a
      │                   `refusal` event on the spine, then raised. (engage.py)
      ▼
 (2) OSINT RECON [opt-in --recon]   Query THIRD-PARTY sources about the target's domain (never the
      │                   target itself): DNS, Certificate Transparency, RDAP/WHOIS, ASN/BGP. Each
      │                   answer becomes an Observation → projected into the shared world-model as a
      │                   Beta belief. Produces an asset inventory; NOTHING predicted is ever scanned.
      ▼
 (3) CRAWL / SURFACE MAP  Crawler fetches the seed and follows in-scope links up to max-pages/max-depth.
      │                   Every response is passively analysed (headers, cookies, disclosures) and
      │                   FINGERPRINTED into a token set (server/language/framework/cms/cdn/waf).
      │                   Output: a set of HttpRequests (the surface) + passive findings + a fingerprint.
      ▼
 (4) INSERTION-POINT      Each discovered request is decomposed into INSERTION POINTS — the individual
      │  DECOMPOSITION    places an attacker controls: each query value/name, each body field, each
      │                   cookie, each header, each JSON leaf/key, the whole body, each URL path segment.
      ▼
 (5) CHECK SELECTION      The fingerprint selects which CHECKS apply (a WordPress payload never fires at
      │                   a Spring app). A Thompson-sampling bandit ORDERS the checks by learned payoff
      │                   for this archetype — but never DROPS one, so coverage is invariant.
      ▼
 (6) AUDIT (issue probes) For each (insertion point, check): craft payload probes and issue them through
      │                   the GATED executor — every request passes the 6-gate safety chain. Collect the
      │                   observed responses (status, body, latency, structure) into a FindingContext.
      ▼
 (7) ORACLE CONFIRMATION  The FindingContext's bug_class routes to the oracle(s) that can prove it. Each
      │                   runs over the observed data; signals combine by noisy-OR; if any fires at
      │                   ≥ 0.70 → a confirmed AuditFinding is minted, carrying its FindingContext as a
      │                   re-runnable CERTIFICATE (`oracle_context`). No oracle fires → no finding.
      ▼
 (8) WORLD-MODEL          Confirmed findings + endpoints are written into the world-model: an ENDPOINT
      │  PROJECTION       node per surface, a FINDING node per confirmation, an EVIDENCES edge between
      │                   them, each with provenance `oracle:...` and a belief.
      ▼
 (9) ATTACK-PATH CHAINING The knowledge attack-graph OPERATORS saturate the graph to a fixpoint (pure
      │  (no traffic)     reasoning, sends nothing), extracting multi-hop attacker→crown-jewel paths.
      │                   Paths are ranked by DETECTION COST (how loud they are) and a stealthiest-
      │                   valuable-subset is chosen within a detection budget.
      ▼
 (10) VERACITY FIREWALL   Every "active" finding is run back through the anti-hallucination firewall:
      │  (re-execute)     it RE-FIRES the finding's own retained oracle_context (never trusting the
      │                   stored verdict). Re-fires → GROUNDED (fact). Won't reproduce → demoted to
      │                   UNGROUNDED. Names a net-refuted entity → CONTRADICTED. Only ever demotes.
      ▼
 (11) SCIENTIFIC          Each confirmed finding is scored as a competing-hypothesis Bayesian problem:
      │  CONFIDENCE (SCE)  focal "real bug" vs. a set of benign alternatives → posterior + credible
      │                   interval + the single most decisive next test. Reasoning OVER the oracle's
      │                   verdict; never overrides it.
      ▼
 (12) SPINE + REWARD      With --spine: every phase, finding (tagged with its live grounding verdict),
      │                   and refusal is mirrored onto the immutable event spine; each confirmed finding
      │                   emits a `reward` event (effort credit for that bug-class surface).
      ▼
 (13) EVIDENCE + REPORT   Findings render to json / SARIF / HTML, each flagged re_verifiable; signed,
                          tamper-evident EvidenceCertificate bundles can be produced; --strict-evidence
                          withholds any finding that does not re-ground as a fact at render time.
```

Key properties visible in that flow: authorization is checked **first and continuously** (not just
once); the LLM is nowhere in the confirmation path (steps 6–7 are pure code); every confirmed fact
carries provenance back to raw data; and the anti‑hallucination pass (step 10) is a *live*
re‑execution over real output, not a test fixture.

### 5.2 Worked example: one request from insertion to confirmed finding

Follow a single boolean‑blind SQL‑injection from a raw URL to a receipt.

1. **Discovery.** The crawler fetches the seed and finds a link to `GET /items?category=books`. That
   becomes an `HttpRequest` in the surface set.
2. **Insertion‑point decomposition.** The engine decomposes the request. One insertion point is the
   **query value** of the `category` parameter (kind `QUERY_VALUE`). ("Insertion point" = a specific,
   attacker‑controllable location in a request.)
3. **Check selection.** The fingerprint says the app is PHP + MySQL, so a `boolean_sqli` check
   applies to `category`. The bandit orders it among the applicable checks by its learned payoff for
   this archetype.
4. **Probe issuance (gated).** The check crafts three requests and sends each through the gated
   executor (so each passes kill‑switch → scope → destructive‑confirm → budget → rate‑limit → egress):
   - baseline: `category=books`
   - "true" probe: `category=books' AND '1'='1`
   - "false" probe: `category=books' AND '1'='2`
   The observed responses (status, body, latency) are collected into a **FindingContext** — a
   structured record of exactly what was sent and what came back — tagged `bug_class = boolean_sqli`.
5. **Oracle routing.** The bug class routes (via the `BUG_CLASS_ORACLES` table) to two oracles that
   can prove boolean SQLi: `BOOLEAN_INFERENCE` and `DIFFERENTIAL_RESPONSE`.
6. **Oracle firing.**
   - `BOOLEAN_INFERENCE` runs a **Wald Sequential Probability Ratio Test (SPRT)** over the aligned
     true/false pairs. In plain terms: across repeated rounds, it checks whether the "true" response
     consistently matches the baseline and the "false" response consistently differs — accumulating a
     log‑likelihood ratio and stopping as soon as the evidence crosses an accept or reject boundary.
     A dynamic‑page control guards against pages that just change on their own. If the app is
     injectable, the pattern is stable and the test *accepts* at a calibrated confidence.
   - `DIFFERENTIAL_RESPONSE` compares **structural signatures** of the responses — a set of
     JSON‑pointer paths for JSON, or an HTML tag‑path multiset for HTML — which are invariant to token
     noise like CSRF tokens or timestamps, so a changed nonce does *not* look like a difference, but a
     new/removed record does.
   - The two signals combine by **noisy‑OR** (`1 − Π(1 − wᵢ)`, capped at 0.99): independent
     corroboration raises confidence, but no single weak dimension can dominate, and the result is
     never a false 1.0.
7. **Confirmation.** The combined confidence clears the `0.70` threshold, so a **confirmed
   AuditFinding** is minted: `bug_class = boolean_sqli`, the insertion point, `confirmed_by =
   boolean_inference`, the confidence, and — crucially — the entire FindingContext embedded as
   `oracle_context`. That embedded context **is** the re‑runnable certificate: it holds the exact
   probes and responses, so the same oracle can re‑fire later with no target.
8. **World‑model projection.** The engine writes an `ENDPOINT` node for `/items`, a `FINDING` node for
   the SQLi, and an `EVIDENCES` edge from finding to endpoint, each stamped with provenance
   `oracle:<id>` and a belief.
9. **Chaining.** The attack‑graph operators run. If `/items` reaches a `DATASTORE` node and the SQLi
   grants read access, an operator derives an attacker→datastore hop, contributing to a multi‑hop
   attack path scored by its weakest link.
10. **Veracity firewall.** The finding is re‑admitted: the firewall pulls the finding's own
    `oracle_context` and **re‑fires the `BOOLEAN_INFERENCE` oracle for bug class `boolean_sqli`.** It
    re‑fires → the finding is labelled **GROUNDED (fact)**, and its confidence becomes the *re‑executed*
    value, not the stored one. (Had someone tampered with the evidence, or had this been a dry‑run
    stub, it would not re‑fire and would be demoted to `UNGROUNDED` — even though the scan marked it
    active.)
11. **Scientific confidence.** The SCE builds the focal hypothesis "a real, injectable SQLi" against
    benign alternatives ("a coincidental differential," "an error page, not injectable"), scores each
    by weight‑of‑evidence (a replayable certificate boosts the focal), and returns a posterior with a
    credible interval plus the most decisive next test ("escalate to a UNION or time‑based probe to
    prove data egress").
12. **Spine + reward + report.** On the spine, a `finding` event (tagged GROUNDED) and a `reward`
    event (`arm = boolean_sqli`, `signal = oracle_confirmed`) are posted. The finding renders to
    JSON/SARIF/HTML flagged `re_verifiable = true`. Anyone can later run
    `python3 -m framework.v2 verify report.json` and the certificate re‑fires with no target — the
    finding proves itself.

At no point did an LLM's opinion promote this finding. The model may have *suggested* trying SQLi on
`category`; the oracle *proved* it.

### 5.3 The OODA reasoning loop: how the agent decides what to do next

The engine's confirmation path is deterministic, but *deciding what to test and when to stop* is
reasoning. Both OBSIDIAN (the agent) and the engine's kernel operate a fast **OODA loop** — Observe,
Orient, Decide/Hypothesize, Act/Test, Update — with critique and pivot built in:

- **Observe** — what is true right now? What did the last probe return? Distinguish *observed facts*
  (a response came back 500) from *inferred* ones (therefore it's injectable) — they age differently.
- **Orient** — where are we in the kill chain? What's the current model of the target's architecture,
  auth flow, trust boundaries? What surface is covered; what is deferred?
- **Hypothesize** — generate *several* falsifiable hypotheses, not one. The bug class most testers
  miss is the one they never hypothesized. The kernel's `hypothesize` binding forces this: given an
  observation and a surface, it returns multiple distinct, testable, refutable hypotheses.
- **Test** — design the *cheapest experiment that could refute* the hypothesis, run it, capture
  evidence, throttle.
- **Update** — did the result confirm, refute, or *surprise*? Surprises are the most valuable signal —
  they mean the model is wrong somewhere, and broken models are where bugs hide.
- **Critique & pivot** — at every phase boundary, and any time a thread has run without progress, run
  a self‑critique ("what am I not even trying? where am I deceiving myself?") and, if stuck,
  **pivot**: give up on the *thread*, never on the *target*. There is always another thread.

The engine makes several of these steps mechanical. **Reflection** (a deterministic agent) scans the
event spine for dead threads and stalls and posts re‑orienting events that *re‑rank or defer* work —
but, per the coverage doctrine, **never skip** an authorized surface. The **bandit** learns which
checks pay off and orders effort accordingly (again, ordering, never dropping). **Self‑consistency**
lowers confidence when the model's own repeated attempts disagree. None of these can promote a
finding; they steer *where effort goes*, while the oracle remains the sole authority on *what is true*.

---

## 6. Repository layout

```
crucible/
├── CLAUDE.md                     # OBSIDIAN's operating constitution (the agent reads this first)
├── README.md                     # this file — the complete explanation
├── HOW-TO-START.md               # literal first-message text to start an OBSIDIAN session
├── ENGAGEMENT-LIFECYCLE.md       # the 10-stage lifecycle, gate by gate
├── SECURITY.md                   # sovereignty tiers, trust model, sovereign-deployment hardening
├── Makefile                      # make gate | bench | test | console
├── bin/                          # init.sh (one-time setup), verify-supply-chain.sh
│
├── framework/                    # shared, target-agnostic
│   ├── cognitive/                # HOW OBSIDIAN thinks — 9 docs incl. metacognition.md (injected
│   │                             #   verbatim into every LLM prompt)
│   ├── playbooks/                # WHAT OBSIDIAN tests — 27 domain playbooks
│   ├── checklists/               # coverage receipts (OWASP WSTG/ASVS/API-Top-10, MITRE, cloud, mobile)
│   ├── knowledge-base/           # deep per-technique refs, standards map, fingerprints, defaults
│   ├── templates/                # charter, threat-model, attack-tree, finding, chain, reports
│   ├── scripts/ · tools/ · wordlists/
│   │
│   └── v2/                       # THE ENGINE (~380 source modules, ~270 test files)
│       ├── __main__.py           # the CLI dispatch table (the contract — all 25 subcommands)
│       ├── engage.py             # the authorized, fully-gated end-to-end runner
│       ├── engage_autonomous.py  # the opt-in `--autonomous` OODA loop (planner + gated tools)
│       ├── engage_fusion.py      # `--autonomous` sensor→world-model fusion seam
│       ├── engage_reasoning.py   # `--autonomous` advisory LLM reasoning hook
│       ├── agents/               # event spine + coordinator + specialist agents + nervous system
│       │                         #   + http_executor (6-gate) + tier3_validation (entitlement-gated)
│       ├── verify/               # deterministic oracles + offline re-verifier + OOB collaborator
│       ├── worldmodel/           # the unified Bayesian evidence graph + attack-path search
│       ├── veracity/             # the anti-hallucination firewall (re-execution)
│       ├── confidence/           # the Scientific Confidence Engine (SCE)
│       ├── calibration/          # reward bus, ledger, isotonic calibration, conformal, meta-monitor
│       ├── memory/               # MLS: SQLite + embeddings + priors + recall
│       ├── planner/              # ACP goal-tree campaign planner (runs under `engage --autonomous` only)
│       ├── intel/               # OSINT recon engine (collectors → observations → beliefs)
│       ├── scanner/              # the web audit engine + 172-check library + browser + arsenal
│       │                         #   + opt-in packs: bizlogic, sso, graphql, access_control, nuclei_compile
│       ├── intruder/             # autonomous Burp-Intruder-style fuzzer (built; not default-wired)
│       ├── repeater/             # gated intercepting repeater (authorized web testing; opt-in)
│       ├── sensors/              # W2-W5 sensor/producer framework: Nmap, tshark, Nuclei/ZAP/Burp,
│       │                         #   cloud-IAM/CSPM, SBOM/SCA, k8s_runtime, fuzz/ASan (NOT default-wired)
│       ├── aegis/                # AEGIS — the defensive dual (lazy-imported; off the offensive path)
│       ├── report/               # deterministic exec/technical/remediation reports + SARIF/JSON export
│       ├── imports/              # third-party tool export → re-verifiable leads
│       ├── mcp/ · api/ · plugins/ # platform seams: MCP tool-server, loopback gated API, capability catalog
│       ├── kernel/               # URK: cognitive prose → typed LLM callables + sovereignty tiers
│       ├── knowledge/            # attack-graph technique operators
│       ├── evidence/             # signed, tamper-evident certificate bundles
│       ├── authority/            # kill-switch + scoped engagement authority
│       ├── entitlement/          # m-of-n capability entitlement for high-impact actions
│       ├── intake/               # UTI: URL → scaffolded engagement
│       ├── analysis/             # DAA: offline static/taint analysis (Semgrep/Joern adapters)
│       ├── defender/             # DEL: purple-team detection modeling (defensive; partly unwired)
│       ├── improve/              # SIL: self-improvement, authorise-not-apply
│       ├── socialdefense/        # inbound phishing / social-engineering defense
│       ├── console/              # read-only loopback operator UI
│       ├── eval/                 # benchmark corpus + regression gate + third-party tool adapters
│       ├── common/               # paths, ethics gates, redaction, error types, structured logging
│       └── docs/                 # deeper design notes (architecture, operator guide, benchmark)
│
└── targets/                      # per-engagement working directories
    ├── _template/                # copy this to start a new target
    └── <your-target>/            # charter.md, threat-model.md, findings/, evidence/, reports/, notes/
```

---

## 7. Quick start

### As the OBSIDIAN agent (Claude Code)

```bash
cd crucible
claude
# Paste the first-message text (there is a ready-made template in HOW-TO-START.md). OBSIDIAN reads
# CLAUDE.md, locates or creates targets/<name>/, walks you through the charter, and begins.
```

OBSIDIAN will not send any traffic to the target until that target's `charter.md` is filled in and
signed by you.

### As the engine (`framework/v2`)

```bash
# one-time setup: rewrites embedded paths for this host and creates local state dirs
bash bin/init.sh
pip install --break-system-packages -r framework/v2/requirements.txt

# 0. choose your SOVEREIGNTY TIER before first run (it gates which LLM backends may even be built)
export CRUCIBLE_SOVEREIGNTY_TIER=PERMISSIVE   # or AIR_GAPPED / SOVEREIGN_CLOUD / TRUSTED_CLOUD

# verify the environment: paths, reachable LLM backends, and the GOVERNANCE STATE (sovereignty tier,
# and whether capability entitlement is ENFORCED or the deployment is running UNGOVERNED)
python3 -m framework.v2 status

# authorize + scaffold an engagement from any URL you own (see step-by-step below)
python3 -m framework.v2 intake authorize https://your-app.example.com --operator you
python3 -m framework.v2 intake run       https://your-app.example.com
#   → writes targets/<slug>/charter.draft.md, threat-model.md, attack-tree.md, recon/fingerprint.json
#   → you review charter.draft.md and save it as charter.md with your signature line;
#     until a signed charter.md exists, ALL active testing is refused.

# loopback-only quick scan of a local app, with a grounded export
python3 -m framework.v2 scan http://127.0.0.1:8080/ --format json --strict-evidence

# the authorized, fully-gated end-to-end engagement against a signed, in-scope target
python3 -m framework.v2 engage <slug> https://your-app.example.com/ --recon --spine

# re-verify a saved report offline — re-runs every retained oracle certificate, no target needed
python3 -m framework.v2 verify report.json
```

**Dependencies are deliberately lean:** `pydantic`, `httpx`/`requests`, `structlog`, `PyYAML`,
`beautifulsoup4`, `Jinja2`, and `cryptography` (for Ed25519 signatures). No numpy, no SMT solver, no
browser‑automation library — the dynamic‑browser driver is stdlib plus a native WebSocket client.
**The engine ships in "DryRun" mode by default:** the scanner and oracles need no LLM at all, and the
reasoning kernel falls back to deterministic fixtures when no LLM backend is reachable, so everything
runs offline (with reasoning quality bounded accordingly).

---

## 8. The CLI surface

The dispatch table in `framework/v2/__main__.py` **is** the contract — all **25** subcommands appear
there and each delegates to its own arg parser. (Because the top‑level dispatcher owns `-h/--help`,
read a subcommand's flags from its module, not `<sub> --help`; the tables below are the flag surface.)

| Subcommand | What it does | Key verbs / flags |
|---|---|---|
| `status` | Environment summary: resolved paths, reachable LLM backends, and the **governance state** — sovereignty tier (and whether it's *sealed*) plus whether capability entitlement is *enforced* or the box is running *UNGOVERNED*. | — |
| `intake` | **UTI** — turn a URL into a scaffolded `targets/<slug>/`. Passive, SSRF‑guarded, ethics‑gated. | `run`, `authorize`, `fingerprint` |
| `scan` | **Loopback‑only** quick web scan with a grounded export. Refuses non‑loopback hosts (use `engage` for those). | `--format {text,json,sarif,html}`, `--strict-evidence`, `--targeted`, `--domxss`, `--browser-xss`, `--spa`, `--arsenal`, `--reverifiable-out`, `--progress-log`, `--bandit-file` |
| `engage` | **Authorized remote** end‑to‑end runner (the full data‑flow of §5.1). Every request passes the 6‑gate chain. | `--recon`, `--spine`, `--waf-adaptive`, `--grammar-fuzz N`, `--arsenal`, `--browser-xss`, `--spa`, `--domxss`, `--oob-relay-url`, `--no-chaining`, `--transfer-archetype NAME`, `--defender`, **`--autonomous`** / `--autonomous-cycles N` / `--autonomous-budget N`, request/page budgets |
| `verify` | Offline re‑verification of a saved report — re‑runs each finding's retained oracle certificate; exit 0 iff every one reproduces and matches its claim. | `<report.json>` |
| `evidence` | Build / sign / verify tamper‑evident evidence bundles. | `keygen`, `certify`, `verify` |
| `report` | Deterministically assemble the executive / technical / remediation reports from the blackboard (or a JSON doc), or **export** machine formats. | `<slug>`, `--from-json`, `--format {markdown,json,sarif}`, `--only`, `--stdout`, `--out` |
| `collaborator` | Run the self‑hostable out‑of‑band (OOB) relay that unlocks blind‑class confirmation on remote targets. | `serve` |
| `intel` | Run OSINT into the shared world‑model. Offline by default; live sources are a gated opt‑in. | `ingest [--live]`, `ingest-cloud`, `ingest-sbom`, `resolve`, `plan`, `predict`, `timeline`, `delta`, `yield` |
| `imports` | Import a third‑party tool export (Nuclei / ZAP / Burp / sqlmap / generic) as **provenance‑tagged leads** the oracles later re‑verify. Dry by default; `--persist` writes them to the intel store. | `<file>`, `--format`, `--source-tool`, `--slug`, `--persist` |
| `memory` | Query the cross‑engagement memory / priors (MLS). | `status`, `seed`, `similar`, `wins`, `payloads`, `priors`, `postmortem` |
| `kernel` | Invoke one cognitive binding as a typed callable. | `hypothesize`, `critique`, `pivot`, `decide`, `opsec`, `threat-model`, `backend` |
| `benchmark` | Precision/recall benchmark; `make gate` uses this as a regression gate. | `--gate`, `--update-baseline`, `--corpus`, `--no-incumbents` |
| `eval` | Score / regression‑check runs against the benchmark corpus. | `score`, `regress`, `show` |
| `authority` | Kill‑switch + engagement‑authority control. | `status`, `halt --reason`, `clear --by`, `authorize` |
| `entitlement` | Capability‑entitlement status / verification. | `status`, `capabilities`, `verify` |
| `capabilities` | Enumerate CRUCIBLE's **unified capability catalog** (CLI subcommands, sensors, oracles, tools) — read‑only, deterministic; the machine‑readable surface an MCP/API/SDK consumer discovers. | `--json`, `--kind`, `--no-commands` |
| `improve` | **SIL** — *authorise* (never apply) a self‑improvement proposal. | `review`, `horizon`, `show` |
| `analysis` | **DAA** — offline static / taint analysis + an autonomous source‑review loop. | `scan`, `index`, `analyzers`, `review` |
| `defender` | **DEL** — purple‑team detection modeling / self‑detection scoring. | `score`, `annotate`, `rules` |
| `socialdefense` | Score an inbound message for phishing / social‑engineering indicators. | `assess` |
| `console` | Read‑only, loopback‑only operator UI (live progress; safe actions only). | `--open` |
| `api` | **Loopback, gated external API** — a read core (enumerate/read the run) plus gated actions through the *same* fail‑closed chain as a local action. Optional bearer / `X-Relay-Key` auth. | `--port`, `--host` (loopback only) |
| `mcp` | **MCP tool‑server seam** — EXPOSE CRUCIBLE's charter‑bound gated capabilities as MCP tools, or CONSUME external MCP tools. | `serve --slug`, `list --slug` |
| `aegis` | **AEGIS** — the *defensive* dual: prove‑don't‑guess AI‑attack detection over one telemetry envelope (see §9.18). Lazy‑imported; never on the scan/engage path. | `detect <envelope.json>`, `demo` |

---

## 9. Subsystem reference (what · why · how · data · wiring)

Every subsystem below is **shipped code** in `framework/v2/`. Where a component is a built primitive
or a schedulable agent that is **not** part of the default `scan`/`engage` loop, it is flagged
`[opt‑in]` or `[built, not default‑wired]`. That distinction is deliberate honesty, not a caveat you
can ignore — it tells you exactly what runs when you press go.

### 9.1 The event spine — the shared nervous system (`agents/blackboard.py`)

**What it is.** An **append‑only, typed, sequence‑clocked, provenance‑linked SQLite event log**: the
single stream through which every subsystem can communicate. Think of it as an immutable ledger of
everything that happened during an engagement.

**Why it exists.** For findings to be auditable and replayable, the system needs a single, ordered,
tamper‑evident record of what it observed, hypothesized, did, and concluded — one that no subsystem
can quietly rewrite. Historically the flagship scanner and the multi‑agent orchestrator were separate
worlds; the spine unifies them into one replayable stream.

**How it works.**
- **Event kinds** (each with a validated payload schema): the eight core kinds `observation`,
  `hypothesis`, `plan`, `action`, `result`, `finding`, `critique`, `decision`, plus four
  nervous‑system kinds `reward`, `critic_verdict`, `reflection`, `refusal`. Oracle authority is
  encoded in the *type system*: a `critic_verdict` can only be `endorse | object | abstain`; a
  `finding`'s status reserves `confirmed` for a fired oracle.
- **Writes go only through `post()` and `supersede()`** (an "edit" is a new row that references the
  old one — history is never mutated). SQL triggers actively `RAISE(FAIL)` on any UPDATE or DELETE.
- **Reads and replay** use `read(...)` and `replay(engagement, since_id=…)`, the latter a durable
  cursor a consumer polls for new events. Any full‑set read **pages** through the log and **fails
  closed** on a truncated read (so a partial read can never be mistaken for the whole history).
- **Cryptographic tamper‑evidence** (`agents/spine_chain.py`): events are **hash‑linked** (each event's
  digest chains to the previous), and the chain is anchored by a **governance‑signed head**. The
  digest deliberately *excludes the wall‑clock* (so replay is byte‑stable) and *binds the engagement
  slug* (so a head from one engagement cannot be replayed onto another). A verifier rebuilds the chain
  from the live log and fails on any altered, reordered, deleted, or appended‑after‑signing event.

**Data in/out.** In: typed events from any subsystem. Out: an ordered, replayable, verifiable stream.

**How it wires in.** With `engage --spine`, the runner mirrors the whole engagement onto the spine via
a best‑effort "sink" (`agents/spine_sink.py`) — phases, findings (each tagged with its live grounding
verdict), refusals, per‑finding rewards, and a summary decision. "Best‑effort" is load‑bearing: a
spine write can *never* perturb a run, so telemetry failures can't sink an engagement. The spine is
also what the reflection agent reads to detect stalls, and what the reporter and evidence layers walk
to bind claims to proofs.

### 9.2 The oracle / verification layer — the confirmation authority (`verify/`)

**What it is.** The set of **deterministic proof programs** that decide whether a finding is real, plus
the machinery to route, combine, and re‑run them.

**Why it exists.** This is the embodiment of prove‑don't‑guess (§1, §3). It is the only place a claim
becomes a fact.

**How it works.** The `OracleKind` enum holds **19 kinds** in all — **15 offensive** and **4
defensive** (the AEGIS classes, §9.18). Of the offensive kinds, the **11 web/injection oracles**
below are the confirmation authority for `scan`/`engage`; the other four (`SERVICE_REACHABILITY`,
`TLS_WEAKNESS`, `VERSION_RANGE`, `POLICY_PATH`) confirm *sensor‑produced* facts (§9.16). Every kind
shares this one routing / combination / re‑execution machinery. The 11 below are backed by **12
oracle *functions*** (`ACHIEVED_STATE` is served by two — a state‑matcher and a declarative predicate
evaluator). Each takes *already‑collected* observations and returns a signal with a calibrated
confidence:

| Oracle kind | Fires when… | Typical bug class |
|---|---|---|
| `DIFFERENTIAL_RESPONSE` | baseline vs. mutated responses diverge across status / length / lexical / **structural** (JSON‑pointer set or HTML tag‑path multiset — invariant to nonce/CSRF noise) / latency / marker | boolean/blind divergence |
| `BOOLEAN_INFERENCE` | a **Wald SPRT** over repeated true/false probe pairs crosses the accept boundary (with a dynamic‑page control) | boolean‑blind SQLi/NoSQLi |
| `TIMING` | a Mann‑Whitney U test **and** a Hodges‑Lehmann median shift **and** (optionally) a dose‑response trend all agree | time‑based blind injection |
| `ERROR_SIGNATURE` | a distinctive datastore/parser error string the payload provoked, absent from a benign control | error‑based injection |
| `EVALUATION` | an injected expression was server‑side **evaluated** (its computed value is present, the literal template text absent) | SSTI / expression‑language |
| `REFLECTION_CONTEXT` | a unique marker landed in an **executable** HTML/JS position (a tag name, inside `<script>`, an `on*` handler, a `javascript:` URI) | reflected XSS |
| `DOM_EXECUTION` | injected JavaScript **actually executed** in a real browser DOM, proven via a CDP callback carrying a unique canary | DOM‑XSS |
| `SIDE_EFFECT` | a unique attacker‑chosen marker reached a sink it should never reach | stored XSS / path‑traversal canary |
| `OOB_CALLBACK` | an out‑of‑band receiver logged an inbound interaction keyed to a per‑finding token | blind SSRF / XXE / OOB SQLi |
| `SANITIZER_SIGNAL` | ASAN/MSAN/TSAN/UBSAN/stack‑smash/panic/SIGSEGV appears in captured process output | memory‑safety / crash |
| `ACHIEVED_STATE` | every attacker‑predicted key/value appears in the observed state, **or** a declarative JSON predicate over the response is satisfied | IDOR / BOLA / auth‑bypass / exposure |

- **Firing and combination.** An oracle "fires" when its signal reaches a calibrated confidence. Within
  an oracle, multiple corroborating dimensions combine by **noisy‑OR** — `1 − Π(1 − wᵢ)`, capped at
  0.99 — so independent evidence adds up, no single weak dimension dominates, and the result is never a
  false certainty of 1.0.
- **The gate** (`OracleVerifier.confirm`): a finding's `bug_class` selects the applicable oracles via
  the `BUG_CLASS_ORACLES` routing table (≈45 canonical classes → the oracle kinds that can prove each,
  e.g. `boolean_sqli → (BOOLEAN_INFERENCE, DIFFERENTIAL_RESPONSE)`, `ssrf → (OOB_CALLBACK,)`,
  `idor → (ACHIEVED_STATE,)`). Each applicable oracle runs; `confirmed = any signal fired at ≥ 0.70`
  (`HIGH_CONFIDENCE`). A non‑firing oracle is recorded as **dissent, never a veto** — one honest proof
  is enough, and an absent input is a non‑firing signal, *never* an assumed pass.
- **Value‑membership (an anti‑hallucination guard).** An out‑of‑vocabulary `bug_class` is rejected *at
  parse time*, so a fabricated class from a structured LLM output cannot ride into an oracle‑provable
  field.
- **The certificate.** A confirmed finding embeds its full `FindingContext` as `oracle_context`. Because
  oracles are pure, that context is a **re‑runnable certificate**: `verify/reverify.py` (the `verify`
  command) re‑fires each stored oracle **with no target**, and refuses to re‑confirm a *relabelled*
  certificate (SQLi evidence cannot be re‑stamped as RCE). Exit 0 iff every certificate reproduces and
  matches its claim.
- **The negative control.** `verify/confirmation.py` proves the authority does *not* rubber‑stamp:
  pointed at a deliberately vulnerable handler it confirms; pointed at the *parameterized twin* (same
  shape, no bug) it returns `None`.
- **Out‑of‑band confirmation.** Blind classes (SSRF, blind XXE, OOB SQLi, blind command injection)
  confirm on an *inbound* interaction against a per‑finding token. `verify/oob.py` binds a loopback
  receiver for co‑resident targets; for genuinely remote targets, `collaborator serve` runs a
  **self‑hostable relay you own** with an authenticated poll endpoint (constant‑time key comparison,
  HTTPS required off‑loopback). The relay host must be on the charter allowlist or `engage` refuses it.

**Data in/out.** In: a `FindingContext` of observed responses/state. Out: a `VerificationResult`
(confirmed? which signals fired? combined confidence?) and, for confirmations, a certificate.

**How it wires in.** The scanner's audit engine hands every observed probe result to this layer; the
veracity firewall re‑invokes it; the reporter re‑invokes it at render time; the `verify` command
re‑invokes it offline. It is the hub every "is this real?" question routes through.

### 9.3 The unified Bayesian world‑model (`worldmodel/`)

**What it is.** One directed, typed multigraph of everything observed or inferred about a target —
spanning **web, identity, and cloud** surfaces (plus OSINT/asset kinds) under a single schema.

**Why it exists.** Attack paths cross surfaces: an exposed endpoint leaks a credential that is valid on
a principal that can assume a cloud role that fronts a datastore. To reason about such a path you need
*one* model where a web finding and a cloud grant live in the same graph — and where every fact carries
a probability and a provenance so a path is explainable, not an oracle's say‑so.

**How it works.**
- **Node kinds:** `HOST, SERVICE, ENDPOINT, WEBAPP, DATASTORE, CLOUD_RESOURCE, NETWORK_SEGMENT,
  PRINCIPAL, CREDENTIAL, SESSION, CONTROL, FINDING` (the attack surface) plus `DOMAIN, CERTIFICATE, ASN,
  NETBLOCK, ORGANIZATION, IDENTITY, APPLICATION, PACKAGE` (OSINT/asset).
- **Edge kinds:** reachability/trust/grant/assume/valid‑on/authenticates‑to/session/control/evidences;
  attacker‑state `OWNS / HOLDS / REACHED`; and asset edges `RESOLVES_TO, PRESENTS_CERT, ANNOUNCES, HOSTS,
  RUNS, ASSET_OWNS, SAME_AS`. (`ASSET_OWNS` is *deliberately distinct* from attacker `OWNS`, so no rule
  ever hallucinates attacker reach from mere ownership.)
- **Beta beliefs + provenance.** Every node and edge carries a `Beta(α,β)` probability distribution, a
  scalar confidence, and a **non‑empty provenance string** pointing back to what asserted it.
  `belief_mean = α/(α+β)` is the current belief; `belief_lcb = mean − z·sd` is the *evidence‑discounted
  lower bound*, so a thinly‑supported high‑mean belief scores *below* a well‑proven one.
- **The refutation channel.** A belief is not a max‑confidence scalar; it is a distribution that a
  *contradicting* observation can move down. A low‑confidence re‑observation lowers `belief_mean`; an
  entity is **net‑refuted** when `mean < 0.35` or `lcb < 0.20`. This is what lets the system *unlearn*
  a fact it later contradicts — something a scalar cannot express.
- **Determinism.** Time is a caller‑supplied monotonic sequence integer; the graph never reads a clock.
  Belief updates are **commutative**, so replaying the same observations in any order yields the same
  belief — essential for offline replay and calibration audits.
- **Grounding tiers.** Provenance classifies into `GROUNDED` (`oracle:` / `cert:` / `finding:`), `INTEL`
  (`intel:` / `derived:` / `scan:`), or `UNGROUNDED` (`llm` / `assume` / `guess`) — a single source of
  truth the veracity firewall reuses.
- **Attack‑path search** (`worldmodel/pathsearch.py`): Yen's *k*‑shortest simple paths, best paths to
  crown‑jewel node kinds, and BloodHound‑style choke‑points. A path's success belief is the **product of
  its edge belief means**; `min_confidence` is the weakest‑link bound; `belief_lcb` is the conservative
  bound. An `edge_kinds` filter scopes the *attack* subgraph apart from the *intel* subgraph.
- **Attacker state as first‑class facts** (`worldmodel/attacker.py`): a canonical attacker principal
  whose `OWNS/HOLDS/REACHED` out‑edges *are* its state — persistent and chainable across steps.
- **Business impact** (`worldmodel/impact.py`): per‑node criticality (from an optional
  `targets/<slug>/impact.yaml`, degrading to uniform) ranks choke‑points by the crown‑jewel value they
  alone sever, and answers counterfactual "what if we remediate X?" questions with pure reasoning (no
  traffic).
- **Forward chaining** (`worldmodel/derivation.py`): a Datalog‑style, monotone, terminating rule engine.
  A rule may never invent a node, and a derived fact's confidence is the *product* of its matched
  premises — so derivation cannot manufacture certainty.

**Data in/out.** In: observations from the scanner, the intel engine, and file‑ingest adapters. Out: a
queryable graph and ranked attack paths with explainable, provenance‑backed beliefs.

**How it wires in.** The scanner projects confirmed findings and endpoints into it; the intel engine
projects OSINT observations into it; the knowledge operators saturate over it to build attack paths; the
veracity firewall reads its net‑refutation status to catch contradicted claims; the SCE and impact model
reason over it. It is the single shared substrate the whole reasoning core operates on.

### 9.4 The veracity (anti‑hallucination) firewall (`veracity/`)

**What it is.** A choke point that admits or demotes claims by **re‑executing their cited proof.** Its
one guarantee: it can only ever **demote or abstain** — it can turn a fabricated "confirmed" into
`UNGROUNDED`, but it can *never* promote a claim the oracle refused.

**Why it exists.** Even with an oracle layer, a hallucinated "fact" could sneak into a report, a
world‑model write, or a downstream claim if anything ever *trusted a recorded verdict.* The firewall's
principle is: **trust nothing that is merely written down; trust only what re‑executes now.**

**How it works.** `firewall.admit(claim)` decides in this order:
1. **Contradiction** — if any entity the claim names sits at *net‑refuted* belief in the world‑model →
   `CONTRADICTED`.
2. **Fabricated entity** — if the claim references a graph entity that does not exist → `UNGROUNDED`.
3. **Re‑execute each grounding token, bound to the claim's subject**, keeping the strongest that
   resolves. FACT strength, strongest to weakest:
   - **ORACLE** — the token's retained `oracle_context` re‑fires **for the claim's own bug_class** (a
     SQLi proof cannot ground an RCE claim); the confidence becomes the *re‑executed* value.
   - **CERT** — a signed evidence certificate validates and its bug_class matches.
   - **WORLDMODEL** — the named node exists, has `belief_lcb ≥ 0.5`, *and* its provenance classifies as
     grounded (mere collected intel or a derivation does **not** reach fact strength).
   - **HYPOTHESIS** — a gated, capped prediction: explicitly *not a fact*, a labelled guess.

A claim marked `from_dryrun` keeps only re‑executable proof, never its own LLM reasoning. Anything that
fails to ground is *not dropped* — it is relabelled `analyst‑commentary` so nothing is silently hidden.

**Data in/out.** In: a claim plus the world‑model. Out: an `AdmittedClaim` verdict —
`GROUNDED (fact) / UNGROUNDED / CONTRADICTED` — with the re‑executed confidence and how to render it.

**How it wires in.** In the default `engage` loop it runs live over every confirmed finding (the "P3"
pass in §5.1 step 10): a shipped "active" finding whose proof no longer reproduces surfaces as *not a
fact*. It is also the gate the evidence layer uses to check that each fact‑bound report sentence still
grounds, and the mechanism by which third‑party tool attestations (Nuclei/Burp/…) get promoted to facts
only when a CRUCIBLE oracle re‑verifies them.

### 9.5 The scanner / audit engine and the intruder (`scanner/` + `intruder/`)

**What it is.** The "hands" — a zero‑manual scanner that crawls a target, attacks every insertion point,
and confirms via oracles; plus an autonomous fuzzer (`intruder/`) modeled on Burp Intruder.

**Why it exists.** Something has to actually *issue the traffic* and collect the observations the oracles
judge. This is that something — and it is built so it can never emit a finding the oracle didn't confirm.

**How it works.**
- **`WebScanCampaign`** (`scanner/campaign.py`) — the one‑call autonomous scan orchestrating the §5.1
  flow: crawl → passive analysis → fingerprint → resolve the bandit → build the audit surface → audit
  under one shared request budget → `ScanReport`. The injected `send` differs by entrypoint: a plain
  loopback client for `scan`, the fully‑gated executor for `engage` — so the safety cage is *the same
  campaign, different plumbing*. After a run it can `populate_worldmodel()` to project endpoints and
  findings.
- **`AuditEngine`** (`scanner/engine.py`) — enumerates every **insertion point** (query value/name, body
  form value/name, cookie, header, JSON leaf/key, whole body, URL path segment), fires each applicable
  check, and hands every observed response to the oracle layer. A finding is emitted **only when a real
  oracle fires**, carrying its certificate.
- **The default arsenal** (both `scan` and `engage`): 11 built‑in checks + 5 request‑level checks
  (CORS, Host‑header, JWT `alg:none`, GraphQL introspection, GraphQL field suggestions), plus static
  DOM‑XSS *candidate* detection — all oracle‑adjudicated.
- **The data‑driven check library** (`scanner/library.py` + `scanner/library_entries/*.json`) — **172
  checks expressed as DATA**, not code. Each entry carries a payload, an `applies_when` fingerprint
  predicate, its insertion kinds, and an oracle spec; loading *validates every file* (a typo, a bad
  predicate, or a duplicate id is a **load‑time error**, never a silent no‑op). Distribution by class:
  boolean_sqli 21, exposure 20, xss 18, command_injection 17, deserialization 14, ssrf 13,
  ssti 11, time_based_sqli 11, blind_xxe 10, error_based_sqli 8, path_traversal 7, and more. Built‑in and
  library checks are adjudicated by the *same* oracles, so precision is identical. `[The library is
  exercised under the eval/benchmark harness (use_library=True); the default interactive scan/engage
  arsenal is the 11 + 5 built‑in checks above.]`
- **Self‑learning order** (`scanner/learning.py`) — a Thompson‑sampling **contextual bandit** keeps a
  Beta posterior per (archetype, check) and samples an order each run; it is persistable/warm‑startable
  (`--bandit-file`). It **orders effort; it never gates** — a low‑posterior check is tried last, not
  dropped, so *coverage is invariant to what the bandit has learned.* ("Bandit" = a reinforcement‑
  learning algorithm that balances exploiting known‑good options against exploring others.)
- **Fingerprinting** (`scanner/fingerprint.py`) — pure, deterministic, stdlib‑only classification of the
  crawl into a token set (server/language/framework/CMS/CDN/WAF) that check selection gates on.
- **The dynamic (browser) stack.** DOM‑XSS is confirmed by *execution*, not reflection. `scanner/cdp.py`
  is a stdlib Chrome DevTools Protocol driver (over a native WebSocket client — no third‑party automation
  dependency) that launches headless Chromium and registers a callback binding *only it* could have
  registered; the browser‑XSS pass injects payloads that, if they execute, call that binding with a
  unique canary → the `DOM_EXECUTION` oracle fires on genuine JS execution. The same driver powers the
  `--spa` crawler, which recovers `fetch`/XHR endpoints a static crawl can't see. `[--browser-xss / --spa
  are exposed on `scan` (loopback); on `engage` the remote browser is confined to the in‑scope host at
  the resolver layer.]`
- **Forward‑reasoning orchestrator** (`scanner/orchestrator.py`, on by default in `engage`) — projects
  confirmed findings into the world‑model, saturates the attack‑graph operators, extracts
  attacker→crown‑jewel paths, ranks them by detection cost, and anneals a stealthiest‑valuable subset
  within a detection budget.
- **Stealth as *accounting*, not evasion** (`scanner/detection_cost.py`) — scores how *loud* each
  technique/path is (noisy‑OR over the detection tells it would trip) so graph search can *prefer*
  quieter edges. It **ranks; it never bypasses a detector.** This is a deliberate line (see §10).
- **The specialized arsenal** `[built, unit‑tested, not in any default loop — reachable via the public
  API/flags]`: HTTP request smuggling (timing‑oracle‑confirmed CL.TE/TE.CL), HTTP race conditions (raw‑
  socket single‑packet barrier), cross‑site WebSocket hijack + message injection, content discovery,
  token/nonce randomness analysis, authenticated sessions, WAF‑evasion via a fixed ladder then a seeded
  genetic algorithm that must *still fire the same oracle*, probabilistic request‑grammar fuzzing
  (`--grammar-fuzz`), constraint/filter inference, post‑quantum/TLS crypto‑posture (`pqc_scan`), and
  eval‑gated check synthesis (*propose, never self‑apply*).
- **The opt‑in coverage packs** `[built, unit‑tested, off the default loop — opt‑in per campaign]`, each
  confirmed by the *same* oracle layer (a lead stays a lead until an oracle fires): **GraphQL** DoS
  breadth (`scanner/graphql.py` — unbounded query *depth*, alias overloading, request batching, missing
  cost limits, probed *minimally* — one bounded query each, never a flood), **business logic**
  (`scanner/bizlogic.py` — drives an operator‑declared workflow state‑machine and reads the illegitimate
  *post‑state* back, adjudicated by the achieved‑state predicate oracle — the one high‑yield class a
  payload library cannot reach), **SSO / SAML / OIDC** (`scanner/sso.py` — forges/tampers an assertion or
  `id_token` and observes *acceptance* vs. a rejected control; softer gaps like a missing `state`/`nonce`
  stay leads), the **access‑control pack** (`scanner/access_control.py` — a two‑identity IDOR/BOLA/BFLA
  cross‑read; **not** in `DEFAULT_CHECKS` because it structurally needs a second authenticated identity +
  operator‑supplied object references), a **Nuclei‑template compiler** (`scanner/nuclei_compile.py` —
  compiles a supported subset of a Nuclei YAML template into a native library entry whose match a CRUCIBLE
  oracle *re‑verifies*, no nuclei binary needed), and **passive client‑side** tells (`scanner/passive.py` —
  `postMessage` wildcard target / listener with no origin check, an anti‑CSRF‑token‑absent form, a framable
  sensitive page — read from collected bytes, sends nothing).
- **`intruder/`** — an autonomous Burp‑Intruder: attack types SNIPER / BATTERING_RAM / PITCHFORK /
  CLUSTER_BOMB, a lazy deterministic payload vocabulary, a Burp‑style payload‑processing pipeline, and
  robust‑statistics (median + median‑absolute‑deviation) outlier detection that replaces a human
  eyeballing the results table. `[built, not default‑wired]`
- **Reporting** (`scanner/report.py`) — renders `ScanReport` to `json` / **SARIF 2.1.0** (the standard
  static‑analysis interchange format, so findings drop into code‑scanning dashboards) / `html`, flags
  oracle‑confirmed findings `re_verifiable`, and — with `--strict-evidence` — *withholds* any finding
  that does not re‑ground as a fact at render time.

**Data in/out.** In: a seed URL + budgets. Out: a `ScanReport` of oracle‑confirmed findings (each with a
certificate), passive findings, discovered endpoints, and the fingerprint.

**How it wires in.** It is the primary sensor: it feeds the world‑model, the veracity firewall, the SCE,
and the spine. Under `engage` its `send` *is* the gated executor, so every probe it issues is
safety‑checked.

### 9.6 The Scientific Confidence Engine (SCE) (`confidence/`)

**What it is.** A layer that turns a *confirmed* finding into a competing‑hypothesis Bayesian assessment
— *how* confident that confirmation leaves us, and what would most decisively settle any residual doubt.

**Why it exists.** An oracle fires or it doesn't, but two confirmations are not equally strong: a
replayable certificate over clean differentials is stronger evidence than a single borderline signal.
Operators need calibrated confidence and a next‑best test, *without* the confidence math ever being able
to override the oracle.

**How it works** (`confidence/decision.py::assess_finding`). It builds a **focal** hypothesis ("this is a
real, exploitable bug") plus a **MECE** set of benign alternatives (mutually exclusive, collectively
exhaustive — e.g. for XSS: "reflected but properly escaped"; for SQLi: "an error page, not injectable";
for SSRF: "the app fetched but reached nothing"). It scores each hypothesis by **weight‑of‑evidence** —
log‑likelihood‑ratios per confirmation method, where a replayable certificate boosts the focal — then
normalizes via log‑sum‑exp into a posterior distribution with a Beta **credible interval**. It ranks the
single most decisive next test by **expected information gain**. A downstream gate consumes the structured
result (`reaches_target`, posterior) — never a bare scalar — so an oracle‑confirmed finding with a
replayable cert earns strong evidence, while a merely passive signal keeps its benign alternatives alive.

**Data in/out.** In: a confirmed `AuditFinding`. Out: a posterior, a credible interval, and the
most‑decisive next experiment.

**How it wires in.** Runs per confirmed finding in the default `engage` loop (index‑aligned with the
active findings); it is *pure reasoning over the oracle's verdicts* and best‑effort, so it can never sink
an engagement.

### 9.7 The learning / calibration core (`calibration/`)

**What it is.** The machinery that lets CRUCIBLE *improve* from outcomes — order effort better, keep its
confidence numbers honest, and report coverage guarantees — **without ever letting learning corrupt the
oracle's authority.**

**Why it exists.** A tool that runs many engagements should get better at *where to spend effort* and
should *know how well‑calibrated its own confidence is.* But naive learning is a trap: if the system
labeled its own findings and then trained on those labels, it would reinforce its own mistakes (a
"circular" loop). The whole design is built to avoid that.

**How it works.**
- **Non‑circular labels** (`reward_bus.py`). The single source of an outcome label, `outcome_label`,
  returns `EXPLOITABLE` **only** when an oracle fired **and ≥ 2 distinct corroborating oracle kinds**
  agree. Critically, a *silent* oracle is **never** auto‑labelled a false positive — that would be an
  oracle judging itself. So the label that trains the learner comes from *independent cross‑oracle
  corroboration*, not from the system's own confidence. `credit_outcome` then fans one confirmed outcome
  to four independent sinks — the bandit (check productivity), the calibration ledger (the non‑circular
  label), memory priors, and a spine `reward` event. `[The full credit_outcome fan‑out is opt‑in — no
  default caller; the default engage loop emits the per‑finding spine reward directly.]`
- **The outcome ledger + isotonic calibration** (`ledger.py`, `calibrate.py`). The ledger is an
  append‑only, sequence‑ordered log of (predicted‑confidence, actual‑outcome) pairs. A **Pool‑Adjacent‑
  Violators (PAV) isotonic regression** (pure Python) learns a monotone mapping from predicted to
  empirically‑observed probability — with an *honest identity passthrough* below a label floor
  (`MIN_LABELS = 8`), a learned oracle prior, and a hard cap `MAX_PROB = 0.999` (never 1.0). It reports
  Brier score and Expected Calibration Error (ECE).
- **Conformal coverage bands** (`conformal.py`). Split‑conformal prediction produces intervals with a
  *coverage guarantee* — but with an **honest fallback**: below the label floor it returns the Bayesian
  credible interval marked `coverage_guaranteed = False`, so it never promises a coverage guarantee it
  can't back.
- **Learning about learning** (`meta_monitor.py`). `assess_learner_health` reports label count, ECE,
  Brier, and realized coverage, and recommends **only more caution** (gather more evidence, trust
  confidence less). It **never gates a surface and never promotes a finding.** `rank_by_policy`
  generalizes the bandit's learned value to *order* (never drop) decisions. `[opt‑in — no default caller]`

**Data in/out.** In: confirmed/refuted outcomes and predicted confidences. Out: a better effort ordering,
calibrated confidences, honest coverage bands, and health diagnostics.

**How it wires in.** The bandit is consulted by the scanner to order checks; the ledger/calibrator/
conformal are the confidence pipeline; the meta‑monitor is a caution advisor. Everything here **orders,
calibrates, or cautions — it never confirms, promotes, or gates a surface.**

### 9.8 The nervous system: critics, reflection, refusal, credit (`agents/`)

**What it is.** A set of deterministic cognition primitives that make the metacognition doctrine (§3)
*mechanical* — adversarial self‑critique, honest refusal, in‑loop reflection, and temporal credit.

**Why it exists.** "Submit to the critics," "refuse honestly," and "reflect in the loop" are doctrine; the
nervous system turns them into code that runs against the event spine — while preserving oracle authority
(none of these can confirm anything).

**How it works.**
- **Multi‑critic panel** (`agents/critics.py`) — differentiated deterministic critics: a *grounding*
  critic re‑fires the finding's own oracle; a *provenance* critic flags anything marked "verified" with no
  certificate; a *calibration* critic flags impossible confidences. `aggregate_panel` is **demote‑only**:
  a major objection stands, high disagreement → abstain, otherwise the modal verdict — and it can output
  `endorse | object | abstain`, **never** `confirm`.
- **Reflection** (`agents/reflection.py`) — scans the spine for dead threads and stalls and posts
  re‑orienting `reflection` events that **re‑rank or defer** work but, per the coverage doctrine, **never
  skip** an authorized surface.
- **Cognitive refusal** (`agents/cognitive_refusal.py`) — `epistemic_refusal` refuses to *conclude* a
  finding that claims oracle verification but will not re‑ground, recording the refusal as evidence.
- **Temporal credit** (`agents/spine_credit.py`) — walks the provenance DAG backward from a confirmed
  finding, crediting the decisions and hypotheses that led to it (so learning can reward the *reasoning*
  that paid off, not just the final step).
- **The MAO coordinator + specialist agents** (`agents/coordinator.py`) — an alternative orchestration
  where six specialist agents (recon, hypothesis, exploit, critique, reporter, memory) post typed events
  and a coordinator schedules them, refusing to quiesce while any finding is unreviewed. The critique
  agent is the mandatory oracle‑authoritative gate; the reporter **re‑executes each finding's oracle at
  report time** and demotes any that no longer fires.

**Wiring status (honest).** In the default `engage --spine` loop *today*: the spine mirror of
findings/refusals, the per‑finding spine `reward` event, and the veracity firewall over findings. The
**ACP goal‑tree planner** and the advisory **kernel reasoning** step now run under `engage --autonomous`
(§9.17) — but *only* there; the default loop does not drive them. The multi‑critic panel, the reflection
agent, cognitive refusal, the `credit_outcome` fan‑out, the meta‑monitor, and the MAO coordinator remain
**additive primitives / schedulable agents you opt into** — unit‑tested and addable to a coordinator, but
not scheduled in the default `engage --spine` loop. Their *doctrine* is nonetheless already live in every
reasoning call, because it is injected into every LLM prompt (§9.11).

### 9.9 Memory and priors (MLS) (`memory/`)

**What it is.** The **Memory & Learning Substrate** — a SQLite + embeddings store of every engagement,
finding, hypothesis, payload, and dead end, plus the priors that bias future runs.

**Why it exists.** Each engagement should make the *next* one smarter: which payloads worked on this kind
of stack, which threads were dead ends, what an archetype tends to be vulnerable to. And it must do so
*with provenance* — a hallucinated prior would be a fatal bug.

**How it works.** Writes route through a write‑only recorder; every read carries provenance back to the
engagement that produced it. `recall.py` ranks past engagements by cosine similarity over embeddings
(default `LexicalEmbedder`, a deterministic 256‑dim feature‑hashing vectorizer — offline, no model
download; `sentence-transformers` is an optional upgrade for semantic neighbours). `priors.py` computes
Laplace‑smoothed success rates with Wilson confidence bounds so future runs lean toward what actually paid
off; `postmortem.py` folds a finished engagement's confirmed/refuted outcomes back into archetype priors.
**Fleet transfer** (`memory/fleet.py`, opt‑in via `fleet=`/`CRUCIBLE_FLEET`) goes one level up: it pools
priors and *de‑duplicated* calibration labels across many CRUCIBLE stores / portable shards into one view,
feeding the *same* similarity‑weighted, discounted, effective‑attempts‑gated transfer math — it only ever
*adds* recorded evidence, never invents a count, and an under‑evidenced blend is still withheld by the
existing honesty gate. Off by default = byte‑identical.

**Data in/out.** In: recorded engagement artifacts and outcomes. Out: similar past engagements, winning
payloads, and per‑archetype priors.

**How it wires in.** Intake seeds priors for a new target's archetype; the scanner's bandit and check
selection can be warm‑started from priors; `credit_outcome` writes outcomes back. It is the
cross‑engagement memory that makes the platform improve over time.

### 9.10 The intelligence / OSINT engine (`intel/`)

**What it is.** An engine that *reasons over* open‑source intelligence rather than just collecting it —
turning third‑party facts about a target's infrastructure into beliefs in the *same* world‑model the
scanner uses.

**Why it exists.** Recon that only produces a flat list of subdomains can't tell you "this host is Finance,
sits in this netblock, shares a registrant with that org, and presents a weak cert." Projecting recon into
the shared graph lets the reasoning core correlate infrastructure with findings.

**How it works.**
- **Collectors** (`intel/collectors/`) — four passive sources, **none of which touch the target**: DNS
  (A/AAAA/CNAME), Certificate Transparency (enumerative, via crt.sh), RDAP/WHOIS (registrant/org
  ownership), and ASN/BGP (routing origin). Each mints a typed `Observation` carrying an Admiralty
  source‑reliability grade, a *polarity* (a high‑confidence observation can *refute*, driving belief
  down), and a monotonic sequence.
- **The projection keystone** (`intel/project.py`). This one seam is what makes it "reason, not collect."
  `project_observation` computes an **effective confidence** `c_eff = clamp(0.5 + reliability · (truth −
  0.5))` — a perfectly reliable affirmation ≈ its raw confidence, a shaky source barely moves off 0.5 —
  then upserts the subject (and object, for an edge) into the world‑model at that confidence. The graph's
  Beta‑belief upsert then handles corroboration, refutation, and provenance *for free*: a re‑observed DNS
  record's `belief_mean` rises; a refuted one falls. The update is commutative, so replay is
  order‑independent. A separate adapter turns an Observation into a `confidence.Evidence` (a likelihood
  ratio weighted by reliability) so the SCE can reason over the same facts.
- **Gated egress** (`intel/transport.py`) — **offline by default** (a disabled transport raises on any
  fetch); a fixture transport replays captured data; a guarded HTTP transport is the *gated live* path —
  it requires a collector‑host allowlist that is *disjoint from the target scope* and enforces it per
  fetch. Live sources are a **code‑level opt‑in** (`intel ingest --live`), never a surprise flag.
- **Value‑of‑information recon planning** (`intel/planner.py`) — ranks (collector, subject) tasks by
  expected information gain per cost, using cross‑engagement source‑yield priors.
- **Entity resolution** (`intel/resolve.py`) — a Fellegi‑Sunter weighted union‑find over shared
  cert/host/CNAME/netblock signals, *fully explainable* (every merge cites its evidence), with an
  anti‑catastrophic‑merge fanout discount. Owners are *linked* by `ASSET_OWNS`, never merged in.
- **Gated prediction** (`intel/predict.py`) — sibling/neighbour hypotheses are emitted **gated**: never a
  graph fact, never auto‑scanned — a where‑to‑look‑next queue awaiting operator approval.
- **Temporal disappearance honesty** (`intel/temporal.py`) — "disappeared" is only asserted when an
  *enumerative* source is re‑run and set‑differenced; a point query's silence is `stale` (unknown), not
  "gone."
- **File‑ingest adapters** — cloud/IAM inventory (`from_cloud.py` → principals/resources/grants), SBOMs
  (`from_sbom.py` → packages/deps), and first‑party scan reports (`from_scan.py`).
- **Asset‑graph inference** (`intel/infer.py`) — *sound* derivation of transitive ownership, co‑hosting,
  and shared‑registrant links, emitting **only** asset‑tier edges (a structural guard forbids inventing
  attacker‑state), with fanout discounts so shared‑infra proxies attribute near‑zero.

**Data in/out.** In: a target domain (+ optional cloud/SBOM/scan files). Out: an asset inventory projected
into the world‑model, plus a gated prediction queue.

**How it wires in.** With `engage --recon` it runs alongside the scan, projecting onto the *same*
world‑model the findings chain over, so recon assets and confirmed findings share one graph. It sends
nothing to the target.

### 9.11 The reasoning kernel (URK) (`kernel/`)

**What it is.** The **Universal Reasoning Kernel** — it wraps each of OBSIDIAN's cognitive documents as a
*typed, validated callable* backed by an LLM, and it enforces the sovereignty and governance rules on
every model call.

**Why it exists.** The reasoning steps (hypothesize, critique, pivot, decide, opsec, threat‑model) need to
be *structured and validated*, not free‑form prose — and every LLM call needs to be *bounded by the
governance doctrine* and *routed to a permitted backend* for the operator's trust posture.

**How it works.**
- **Typed cognitive bindings.** `hypothesize`, `critique`, `pivot`, `decide`, `opsec`, `threat_model` take
  structured inputs, prompt an LLM, and return **Pydantic‑validated** results (with a call trace for
  audit). `hypothesize` returns *multiple* distinct falsifiable hypotheses; `critique` returns
  `confirm | objections | more_evidence_needed` (and is deliberately rigorous — it demands evidence
  proportional to the claim); `decide` returns a severity/CVSS/regulatory judgment; `opsec` gates a
  proposed action against the safety absolutes.
- **The governance preamble** (`kernel/binding.py`). The metacognition/oracle‑authority/critic/refusal/
  self‑consistency/learning doctrine is quoted **verbatim** into *every* LLM system prompt — bounded and
  cache‑stable. Untrusted, target‑derived text (a response body, a header) is isolated behind an
  unguessable, nonce‑derived delimiter with in‑place injection annotation, so a malicious target cannot
  smuggle instructions into the model's context.
- **Self‑consistency** (`kernel/consistency.py`). For **no‑oracle** judgments only (severity, impact,
  chain synthesis, threat‑model), it samples the model N times and measures agreement + semantic entropy;
  high disagreement → **ABSTAIN**, and the entropy is a confidence *penalty*, never a boost, and never
  enters the oracle or SCE path.
- **LLM backends** (`kernel/backends/`). `anthropic` (the Messages API; default model `claude-sonnet-4-6`;
  in‑backend backoff + a capped Retry‑After), `ollama` (a local daemon), and **`dryrun`** (always
  available — writes the fully rendered prompt to a `.dryrun/` file for audit and returns a deterministic
  per‑schema fixture, so the system works fully offline with bounded reasoning quality). Also present:
  Bedrock, Vertex, Mistral, a Claude‑Code subprocess backend, and an Anthropic zero‑data‑retention
  variant.
- **Sovereignty tiers** (`kernel/sovereignty.py`). Four tiers gate which backends may even be *constructed*
  — fail‑closed *before* any cloud SDK is imported: `AIR_GAPPED` (local only) → `SOVEREIGN_CLOUD` (adds
  regional Bedrock/Vertex/Mistral) → `TRUSTED_CLOUD` (adds Anthropic zero‑data‑retention) → `PERMISSIVE`
  (development default; adds plain consumer Anthropic/Claude Code). An unknown tier fails closed to
  `AIR_GAPPED`; a "sealed" latch pins the tier for the process lifetime (it can only tighten, never relax);
  in‑tier failover backs off on transient overload but never escapes the tier.

**Data in/out.** In: a structured reasoning request. Out: a validated, typed reasoning result — an
advisory input to the loop, never a confirmation.

**How it wires in.** OBSIDIAN and the engine call the bindings for the "propose" half of the loop; the
governance preamble means every one of those calls carries the prove‑don't‑guess doctrine; the sovereignty
tier keeps all of it inside the operator's trust boundary.

### 9.12 Knowledge: attack‑graph operators (`knowledge/`)

**What it is.** The library of **reasoning steps** over the world‑model — twelve STRIPS‑style technique
operators (6 seed + 6 extended) with typed pre/post‑conditions, standards references, and detection
signals.

**Why it exists.** Chaining findings into attack paths needs *rules*: "if the attacker has reached an
endpoint with an IDOR, they can read another user's object"; "if they captured a credential valid on a
principal, they can authenticate as it." Each operator encodes one such step declaratively.

**How it works.** Each operator (e.g. `unauth-endpoint-read`, `credential-reuse`, `ssrf-internal-reach`,
`deserialization-to-code-exec`, escalating through `credential-leak-capture`, `datastore-secret-
extraction`, `host-takeover`, `lateral-pivot`) states typed preconditions over the world‑model's own
node/edge kinds, the postconditions it establishes, the ATT&CK/CWE/CAPEC references, the observable
detection signals, and the `OracleKind` that would confirm it. Operators carry **no payloads** — they
describe *what must be true, what becomes true, and how a defender sees it*. `operators.py` saturates a
catalog to a fixpoint against the graph, deterministically.

**Data in/out.** In: the current world‑model. Out: newly derived attacker‑state edges (the raw material
for attack paths).

**How it wires in.** The scanner's orchestrator runs these to a fixpoint after projecting findings, and
`pathsearch` reads the resulting graph to enumerate attacker→crown‑jewel routes.

### 9.13 Signed evidence bundles (`evidence/`)

**What it is.** Tamper‑evident, independently verifiable evidence packages for findings and reports.

**Why it exists.** A finding you can re‑run is good; a finding wrapped in a *cryptographically signed*
bundle that *fails closed* on any tampering is what makes CRUCIBLE's output admissible as evidence.

**How it works.** An `EvidenceCertificate` is an authenticated wrapper over a finding's replayable
`oracle_context` (plus an artifact manifest and optional report claims); `SignedEvidence` adds m‑of‑n
Ed25519 signatures. `verify_certificate` checks **five independent layers, all of which must hold**:
authenticity (threshold signatures), binding (context‑digest match), artifact integrity (per‑file hashes,
path‑confined), reproduction (the oracle re‑fires), and claims‑grounded (each fact‑bound report sentence
re‑admits through the veracity firewall). `verify_bundle` binds the certificate set to the event‑spine
hash chain (no silent suppress / inject / reorder) and anchors everything to a governance‑signed head with
anti‑rollback — *all fail‑closed.* Domain‑separated signing bytes prevent cross‑protocol signature replay.
`[Signing is a provisioning step; the runtime path is verify‑only.]`

**How it wires in.** The reporter binds report sentences to certificates; the `evidence` and `verify`
commands produce and check bundles; the spine chain provides the anchoring.

### 9.14 The fail‑closed safety stack (the 6‑gate chain + authority + entitlement + sovereignty)

**What it is.** The cage that makes autonomy safe. Every target‑touching request under `engage` passes
**six load‑bearing gates, in this exact order, none bypassable without a code change**
(`agents/http_executor.py` — under `engage`, the scanner's injected `send` *is* this gated executor):

```
  every action
      │
      ▼
  1. AUTHORITY / KILL-SWITCH   Re-read the kill-switch file from disk EVERY action. A trip anywhere
      │                        (this CLI, another process, the console) halts the very next request.
      │                        Fail-closed: an ambiguous stat error reads as TRIPPED.
      ▼
  2. SCOPE GATE                The target host must be in the charter's in-scope list. Redirects are
      │                        re-gated PER HOP — an in-scope URL cannot bounce you to cloud metadata.
      ▼
  3. DESTRUCTIVE-CONFIRM       A destructive method/URL prompts the operator. DEFAULT-DENY on a timeout
      │                        or a non-interactive terminal — silence never authorizes destruction.
      ▼
  4. PER-ENGAGEMENT BUDGET     A hard ceiling on total requests for the whole engagement.
      │
      ▼
  5. POSTURE RATE-LIMIT        Pacing + jitter by posture: TEST (gentle) / AUDIT / EMULATE. Protects
      │                        production from a request storm.
      ▼
  6. EGRESS ALLOWLIST          When set, a sovereign transport refuses any non-allowlisted host BEFORE
      │                        bytes leave the box — the last line against exfil / off-scope pivots.
      ▼
   issue → archive request+response to evidence/ → structured (redacted) log event
```

**Why this order.** The cheapest, most absolute stops come first: the kill‑switch (a human's emergency
brake) before scope, scope before the expensive destructive prompt, budgets and pacing before egress.
Each gate RAISES and propagates; nothing swallows a refusal — and **a refusal is recorded as evidence,
not a crash.** The system preserves that it *chose not to act.*

**The supporting pieces:**
- **Kill‑switch** (`authority/killswitch.py`) — a file on disk, so a trip *survives a process restart*.
  `authority halt` stops the next request immediately; clearing it is a separate, explicit, logged act.
- **Engagement authority** (`authority/`) — a scoped, time‑boxed, environment‑aware
  (`TWIN`/`STAGING`/`LIVE`) authorization object; live‑destructive actions are double‑gated; optionally
  Ed25519 threshold‑signed, with fail‑closed loading when a trust root is configured.
- **Capability entitlement** (`entitlement/`) — high‑impact capabilities (`exploit_execution`,
  `deep_static_analysis`, `defender_telemetry`, and the entitlement‑locked `full_chain_exploitation` /
  `self_improvement_merge`) require a valid, current, **host‑bound, unrevoked, m‑of‑n Ed25519‑signed**
  entitlement over a capability ladder (BASELINE → STANDARD → OFFENSIVE → ADVANCED). Baseline reasoning and
  intake always work; everything else fails closed. **The default is permissive / UNGOVERNED** until a
  trust root is provisioned or `CRUCIBLE_ENTITLEMENT_ENFORCED` is set — and `status` surfaces this
  prominently so an operator can't be *unknowingly* ungoverned.
- **Tier‑3 validation** (`agents/tier3_validation.py`) — the doctrine‑*maximum*, deliberately *narrowest*
  slice, **entitlement‑gated OFF by default**. It does exactly one thing: prove an *already
  oracle‑confirmed* finding is real by **re‑firing the minimal proof the oracle already fired on** (the
  finding's retained `oracle_context`) — and only when a full fail‑closed gate stack, a localhost/authorized
  target, and a human approving *that* action all say yes. It is **not** a generic exploit engine: it mints
  no payloads, drives no weaponization, establishes no persistence, and does no lateral movement (those are
  hard‑excluded per `AUTONOMY-CHARTER.md`). A proof that no longer re‑fires demotes to a refusal.
- **IPv6‑aware scope** — the scope gate, egress guard, `common/ethics` charter matching, and the Nmap
  sensor treat IPv6 literals/ranges (and `::1` loopback) the same as their v4 equivalents, so a v6 host is
  scoped and gated identically, never an accidental blind spot.
- **Sovereignty** (`kernel/sovereignty.py`) — the four‑tier LLM‑egress model (§9.11), the *data*
  counterpart to the *action* gates: it controls where your reasoning data may go.
- **Egress guard** (`agents/egress_guard.py`) — the runtime transport that enforces the allowlist; recon
  collector hosts are asserted disjoint from the target scope.

Self‑improvement (`improve/`, §9.15) is **authorise‑not‑apply**: it never self‑mutates offensive code.

### 9.15 The remaining subsystems

| Subsystem | Path | What it is · why · how · wiring |
|---|---|---|
| **UTI — intake** | `intake/` | **Turns a URL into a scaffolded engagement** so you can start fast without hand‑writing boilerplate. It fetches a handful of polite paths (SSRF‑guarded — it re‑resolves the host per request to refuse internal addresses), fingerprints the stack, classifies an archetype, and drafts a `charter.draft.md`, threat‑model, attack‑tree, and fingerprint JSON. The charter is drafted **unsigned** so active testing stays blocked until you review and sign it; scaffolding at all requires a prior operator attestation in an authorization ledger. **Status: shipped.** |
| **DAA — analysis** | `analysis/` | **Offline white‑box static analysis** for the source‑review stage. An always‑available pattern analyzer gives lexical *leads*; optional **Semgrep** (taint/dataflow) and **Joern** (cross‑function CPG) adapters give *provable source→sink flows* and degrade cleanly when the binaries are absent; a Python‑AST symbol index answers structural queries; and an autonomous DAA→kernel review loop critiques dataflow findings with the kill‑switch checked before every model call. Python‑only taint today. **Status: shipped (external analyzers optional).** |
| **DEL — defender** | `defender/` | **Purple‑team, defensive detection modeling** — the constructive alternative to evasion. It models what telemetry each action emits (access‑log/WAF/auth/netflow channels), matches a Sigma‑style ruleset, scores self‑detectability ("how loud am I"), and synthesizes *detection gaps*. Its EMULATE guidance is self‑assessment ("you would be caught by rule X"); a test asserts no evasion vocabulary ever appears. **Status: shipped; the detection‑gap synthesizer (`gap_report.py`) is built but not yet wired into `engage`.** |
| **SIL — improve** | `improve/` | **Self‑improvement as continuous discovery + gated deployment.** A deterministic reviewer mines an engagement for capability gaps; a horizon scanner folds newly disclosed CVEs/techniques into gaps (file‑fed); a patcher drafts *described‑only* proposals (it **authors no code diff**); and a merge gate *authorises* — **never applies** — only when the benchmark is green **and** a threshold of governance approvals over the proposal holds **and** the `self_improvement_merge` capability is entitled. The load‑bearing safety property (the gate changes nothing in the tree) is tested. **Status: shipped, authorise‑not‑apply.** |
| **socialdefense** | `socialdefense/` | The **defensive** answer to social‑engineering: it scores an *inbound* message for phishing indicators (urgency, credential‑harvest, authority impersonation, lookalike/punycode domains, reply‑to/display‑name mismatch, secrecy/financial requests, dangerous attachments) and recommends action. It reads a message you received; it **sends nothing and generates nothing.** Heuristic, text/email‑only. **Status: shipped.** |
| **console** | `console/` | A **read‑only, loopback‑only** operator UI (a stdlib HTTP server bound to `127.0.0.1` only, serving a self‑contained page + read‑only JSON endpoints + a live Server‑Sent‑Events log tail). It issues zero outbound calls. The only mutations are three *safe* actions (launch a gated loopback scan, re‑verify a saved run, trip the kill‑switch), guarded against DNS‑rebinding/CSRF. **Status: shipped.** |
| **eval** | `eval/` | The **measurement spine** that keeps precision honest. It defines one normalized finding shape every tool speaks, scores precision/recall with a greedy one‑to‑one matcher that **includes safe controls a precise scanner must leave alone** (so an off‑manifest detection is a false positive *by construction*), persists runs, and turns a committed baseline into a **zero‑tolerance regression gate** (`make gate`). It loads neutral OWASP‑Benchmark ground truth and parses third‑party tool output (Nuclei/ZAP/sqlmap/Burp/Wapiti/Nikto) into the common shape so those tools can be scored — or admitted as attestations the oracles re‑verify. **Status: shipped.** |
| **common** | `common/` | The shared spine: `paths` (root discovery, owner‑only file/dir creation, umask tightening), `ethics` (the three inviolable gates — signed charter, in‑scope host, authorized intake — whose violations *must* propagate), `redact` (mask secrets by key/segment/suffix, never a bare substring that could over‑redact), `errors` (the `CrucibleError` hierarchy), and `logging` (per‑engagement, redacted, structured JSON lines). **Status: shipped.** |

### 9.16 The universal sensor / producer framework and live fusion (`sensors/`)

**What it is.** A uniform, gated **sensor / producer** framework (the Wave 2-5 build): every external tool
or file is a *fact producer* that normalizes its output into the one `Observation` model — plus the seam
that folds those observations into a *live* engagement's world-model.

**Why it exists.** Instrumentation is a solved problem (§4): CRUCIBLE integrates mature engines as
interchangeable, gated sensors rather than reinventing them — and keeps prove-don't-guess across all of
them. A sensor mints **leads**; only an oracle mints **facts**.

**How it works.**
- **Sensors** (`sensors/*.py`): **Nmap** (service/port discovery, single-host guard), **tshark** (packet
  capture), a **web-scanner** adapter (drives Nuclei/ZAP as gated producers), **cloud-IAM/CSPM**, **SBOM/SCA**
  (`sbom.py`), a **k8s-runtime** posture sensor (`k8s_runtime.py` — kube-bench JSON → CIS-control-failure
  leads), a **log-source** sensor (offline operator logs), and the opt-in **fuzz/ASan** producer (`fuzz.py`).
- Each runs through `sensors/pipeline.py::run_sensor` → the *same* fail-closed gate chain
  (kill-switch / entitlement / scope / destructive / egress). A refused or failed sensor mints nothing.
- **The sensor-fact oracles** (§9.2) that promote a sensor lead to a fact: `SERVICE_REACHABILITY` (a live
  handshake), `TLS_WEAKNESS`, `VERSION_RANGE` (an SBOM package inside an advisory's affected range),
  `POLICY_PATH` (a cloud-IAM reachable-policy path).
- **The fuzz/ASan producer** is *robustness* testing, not weaponization: it drives a bounded fuzz against a
  **localhost / operator-authorized binary that must resolve inside an operator-declared `allowed_root`**
  (defaults to `None` → refuses everything until wired), captures the process's stdout+stderr, and hands it
  to the existing `SANITIZER_SIGNAL` oracle so a real ASan/UBSan/panic/abort marker becomes a fact. It
  refuses unless `authorized=True` — no implicit default fire.
- **Live fusion** (`engage_fusion.py`) is the missing seam: given a run's world-model + slug it runs a small
  allowlist of SAFE, OFFLINE sensors through the gated pipeline, folds their observations in as `intel:`
  **leads**, and lets the oracles (e.g. version-range over SBOM advisories) re-verify **in-run** → `oracle:`
  **facts**. Deterministic and idempotent (stable `obs_id`, caller-supplied `seq` — re-ingest never inflates
  a belief).

**Wiring status (honest).** The framework is **built, unit-tested, and NOT default-wired into
`scan`/`engage`** — it runs standalone (`intel ingest-*`, `imports`, the sensor pipeline) and, for *fusion*,
**only under `engage --autonomous`** (§9.17). Off by default = byte-identical.

### 9.17 The opt-in autonomous OODA loop and the reasoning hook (`engage_autonomous.py`, `engage_reasoning.py`)

**What it is.** The opt-in `engage --autonomous` cycle that finally *drives* the built-but-dormant planner +
gated tool seam in a real run, plus the advisory LLM reasoning hook it can consult.

**Why it exists.** `engage` is otherwise a fixed pipeline (crawl → audit → confirm → chain → score); the
reasoning/planning/tool-driving machinery (`planner.Planner`, `agents.coordinator`,
`agents.tools.invoke_tool`) was **built but never run** in an engagement. This wires *one* bounded OODA
cycle over the authoritative scan result — only when the operator opts in.

**How it works.** One cycle over the `EngagementResult` the scan already produced:
- **OBSERVE** — the run's shared world-model (post-scan WEBAPP/ENDPOINT/finding nodes + the chained attack
  facts) and the oracle-confirmed findings.
- **ORIENT** — build a goal tree and construct the `Planner` over the run world-model (objectives =
  crown-jewel node kinds); its world-aware selection **picks** the next action — a leaf on the highest-value
  route to a crown jewel, not the greediest one.
- **ACT** — drive that action as a **gated tool call** through `invoke_tool` (kill-switch → entitlement →
  scope → destructive-confirm → egress). The first slice drives the SAFE built-in `reverify_finding` tool
  (re-fire a finding's own retained certificate — deterministic, Tier-1, no egress). A tripped kill-switch
  refuses it and the tool never runs.
- **UPDATE** — fold the observation back into the world-model (annotate the finding's node with the live
  re-grounding verdict) and update the goal tree.
- **RE-ORIENT** — re-run the planner's selection over the now-updated tree/world; the pick changes, proving
  the loop closed.
- **The reasoning hook** (`engage_reasoning.py`) runs ONE bounded kernel step (reusing `hypothesize` /
  `pivot` / `critique` + their self-consistency wrappers) and returns structured **advice** — which
  surface / bug-class / hypothesis to prioritise, and lateral moves when a thread stalls. It carries **no
  `confirmed` field by construction**; it never mutates a finding, the world-model, or an oracle verdict.
  Sensor **fusion** (§9.16) composes in through the same fixed hook contract.

**Wiring status (honest).** Everything here runs **only under `--autonomous`** (`--autonomous-cycles N`,
`--autonomous-budget N`); the default `engage` path never imports it, so `make gate` and every replayed run
stay **byte-identical**. This is the one place the ACP goal-tree planner actually runs — it is *not* in the
default loop.

### 9.18 AEGIS — the defensive dual (`aegis/`)

**What it is.** The same prove-don't-guess core pointed *inward*: an embeddable library that detects
**AI-application attacks** in an app the operator runs, over one telemetry envelope, returning an
oracle-confirmed verdict with a re-runnable certificate.

**Why it exists.** The offensive engine proves *offensive* facts; the defensive dual proves *defensive* ones
— a detection you can trust and re-verify offline, not an LLM classifier's guess.

**How it works.**
- **The `detect()` pipeline** (`aegis/pipeline.py`): `boundary.ingest` (untrusted-input hardening + PII
  redaction) → `sensors.normalize` (provenance-tagged Observations = a **lead**) → `actor_graph.observe`
  (per-actor Beta belief) → `OracleVerifier.confirm` (a deterministic AEGIS oracle fires over retained
  evidence) → `veracity.admit` (re-executes the ground bound to the class; can **only demote**) →
  `confidence.assess_finding` (posterior vs. the MECE benign twin — the honest false-positive guard) → a
  `Verdict`.
- **Four attack classes / four defensive oracle kinds**: **prompt injection / jailbreak**
  (`PROMPT_INJECTION`), **system-prompt disclosure** (`SYSTEM_PROMPT_DISCLOSURE` — proven by a planted
  canary), **automated access** (`AUTOMATED_ACCESS` — a seeded honeypot hit proves *automation*, not merely
  "scraping"), and **credential stuffing / account takeover** (`CREDENTIAL_STUFFING` — an SPRT + Holm oracle
  over unseen-(actor,credential)-pair successes).
- **Invariants** (enforced by the `Verdict` model validator): `decision == "confirmed"` ⇒ a re-runnable
  certificate; `provenance == "grounded:…"` ⇒ an oracle fired **and** `admit()` re-admitted it as a fact.
  Fully deterministic — same evidence → byte-identical verdict + certificate id.
- **Additive by construction** (`aegis/registry.py`): AEGIS owns *no* private oracle set — it **appends**
  kinds / routing rows / aliases to the ONE shared verifier/world-model vocabulary, so a hallucinated
  AI-attack label is parse-rejected and no existing class's oracle set or verdict changes.
- **Embedding it in a web app**: wire the middleware/guard (`aegis/middleware.py`, `aegis/guard.py`) to hand
  each request's telemetry to `detect()`, or shell out to `aegis detect <envelope.json>`; `aegis demo` runs
  the canary-disclosure flow end-to-end.

**Wiring status (honest).** AEGIS is **defensive-only**, **lazy-imported**, and **never touched by
`scan`/`engage`/`benchmark`** — the offensive gate path never imports it, so it cannot perturb `make gate`.
Current scope: the four classes above (MVP).

### 9.19 Reporting, export, and the platform seams (`report/`, `mcp/`, `api/`, `plugins/`, `imports/`)

**What it is.** The seams that turn a run into deliverables and expose CRUCIBLE to other tools — all
read-only or gated, none able to promote a claim the oracle refused.

**How it works.**
- **Report assembly + machine export** (`report/`). `report <slug>` deterministically assembles the three
  operator documents (executive / technical / remediation) from the blackboard (or `--from-json`);
  `report/export.py` adds two machine renderers — **SARIF 2.1.0** (CI code-scanning ingest) and structured
  **JSON** — over the *same* graded-findings input, so a document and an export grade a finding identically.
  Every exported finding states its `grounding` — `fact` (its retained proof re-fired at export), `demoted`
  (recorded confirmed but no longer reproduces), or `lead` (no oracle signal). In SARIF, only a FACT is
  levelled by its severity; a LEAD is capped at `note` and tagged `grounding=lead`, so a CI gate is never
  *blocked* by an unproven lead yet still sees it.
- **Third-party import** (`imports/`). `imports <file> --format nuclei|zap|burp|sqlmap|generic` parses a tool
  export into provenance-tagged **leads** in the common shape; `--persist` writes them to the intel store. A
  lead becomes a fact only when a CRUCIBLE oracle re-verifies it — the tool's own verdict is never trusted.
- **MCP tool-server** (`mcp/`). `mcp serve --slug` exposes CRUCIBLE's charter-bound, gated capabilities as
  MCP tools over stdio (and can *consume* external MCP tools); `mcp list --slug` prints what a given
  engagement would expose without serving.
- **Loopback gated API** (`api/`). A read core (enumerate/read the run) plus gated *actions* that pass the
  **same** `invoke_tool` fail-closed chain as a local action — an unauthorized action is REFUSED over the API
  exactly as it would be locally. Bound to loopback; **optional** bearer / `X-Relay-Key` auth (`api/authn.py`,
  opt-in via `CRUCIBLE_API_KEY`, fail-closed so a misconfigured empty key never silently disables auth).
- **Capability catalog** (`plugins/`). `capabilities [--json]` enumerates the unified catalog (subcommands,
  sensors, oracles, tools) deterministically — the discovery surface an MCP/API/SDK consumer reads.

**Wiring status (honest).** `report` and `imports` are shipped operator commands; `mcp` / `api` /
`capabilities` are the platform seams (loopback/stdio, gated, read-or-gated-action). None is on the
`scan`/`engage`/`benchmark` gate path.

---

## 10. The doctrine and posture, in depth

CRUCIBLE's behavior is governed by an explicit doctrine (the OBSIDIAN constitution in `CLAUDE.md`), and
that doctrine is a *design*, not a disclaimer. Four pillars:

**Authorized owner‑testing only.** Before any action that touches a target, the active target's
`charter.md` must be signed, and the target host must be in its in‑scope list. Third parties (payment
processors, IdPs, CDNs, upstream APIs) are out of scope by default — you may test *your integration* with
them (webhook handlers, callbacks, key handling) but never attack the third party itself. If an in‑scope
bug can pivot to an out‑of‑scope system (SSRF reaching cloud metadata, webhook forgery), CRUCIBLE
*documents* it, does **not** exploit further, and surfaces it immediately. There are hard stops: signs of
service degradation, evidence of a *prior* compromise, readable real user PII/credentials, or any doubt
about authorization → pause and ask. All of this is enforced by the code (§9.14), not just recommended.

**Correlatable, not anti‑defender — and *why that's a design choice, not a limitation.*** In owner‑test
context, "stealth" has a specific, unromantic meaning: don't break production (throttle, stage, ask before
destruction), don't spam real users, don't pollute the database (tag every artifact), and — crucially —
**make yourself correlatable**: a recognizable User‑Agent, a stable source, so the operator can grep their
own logs and find exactly what the test did. CRUCIBLE therefore **declines by design** any capability to
evade detection, rotate identities, or stay hidden from defenders. This is deliberate for three reasons:
(1) the goal of an owner‑test is to *improve* the operator's security, which includes their *detection* —
so measuring and closing detection gaps (the purple‑team `defender/` subsystem) is strictly more valuable
than defeating them; (2) a tool that can't be correlated in your own logs can't be *trusted* in your own
environment; (3) evasion tradecraft is exactly the capability that turns an owner‑test tool into a weapon
if it leaks. Accordingly, full exploitation frameworks, credential‑attack suites, and command‑and‑control /
persistence are **excluded from the reasoning engine** entirely. Stealth in CRUCIBLE is *accounting* (know
how loud you are), never *evasion* (defeat the detector).

**The OODA cognitive framework.** The agent reasons in fast Observe → Orient → Hypothesize → Test → Update
cycles with critique and pivot (fully described in §5.3). The point is *cheap falsification*: generate
several hypotheses, run the cheapest experiment that could refute each, treat surprises as the signal that
your model is wrong, and — when a thread stalls — pivot to another thread rather than giving up on the
target. Slow, single‑hypothesis cycles are the failure mode of inexperienced testers; the framework forces
the opposite.

**Coverage doctrine — every modern attack surface.** Completeness is mandatory: for every surface that
*exists* on the target, the corresponding playbook is run — and if a surface *might* exist, that is
determined before deciding to skip it. Learning and reflection may *deprioritize* a surface (re‑rank,
defer) but may **never silently drop** one. The surfaces: web application; REST/RPC/GraphQL API;
authentication & identity; authorization (RBAC/ABAC/BOLA/BFLA); injection (SQL/NoSQL/LDAP/OS/SSTI/XXE);
client‑side (XSS/CSRF/clickjacking/postMessage); **business logic** (the highest‑yield, hardest‑to‑automate
class); cryptography & secrets; network/infrastructure; cloud (AWS/GCP/Azure); container/Kubernetes;
CI/CD & supply chain; microservices; mobile; LLM/AI integration; SSO/federated (SAML/OIDC); source review;
post‑exploitation and data‑exfil/impact (per rules of engagement). A target is *done* only when every
surface that exists has been covered and a self‑critique pass finds nothing missing.

**The engagement lifecycle (stages 0–10).** Every engagement passes through these gates — interleaved in
practice (stages 4–6 especially), never skipped. This is the structure that guarantees nothing is
forgotten:

| Stage | Goal | Gate to advance |
|---|---|---|
| **0 · Charter** | Written, scope‑bounded authorization + objectives + hard/soft limits + stop conditions | Operator signs `charter.md` |
| **1 · Threat model** | Assets, actors, trust boundaries, STRIDE per boundary, an attack tree whose leaves are testable | Operator reviews the tree |
| **2 · Recon** | Passive (cert transparency, archives, dorks) then active (HTTP/TLS probe, light port scan, tech fingerprint, obvious‑leak pass) | Asset inventory complete; immediate criticals surfaced |
| **3 · Surface mapping** | Every endpoint, parameter, role, and data flow; the role × endpoint matrix | Every endpoint/parameter has a row; every role cell observed |
| **4 · Vulnerability hunting** | Run the relevant playbook for every applicable surface; findings logged the moment they're confirmed | Every surface tested; every attack‑tree leaf has a status |
| **5 · Exploitation** | Confirm *real* impact (not "theoretically exploitable"); chain small bugs into large ones | Every finding has a working PoC; chains documented |
| **6 · Post‑exploitation** | Demonstrate consequences within the rules of engagement (skipped unless the charter authorizes it) | Documented per ROE |
| **7 · Source review** | With source in hand, verify black‑box hypotheses, find source‑only bugs, propose minimal patches | Finding list re‑ranked and final |
| **8 · Reporting** | Executive (plain‑language business impact) + technical (PoCs + remediation) + remediation roadmap | Operator confirms reports are actionable |
| **9 · Remediation validation** | Re‑run each PoC after a fix; variant‑test (encoding/case/whitespace) so pattern fixes aren't trivially bypassed | Every finding has a final status; retest report delivered |
| **10 · Continuous testing** | Quarterly re‑engagement, per‑release smoke tests, public‑surface monitoring | Cadence agreed |

Severity uses CVSS 3.1 as a base plus a *contextual* adjustment with explicit reasoning — because
automated scores routinely misjudge the real impact for a specific product. Findings carry standards
mappings (OWASP WSTG/ASVS/API‑Top‑10/LLM‑Top‑10/MASVS, MITRE ATT&CK, PTES, NIST 800‑115, CWE, CVSS 3.1,
CIS Benchmarks) so they translate to compliance and detection contexts.

---

## 11. Testing and verification

CRUCIBLE holds *itself* to prove‑don't‑guess.

- **`make gate` — the credibility spine.** Runs CRUCIBLE against a labelled in‑process benchmark app
  (real single‑class bugs **plus safe controls that a precise scanner must leave alone** — the controls
  are the false‑positive ruler) and **fails on any regression** versus the committed baseline: a new false
  positive, a newly‑missed finding, or a precision drop. It needs no Docker and no external tools, so it
  runs anywhere. `make bench-corpus` extends this to a dockerized multi‑app corpus with neutral
  OWASP‑Benchmark ground truth.
- **`make test`** — the full engine suite: **~270 test files** across ~380 source modules, almost all
  deterministic and offline (only a couple of opt‑in live‑LLM / live‑HTTP integration tests touch a
  network or a model).
- **`python3 -m framework.v2 verify <report.json>`** — *anyone* can re‑verify a saved engagement offline:
  because oracles are pure, each retained certificate re‑fires with no target. Findings prove themselves.
- **Determinism is a *testable* invariant.** There is no wall‑clock or global RNG in the learning /
  reward / spine / normalization math (caller‑supplied sequence numbers, injected RNG), so the calibration
  audit, the event‑spine replay, and DryRun output are all byte‑reproducible — and every capability change
  must keep `make gate` byte‑identical.
- **Adversarial review cadence.** Each shipped program phase (see §12) went through a build → suite‑green
  + gate‑pass → distinct‑lens adversarial review → fix → merge cycle; that review caught a real bug in
  every phase.

---

## 12. Roadmap / in progress

> Everything in this section is **forward‑looking.** Nothing here is presented as a shipped capability;
> where a piece exists as an unmerged branch or a built‑but‑unwired primitive, it says so.

**The thesis — the "Reasoning OS" sensor‑fusion split.** Divide the world into two layers and invest
asymmetrically. **Layer 1 — instrumentation** (network discovery, packet capture, crawling, cloud
inventory, static analysis) is a *solved* problem; CRUCIBLE **integrates** mature engines as
interchangeable, gated **sensors** rather than reimplementing them. **Layer 2 — intelligence** (the
evidence graph, oracle engine, veracity firewall, calibration, planner, memory, learning) is the **moat**,
built from scratch — and most of it already ships as the crown jewels above. The defining idea:
*every observation, regardless of origin, is normalized into one evidence model, reasoned over
consistently, and backed by verifiable proof.* Nmap alone can't correlate a weak‑TLS port with "this host
is Finance," "runs commit abc123," "uses vulnerable OpenSSL," "an exploit exists," and "segmentation
blocks lateral movement." CRUCIBLE reasoning over all producers can — that cross‑layer, provable,
autonomous loop is the seam no siloed tool has.

**Provability survives integration.** A third‑party tool's claim enters as a *provenance‑tagged
attestation* and becomes a `fact` only when a CRUCIBLE oracle **re‑verifies** it over the retained
evidence; otherwise it stays a labelled lead. Prove‑don't‑guess holds across every sensor.

**Three‑tier sensor governance** (mapped onto the existing fail‑closed stack, so power rises with the
gate):
- **Tier 1 — passive observation** (discovery / telemetry / inventory; read‑only): gate = charter scope +
  egress allowlist + kill‑switch. *(The OSINT collectors already live here.)*
- **Tier 2 — active, non‑destructive validation** (crafted requests that don't damage or persist; this is
  where the 12 oracle functions re‑verify each third‑party claim → fact): gate = **+ capability
  entitlement + throttle**.
- **Tier 3 — high‑impact adversary simulation** (identity‑resilience exercises, controlled exploitation
  validation): an **isolated authorized‑validation layer**, **per‑action operator approval + audit**,
  never part of the routine loop. Full exploitation frameworks, credential‑attack suites, and C2 /
  persistence stay **excluded from the reasoning engine** entirely.

**The seven waves.**

| Wave | Theme | Status |
|---|---|---|
| **1** | **The intelligence core** — build the brain first, so a superior operator drives every sensor | **in progress** |
| 2 | Universal Sensor/Producer framework + a first reference integration (Nmap) + a service‑reachability oracle | planned |
| 3 | Packet & network sensors (tshark/Zeek/Suricata) + TLS‑weakness / flow‑signature oracles | planned |
| 4 | Web breadth — wire the built arsenal into the default run + integrate Nuclei/Burp/ZAP as re‑verified sensors | planned |
| 5 | Cloud/IAM/SBOM/static/identity + threat‑intel (MISP/STIX/NVD) + wire `defender/gap_report.py` into `engage` | planned |
| 6 | Platformization — a plugin registry, an MCP tool‑server (expose CRUCIBLE as tools *and* consume external tools), an external API, report automation | planned |
| 7 | Consolidation / hygiene — unify the two Beta learners, de‑dup seed checks / fingerprint stacks, right‑size `quantum_era` | planned |

**Wave 1 sub‑phases:**
- **W1.1 — wire the nervous system into the default loop (advisory‑only).** Add the multi‑critic panel,
  reflection agent, cognitive refusal, the `credit_outcome` learning fan‑out, and the meta‑monitor caution
  to `engage --spine` **without** changing which surfaces run or the oracle verdict. *Status: implemented
  on branch `w1.1-wire-nervous-system` (advisory‑only); **not yet merged to `main`** — the default loop on
  `main` today does not schedule these primitives (see §13).*
- **W1.2 — lookahead planning.** Replace the greedy goal‑tree leaf score with a deterministic,
  budget‑bounded multi‑step planner (beam / MCTS‑lite over the belief graph + attack‑path value). Orders
  effort, never gates. *Status: **in progress.***
- **W1.3–W1.6** — cross‑engagement transfer (embedding‑smoothed priors), agentic tool‑use as the
  sensor‑driving seam, self‑consistency for no‑oracle bindings, multi‑target campaigns. *Planned.*

**Shipped foundations this roadmap builds on** (already in `main`): the **anti‑hallucination veracity
firewall** program (P0–P7), the **nervous‑system event‑spine** program (N0–N7), and the **speed /
resilience / protection** hardening (X1–X6: determinism‑safe caching, data‑at‑rest owner‑only permissions
+ secret redaction, indexed spine I/O + cursors, LLM backoff + in‑tier failover, opt‑in parallel recon,
and runtime‑security hardening). These are framed here as done foundations, not roadmap items.

---

## 13. Status and honesty

CRUCIBLE's own rule is *never overclaim what the deterministic layer enforces.* In that spirit, precisely
what ships versus what is experimental or dormant:

**Production‑grade (shipped, tested, in the default path):**
- The oracle/verification layer, offline re‑verification, and OOB/collaborator confirmation.
- The unified Bayesian world‑model, attack‑path search, and forward‑chaining derivation.
- The veracity firewall over live findings, the SCE per‑finding confidence, and the world‑model chaining —
  all live in the default `engage` loop.
- The scanner/audit engine, the 11 built‑in + 5 request‑level default checks, the self‑learning bandit
  (orders, never gates), fingerprinting, and the CDP‑confirmed DOM‑XSS path.
- The 6‑gate `HttpExecutor` chain, the fail‑closed kill‑switch, sovereignty tiers, the egress allowlist,
  signed evidence bundles, and redacted structured logging.
- The append‑only event spine with cryptographic tamper‑evidence, and the `--spine` engagement mirror.
- The benchmark + `make gate` regression spine; the OSINT intel engine (offline by default).

**Experimental, opt‑in, or built‑but‑not‑default‑wired:**
- The **167‑entry check library** is exercised under the eval/benchmark harness; the *default interactive*
  scan uses the 11 + 5 built‑in checks (enable the library per‑campaign via `use_library`).
- The **nervous‑system primitives** (multi‑critic panel, reflection, cognitive refusal, `credit_outcome`
  fan‑out, meta‑monitor) and the **MAO coordinator + specialist agents** are unit‑tested and schedulable
  but **not scheduled in the default `engage` loop** — their *doctrine* is nonetheless live in every
  reasoning call via the governance preamble. Wiring them advisory‑only into `engage --spine` is **W1.1**,
  which exists on branch `w1.1-wire-nervous-system` and is **not yet merged to `main`.**
- The **ACP goal‑tree planner** (budget/pruner/watchdog/resume) is built and tested but **not wired into a
  default runner** — `engage` drives the scanner campaign + orchestrator, not the planner.
- The **specialized scanner arsenal** (smuggling, race, WebSocket, discovery, sequencer, grammar‑fuzz,
  WAF‑evasion, `pqc_scan`) and the **`intruder/`** package are built and unit‑tested but reachable only via
  the public API / flags — not part of the default campaign.
- `defender/gap_report.py` is **built but unwired** into `engage`. DAA taint is **Python‑only** and the
  Semgrep/Joern adapters are optional. The remote browser path is **loopback‑only on `engage`**. OOB
  confirmation is **HTTP‑only** (a DNS‑only interaction needs a DNS‑capable relay). Memory embeddings are
  **lexical by default**. Capability entitlement is **permissive / UNGOVERNED** until a trust root is
  provisioned.
- **Reasoning quality without a live LLM backend is bounded** — DryRun returns deterministic fixtures. The
  scanner and oracles need no LLM; the reasoning kernel benefits from one.
- **The at‑scale autonomous finding‑discovery loop is not proven.** The plumbing is verified against a real
  target, but the one conservative real‑target run to date emitted zero findings. CRUCIBLE today is a
  precision, prove‑don't‑guess scanner with a genuine reasoning/OSINT/evidence spine — **not** an
  unattended frontier‑autonomy loop, and this README does not claim it is.

**Posture, restated:** authorized owner‑testing only; correlatable, not stealthy; deliberately **not**
anti‑defender. If an operator instruction conflicts with scope, destruction, evidence, or honesty,
CRUCIBLE asks before deviating — it never silently relaxes those rules.

---

## 14. Where this lives in the repo

Everything above is explained in full in this README; these files are the *authoritative source of the
mechanisms described here*, for when you want to read the code or the deeper design notes. You do not need
them to understand the system — they are for when you want to modify or audit it.

- **Doctrine & agent:** `CLAUDE.md` (the OBSIDIAN constitution), `framework/cognitive/metacognition.md`
  (the doctrine injected into every LLM prompt), `framework/cognitive/*.md` (the reasoning framework),
  `framework/playbooks/*.md` (per‑domain testing), `framework/checklists/`, `framework/templates/`,
  `framework/knowledge-base/`.
- **The one rule & oracles:** `framework/v2/verify/{oracles.py,verifier.py,confirmation.py,reverify.py,
  oob.py,collaborator.py}`.
- **World‑model & chaining:** `framework/v2/worldmodel/*`, `framework/v2/knowledge/operators.py`.
- **Anti‑hallucination:** `framework/v2/veracity/*`.
- **Scanner & arsenal:** `framework/v2/scanner/*`, `framework/v2/intruder/*`.
- **Reasoning core:** `framework/v2/confidence/*`, `framework/v2/calibration/*`, `framework/v2/agents/*`
  (spine + critics + reflection + refusal + coordinator), `framework/v2/kernel/*` (URK + sovereignty),
  `framework/v2/memory/*`, `framework/v2/intel/*`, `framework/v2/planner/*`.
- **Evidence & safety:** `framework/v2/evidence/*`, `framework/v2/authority/*`,
  `framework/v2/entitlement/*`, `framework/v2/agents/{http_executor,egress_guard,scope_gate}.py`.
- **Other subsystems:** `framework/v2/{intake,analysis,defender,improve,socialdefense,console,eval,common}/*`.
- **Entry points & lifecycle:** `framework/v2/__main__.py` (the CLI contract),
  `framework/v2/engage.py` (the end‑to‑end runner), `ENGAGEMENT-LIFECYCLE.md`, `HOW-TO-START.md`,
  `SECURITY.md`, `Makefile`.
- **Deeper design notes (optional):** `framework/v2/docs/` (architecture, operator guide, benchmark
  methodology, check‑authoring), and the honest limitations ledger `V2-LIMITATIONS.md`.
