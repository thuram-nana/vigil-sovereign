# VIGIL — Vision & Feature Roadmap

*The strategic map of what makes VIGIL the first name people think of for pentesting.*
*Version 1 · 2026-07-28. This is a living document; the status tags are the truth, not the prose.*

---

## The moat

**VIGIL is the only pentest system where the machine cannot lie about a finding.**

Every other AI security tool builds the same loop: the AI *proposes* a finding and the AI (or a second
AI acting as judge) *decides* it is true. That loop is why industry tools have been measured at 35–90%
false-positive rates, and why curl ended its bug-bounty program over AI "slop." VIGIL breaks the loop at
the one place that matters: **the AI is never the authority.** A finding becomes a FACT only when a
separate, deterministic (non-AI) **oracle** independently re-fires over data the real target produced —
and only then is it cryptographically signed, written to an append-only record, and turned into a
certificate anyone can re-check offline, forever.

That single property is defended by a **four-part combination no competitor has**:

| Property | What it means | Why it's hard to copy |
|---|---|---|
| **Oracle-confirmed findings** | A deterministic checker re-proves the bug over the target's own bytes | Requires a real proof program per bug class — not a prompt |
| **Signed, offline-verifiable evidence** | Every FACT is a certificate a third party re-checks with zero trust in VIGIL | Requires a signed, append-only spine and a re-execution harness |
| **Scope enforced at the OS / network layer** | A prompt-injected agent physically cannot leave its target | Requires a deny-by-default egress gate, not a polite instruction |
| **Sovereign** | Your hardware, your keys; the offense side holds no owner key | Requires a two-environment boundary that cannot co-load |

In our own survey of the field ([`docs/research/FRONTIER.md`](research/FRONTIER.md)), **no existing tool
combined more than two of these.** VIGIL is built on all four, and they compound: signed evidence is only
worth anything because an oracle — not the AI — minted it; scope enforcement is only credible because it's
on the wire, not in the prompt; sovereignty is only real because the two planes cannot merge. Break any one
and the others lose their meaning. That interlock is the moat.

**The thesis of this document:** every feature below — built, building, or planned — is here because it
amplifies that moat along one of four axes: **proof** (a claim you can re-run), **trust** (a signature you
can verify), **autonomy** (a machine that gets more capable without ever gaining the power to lie), or
**client-verifiability** (a result the buyer can check without trusting us). We do not chase features that
don't. A feature that made VIGIL faster or flashier but blurred the FACT/LEAD line would make VIGIL worse.

---

## How to read this

Three status tags, used exactly:

- **[BUILT]** — shipped and merged on `main`. Some BUILT items are flagged *(elevate)*: the capability
  already exists deep in the system, and the current program surfaces it as a first-class, named,
  sellable feature.
- **[BUILDING — this program]** — a committed deliverable of the program now in flight (connect the
  built-but-unwired cortex, the deterministic **Proof Studio**, and the four flagship features). Designed
  and being landed slice-by-slice; not yet fully complete.
- **[ROADMAP]** — planned, not started. Where partial building blocks already exist, the entry says so
  plainly rather than implying more than is true.

> **This roadmap obeys VIGIL's own core rule.** A shipped capability is a FACT; a plan is a LEAD about our
> own product. We will not print a plan as though it were a fact — the status tag *is* the line between the
> two, and we keep it as sharp here as the oracle keeps it in an engagement. If it isn't BUILT, we say so.

---

## Theme A — Proof & Evidence (the moat itself)

This is the category VIGIL is trying to own. Everything in every other theme is amplification of this one.
VIGIL's proof layer is not a report generator that dresses up an AI's opinion — it is a **re-execution
engine**. A finding is a thing you can run again.

- **Proof Studio — deterministic proof generation.** `[BUILDING — this program]`
  Today an agent's PoC is a free-text string that is never re-run, oracle-confirmed, or signed. The Proof
  Studio replaces "the agent says it worked" with "a deterministic oracle re-fired over the target's own
  captured bytes." The mint runs host-side in the **keyless** offense environment over executor-captured,
  non-LLM bytes — never over the model's own PoC text — and a dedicated screen shows the environment
  manifest (container image *digest*, tool versions, seed, nonce), the captured request/response, which
  oracle fired at what confidence, and an offline verify-certificate badge. This *is* the moat, made into
  a product surface.

- **Client-verifiable "proof-of-pwn" bundles.** `[BUILDING — this program]`
  A one-command export a client, auditor, or court runs **offline, with zero trust in VIGIL**:
  `python -m framework.v2 evidence verify …` returns exit 0 iff the finding is authentic (m-of-n signed),
  oracle-context-bound, artifact-intact, reproducible, and un-rolled-back. A CI job runs that same verify
  in a **VIGIL-free environment** to prove the bundle needs nothing of ours. No competitor hands you a
  finding you can re-prove without trusting the vendor — this is the feature that turns a report into
  evidence.

- **Continuous proof / drift watch.** `[BUILDING — this program]`
  A scheduled tick re-fires each retained finding's oracle context and classifies it **still-proven /
  regressed-fixed / newly-appeared / newly-fixed**, emitting a signed drift record and an "Assurance"
  badge. It turns a point-in-time pentest into continuous, provable assurance: a finding is no longer "as
  of the report date," it is "as of the last re-proof." Off by default; a live re-fire passes the same gate
  chain as any other engagement.

- **Proof-carrying living report.** `[BUILDING — this program]`
  Every sentence in the client report is backed by a re-checkable certificate, and the report is not a
  stale PDF but a read-only, always-current view over the signed spine. A reader can click any claim and
  re-verify it offline. A report you can independently re-prove, claim by claim, is a different kind of
  object than a document you have to believe.

- **Full engagement time-travel replay.** `[ROADMAP]`
  Replay the append-only spine to any point in an engagement and re-fire every oracle from that state,
  reconstructing exactly what was proven, when, and in what order. The spine already checkpoints every run;
  this makes the *entire history* independently re-verifiable — not just the final findings — so a dispute
  about "what did the tool actually do at 14:32" is settled by re-execution, not by logs anyone could edit.

---

## Theme B — Autonomy & Reasoning

Autonomy without proof is the failure mode of every other AI hacker: it acts fast, then hands you a pile of
confident fiction. VIGIL's autonomy is *safe to run at all* precisely because nothing it concludes is
believed until an oracle re-fires. The more autonomous it gets, the more the proof layer earns its keep.

- **Self-evolving knowledge engine, end-to-end.** `[BUILDING — this program]`
  Closes the K2b→K3 keystone: an owner-approved learn-proposal produces a signed, **inert** grant that
  crosses the plane seam and drives `deep_learn`, writing FIND/PREVENT skills and mapping DETECT only onto
  oracle kinds that actually exist (invented kinds are rejected). The system gets better at *proposing*
  without ever gaining the power to self-mint a fact — learning bumps no priors, mints no tier, and every
  new skill still has to survive the oracle like any other lead.

- **Signed multi-step attack-path kill-chains (PathCertificate).** `[ROADMAP]` *(partial exists)*
  Attack-path reasoning over proven facts already ships in the CRUCIBLE engine. The roadmap item is a
  first-class, signed **PathCertificate** that binds a whole kill-chain — each hop an oracle-proven fact —
  into one offline-verifiable artifact. A chain is only as trustworthy as its weakest hop, so the rule is
  strict: every hop is a FACT or the whole chain is a LEAD. No "and then the attacker probably could…"

- **ATT&CK adversary-emulation campaigns + coverage matrix.** `[BUILDING — this program]`
  A deterministic mapper attaches MITRE ATT&CK techniques to each graded finding and builds an **honest**
  coverage matrix: *tested-and-proven* vs *tested, no finding* vs *not tested* — never implied coverage.
  Blue teams and regulators get a defensible map of what was actually exercised and proven, not a checkbox
  wall that quietly conflates "we ran a scanner" with "we proved you're safe."

- **Autonomous provable pivots / asset-graph expansion (gated).** `[ROADMAP]`
  Let the agent roam: expand along the discovered asset graph and pivot on its own — with **every** new
  edge still passing the conjunctive gate, the egress pin, and the oracle before it counts for anything.
  Breadth of discovery with zero relaxation of the proof or scope discipline. Roaming is a proposal
  generator; the gates and the oracle remain the authority.

- **Reasoning transparency — "watch the AI think."** `[BUILT]` *(elevate)*
  The reasoning loop, every gate decision, and every oracle verdict already stream to the spine and the UI.
  The program elevates this into a first-class "watch it reason, then watch the oracle check it" view.
  Transparency is itself a moat feature: you can see the exact moment a proposal is demoted to a LEAD, or
  promoted to a FACT — and you can see that the thing doing the promoting is the oracle, never the model.

---

## Theme C — Collaboration, Reporting & Enterprise

Enterprises don't just need findings; they need findings they can hand to a client, an auditor, or a court
and have them hold up under someone else's scrutiny. This theme is the moat turned outward — from "we
proved it" to "you can re-prove it."

- **Living client portal.** `[BUILDING — this program]`
  A read-only, token-scoped, always-current portal over a session's signed spine: findings appear **as they
  are proven, in real time** (reusing the blackboard SSE), each backed by a re-checkable cert, remediation
  tracked to closure. It is strictly read-only, binds to loopback / an owner tunnel (never public), and
  **cannot launch or widen anything**. A shareable, verifiable artifact — not a stale PDF emailed once and
  never trusted again.

- **Remediation loop closure with a signed "fix-proven" cert.** `[BUILDING — this program]` *(A6a)*
  After a gated clone → edit → build, the **same** oracle that confirmed the driving FACT re-fires against
  the patched build; remediation is marked true **iff it goes silent** — never asserted. The client gets a
  signed proof that the fix actually closed the hole, not a developer's word that it did. Closing the loop
  with proof is as important as opening it with proof.

- **Compliance mapping — OWASP / CWE / PCI-DSS / SOC2 / ISO 27001.** `[BUILDING — this program]` *(C3)*
  A deterministic mapper from bug-class / oracle-kind to control frameworks, attached to each graded
  finding, plus a signed, offline-verifiable compliance attestation. Honest by construction: a LEAD is
  capped at "note" and never claims coverage. A compliance artifact that maps to a *proven* finding is
  worth more than a spreadsheet mapping to a scanner's guess.

- **Multi-tenant / team + RBAC.** `[ROADMAP]`
  Team workspaces, role-based access, and per-tenant isolation over the same signed spine, so an
  organization or an MSSP can run many engagements without cross-contamination. Built on the existing
  owner-key trust root rather than bolted on beside it, so tenancy inherits the same tamper-evidence the
  rest of the system already has.

- **Marketplace of proven-finding templates.** `[ROADMAP]`
  A library of oracle-backed finding templates — the payload, the oracle context, and the mandatory
  negative control — that others can import and **re-prove against their own targets**. A shared template
  is useful precisely because it re-fires deterministically; the marketplace inherits the moat instead of
  degrading into a swap-meet of unverifiable "I found this once" claims.

---

## Theme D — Coverage breadth (an honest coverage map)

Breadth is worth nothing if the breadth lies. Every new surface is added the same way it is everywhere
else in VIGIL: **it does not count as covered until an oracle can prove a finding on it.** The coverage map
itself is honest — *tested-and-proven* vs *tested, no finding* vs *not tested* — so breadth arrives as
*provable* breadth or not at all.

- **Web / API / GraphQL / cloud (AWS · GCP · Azure) / K8s / mobile / SSO / supply-chain.** `[ROADMAP]` *(phased)*
  Extend the oracle-backed surface across the full modern attack landscape, one surface at a time, each
  gated behind a real deterministic checker before it is advertised as covered. This is deliberately
  sequenced, not claimed all at once — the value is that when a surface goes green, it means an oracle can
  prove a bug there, not that we pointed a scanner at it.

- **LLM / AI-app red-teaming as a first-class, oracle-backed surface.** `[ROADMAP]` *(high-priority)*
  Prompt-injection, tool-abuse, and data-exfil **proven by a deterministic oracle over the target model's
  own outputs** — not "the judge model thinks it jailbroke." This fits VIGIL's model better than any other
  surface: the AI-Gauntlet already treats another AI's judgment as a permanent LEAD, so an oracle-backed
  proof is the natural next step, and the market for *provable* AI red-teaming — as everyone ships agents
  they can't trust — is wide open and largely ungoverned. A high-priority bet precisely because the moat
  transfers to it cleanly.

- **Cloud / IaC provable privilege-escalation paths.** `[ROADMAP]`
  Prove a concrete privilege-escalation path through cloud IAM / infrastructure-as-code as an
  oracle-confirmed, signed chain — not a scanner's speculative "possible" list. One privesc path you can
  re-prove offline is worth more than a hundred maybe-findings that a client has to triage by hand.

---

## Theme E — Operator experience

The moat is only valuable if an operator can actually drive it. VIGIL's operator surface aims to make
proof-grade pentesting feel like a conversation — **without ever letting the conversation become the
authority.** The words are always a proposal; the charter-signed scope, the gates, and the oracle are
always the deciders.

- **SIGIL fully embodied — voice cockpit + HUD + gesture.** `[BUILDING — this program]`
  "SIGIL, prove the SQLi on the login form," spoken aloud, driven through the *same* gate/oracle chain,
  with a heads-up display and gesture control. The embodiment is opt-in and hardware-gated; it changes how
  you drive VIGIL, never what VIGIL is allowed to do. A voice command is a proposal like any other — it
  still queues for approval and still has to survive the oracle.

- **Natural-language → gated engagement.** `[BUILT]` *(deepen)*
  Plain-language intent already lowers into a scoped, gated engagement; the program deepens the loop
  (wizard → live run → findings → fixes). The natural-language layer is a convenience over the top of the
  authority chain, not a way around it — you can ask in English, but the charter-signed `--scope` the UI
  can never widen is what actually binds the run.

- **Agent-to-agent coordination.** `[BUILDING — this program]` *(A5)*
  Fireteam members pass directed hints to next-phase siblings, folded into an **advisory objective only**.
  The load-bearing property: a message is *structurally* not evidence — the inbox filters to
  `agent_message` and no fact-building path reads it — so coordination speeds discovery without ever
  manufacturing a finding, and a hinted member's every action still passes the gate and the oracle.

---

## Theme F — Trust & Safety as a *feature*

For most tools, safety is a compliance cost. For VIGIL it is the product. The same machinery that keeps an
autonomous hacker from going rogue is exactly what makes its output auditable and, ultimately,
court-admissible. We sell the guardrails.

- **m-of-n cryptographic governance for destructive actions.** `[BUILT]` *(elevate)*
  Irreversible, high-impact actions require a real **m-of-n** threshold sign-off with a mandatory owner
  signer fixed at deployment, action-binding, a dead-man's-switch window, and single-use tokens. This is a
  sellable guarantee: no single person — and no compromised agent — can trigger destruction alone. It is
  built and merged; the program elevates it to a named, front-of-house feature.

- **Tamper-evident engagement ledger (for regulators / EU AI Act Art. 12).** `[BUILT]` *(elevate)*
  An always-on, append-only usage record — *who / when / against what* — tied to a never-decreasing counter
  (hardware-anchored where a secure chip is present) so it cannot be back-dated, replayable and
  chain-verifiable via `vigil ledger` / `vigil verify-ledger`. This is precisely the append-only,
  tamper-evident logging that regimes such as the **EU AI Act (Article 12)** require of high-risk AI
  systems — a legal obligation that most AI tools have no way to meet.

- **Kill-switch + blast-radius containment.** `[BUILT]`
  A kill-switch and scope floor that **always win**, deny-by-default egress pinned to the one authorized
  target, and fail-closed behavior everywhere (unknown tool → strictest tier, missing gate → deny,
  malformed input → safest action, approval timeout → reject). Sold as a feature in its own right: you can
  hand an autonomous offensive agent a target and know — in code and on the wire, not in a prompt — exactly
  how far it can reach.

---

## Why this wins

**The combination is one of a kind.** Oracle-confirmed findings **+** signed, offline-verifiable evidence
**+** OS/network-layer scope enforcement **+** sovereignty. Our survey of the field found **no competitor
combining more than two** of these four; VIGIL is built on all four, and every feature on this roadmap
compounds them rather than diluting them. Anyone can add another AI. Almost no one can add another *oracle*,
another *signed spine*, another *egress gate on the wire*, and another *keyless offense plane* — and make
them interlock so tightly that removing one collapses the rest.

**Who it's for:**

- **Pentesters and red teams** drowning in AI false positives, who want an autonomous partner whose findings
  they never have to hand-verify — because the tool already did, deterministically, and signed the proof.
- **Enterprises and MSSPs** that must deliver *provable, auditable* results — a finding a client can
  re-prove offline, with zero trust in the vendor, and a remediation cert that proves the fix actually
  closed the hole.
- **Regulators, auditors, and compliance owners** (EU AI Act Art. 12, SOC2, PCI-DSS, ISO 27001) who need a
  tamper-evident, offline-verifiable record of exactly what an autonomous AI system did, when, and against
  what — the one thing the current generation of AI tools structurally cannot provide.

The AI proposes, the oracle proves, the gates constrain, the signature attests. Everything on this roadmap
widens exactly one gap — the distance between what VIGIL can *claim* and what VIGIL can *prove*. Today that
distance is zero. The whole point of this document is to keep it zero while proving more, on more surfaces,
for more people — until "can you actually prove it?" has exactly one answer, and it's ours.
