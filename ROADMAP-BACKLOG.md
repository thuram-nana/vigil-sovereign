# CRUCIBLE — ROADMAP BACKLOG (self-replenishing work queue)

This is the **open-ended, self-replenishing work queue** the perpetual cloud
agent pulls from every run and **extends** when it runs low. It must never run
dry: when the top of the backlog is exhausted, the agent runs the SELF-REPLENISH
protocol (§4) to mint new items, so progression toward #1 is never-ending.

Companion to `ROADMAP-FLAGSHIP.md` (the narrative target) and `V2-LIMITATIONS.md`
(the honest floor). Where the flagship roadmap states *why*, this file states
*what to pick up next* — as executable, acceptance-gated checklist items.

---

## 1. The north star

CRUCIBLE is the **#1 platform for vetted national red teams** when four things
are simultaneously true and provable: **(a) prove-don't-guess** — every
"confirmed" finding is confirmed by a *fired deterministic signal* from a
multi-oracle verification layer, never by LLM opinion, and carries a
*calibrated* exploitability score, not a hardcoded 1.0; **(b) world-model +
planning** — a persistent typed attack graph holds attacker state so the
platform can *chain* primitives and *plan* an objective-directed path
(k-best-path / min-cut / sequential-decision), rather than emitting isolated
findings; **(c) deep program analysis** — symbolic/concolic execution + SMT,
coverage-guided fuzzing, and IFDS/IDE taint over a code-property graph give
depth no LLM-only competitor can match; **(d) governed & sovereign** — every
capability is entitlement-gated (Ed25519 m-of-n), kill-switchable, and leaves a
tamper-evident provenance record, so the platform is *accreditable for classified
deployment*. The governance/sovereignty stack is the moat; the oracle + world-model
+ deep-analysis stack is the reason anyone wants past the gate. Everything in this
backlog moves one of those four dials, and **nothing** in it crosses the boundary
into turnkey offensive weapons, working evasion of real defenders, or unattended
attacks on live/third-party targets.

---

## 2. Guardrails (encoded into every item — non-negotiable)

- **Tests green before commit.** 0 failures. An item is not "done" until its
  acceptance test passes *and* the full suite stays green.
- **Never merge to main.** The agent opens a PR from its working branch; a human
  reviews and merges. Never force-push, never rewrite history.
- **No fixture-theatre.** Acceptance tests must exercise real code paths and real
  fired signals — never assert on hand-baked fixtures shaped to pass. If a test
  can pass without the capability existing, it is invalid.
- **Honesty doctrine.** Never claim completeness not achieved. If an item is
  partial, it stays unchecked and the DONE LOG records exactly what shipped.
- **Defensive / verification / planning only.** No turnkey offensive weapons, no
  working evasion of real defenders, no attacks against live or third-party
  targets. Test targets are **localhost-only**, operator-owned, and consented.
- **Governed posture preserved.** Each new capability is entitlement-gateable and
  kill-switchable; provenance is recorded. Items that expand reach are
  **[ENTITLEMENT-GATED]**; items that only observe/verify/plan are **[DEFENSIVE]**.

Legend: effort **S** (<0.5d) · **M** (~1–2d) · **L** (~3–5d) · **XL** (multi-week,
usually split before starting). Tags: **[ENTITLEMENT-GATED]** · **[DEFENSIVE]** ·
**[ONTOLOGY]** · **[ALGORITHM]** · **[HARDENING]**.

---

## 3. The backlog (living checklist — work top-down within a wave)

### WAVE 4 — Close the oracle loop end-to-end (make the confirmation authority actually fire on real runs)

The oracle exists and `critique_agent` already treats `oracle_context` as the
confirmation authority — but the **producer never populates it** (`produce.py`
has zero references) and the reporter never surfaces it. Until this loop is
closed, the headline win ("a real target drove a real confirmed finding") is
true only in the confirmation unit tests, not on a full produce→critique→report
run. This wave is the highest-EV work on the board.

- [ ] **Producer → `oracle_context` wire-in.** `[DEFENSIVE]` **M** —
  `eval/produce.py` builds a `verify.adapter.FindingContext` for each candidate
  finding it emits (target handle, primitive, observable channel, OOB token where
  applicable) and attaches it as `finding.oracle_context`. *Why #1:* this is the
  single wire that makes the deterministic oracle the confirmation authority on a
  real end-to-end run instead of only in isolation. *Done =* a green e2e test runs
  `produce → critique` against a localhost test target where the finding is
  confirmed **only** because an oracle signal fired (assert: with the signal
  suppressed the same finding is NOT confirmed).
- [ ] **Reporter surfaces oracle provenance.** `[DEFENSIVE]` **S** —
  `reporter_agent` renders, per confirmed finding, *which oracle kind fired*, the
  signal evidence, and the calibrated confidence (not 1.0). *Why #1:* prove-don't-
  guess is only credible if the report shows the proof. *Done =* a green test
  asserts a reported finding contains the firing oracle id + evidence + a
  calibrated (non-1.0) score.
- [ ] **OutcomeLedger wire-in on every confirm/refute.** `[DEFENSIVE]` **M** —
  each oracle decision (confirmed / refuted / inconclusive) appends an outcome to
  `calibration.OutcomeLedger`, keyed to the finding's provenance. *Why #1:* the
  ledger is the training signal for calibrated scoring and the audit trail that
  ends the self-contradicting honesty ledger. *Done =* a green test runs N
  produce→critique cycles and asserts the ledger contains N outcomes with correct
  confirmed/refuted labels.
- [ ] **Calibrated score replaces the hardcoded 1.0 at the confirmation site.**
  `[DEFENSIVE]` **S** — the confidence attached to a confirmed finding is drawn
  from `calibration.calibrate` (PAV isotonic over the ledger), not a constant.
  *Why #1:* directly kills the audit's "confirmed carried a hardcoded 1.0" defect.
  *Done =* a green test shows two confirmed findings of differing evidence strength
  receive *different* calibrated scores, both ≠ 1.0.
- [ ] **Multi-oracle disagreement policy.** `[DEFENSIVE]` **M** — when >1 oracle
  applies to a finding, define and test the combine rule (e.g. any-fired-confirms
  for safety-monotone oracles; record dissent). *Why #1:* multi-oracle is the bar;
  a stated, tested policy prevents silent single-point trust. *Done =* a green test
  with two oracles (one fires, one doesn't) asserts the documented outcome + dissent
  recorded in provenance.

### WAVE 5 — The three ontologies (the custom knowledge substrate)

- [ ] **(A) Target World-Model / Attack Graph — persistence + attacker state.**
  `[ONTOLOGY][DEFENSIVE]` **L** — extend `worldmodel/` so a graph persists across
  runs of an engagement and holds *attacker state* (owned nodes, held creds/tokens,
  reachable services) as typed facts. *Why #1:* without persistent state the
  platform cannot chain or resume. *Done =* a green test builds a graph, records a
  primitive's postcondition (e.g. cred obtained), reloads from `store`, and shows
  the state survived and enables a follow-on edge.
- [ ] **(B) Technique Knowledge Graph — operators with typed pre/post-conditions.**
  `[ONTOLOGY][DEFENSIVE]` **L** — grow `knowledge/` so each technique is a planning
  operator with typed preconditions and postconditions, cross-referenced to
  CWE/CAPEC/ATT&CK/D3FEND and (where present) CVE/EPSS. *Why #1:* operators with
  typed conditions are what make attack-path planning *sound* rather than heuristic.
  *Done =* a green test loads the catalog, queries "operators whose preconditions
  are satisfied by world-model state S", and gets the correct applicable set.
- [ ] **(C) Evidence / Provenance Graph.** `[ONTOLOGY][DEFENSIVE]` **M** — a typed
  graph linking finding → firing oracle signal → raw evidence → ledger outcome →
  entitlement under which it ran. *Why #1:* accreditation demands a tamper-evident
  chain from claim to proof; this is the moat made queryable. *Done =* a green test
  confirms every confirmed finding resolves to a complete provenance chain and that
  a missing link fails validation.
- [ ] **Ontology (B) enrichment loader.** `[ONTOLOGY][DEFENSIVE]` **M** — offline,
  vendored CWE/CAPEC/ATT&CK/D3FEND mappings loaded deterministically (no live
  fetch at run time). *Why #1:* sovereign/air-gapped deployment can't depend on
  network. *Done =* a green test loads the vendored corpus offline and resolves a
  technique to its full cross-reference set.

### WAVE 6+ — The algorithms (depth that LLM-only platforms cannot match)

- [ ] **Attack-path planning surfaced to the planner.** `[ALGORITHM][DEFENSIVE]`
  **M** — wire `worldmodel.pathsearch` (best_paths / choke_points already seeded)
  into `planner/ACP` so the goal tree is driven by objective-directed paths and
  min-cut chokepoints. *Why #1:* turns isolated findings into a planned chain toward
  a charter objective. *Done =* a green test with a multi-hop test graph shows the
  planner selects a k-best path and identifies the min-cut chokepoint.
- [ ] **Sequential decisioning under uncertainty (POMDP / MCTS).**
  `[ALGORITHM][DEFENSIVE]` **XL (split)** — a bounded planner that chooses the next
  probe to maximise information gain toward an objective given partial observability.
  *Why #1:* real engagements are partially observed; greedy path-search leaves EV on
  the table. *Done =* a green test on a toy POMDP shows the planner's expected cost
  beats a greedy baseline over N seeds. *(Planning only — never auto-fires against
  live targets.)*
- [ ] **Guided verification/synthesis + more oracle kinds.** `[ALGORITHM][DEFENSIVE]`
  **L** — expand `verify/oracles.py` with additional *deterministic* oracle kinds
  (e.g. differential-response, OOB DNS/HTTP interaction via `oob.py`, crash/assert,
  invariant-violation) and template-guided *verification-proof* construction against
  localhost test targets. *Why #1:* more prove-don't-guess coverage across bug
  classes. *Done =* a green test per new oracle kind confirms a localhost finding
  via a fired signal and refutes a negative control. *(Verification, not weaponised
  exploitation — no payload leaves the test target.)*
- [ ] **Concolic / symbolic execution + SMT.** `[ALGORITHM][DEFENSIVE]` **XL (split)**
  — a symbolic engine over the analysis IR that solves path constraints (SMT) to
  reach a target predicate, feeding the oracle layer with concrete witnesses. *Why
  #1:* depth; reaches conditions fuzzing/taint miss. *Done =* a green test solves a
  guarded branch in a localhost sample and produces a concrete input the oracle
  confirms.
- [ ] **IFDS/IDE taint over a code-property graph.** `[ALGORITHM][DEFENSIVE]` **XL
  (split)** — upgrade `analysis/DAA` from the current taint passes to an IFDS/IDE
  solver over a unified CPG (AST+CFG+DFG). *Why #1:* precise interprocedural
  dataflow is the backbone of high-signal static findings. *Done =* a green test on
  a labelled source→sink corpus shows IFDS precision/recall beating the current
  builtin pass on the same corpus (honest numbers, no fixture-theatre).
- [ ] **Coverage-guided fuzzing over the CPG.** `[ALGORITHM][DEFENSIVE]` **L** —
  a coverage-guided fuzzer targeting localhost harnesses, prioritised by CPG
  reachability to candidate sinks, results routed to the oracle layer. *Why #1:*
  finds what static analysis argues about. *Done =* a green test shows the fuzzer
  reaches an instrumented sink in a localhost harness and the crash/assert oracle
  confirms it. *(Harnessed localhost targets only.)*
- [ ] **Calibration hardening.** `[ALGORITHM][DEFENSIVE]` **M** — ECE monitoring,
  reliability-curve regression gates, and drift detection over the OutcomeLedger,
  wired into eval. *Why #1:* a calibrated score that silently decays is worse than
  none. *Done =* a green test asserts ECE stays below a threshold on a held-out set
  and that a deliberately mis-calibrated model trips the gate.
- [ ] **Cross-engagement bandits.** `[ALGORITHM][DEFENSIVE]` **L** — a bandit over
  technique-operator selection that learns which operators pay off per target class,
  from the ledger, without leaking one engagement's data into another beyond policy.
  *Why #1:* the platform gets sharper every engagement — the self-improvement moat.
  *Done =* a green test shows regret decreasing over simulated engagements and
  strict per-engagement data isolation upheld.
- [ ] **Deconfliction leasing.** `[ALGORITHM][HARDENING]` **M** — a lease/lock layer
  so concurrent operators/agents don't collide on the same target surface. *Why #1:*
  national teams run many operators; deconfliction is table-stakes for accreditation.
  *Done =* a green test shows two agents contending for one surface and exactly one
  acquiring the lease, the other deferring.

### HORIZON — Enterprise graph, detection-cost, accreditation-grade governance

- [ ] **Enterprise identity / cloud / AD / K8s graph.** `[ONTOLOGY][ALGORITHM]
  [DEFENSIVE]` **XL (split)** — model identity, cloud IAM, Active Directory, and
  Kubernetes RBAC as typed nodes/edges in the world-model, so attack-path search
  reasons over enterprise trust relationships (all against localhost/simulated
  fixtures of these systems). *Why #1:* the surfaces national teams actually engage.
  *Done =* a green test builds an AD/K8s test graph and path-search finds a known
  privilege-escalation chain in the *simulated* environment. *(Simulated/localhost
  only — no live directory or cloud tenant.)*
- [ ] **DEL detection-cost model.** `[ALGORITHM][DEFENSIVE]` **L** — extend
  `defender/DEL` so each planned action carries a modelled *detection cost*, letting
  the planner trade objective progress against defender-visibility (to *inform*
  defensive posture and reporting, not to evade real defenders). *Why #1:* defender-
  aware planning is a differentiator; framed as detection accounting it stays
  defensive. *Done =* a green test shows the planner's chosen path reflects modelled
  detection cost and the cost is reported. *(Model/estimate only — no working
  evasion of any real detector.)*
- [ ] **Governance / entitlement hardening to accreditation grade.**
  `[HARDENING][ENTITLEMENT-GATED]` **L** — key-rotation, quorum-change ceremonies,
  offline entitlement verification, and full audit-chain coverage for every new
  Wave-4/5/6 capability. *Why #1:* the moat only holds if it's airtight; every new
  capability must be gate-able before it ships. *Done =* a green test asserts each
  new capability refuses to run without a valid m-of-n entitlement and logs the
  denial to the audit chain.
- [ ] **Sovereign egress conformance.** `[HARDENING][DEFENSIVE]` **M** — extend the
  `SOVEREIGNTY-EGRESS-AUDIT` posture with automated tests that fail if any subsystem
  performs unauthorised network egress at run time. *Why #1:* air-gapped/classified
  deployment demands provable no-egress. *Done =* a green test runs a produce cycle
  under an egress monitor and asserts zero unauthorised outbound connections.
- [ ] **Kill-switch coverage for new capabilities.** `[HARDENING][ENTITLEMENT-GATED]`
  **S** — every Wave-4+ capability honours `authority` kill-switch mid-run. *Why #1:*
  authority-to-halt is core to governed operation. *Done =* a green test trips the
  kill-switch during a planning/verification run and asserts the capability halts and
  records the halt.

---

## 4. SELF-REPLENISH protocol (how the queue never runs dry)

When the agent finds the actionable top of the backlog exhausted (or when the
count of unchecked items in the current wave drops below ~3), it MUST replenish
before ending the run:

1. **Run the completeness critic.** Ask, against the #1 bar (§1) and the gap
   analysis, the four questions and write down concrete gaps:
   - *Capability:* which prove-don't-guess / world-model / deep-analysis /
     governance capability is still missing or only partial?
   - *Ontology facet:* which node/edge type, condition, cross-reference, or
     provenance link is absent from ontologies (A)/(B)/(C)?
   - *Algorithm:* which algorithm from the target set (attack-graph derivation,
     k-best/min-cut, POMDP/MCTS, guided synthesis, concolic+SMT, IFDS/IDE,
     coverage-guided fuzzing, calibration, bandits, deconfliction) is unimplemented,
     shallow, or unverified?
   - *Hardening:* what accreditation/sovereignty/entitlement gap would block a
     classified deployment review?
2. **Diff against reality.** Grep the codebase to confirm the gap is real (a
   capability that already has a green acceptance test is *not* a gap). Never mint
   an item the code already satisfies — that would be fixture-theatre of the backlog.
3. **Mint new checklist items.** For each confirmed gap, add a `- [ ]` item under
   the right wave (or open a new Horizon cluster) with: deliverable, tags, effort,
   a *why-#1* line, and a *"done = a real green test proving X"* acceptance line.
   Every minted item must stay inside the defensive/verification/planning + governed
   boundary. Split any XL before it reaches the top.
4. **Re-prioritise.** Keep the highest-EV, dependency-unblocked item at the top of
   its wave. Oracle-loop and provenance items outrank depth items when both are open.
5. **Record the replenish.** Append a dated entry to the DONE LOG noting the run,
   the critic's findings, and the item count added. A run that replenishes but
   completes no delivery still logs the replenish so progression is auditable.

This loop is the engine: as long as the #1 bar is not fully met, the completeness
critic will always surface at least one real gap, so the queue is self-sustaining.

---

## 5. DONE LOG (append-only — each run records what it completed)

Format per entry:
`YYYY-MM-DD · <branch/PR> · COMPLETED: <items checked + acceptance test names> · REPLENISHED: <n items added, critic summary> · TESTS: <green/red + count>`

- 2026-07-03 · claude/flagship-wave1 · SEEDED: initial backlog authored from the
  Wave 1–3 audit + gap analysis. Verified against code: `critique_agent` already
  consumes `oracle_context` as confirmation authority, but `eval/produce.py` has
  0 references (producer→oracle wire-in confirmed as the genuine Wave 4 first item)
  and the reporter does not yet surface oracle provenance. REPLENISHED: ~30 items
  across Wave 4 / 5 / 6+ / Horizon. TESTS: not run this session (authoring only).
