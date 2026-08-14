---
name: crucible-beyond-sota-program
description: "The 14-wave beyond-SOTA capability program for CRUCIBLE (framework/v2), on branch crucible-beyond-sota / PR"
metadata: 
  node_type: memory
  type: project
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
---

CRUCIBLE (`framework/v2/`, GitHub Water-Hacker/PENTEST) got a 14-wave "beyond
state-of-the-art" upgrade, delivered on branch `crucible-beyond-sota` (PR #21,
opened 2026-07-05), one commit per wave. Plan lives at
`.claude/plans/parsed-popping-lemur.md`.

Waves: 1-3 foundation (wire the arsenal + campaign; `engage` runner with a gated
scanner-send adapter + live `oracle_context`; certificate re-verifier `verify` CLI
+ de-circularized calibration). 4-7 rigorous oracles (timing=Mann-Whitney+effect-
floor+dose+Holm; SPRT boolean inference; structural AST diff + HTML-context
reflection; predicate oracle killing the achieved-state rubber-stamp). 8-9
Bayesian belief (Beta per node/edge, lowers on refutation) + risk-averse
`lcb_weight` + expected-information-gain VOI planning. 10-11 membership-query
constraint inference + GA oracle-proximity fitness + PCFG grammar inference. 12
neurosymbolic chain synthesis (LLM proposes, oracle discharges per hop). 13
stealth-aware planning + `defender/gap_report.py`. 14 archetype transfer learning
+ eval-gated `scanner/check_synthesis.py`.

**Invariants that any future work MUST preserve:** every confirmation is a pure
oracle routed through `verify/verifier.py`'s safety-monotone gate, or a proposer
that never confirms; no traffic bypasses the gated `send`; each finding carries a
re-verifiable `oracle_context`. See [[crucible-testing-and-gotchas]].
