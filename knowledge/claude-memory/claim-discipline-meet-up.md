---
name: claim-discipline-meet-up
description: "VIGIL's binding rule for handling overclaims — RAISE the system to meet the claim, never downgrade the claim"
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 7758e121-f349-47d5-886b-6bb5a1d60e27
  modified: 2026-08-10T18:20:58.423Z
---

The operator's binding directive (2026-08-10) and the document that specifies it, `docs/CLAIM-DISCIPLINE.md`
(repo thuram-nana/vigil-sovereign): **"This document raises the system; it does not lower the claim."**

When a red-pen / audit finds an overclaim, DO NOT fix it by softening the claim to match current code
(a "silent downgrade destroys the product"). Instead:
- A claim must be true **today** — so a present-tense assertion of a capability VIGIL lacks is still forbidden
  (that's the overclaim direction).
- Where the capability is not yet true, the gap becomes **build work with a name**: an entry in
  `docs/capability-matrix/evidence-branches.json` under the `blocking_work` vocabulary, **enforced by a test**
  — the target STANDS and the engineering comes up to meet it. Lowering a *target* requires arguing it is
  *unachievable*, not merely inconvenient.
- Prefer to **BUILD the capability now** (raise the system) so the claim becomes a verified FACT; only name it
  as tracked `blocking_work` when it can't be built immediately, and honestly mark the truly irreducible.

Both enforcement directions are equal partners: (1) never assert what is not established (overclaim destroys
trust); (2) never leave a capability unbuilt by narrowing the claim (silent downgrade destroys the product).
Enforced by `engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py` (CRUCIBLE-core CI leg):
registry lint + `admit()` runtime admission tests + capability-doc boundary lint. "When this file and the code
disagree, the code is the claim — fix the code or the claim, never the description alone."

**How to apply:** on any audited overclaim in VIGIL, build the detection/capability up to meet it (with a
mandatory negative control + make-gate byte-identity + red-pen), or register a named `blocking_work` target;
NEVER just reword a DETECTS down to a MISSES. This is the core of the [[vigil-truthenovation-program]].
