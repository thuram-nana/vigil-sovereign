# CLAIM DISCIPLINE — the capability contract VIGIL is held to

**This document raises the system; it does not lower the claim.**

Read that first, because the failure mode of every "do not overclaim" rule is a ratchet: each inconvenient
capability gets quietly redefined as out of scope, every sentence stays technically true, and the product
becomes honest about doing less and less. That is not the goal and it is not permitted here.

The contract is two-sided. A claim must be true *today* — and where it is not yet true, the gap is **build
work with a name**, recorded in `docs/capability-matrix/evidence-branches.json` as `blocking_work` and
enforced by a test. A capability may never be abandoned by editing the claim down; the claim stands and the
engineering comes up to meet it. Lowering a *target* requires arguing the capability is unachievable, not
merely inconvenient.

So the two enforcement directions are equal partners:

1. **Never assert what is not established** — an overclaim destroys trust in everything else.
2. **Never leave a capability unbuilt by narrowing the claim** — a silent downgrade destroys the product.


VIGIL's entire value proposition is that its output is *true*. A tool that finds real bugs but also asserts
things it has not established is worth less than one that finds fewer bugs and never misstates them: its
findings can be relied upon through deterministic offline verification, without repeating the original
investigation. Re-running the engagement is the expensive part; re-checking a signed certificate is not.

This document is **binding and enforced**. `engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py`
mechanically checks the rules marked **[ENFORCED]** on every CI run — as a **registry lint plus runtime
admission tests**, which is narrower than "the codebase obeys this". Specifically it validates the
declarations in the registry, that admission behaves as declared, and that capability-describing documents
carry their boundaries. It does **not** statically prove that every code path routes through admission; that
property rests on rule 5's adversarial review and is marked accordingly. A rule written here that is not enforced
is marked **[REVIEW]** and must be checked by a human reviewer before merge. Adding prose here without either
an enforcement test or a `[REVIEW]` marker is itself an overclaim about this document.

---

## 0. The one rule everything else serves **[REVIEW]**

> **Never assert more than the evidence establishes — in either direction.**

Both directions matter equally, and this is the rule people get half-right:

- Asserting a vulnerability that is not there (**false FACT**) destroys trust in every finding.
- Asserting *safety* that was not established (**false CLEAN**) is worse, because nobody goes looking again.

"We looked and found nothing" is only CLEAN if we actually looked. If anything prevented us from looking —
no channel, an undecodable body, a truncated response, an unsupported encoding, a parser we do not trust for
this input — the answer is **INCONCLUSIVE**, and INCONCLUSIVE must be reported, never quietly folded into
CLEAN.

---

## 1. Claim vocabulary — the only four verdicts **[ENFORCED]**

| Verdict | Means | Required to say it |
|---|---|---|
| **FACT** | The declared predicate was **established** under the certified target, inputs, system state and observation interval | A deterministic VIGIL-owned oracle re-derived it over evidence VIGIL itself captured live through a gated channel, and the certificate re-verifies offline |
| **LEAD** | Something suggests this; we did not prove it | Any weaker signal — a tool's assertion, a heuristic, an LLM's opinion, a regex over a context we cannot fully parse |
| **CLEAN** | The declared predicate was **conclusively refuted** under the certified target, inputs, system state and observation interval | We had a real channel, the evidence was *semantically available* for that branch, and a conclusive oracle refuted the predicate |
| **INCONCLUSIVE** | We could not tell | Everything else — and it is a first-class result, never a rounding error toward CLEAN |

Nothing else may appear in output — the verdict type is a closed enum, so this is a property of the type
rather than a convention. "Probably safe", "no issues found", "secure" are not verdicts.

Both FACT and CLEAN are **bounded observations, not timeless properties of the target.** A live system
changes; a verdict describes what was established during a specific observation of a specific configuration.
This costs CLEAN none of its strength — a conclusive refutation under stated conditions is exactly what a
defender needs — while keeping the claim honest about what an observation can support.

## 2. CLEAN-capability must be declared per evidence branch **[ENFORCED]**

FACT-capability and CLEAN-capability are **different claims** and must be tracked separately. A branch can be
sound for confirming a bug and unsound for asserting its absence — the discriminator that safely under-claims
in one direction becomes a false negative in the other.

Every evidence branch that can produce a verdict is declared in
`docs/capability-matrix/evidence-branches.json` with:

- `fact_capable` — may this branch mint a signed FACT?
- `clean_capable` — may a non-firing of this branch be reported as CLEAN?
- `preconditions` — what must hold for the evidence to be usable at all
- `limitation` — the honest statement of what it cannot see

**A branch with no declaration may not produce a verdict.** This is enforced at RUNTIME, not by a lint:
every verdict passes through `integration/vigil_integration/live/verdict.py::admit`, which raises
`UnregisteredBranch` for an id that is not in the registry, downgrades a fired oracle to LEAD when the branch
is not `fact_capable`, and returns INCONCLUSIVE instead of CLEAN when the branch is not `clean_capable` or
its preconditions did not hold for that observation. The registry therefore governs behaviour rather than
describing it.

Preconditions are evaluated **per branch against that specific observation** — not once per response. "The
body was readable" is irrelevant to a header-derived branch and decisive for a markup one, so a single
capture can legitimately yield a header-derived CLEAN and a body-derived INCONCLUSIVE at the same time.

## 3. Capability claims must state their boundary **[ENFORCED-LINT + REVIEW]**

Any document that claims a capability must state the boundary of that capability in the same place. Naming a
family ("the web family is FACT-capable") when only part of it qualifies is an overclaim even when every
individual sentence is true — scope inflation is the most common way honest text becomes dishonest.

The lint rejects capability-describing text containing an absolute claim with no qualifier in the same
paragraph. **The banned list is not reproduced here.** It lives in `_ABSOLUTES` in the enforcement test and
is the single source of truth — duplicating it into prose is how a checker and its documentation drift apart,
and a stale list in a governance document is itself a false claim about what is enforced. Read the test.

The lint half is mechanical; the REVIEW half is not, and matters more: **adjacency does not prove the
qualifier actually bounds the claim.** A reviewer must judge whether the stated limitation genuinely covers
what the sentence asserts.

## 4. Do not hand-approximate a specified algorithm **[REVIEW]**

If a verdict depends on how a specification behaves — HTML tokenization, character encoding, a URL parser, a
protocol state machine — use a real implementation of that specification, or implement its steps literally
with the spec open. Do **not** pattern-match your intuition of it.

This is not style advice, and it is not a universal law either — it is a bounded, replayable observation
about this repository. In wave #3 (branch history `53cc6fc..82b9096`, PR #250), a hand-written HTML masker
accounted for ~15 of the wave's defects across four adversarial rounds before it was deleted, and three
hand-approximations (tokenization, script-data escaping, declarative refresh) were each observed wrong in
**both directions at once** — minting false FACTs *and* certifying vulnerable pages clean. In each of those
three cases the defect class stopped recurring only after the real implementation replaced the guess. Re-read
the commits before treating this as settled for a new context.

Corollary: pair any such parser with a **differential test** against a reference implementation, asserting
both directions, plus a guard proving the corpus is non-vacuous.

## 5. A fix is not done until it is re-attacked in both directions **[REVIEW]**

Across the eleven adversarial rounds of wave #3, every round found a real defect in the previous round's
fix — including cases where a *performance* fix introduced *correctness* defects (twice) and a *hardening*
fix silently dropped a real vulnerability (twice). That is a measured property of that wave, not a proof
about all future changes; treat it as a strong prior, and note that round 7 did return a clean PASS.

So: after fixing, ask both questions explicitly — *can this now mint something false?* and *can this now miss
something real?* — and get an independent adversarial pass before merge. Green tests and a green gate are the
starting point of verification, not the end of it.

## 6. Tests must be able to fail **[REVIEW]**

- A negative control must exercise the surface it claims to cover. A control chosen to avoid the failure mode
  is worse than none, because it manufactures confidence.
- A performance bound must use an input that does **not** short-circuit; a payload that returns on the first
  iteration keeps the test green while the slow path reopens.
- Prefer **mutation-verifying** a guard: break the implementation, confirm the test fails, restore.
- A test asserting what the implementation happens to do — rather than what the specification requires — is
  not a test. Two such tests shipped here and both encoded a wrong premise.

This rule is [REVIEW]: no machine decides whether a control is substantive. What exists is a practice —
mutation-verify each guard — which found four defects in this contract's own tests, including a precondition
check that passed for the wrong reason and an untested default that would have let an unreported fact unlock
a CLEAN.

## 7. Verification claims must be re-checkable **[REVIEW]**

Never state a test result you have not just observed. Quote counts, commands and outcomes as run. If a suite
was skipped, say skipped. If a check was not wired into CI, do not describe it as gating anything —
`framework/v2/scanner` held 76 test files and **zero** CI references while its results were being cited as
evidence, which made every "CI green" claim about those predicates false.

Corollary: a guard that tests *availability* where *capability* is what matters is not a guard. Browser tests
here checked that a Chrome binary existed rather than that it could render.

**Why this is [REVIEW] and not [ENFORCED]:** nothing currently proves that a quoted result was just observed,
that counts match a real artifact, that a cited suite is wired into CI, or that skips were disclosed. Marking
it enforced would be this document committing the exact error it prohibits. Closing it requires CI to emit a
machine-readable **verification manifest** — command, commit, exit status, pass/fail/skip counts, artifact
digest — that claims can be checked against. That is named work, tracked in the registry's `blocking_work`
vocabulary, not an accepted permanent gap.

## 8. Residuals are published, not buried **[ENFORCED-LINT + REVIEW]**

Every known limitation lives in the code at its point of use **and** in the capability matrix. "Contrived to
trigger" is a reason to rank something low, never a reason to leave it undocumented. An honest residual costs
almost nothing; a discovered-but-unmentioned one costs the project its credibility.

Each branch also carries `implementation_refs` (`path:symbol`) and the lint verifies those resolve, so the
declaration cannot drift away from the code it describes. What the lint **cannot** establish, and a reviewer
must: that every known residual reached the registry at all, and that a non-empty `limitation` string is
complete or meaningful. A registry entry proves a limitation was *written*, not that it is *true*.

---

## Enforcement

```
pytest engine/crucible/framework/v2/scanner/tests/test_claim_discipline.py
```

Runs in the `CRUCIBLE core` CI leg. What it actually verifies, precisely:

- the registry is internally consistent (every branch declares `fact_capable`, `clean_capable`, evidence and
  a limitation as explicit values);
- every gap between current and target capability names the `blocking_work` that closes it, and a lowered
  target carries a rationale;
- `admit()` behaves as declared — unregistered branches are refused, a non-`fact_capable` branch cannot mint,
  a non-`clean_capable` branch or an unmet precondition yields INCONCLUSIVE rather than CLEAN;
- capability-describing documents contain no unqualified absolute claims.

What it does **not** verify: that every verdict-producing code path calls `admit()`, that the registry's
limitations are *complete*, or that any branch's underlying oracle is correct. Those rest on the differential
tests, the adversarial rounds, and human review.

When this file and the code disagree, **the code is the claim** — fix the code or fix the claim, never the
description alone.
