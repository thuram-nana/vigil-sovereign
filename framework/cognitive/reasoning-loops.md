# Reasoning loops

How OBSIDIAN cycles through observation, hypothesis, test, and update —
fast and many times — instead of running a static checklist.

---

## 1. The basic loop

```
   ┌────────────────────────────────────────────────────────────┐
   │                                                            │
   ▼                                                            │
OBSERVE  ──►  ORIENT  ──►  HYPOTHESIZE  ──►  TEST  ──►  UPDATE ─┘
                                                                 │
                                                  ┌─ CRITIQUE ◄──┘
                                                  ▼
                                              CONTINUE / PIVOT
```

Each cycle is fast — minutes — not hours. Slow cycles are the failure
mode of inexperienced testers. Senior testers run hundreds of cycles
per day, most refuting cheap hypotheses cheaply.

---

## 2. OBSERVE — what's true now

Pure description, no inference.

- What did the last test return? Status, body, headers, timing,
  cookies set, redirects.
- What does the application actually do, observably, vs what its
  docs / UI claim?
- What error messages did it produce? What does the error format tell
  me about the framework?
- What state has changed in the target? In my own working directory?

Do not skip observation. The bug class most testers miss is the one
they did not actually look at — they pattern-matched to expectation
and moved on. When something feels boring, look harder.

---

## 3. ORIENT — where am I

Place the observation inside the target model.

- Where am I in the kill chain? (recon / mapping / vuln-hunt /
  exploitation / post-exploit / chaining)
- Which trust boundary did this observation come from? Same-origin?
  Cross-tenant? Privileged? Public?
- What attack surface is this on the surface inventory? Have I covered
  it before? Partially?
- What's my current belief about how this part of the app is built?
  What would falsify that belief?

Reference: `framework/cognitive/threat-modeling.md` (the model you're
orienting against), `framework/cognitive/kill-chain.md` (the phase
context).

---

## 4. HYPOTHESIZE — generate, then narrow

The trap: form one hypothesis, fall in love, test only it, miss
everything else. Defeat the trap by forcing breadth before depth.

For any meaningful observation, generate **at least five** plausible
hypotheses before committing to a test. If you cannot generate five,
your model of the target is too thin — go back to ORIENT and look
harder, or read the source if available, or run more recon.

Hypothesis-generation prompts (use as forcing function):

- *Class*: "If this app has a flaw of class {SQLi / IDOR / SSRF / race
  / business-logic / SSTI / deserialization / auth-bypass / mass-
  assignment / XXE}, what would I observe at this surface?"
- *Adversary*: "What would a {script kiddie / financially-motivated
  criminal / nation-state actor / disgruntled insider / supply-chain
  attacker} try here that I haven't?"
- *Inversion*: "What invariant is this code enforcing? What if I
  violate it in a way the developer didn't anticipate?"
- *Side-effect*: "What's the side-effect of this action that I'm not
  observing? Where does it write? What does it call?"
- *Race*: "Is this idempotent? What happens if I do it twice
  simultaneously?"
- *Boundary*: "What's the trust boundary here? Who's allowed to do
  this, and how is the check implemented?"

Each hypothesis must be falsifiable — name an observation that would
disprove it.

---

## 5. TEST — design the cheapest experiment

Before sending traffic, ask:

- What is the **minimum** test that would refute the hypothesis?
- What evidence will I capture? (request, response, timing, side-
  effect)
- What's the risk to the target? (low → just send; medium → throttle;
  high → ask operator)
- How will I clean up? (DB rows, files, accounts, sessions)

Run. Capture evidence to `targets/<name>/evidence/`.

Default to **manual probing first**, automated tools second. A
single curl or browser request, examined by you, beats `nuclei -t
all/` for understanding. Automated tools are for coverage and
confirmation, not discovery.

---

## 6. UPDATE — confirm, refute, surprised

Three outcomes from a test:

- **Confirmed**: hypothesis stands; finding candidate. Write it up
  immediately (`findings/NNN-slug.md`) — don't defer; the details fade
  fast.
- **Refuted**: hypothesis disproven. Note in `notes/hypotheses.md`
  with status `refuted` and the test result. This is value — you've
  closed off a thread.
- **Surprised**: result didn't fit any of your hypotheses. **Stop
  and investigate.** Surprises are the most valuable signal an
  attacker sees. Re-orient: what does the unexpected behavior tell
  you about the target? Generate fresh hypotheses against the new
  observation.

Update working memory:
- `notes/hypotheses.md` (status, result)
- `notes/engagement-log.md` (significant moments)
- `notes/command-log.md` (commands run)
- `findings/NNN-*.md` (if confirmed)

---

## 7. Coupling depth and breadth

Two failure modes to avoid:

- **Pure depth (rat-hole)**: one thread for hours. Symptom: spent
  three hours on a single suspected SQLi without a working PoC and
  without trying any other class.
- **Pure breadth (skim)**: every surface poked once. Symptom: lots
  of "looked at it, no obvious bug" without a hypothesis tested
  rigorously enough to actually rule the class out.

Calibration:
- Set a soft budget at hypothesis time: "I'll spend up to 30 min on
  this hypothesis, then re-evaluate." If 30 min in you have neither
  PoC nor refutation, run a critique cycle (next section).
- Maintain a TODO of attack surfaces × classes. Visit one, complete a
  cycle, return to TODO, pick next-highest-EV.

---

## 8. Critique cadence

Run `framework/cognitive/self-critique.md` at:

- Every phase boundary (`ENGAGEMENT-LIFECYCLE.md`).
- Every 30 minutes on a single thread without progress.
- Any time the operator asks "what's left?".
- Before declaring the target done.

The critique routine is the antidote to confirmation bias and depth
fixation. It's not optional.

---

## 9. Working memory hygiene

You operate inside a context window that loses old detail. Compensate
by writing down:

- Hypotheses as they're formed (`notes/hypotheses.md`)
- Refutations as they're confirmed (`notes/hypotheses.md` with status)
- Confirmed findings the moment they're confirmed (`findings/`)
- Any commit-worthy fact that you'd want to recall after a break
  (`notes/engagement-log.md`)

When returning to a target after a session boundary, **start by
reading these files**. The framework's purpose is to be the working
memory you don't have natively.

---

## 10. Anti-patterns to refuse

- "I'll just check this one more thing" — without writing down what
  you're doing or why.
- "It's probably fine" — based on no test.
- "The framework escapes that" — without verifying which framework
  and which version.
- "I'd need to look at the source" — when the source is available
  in `loot/source/`.
- "It works in the wild but I can't reproduce it" — go reproduce it.
  An unreproducible finding is not a finding.
- "I'll write this up at the end" — at the end you've forgotten the
  request that fired it.

When you catch yourself in any of these, stop. Run a critique cycle.
Reset.
