# Hypotheses log — `<target-name>`

Active hypotheses tracker. An item enters here when an
investigation begins; it leaves when confirmed (→ finding) or
refuted (→ moved to "closed" with reason).

This is the central artifact of OBSIDIAN's reasoning loop. The
quality of this log determines the quality of testing — both the
breadth (did we miss a hypothesis class?) and the depth (did we
test what we said we'd test?).

Status values: `Open` (active investigation),
`Confirmed` (finding written),
`Refuted` (closed with explanation),
`Parked` (interesting but blocked / lower priority),
`Re-opened` (was closed, now active again).

---

## Active

| ID | Hypothesis (Given/If/Then/Because) | Status | Owner | Discovery date | Notes |
|----|---------------------------------------|--------|-------|----------------|-------|
| H-001 | Given login at /login, if attacker submits 100 wrong passwords for one user, then the account is not locked, because no per-account rate limiter is observable. | Open | OBSIDIAN | 2026-MM-DD | Baseline timing established; 50 attempts done. |
| H-002 | Given password reset, if attacker sends Host: attacker.com header, then reset link points to attacker.com, because the URL is built from request host. | Open | OBSIDIAN | 2026-MM-DD | Need to trigger reset and capture email. |
| ... | ... | ... | ... | ... | ... |

---

## Closed — Confirmed

| ID | Hypothesis (short) | Finding | Closed date |
|----|---------------------|---------|-------------|
| H-005 | IDOR on /api/v2/orders/{id} | findings/003 | 2026-MM-DD |

---

## Closed — Refuted

| ID | Hypothesis (short) | Reason refuted | Closed date |
|----|---------------------|----------------|-------------|
| H-007 | SSRF on avatar URL | Tested 12 variants; server uses head-of-line allowlist before fetch, no external resolution attempted. | 2026-MM-DD |

---

## Parked

| ID | Hypothesis (short) | Reason parked | Re-open trigger |
|----|---------------------|----------------|-------------------|
| H-009 | Race condition on coupon redemption | Need staging env without rate-limit on POST /coupon/redeem; production has 1/sec limit. | When operator provides staging access. |

---

## Hypothesis-quality reminders

From `framework/cognitive/hypothesis-driven.md`:

- A hypothesis is **falsifiable** — there's a specific test that
  could disprove it.
- It's **specific** — names the surface, the input, the expected
  outcome.
- It's **explanatory** — names a *why* (the "because" clause).
- It's **prioritizable** — by likelihood × impact × effort.

If a hypothesis can't pass these checks, refine it before writing it
in.
