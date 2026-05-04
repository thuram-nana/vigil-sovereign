# Decision frameworks

How you score severity, prioritize remediation, decide when to chain
findings, and decide when something is worth surfacing as a finding
at all.

---

## 1. Severity — CVSS plus contextual adjustment

Use CVSS 3.1 base score for the per-finding score. Then add a
**contextual adjustment** with explicit reasoning, because CVSS base
is generic and a textbook score often misses what matters in this
specific product.

Each finding gets:
- `cvss_vector`: the vector string.
- `cvss_base`: the numeric base score.
- `severity`: the human label (Critical / High / Medium / Low / Info).
- `contextual_note`: why the severity differs from CVSS base, if it
  does.

### 1.1 When to override CVSS up

- Bug touches money flow directly. CVSS often underweights financial
  impact.
- Bug is exploitable at scale (any user, any tenant) without
  privilege.
- Bug is on a primary feature (the thing the product is for, not an
  admin-only edge case).
- Bug has known active exploitation in the wild for similar products.
- Bug provides a step in a chain that reaches Critical (chain bonus).

### 1.2 When to override CVSS down

- Bug requires preconditions that aren't realistic on this product.
  (E.g. CVSS counts admin-required attacks lower; if the product has
  no admin tier, an "admin XSS" CVSS is a reasonable target itself,
  but check.)
- Compensating controls are real and verified (WAF rule, monitoring,
  alerting, rate limit observed in practice).
- Bug is information-only (e.g. version disclosure) without a clear
  path to exploitation in this stack.

Always justify the override in `contextual_note`. Never override
silently.

### 1.3 Severity ladder — pragmatic definitions

| Severity | Practical meaning |
|----------|-------------------|
| **Critical** | Pre-auth or low-priv direct path to: full takeover, mass user data, money movement, RCE, mass ATO. Immediate operator action required. |
| **High** | Path to those outcomes with realistic preconditions; OR direct compromise of a single user's account/data; OR compromise of admin via low-priv path. |
| **Medium** | Bug with real impact but constrained scope. Single-user data leak, IDOR with limited cascading, weak auth that's slowed-but-not-stopped by other controls. |
| **Low** | Real bug, low real-world risk. Information disclosure without obvious attack path; weak headers; outdated banner; verbose errors. |
| **Info** | Hardening recommendations, non-bugs worth noting (no HSTS preload, no CAA records, etc.) |

When in doubt between two severities, pick the higher one and
justify. Operators react to the label — better to have them react
to a slight overshoot than to miss an actual high.

---

## 2. Likelihood × impact — a second axis

For prioritizing remediation (not for severity scoring), consider:

| | Low likelihood | High likelihood |
|---|---|---|
| **High impact** | Fix soon | Fix immediately |
| **Low impact** | Defer / risk-accept | Fix opportunistically |

Likelihood factors: ease of exploitation, attacker skill required,
attacker effort required, public availability of exploit
techniques, incentive (does anyone gain from this?), preconditions,
detection probability.

The remediation roadmap (`reports/remediation-roadmap.md`) sorts
findings on this 2x2, not just by severity.

---

## 3. Worth reporting? — the threshold question

Some test results are interesting but not real bugs. Some are real
bugs but not actionable. Decide:

- **Report as finding**: anything where the operator should change
  something (code, config, process). Includes Info.
- **Note in engagement log only**: things that are interesting but
  not bugs (technology choice, design tradeoffs, "could be improved
  but isn't broken"). The operator may want to know, but not as a
  finding.
- **Skip entirely**: trivial things that distract — minor banner
  disclosures on a dev tool, nginx version exposure when there are
  10 critical bugs above it.

Senior testers don't pad finding counts. A 30-finding report with
20 padded Lows is worse than a 10-finding report where every entry
is real.

---

## 4. Chains — when to combine findings

Combine when the chain reaches an outcome that no constituent
reaches alone, and the chain is realistic (not "and then a unicorn
shows up").

A chain finding (`findings/CHAIN-NNN-slug.md`):
- References each constituent finding.
- Has its own severity (often higher than any constituent).
- Has its own impact statement (the chained outcome).
- Has its own remediation — sometimes "fix any one of the constituent
  findings" is enough; sometimes a structural fix that breaks the
  chain entirely is better.

Don't artificially compose chains for severity inflation. The chain
must be a path a real adversary would walk.

---

## 5. The "explain it to a regulator" test

For each Critical and High finding, draft the impact in language a
non-technical regulator (or partner, or insurance carrier) would
understand:

> *Without this fix, an attacker could [action] and obtain [data]
> with [effort]. The estimated business impact is [number/range].
> A similar issue at [public reference, if applicable] led to
> [outcome].*

If you can't write that paragraph, you don't fully understand the
finding's impact, and the operator can't act on it confidently.
Don't move on until you can.

---

## 6. When to surface immediately vs hold

Surface to the operator immediately (don't wait for phase summary):

- Anything that allows account takeover at scale.
- Anything that allows direct money movement.
- Anything that gives RCE on the host.
- Evidence of prior compromise (active intruder).
- Exposed credentials, keys, or secrets that need rotation now.

Hold for phase summary:

- Medium/Low findings.
- Information disclosure without an obvious chain.
- Things that depend on the operator's roadmap (e.g. "you should
  switch to OAuth" — a project-level decision).

The asymmetry: missing a critical for a few hours is bad; double-
notifying for a low is fine.

---

## 7. The "is this exploitable in this product" question

A textbook bug class that doesn't actually compose into impact in
this product is a Low-or-Info, not a High.

Example: open redirect on `/login?next=`. Textbook Low. But:

- If the login page does OAuth → potential auth-code theft (High).
- If `next=` is whitelisted to the login domain only → Info.
- If the login page is unauthenticated and `next=` is rendered into
  HTML somewhere → reflected XSS (Medium-High).

Always trace the bug from the surface where it exists to the actual
impact in this product. Don't paste a CVSS calculator output without
the trace.

---

## 8. Risk acceptance

Operators can choose to accept a risk rather than fix it. That's a
legitimate decision. Document, don't argue:

```
Status: Risk Accepted
Reason: <operator's reason>
Compensating controls: <what they're relying on instead>
Re-evaluate: <date or trigger>
```

Risk acceptance for a Critical without compensating controls should
be challenged once, with the risk clearly stated. After that, it's
the operator's call. Document and move on.

---

## 9. Effort estimates for remediation

For the remediation roadmap, estimate effort per finding:

- **S** (small): config change, one-line code change, one-file edit.
  Hours.
- **M** (medium): refactor a controller, add middleware, change a
  schema. Days.
- **L** (large): structural change (auth layer, payment integration
  redesign, framework upgrade). Weeks.
- **XL** (extra large): cross-team or external dependency. Quarter+.

Effort estimates inform sequencing. A High-severity S-effort fix is
the operator's first move; a Medium-severity XL fix is a roadmap
item.
