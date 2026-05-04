# Threat modeling

Before testing a target, you build a model of it. The model tells you
where to look, what's worth looking at hardest, and what attacks
matter. Without a model, you are running automated tools and hoping.

The threat model is a **living document**. Started in stage 1, updated
every time you learn something material. Lives at
`targets/<name>/threat-model.md`.

---

## 1. What a threat model contains

Five sections:

1. **Assets** — what does the target hold/process that an attacker
   would want? (credentials, money, PII, intellectual property,
   compute, reputation, regulatory standing)
2. **Actors** — who would attack? (script kiddie, financially-
   motivated criminal, insider, competitor, nation-state, supply-
   chain attacker, automated bot)
3. **Trust boundaries** — where does data/control cross between
   privilege levels? (anon → authenticated user, user → admin,
   tenant → tenant, app → DB, app → cloud, app → third-party)
4. **Threats per boundary** — STRIDE applied at each boundary.
5. **Attack tree** — adversary objectives at the root, decomposed
   into sub-goals and concrete techniques at the leaves.

Build them in that order. Skipping the assets step is the most common
threat-modeling mistake; you end up listing CVEs instead of impact.

---

## 2. Assets — what's worth attacking

For each asset, three questions:

- **Confidentiality**: who would pay to see this?
- **Integrity**: who would pay to change this?
- **Availability**: who would pay for this to be unavailable?

Rank by combined business impact, not by how interesting the
technology is.

Example for an SMM panel:

| Asset | Conf | Integ | Avail | Top adversary | Why |
|-------|------|-------|-------|---------------|-----|
| User credentials | high | high | low | criminal | resale, ATO |
| User balances | low | critical | low | criminal | direct theft |
| User social-account targets | high | low | low | competitor | lead lists |
| Payment-provider keys | critical | critical | medium | criminal | drain processor |
| Order pipeline upstream creds | high | high | low | criminal | service theft |
| Admin panel | critical | critical | medium | criminal | full takeover |

The first row to study is the row with the highest combined column
weighted by adversary realism.

---

## 3. Actors — who's actually attacking

Profile the realistic adversary set for *this target*, not all of them
in the abstract:

- **Skill**: novice / journeyman / expert / nation-state.
- **Motivation**: opportunistic (will move on if friction) /
  motivated (specific target, will persist) / strategic (will pivot
  through the network of related apps).
- **Resources**: solo / small team / well-funded.
- **Tools**: public scanners / CVE chaining / 0-days.
- **OPSEC**: noisy / stealthy.
- **Goal**: data theft / monetization / disruption / reputation.

For an owner-test, you emulate the **likely adversary set**, not the
worst case. A small SaaS doesn't need APT-grade emulation; it needs
to survive the criminal-with-public-tools tier robustly. Calibrate
your effort to the realistic threat.

---

## 4. Trust boundaries — where you focus

Find every place where data or control crosses a privilege level.
Each crossing is a potential bug site.

Common boundaries on a web app:

- Browser → web app (anonymous)
- Authenticated user → web app
- User-A → User-B (tenant isolation)
- User → admin
- Web app → DB
- Web app → cache (Redis, Memcached)
- Web app → message queue
- Web app → third-party (payment, email, SMS, upstream API)
- Web app → cloud metadata service
- Web app → file system
- Browser → another origin (CORS)
- Server-to-server within the cluster (microservices, mTLS)
- Build pipeline → deployed artifact
- Repository → CI/CD → cloud (IAM)

For each boundary, document:
- What data crosses?
- What's the auth/authz check?
- Where in code is the check?
- What's the failure mode if the check fails?

This list is your priority for vulnerability hunting in stage 4.

---

## 5. STRIDE per boundary

For each boundary, walk STRIDE and note plausible threats:

| STRIDE class | Question to ask |
|--------------|-----------------|
| **S**poofing | Can someone impersonate a legitimate party here? |
| **T**ampering | Can data crossing the boundary be modified in transit or at rest? |
| **R**epudiation | Can an action be denied by its actor? Is logging trustworthy? |
| **I**nformation disclosure | Can an attacker read what they shouldn't? |
| **D**enial of service | Can an attacker exhaust resources? |
| **E**levation of privilege | Can an attacker increase their privilege by crossing this boundary? |

Don't list every theoretical possibility — list the realistic ones for
this target. A stripe-down STRIDE pass per boundary takes 5–15 min
and produces real test ideas.

---

## 6. Attack trees

Take the top assets, root each one as an adversary objective,
decompose to sub-goals, decompose to techniques. The leaves are
testable.

Example fragment for "drain user balances":

```
Drain user balances
├── ATO targeted users and place orders
│   ├── Brute force / credential stuffing
│   │   └── No rate limit / weak rate limit on /login
│   ├── Password reset abuse
│   │   ├── Predictable reset token
│   │   ├── Host header injection in reset email
│   │   └── Reset token leaks via Referer
│   ├── Session hijack via XSS
│   │   ├── Stored XSS in support ticket subject
│   │   └── Stored XSS in profile name (admin view)
│   └── Steal session via CSRF + session-bound action
├── Forge balance crediting
│   ├── Webhook callback without auth
│   ├── Webhook with weak signature (length-extension, timing)
│   └── Manual deposit "I paid" with reused tx hash
├── Bypass balance deduction at order time
│   ├── Race condition (HTTP/2 single-packet attack)
│   ├── Negative quantity in order
│   ├── Client-trusted price/total field
│   └── Mass-assignment of balance in profile update
├── Refund-loop abuse
│   ├── Refund eligibility window misenforced
│   ├── Race-double refund
│   └── Refund without authorization (IDOR on /refund)
└── Coupon/voucher abuse
    ├── Reuse same code
    ├── Stack codes
    └── 100%+ off arithmetic
```

Each leaf maps to one or more playbook tests. The tree gives you
**coverage** (you can see which branches have not been tested yet) and
**prioritization** (some branches are clearly higher-impact than
others).

Build the tree at the start. Refine it as you learn. Mark each leaf
as tested / found-vulnerable / found-safe / blocked / deferred. The
tree at the end of the engagement is your coverage receipt.

---

## 7. Abuse cases — flip the user story

For each major user feature ("user places an order", "user resets
password", "admin manages services"), write the abuse case:

> **As an attacker, I want to ... so that ...**

Examples:
- *As an attacker, I want to place an order without paying so that I
  can drain a user's balance.*
- *As an attacker, I want to register an account with role=admin so
  that I have full panel control.*
- *As an attacker, I want to upload a file that executes server-side
  so that I can take over the host.*

Abuse cases force you out of the "happy path" mindset that
documentation and code reviews live in. Each abuse case yields several
attack-tree leaves.

---

## 8. PASTA (process-level threat modeling)

For larger or more critical engagements, follow PASTA stages:

1. **Define objectives** — business goals and risk appetite.
2. **Define technical scope** — components, frameworks, dependencies.
3. **Decompose application** — data flow, trust boundaries.
4. **Threat analysis** — relevant adversaries and their methods.
5. **Vulnerability analysis** — actual flaws.
6. **Attack modeling** — chain vulnerabilities into realistic attacks.
7. **Risk and impact** — score and prioritize remediation.

PASTA is heavier than STRIDE. Reach for it on engagements where the
operator wants a defensible, repeatable threat model used for
governance — not on a quick weekend audit.

---

## 9. Output

The threat model document at `targets/<name>/threat-model.md` is the
output. It is:

- A reference for you while testing.
- A communication tool for the operator (they understand "we tested
  these branches" better than they understand a dump of CVE-style
  findings).
- A persistent artifact that survives the engagement and helps with
  re-tests, hires, and governance reviews.

Use the template at `framework/templates/threat-model.md`. Don't make
it pretty. Make it complete.

---

## 10. Common mistakes

- **Listing CVEs instead of threats.** A CVE is a vulnerability, not
  a threat. The threat is what an adversary wants to do.
- **Pretending nation-state is the threat.** It's almost never the
  realistic top threat. Don't gold-plate against APT while ignoring
  credential stuffing.
- **Not updating the model.** Threat models that aren't revised
  during the engagement become decorative. Update at every phase.
- **Conflating "what could happen" with "what will happen".** The
  model should highlight realistic, motivated adversary actions, not
  every theoretical possibility.
- **Skipping it.** "I'll just start testing" is what gets engagements
  to spend two weeks on the wrong things.
