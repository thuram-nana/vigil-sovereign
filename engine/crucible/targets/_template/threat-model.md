# Threat model — `<target-name>`

**Version:** 1.0
**Last updated:** YYYY-MM-DD

This document is a **living** artifact. Initialized at stage 1 and
updated whenever something material is learned during the engagement.
At engagement close, a cleaned-up version may be produced as a
deliverable (`reports/threat-model.md`).

---

## 1. Target description

- **What it is**: one paragraph in plain language.
- **What it does**: top user features.
- **Who uses it**: user types and rough scale.
- **Where it runs**: hosting topology (single host, multi-region,
  cloud, etc.).
- **Stack**: language, framework, primary database, cache, queue,
  third-party integrations.
- **History**: notable architecture changes, prior incidents, known
  pain points.

## 2. Assets

What does the target hold or process that an adversary would want?

| Asset | Confidentiality | Integrity | Availability | Top adversary | Why valuable to them |
|-------|----------------|-----------|--------------|---------------|----------------------|
| User credentials | High | High | Low | Criminal | Resale, account takeover |
| User balances / wallet | Low | Critical | Low | Criminal | Direct theft |
| Payment-provider API keys | Critical | Critical | Medium | Criminal | Drain at provider |
| User PII (email, name, address) | High | Low | Low | Criminal | Resale, fraud |
| Admin credentials | Critical | Critical | Medium | Criminal | Full takeover |
| Source code / proprietary logic | Medium | High | Low | Competitor / criminal | Replication or attack-prep |
| Customer relationships / reputation | High | High | Medium | Operator (defender) | Business continuity |

Rank assets by combined adversary value. The top three are where the
attack tree should focus most.

## 3. Adversary profile

Who realistically attacks this target?

| Adversary | Motivation | Skill | Resources | Likely behavior |
|-----------|-----------|-------|-----------|-----------------|
| Script kiddie | Opportunity, kudos | Novice | Public tools | Loud scans, public exploits, pivots away if friction |
| Financially-motivated criminal | Money | Expert | Moderate | Targeted, persistent, automation, cashout savvy |
| Competitor | Disruption / IP | Variable | Variable | Subtle, targeted, low-noise |
| Disgruntled insider | Revenge / theft | Insider knowledge | Insider access | Low-noise, abuses legitimate access |
| Supply-chain attacker | Pivot / scale | Expert | High | Targets dependencies, build systems, vendor accounts |
| Nation-state | Strategic | Top-tier | Vast | Realistic only at certain scales / sectors |

Mark the **realistic top 1–3** for this product. Test your
methodology against those, not against the abstract "all
adversaries". Most operators face script-kiddie + financially-
motivated criminals as the realistic top tier. Don't gold-plate
against APT while a credential-stuffing bot is breaking in daily.

## 4. Trust boundaries

Where does data or control cross between privilege levels?

```
[Anonymous]  →  [User]  →  [Reseller]  →  [Admin]  →  [System root]
       \           \            \             \             |
        \           \            +→ [DB]      +→ [Cloud]    |
         \           +→ [Cache, Queue]                       |
          +→ [Static asset CDN]                              |
```

For this target, document each non-trivial boundary:

| Boundary | What crosses | Auth/authz check | Where (file:line if known) | Failure mode |
|----------|--------------|------------------|----------------------------|--------------|
| Anonymous → User (login) | Credentials | Username + password (+ MFA?) | `<file>` | Rate limit, lockout |
| User-A → User-B (resource access) | Object IDs | `WHERE user_id = session.user.id` | `<controller>` | IDOR if check missing |
| User → Admin | Privileged endpoint access | Middleware role check | `<middleware>` | Bypass if check incomplete |
| Web → DB | SQL query | Parameterization, query allowlist | `<ORM>` | SQLi |
| Web → Cache | Cache key | Key derivation includes user/tenant | `<cache layer>` | Cross-tenant cache hit |
| Web → Cloud metadata | HTTP fetch | None at IMDS by default | `<libcurl>` | SSRF reaches IMDS |
| Web → Third-party (payment) | API call | API key / HMAC sig | `<integration>` | Key leak / sig forge |
| Build → Runtime | Artifact deploy | Signature / provenance | `<CI>` | Forged artifact |

This table drives where vulnerability hunting focuses.

## 5. STRIDE per top boundary

For the top 3–5 boundaries, walk STRIDE briefly. Skip cells where
the threat is implausible.

| Boundary | S | T | R | I | D | E |
|----------|---|---|---|---|---|---|
| Login | impersonation via cred-stuff, ATO via reset, … | … | … | … | … | role injection in profile |
| Order placement | impersonation via session theft | quantity / price tamper | repudiation if no audit log | order data leak via IDOR | resource exhaustion | … |
| Payment webhook | forged callback | replay | … | … | … | balance update without proper auth |

These are seeds for hypotheses; not exhaustive.

## 6. Attack tree

Adversary objectives at the root, decomposed to concrete techniques
at the leaves. See `framework/cognitive/threat-modeling.md` for
guidance on building the tree.

Stored separately at `attack-tree.md` for editability. Referenced
here.

## 7. Abuse cases

For each major user feature, the attacker version of the user story:

- *As an attacker, I want to **place an order without paying** so that
  I can drain a user's balance.*
- *As an attacker, I want to **register an account with role=admin**
  so that I have full panel control.*
- *As an attacker, I want to **upload a file that executes server-
  side** so that I can take over the host.*
- *As an attacker, I want to **read another user's order history**
  so that I can build a list of competitor's customers.*
- *As an attacker, I want to **redirect a victim's password reset
  email to my domain** so that I can take over their account.*
- *(continue for each major feature)*

Each abuse case spawns hypotheses against the relevant attack tree
branches.

## 8. Defenses present (observed)

What controls are in place that the attacker must defeat?

- **WAF**: `<vendor / config posture>`.
- **Rate limiting**: `<observed thresholds, per-IP / per-user>`.
- **Input validation**: `<framework default / custom>`.
- **Output encoding**: `<framework default / custom>`.
- **Authentication**: `<scheme, MFA optional/required>`.
- **Authorization**: `<RBAC / ABAC / ad-hoc>`.
- **Cryptography**: `<TLS posture, password hashing algorithm>`.
- **Logging**: `<what's logged, where, retention>`.
- **Monitoring / alerting**: `<what alerts on what>`.
- **Backup / DR**: `<frequency, recovery test cadence>`.

Note absences as well as presences. An absent control is not a
finding by itself, but it determines exploitability for findings
nearby.

## 9. Re-evaluation triggers

This threat model should be revisited when:

- A new feature class is added (e.g. a new payment method, new
  admin tool, new integration).
- The architecture changes (new microservice, new data store, new
  cloud region).
- A dependency is upgraded across major versions.
- An incident occurs (the model wasn't predicting whatever
  happened).
- Annually as a baseline.

## 10. Notes from the engagement

Append findings, surprises, model corrections here as they occur.
This becomes the "what we learned" section of the long-term threat
model document.

```
- YYYY-MM-DD — observation that changed the model: ...
```
