# Security Assessment — Executive Summary

**Target:** `<target-name>`
**Engagement window:** `<start>` — `<end>`
**Status:** `Draft | Final` — `<date>`
**Audience:** business owner, partners, investors, regulators, non-technical stakeholders.

> ~Two pages. Plain language. If the reader is technical, point them
> to the technical report.

---

## At a glance

| Severity | Count | Status |
|----------|------:|--------|
| Critical | N | M fixed, K open |
| High | N | M fixed, K open |
| Medium | N | |
| Low | N | |
| Info | N | |

**Posture before remediation:** `<Poor / Below average / Adequate / Good>`
**Posture after remediation:** `<...>`

## What we tested

End-to-end security assessment of `<target>`, covering: account
security and login, session handling, authorization, input handling,
business logic, payment flows, the public API, infrastructure,
`<other surfaces>`, and the source code (in stage 7).

We did not test third-party services the platform depends on
(payment processors, upstream providers, hosting infrastructure
beyond what the operator controls).

## What we found

3–5 short bullets, business framing.

- **Account takeover was possible** through `<short reason>`.
  **(Fixed — `<date>`)**
- **User balances could be increased without payment** by `<short
  reason>`. **(Fixed — `<date>`)**
- **`<n>` users' order history was visible across accounts**
  through `<short reason>`. **(Fixed — `<date>`)**
- **The admin panel was reachable at predictable URLs** with
  `<short reason>`. **(Fixed — `<date>`)**

(Add or remove bullets to match the actual findings — only the most
important. Do not pad.)

## How an attacker could chain these

A short paragraph describing the worst-case adversary path through
the findings, in plain language.

> *An attacker who exploited Finding 003 could credit any user's
> balance, then chain Finding 014 to dump the user list and target
> them systematically. Combined with Finding 022 (no rate limit on
> login), the path from external attacker to drained users was
> approximately 12 minutes per victim. Both Finding 003 and Finding
> 022 are now fixed and verified, breaking this chain.*

## What's been done

- N findings fixed and verified.
- M findings have fixes in development, expected by `<date>`.
- All test artifacts created during testing have been cleaned up.
- Production credentials were not used; test accounts only.
- `<any other operator-noted action: cred rotation, monitoring
  added, etc.>`

## Residual risk

What's left, framed for non-technical readers:

- Open Critical: `<list, plain-language, with operator's planned
  fix date>`.
- Open High: `<list>`.
- Risk-accepted items: `<list with operator's reasoning>`.
- Defensive recommendations beyond individual fixes (logging,
  alerting, monitoring): `<short list>`.

## Recommendation cadence

- **Monthly**: re-run smoke tests on new endpoints and changed
  flows (using this framework's continuous-testing playbook).
- **Quarterly**: full self-driven re-engagement using this
  framework against a snapshot of the target.
- **Annually**: external pentest by an independent firm (especially
  before institutional partnerships, major releases, or
  significant scaling).
- **Continuous**: monitoring of public-facing surface for new
  exposures (subdomain takeover, leaked secrets, exposed services).

## Sign-off

- **Operator:** `<name>` — date: ____________
- **Tester:** OBSIDIAN, on behalf of operator — date: ____________
