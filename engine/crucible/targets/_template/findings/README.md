# `findings/`

One file per finding. Two file classes:

| Prefix | Purpose | Template |
|---|---|---|
| `FINDING-NNN-<slug>.md` | A standalone vulnerability. | `framework/templates/finding.md` |
| `CHAIN-NNN-<slug>.md` | An attack chain composed of two or more findings (or one finding + a precondition) producing impact greater than the sum of parts. | `framework/templates/chain.md` |

## Numbering

- Sequential, three-digit, never reused: `FINDING-001`, `FINDING-002`, ...
- Chains have their own sequence: `CHAIN-001`, `CHAIN-002`, ...
- If a finding is later determined to be invalid, **do not delete or renumber** — mark it `Status: WITHDRAWN` with a one-paragraph explanation. Numbers are referenced from reports, evidence, and notes.

## Naming

- Slug should be a short kebab-case description: `idor-on-orders-endpoint`, `jwt-none-algorithm-accepted`, `oauth-redirect-uri-bypass`.
- Avoid client/target names in slugs — those are implicit from the directory.

## Required Fields

Every finding must have:

- Title, Severity (with CVSS vector + contextual note), Status, Discovery Date.
- Affected Component(s) and version(s) where known.
- Reproduction steps that a fresh operator could follow.
- Evidence references (`evidence/<finding-id>/...`).
- Impact narrative grounded in the threat model.
- Remediation recommendation.
- Standards mapping (CWE, OWASP WSTG, MITRE ATT&CK, OWASP API Top 10 / ASVS where relevant).

See `framework/templates/finding.md` for the full structure.

## Lifecycle

```
DRAFT → CONFIRMED → REPORTED → REMEDIATION-IN-PROGRESS → REMEDIATED → RETESTED → CLOSED
                                                                    │
                                                                    └→ NOT-FIXED → CLOSED-RISK-ACCEPTED
```

Mark transitions in the finding's `Status:` field with date and operator initials.
