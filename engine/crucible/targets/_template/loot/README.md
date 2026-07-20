# `loot/`

> **GITIGNORED. Never committed. Never copied to client deliverables. Stays on disk only as long as needed for the engagement.**

---

## Purpose

Extracted secrets and access tokens that are necessary for engagement continuity (re-authentication after session expiry, chain replay) but cannot be checked into version control or shared. Examples:

- Captured session tokens / JWTs.
- Discovered API keys.
- Cracked password hashes.
- Service account credentials harvested from misconfigurations.
- Cookies for authenticated test accounts.

## Structure (suggested)

```
loot/
├── credentials.md              ← what was captured, when, from where, scope
├── tokens/                     ← raw token files
├── cookies/                    ← cookie jars per role
├── hashes/                     ← captured hashes (cracked + uncracked)
└── README.md                   ← this file
```

## Discipline

- **Time-bound.** Each item should record its expected expiry. Stale loot adds risk and provides no value.
- **Source-traced.** Each item must reference the finding ID where it was obtained, so it is not used circularly to "discover" the same finding again.
- **Use-traced.** When loot is reused as part of an attack chain, log it in `notes/command-log.md` so the chain in `findings/CHAIN-NNN-*` is reconstructible.
- **Disposal.** At engagement close, `loot/` is purged (`shred -u` on Linux, secure erase). Do not retain past `CLOSED` state without explicit charter authorization.

## Deliverables

Loot **never appears verbatim** in `reports/`. If a token's value is necessary to demonstrate impact, it appears redacted (`eyJ...***REDACTED***...XYZ`) with a footnote referencing the corresponding finding's `evidence/` for the full capture.

## Authorization Reminder

Capturing and possessing credentials of real users (even by exploiting an authorized vulnerability) carries legal weight. Confirm the charter's "Authorized Data Access" section explicitly permits credential capture for the test accounts and that any cross-tenant captures (other clients of a multi-tenant SaaS) are explicitly excluded or authorized.
