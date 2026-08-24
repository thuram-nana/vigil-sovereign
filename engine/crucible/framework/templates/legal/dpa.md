<!-- STATUS: DRAFT — NOT COUNSEL-REVIEWED — DO NOT SHIP -->
# Data processing agreement (DPA) — `<engagement-slug>`

**Version:** 0.1 (DRAFT)
**Status:** DRAFT → PENDING COUNSEL REVIEW → Signed
**Date:** YYYY-MM-DD

> **DRAFT — PENDING COUNSEL REVIEW.** This is a framework *template*, not an
> executed agreement. Its terms have **not** been reviewed by qualified legal
> counsel, and the governing-law and party placeholders below are **not yet
> resolved**. Both are HUMAN actions. The counsel-review manifest
> (`counsel-review-status.json`) records this instrument as PENDING, and the
> ship gate (`authority.counsel_review`) refuses to assemble it into any
> deliverable until counsel has reviewed it and every placeholder is resolved.

This DPA sets the terms under which the Operator processes any personal data on
the Customer's behalf during a security engagement. The engagement's default
posture is to **avoid** personal data (see the constitution's OPSEC rules); this
DPA governs the residual case where in-scope systems expose it and minimum
proof-of-impact requires touching it.

## 1. Parties and roles

- **Controller (Customer):** `<customer legal name>`
- **Processor (Operator):** `<operator legal name>`

The Customer is the data Controller; the Operator acts as a Processor and
processes personal data only on the Customer's documented instructions.

## 2. Subject-matter, nature and purpose

The Processor processes personal data only to the extent an in-scope finding
requires, and only to prove impact — never to exfiltrate, retain, or exploit it
beyond the minimum. Categories of data subjects and personal data are those
incidentally present on the in-scope systems named in the authorization letter.

## 3. Processor obligations

The Processor shall: (a) process only on documented instructions; (b) ensure
personnel are bound by confidentiality; (c) apply appropriate technical and
organizational security measures; (d) engage no sub-processor without
authorization; (e) assist the Controller with data-subject requests and breach
notification; and (f) delete or return personal data at the end of the
engagement, retaining only redacted minimum-necessary evidence.

## 4. Sub-processors

The Processor engages no sub-processor for personal data without the
Controller's prior written authorization.

## 5. International transfers

The Processor shall not transfer personal data outside `<permitted region>`
without a lawful transfer mechanism agreed in writing.

## 6. Breach notification

The Processor shall notify the Controller without undue delay, and in any event
within `<notification window>`, after becoming aware of a personal-data breach.

## 7. Governing law

This Agreement is governed by, and construed in accordance with, the laws of
**[GOVERNING LAW]**, and any data-protection-specific terms are read consistently
with the applicable regime (**[DATA PROTECTION REGIME]**). The parties submit to
the exclusive jurisdiction of the courts of **[VENUE]**.

<!-- The governing law, data-protection regime, and venue above are UNRESOLVED
     placeholders. Resolving them is a human (counsel) action; until then the
     ship gate refuses this instrument. -->
