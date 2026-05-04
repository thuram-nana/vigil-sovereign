# Playbook 24 — Reporting deliverables

**Goal:** produce three reports the operator can act on
immediately, and which support stakeholder communication if the
operator needs to brief partners, regulators, or insurance carriers.

**Stage in lifecycle:** 8.

---

## 24.1 The three reports

| Report | Audience | Length | Purpose |
|--------|----------|--------|---------|
| Executive | Business owners, investors, partners | 2 pages | What's the risk picture; what's done; what remains |
| Technical | Engineering team, security team | Full | Findings detail with PoCs and remediation |
| Remediation roadmap | Tech lead / project manager | 2-4 pages | Prioritized fix sequence with effort estimates |

Optional fourth: **Threat model document** — the artifact from
stage 1, refined with what was actually found. Useful for ongoing
operations and onboarding.

---

## 24.2 Executive summary

`reports/executive.md`. Use `framework/templates/report-executive.md`.

Constraints:

- Two pages maximum. Stop at two.
- Plain language. No CVE-IDs, no CVSS vectors, no acronyms not
  glossed.
- Lead with **what the assessment tested and what was found**, not
  with methodology.
- Use **business-impact framing**: "users could be locked out,"
  "balances could be drained," "personal data was reachable" —
  not "IDOR in /api/v2 /users."
- Include severity-distribution table.
- Include status-distribution table (after retest).
- One paragraph on residual risk.
- One paragraph on cadence recommendations.

The kill-chain narrative section (per
`framework/cognitive/kill-chain.md` §7) goes here:

> *An attacker reaching the worst-case objective could do the
> following: they would start with X, pivot via Y, and reach the
> objective via Z. The current product has approximately N
> independent paths to this objective.*

This is the single most useful paragraph for non-technical readers.

---

## 24.3 Technical report

`reports/technical.md`. Use `framework/templates/report-technical.md`.

Structure:

1. **Engagement summary** — scope, methodology, dates, limitations.
2. **Findings overview** — table of every finding with severity,
   status, ID, title.
3. **Severity / status distribution** — visualizations or tables.
4. **Findings detail** — embed each `findings/NNN-*.md` verbatim,
   sorted by severity, then ID.
5. **Chains** — embed `findings/CHAIN-*.md` after the individual
   findings.
6. **Cross-cutting recommendations** — patterns that fix multiple
   findings (centralize auth, output-encode by default, atomic
   transactions for money invariants).
7. **Methodology and tools** — brief, with link to
   `framework/playbooks/`.
8. **Appendices**:
   - Endpoint inventory.
   - Role / authorization matrix.
   - Test artifacts and cleanup status.
   - Command log excerpt (selected, not full).
   - Glossary.

---

## 24.4 Remediation roadmap

`reports/remediation-roadmap.md`. Use
`framework/templates/report-remediation-roadmap.md`.

Structure:

### Per finding

```
| ID | Title | Severity | Effort | Priority | Sequence |
|----|-------|----------|--------|----------|----------|
| 001 | <title> | Critical | S | 1 | Immediate |
| 002 | <title> | High | M | 2 | Sprint 1 |
| ... | ... | ... | ... | ... | ... |
```

Effort: **S** (hours), **M** (days), **L** (weeks), **XL**
(quarter+).

Priority: derived from impact × likelihood × effort. High-impact +
Low-effort goes first.

### Sequencing

Suggested fix order, accounting for dependencies:

1. **Immediate** — Critical findings deployable in hours.
2. **Sprint 1** — Highs and quick Mediums.
3. **Sprint 2** — Remaining Mediums; structural improvements.
4. **Quarter** — Larger refactors that close multiple findings.
5. **Ongoing** — Lows, hardening recommendations, governance.

### Cross-finding initiatives

When several findings share a root cause, recommend the structural
fix rather than per-finding patches:

- "Centralize authorization in policy classes" (closes 5 IDORs).
- "Implement webhook signature verification helper used by all
  payment integrations" (closes 3 forgery findings).
- "Auto-escape templates by default" (closes most XSS).
- "Move secrets to a dedicated secret manager" (closes secrets in
  repo, in env vars, in logs).
- "Database constraints for money invariants" (closes race,
  negative-balance, double-spend).

### Effort estimate caveats

You're estimating from the outside. Note that estimates are rough
and the operator's team will refine.

---

## 24.5 Threat model document (optional fourth deliverable)

If the operator wants the threat model as a delivered artifact:

`reports/threat-model.md` — the artifact from stage 1, refined
with:

- What was found (per attack-tree leaf, mark vulnerable / safe).
- Updated adversary model (what would change in a real attacker's
  approach now that we know what's exploitable).
- Defensive gaps identified beyond individual findings (logging
  coverage, anomaly detection, segmentation).

Useful for operators who want a long-lived document the engineering
team references, not just a one-shot test report.

---

## 24.6 Tone and language

- Direct, neutral, factual. Avoid hyperbole ("catastrophic",
  "devastating") — the severity ratings convey that.
- No editorial about the operator's process / team / past
  decisions. Findings are about the product.
- Use active voice when describing the bug ("attacker can do X");
  passive when describing the response ("the request is logged").
- Be specific about preconditions ("requires logged-in user with
  any role") so severity is contextualized.
- Acknowledge what's done well, not just what's broken.

---

## 24.7 Sensitive content in reports

- **Never** include real user PII in reports, even if exfilled
  during proof-of-impact. Redact.
- **Never** include working malicious payloads beyond what the
  reader needs (no full RCE chain). Show the principle, link to
  the evidence file.
- **Redact secrets / keys** in any quoted output.
- **Redact internal IPs / hostnames** when reports may be shared
  with third parties.

The technical report often has two versions: full (for internal
engineering) and redacted (for external sharing).

---

## 24.8 Delivery format

- Markdown is the working format (in-repo).
- Convert to PDF for stakeholders who want PDFs (`pandoc -o
  report.pdf reports/executive.md`).
- For the technical report, a versioned PDF (1.0 draft → 1.0 final)
  with sign-off date is convention.

---

## 24.9 Phase exit checklist

- [ ] Executive summary written, ≤ 2 pages.
- [ ] Technical report assembled with all findings embedded.
- [ ] Remediation roadmap with effort estimates and sequencing.
- [ ] Threat model document refined (if operator requested it).
- [ ] Sensitive content redacted appropriately.
- [ ] Reports reviewed for tone / language consistency.
- [ ] Delivered to the operator.
- [ ] Operator confirms reports are clear and actionable.
