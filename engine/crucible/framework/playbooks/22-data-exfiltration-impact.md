# Playbook 22 — Data exfiltration and impact assessment

**Goal:** for findings that involve potential data access, quantify
the realistic exfiltration impact in a way the operator can use to
prioritize remediation, brief stakeholders, and respond if the same
flaw was exploited in the wild.

**Stage in lifecycle:** 5–6. **Read-only assessment**, not actual
exfiltration. We measure reach and rate; we don't move data.

**Standards:** OWASP ASVS V8 (Data Protection), GDPR Art 33 (breach
notification thresholds), NIST SP 800-66.

---

## 22.1 Operating principle — measure, don't move

The point of this stage is to answer:

- "If this bug had been exploited last month, how much data could
  have been taken?"
- "What's the realistic monetization or harm path?"
- "Which compliance regimes apply, and what notification thresholds
  are crossed?"

You answer these without actually copying data. You measure rates,
sample one redacted row, document scope.

The reason: actual exfiltration creates real legal and ethical
issues (was the operator's data appropriately protected during your
engagement? was your test environment certified to hold PII? is the
operator obligated to notify users about your *test* access?). Avoid
the entire problem by not exfiltrating.

---

## 22.2 Reach — what data is reachable

For each finding that exposes data:

- Categories: PII, payment data, credentials, business-confidential,
  metadata.
- Volume: how many records?
- Field richness: full row vs sparse?
- Per-tenant or cross-tenant?
- Live or historical?
- Encrypted at rest with separate KMS, or readable directly?

Quantify with **counts** (`SELECT COUNT(*)`, `db.users.count()`),
not exports. Counts are sufficient for the impact statement.

---

## 22.3 Rate — how fast could exfil happen

For SQLi or IDOR-style bugs:
- Records per request.
- Requests per minute the bug supports (rate limit?).
- → records per hour.
- → time to exfiltrate the full dataset.

This number is what regulators and lawyers care about. "1M records
in 4 hours" is a different conversation than "1M records over 6
months at 500/day."

For SSRF / RCE / shell-style access:
- Bandwidth out of the host.
- Egress controls (does the network restrict outbound to any
  destination, or only to allowlisted endpoints?).

---

## 22.4 Detection — would they notice

For the same bug, separately assess:

- Logging — are these accesses logged?
- Alerting — would the volume / pattern trigger alarms?
- Anomaly detection — IDS/EDR/SIEM?
- Retention — how far back do logs go?

A bug with logging + alerting is meaningfully less severe (chain-
break exists) than the same bug without. Document explicitly.

---

## 22.5 Categorization for compliance

Map exposed data to compliance regimes:

- **PCI DSS** if payment card data (PAN, CVV, expiry).
- **GDPR / CCPA / regional privacy** if PII.
- **HIPAA** if health data.
- **SOX** if financial controls data.
- **GLBA** if financial PII (US).
- **FERPA** if education records (US).

Each regime has notification triggers. Document which apply, what
thresholds are crossed, what timeline applies. The operator may
need to engage counsel.

---

## 22.6 Monetization model — adversary economics

For the criminal-grade adversary, what's the dollar value of what's
reachable?

- Credentials: $1-$50 per account on dark markets, depending on
  account type (financial > consumer).
- Credit cards: $5-$50 each.
- PII for stuffing / phishing: $0.10-$1 per record.
- Crypto-wallet seeds: full balance.
- Business-confidential (M&A, customer lists): high case-by-case.

Estimate roughly. The operator uses this to compare "fix cost" vs
"breach cost".

---

## 22.7 Sampling for proof

Capture **one** redacted record in evidence. That's enough.

Redaction:
- Names → first letter only.
- Email → `<j>***@<d>***.com`.
- Phone → last 4 only.
- Address → city only.
- Card number → last 4 only.
- Password hash → algo + first 8 chars.

The redacted sample shows the operator that the bug is real;
reading more is unnecessary for proof and creates legal exposure.

---

## 22.8 Other impact dimensions

Beyond pure data theft:

- **Integrity**: can attacker modify data? Audit trail / undo
  available?
- **Availability**: can attacker delete or DoS?
- **Reputational**: would this become a press story?
- **Regulatory**: notification fines, license risk.
- **Business continuity**: how long to recover from worst case?
- **Customer trust**: churn risk after a breach of this kind.

Note all dimensions in the impact statement, even when the headline
finding is data theft.

---

## 22.9 Documentation

Each finding that triggers this playbook gains a structured impact
section:

```
## Impact assessment

| Dimension              | Detail |
|------------------------|--------|
| Data categories        | <list> |
| Records reachable      | <count> |
| Field richness         | full row / 5 of 12 fields / etc |
| Cross-tenant?          | yes / no |
| Exfil rate (theoretical) | N records / hour |
| Time to full dataset   | <hours / days> |
| Logging                | enabled / disabled |
| Alerting               | enabled / disabled |
| Compliance regimes     | GDPR (Art 33 trigger), PCI |
| Estimated dark-market value | $X for full dataset |
| Integrity / Availability impact | <details> |
```

Operators can use this directly in stakeholder briefings.

---

## 22.10 Phase exit checklist

- [ ] For each data-exposing finding, reach quantified.
- [ ] Rate quantified.
- [ ] Detection coverage assessed.
- [ ] Compliance mapping done.
- [ ] One redacted sample captured per finding (no more).
- [ ] Impact section appended to each finding.
- [ ] Operator briefed on the worst-case quantitative picture.
