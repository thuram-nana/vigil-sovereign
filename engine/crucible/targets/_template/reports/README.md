# `reports/`

Client-facing deliverables. Each is generated from the corresponding template in `framework/templates/` and references findings in `targets/<name>/findings/`.

## Deliverables Per Engagement

| File | Audience | Source Template | Produced |
|---|---|---|---|
| `executive-summary.md` | C-level / board | `framework/templates/report-executive.md` | At engagement close |
| `technical-report.md` | Engineering / security team | `framework/templates/report-technical.md` | At engagement close |
| `remediation-roadmap.md` | Engineering leads / PMs | `framework/templates/report-remediation-roadmap.md` | Mid-engagement (provisional) and updated at close |
| `retest-report.md` | Engineering / security team | `framework/templates/report-retest.md` | After remediation cycle |

Optional add-ons depending on charter:

- `methodology-appendix.md` — what was tested, with what coverage, and what was explicitly out of scope. Useful for compliance.
- `evidence-pack.zip` — bundle of `evidence/` for the client (post-redaction).
- `attack-narrative.md` — single-incident-style storytelling of the most impactful chain, useful for tabletop exercises.

## Structure of a Final Report

```
reports/
├── executive-summary.md
├── technical-report.md
├── remediation-roadmap.md
├── retest-report.md           ← after first remediation pass
├── methodology-appendix.md    ← optional
├── evidence-pack/             ← optional bundle, redacted
└── README.md                  ← this file, plus delivery log
```

## Delivery Log

Maintain a delivery log in this README (or a separate `DELIVERY.md`) capturing:

- Date and version of each report sent.
- Recipient(s) and channel (encrypted email, secure portal, in-person).
- Hashes of files delivered (SHA-256) for tamper-evidence.
- Acknowledgement of receipt.

Example log entries:

```
2026-04-15  technical-report.md v1.0     SHA256:abc123... → security@client.example via PGP-encrypted email; ack 2026-04-15.
2026-04-22  remediation-roadmap.md v1.1  SHA256:def456... → eng-leads@client.example via portal; ack 2026-04-22.
2026-05-10  retest-report.md v1.0        SHA256:789abc... → security@client.example via PGP-encrypted email; ack 2026-05-11.
```

## Tone & Style

- **Executive Summary:** plain language, business impact first, technical detail only as needed for credibility. 1-2 pages.
- **Technical Report:** comprehensive, finding-by-finding, reproducible. Long is fine; each finding self-contained.
- **Remediation Roadmap:** prioritized by impact × ease, organized as sprints/quarters. Engineering can act on it directly.
- **Retest Report:** per-finding "Fixed / Not Fixed / Not Applicable / Risk Accepted" with re-verification evidence.

Avoid: bug-bounty-style braggadocio, unnecessary jargon, unsubstantiated severity inflation, vendor product placements.

Aim for: clarity, calibrated severity, actionable remediation, defensible standards mapping.
