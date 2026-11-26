# ADR 0004 — Competitive posture: rent the pipes, own the intelligence (E3)

**Status:** Accepted

## Context

AEGIS competes with CDN-WAF incumbents without rebuilding a global edge. The owner's
decision E3 sets the strategy: rent commodity edge capacity, and differentiate on
the reasoning layer VIGIL already has. This ADR records that split, the two lead
differentiators, and the benchmark discipline that any comparative claim must meet.

## Decision

**E3 — rent the pipes, own the intelligence.**

- **(a) Rent the edge.** AWS CloudFront + Shield are the edge and the
  volumetric-DDoS layer, replacing the former SNI router and in-unit ACME. Own
  anycast is deferred. CloudFront/Shield is an edge and DDoS layer — it is **not**
  an AEGIS enforcement point; enforcement happens at the unit (the gateway), and the
  ten-question validator (plan §13.5) answers "enforce where?" with the unit/stage
  placement, never the edge.
- **(b) Bring path 1b forward, Cloudflare first.** The customer keeps its own CDN;
  AEGIS pushes verified, host-scoped, self-expiring rules to it rather than demanding
  a re-point. Rule writes are per-rule and never overwrite customer rules; every
  expression is pinned to a proven host; SIGIL withdraws its rules at expiry.
- **(c) Own the intelligence — the two lead differentiators.**
  - **Exploit-proven virtual patching.** A proven finding (a fact with a
    reproducible proof, never a lead) drives a narrow, self-expiring edge or
    provider rule. After it is applied, an isolated retest confirms the exploit is
    refused through the edge while the benign workflow still passes; the result is
    recorded as `STILL_VULNERABLE + mitigated_by_edge` until a direct retest clears
    it — an honest statement that the edge mitigates, it does not fix the origin.
  - **Signed, offline-re-verifiable outcomes.** Each intervention yields a signed
    verification record an auditor can replay offline with no trust in AEGIS
    (ADR 0005).
- **(d) Benchmark discipline.** Any comparative claim — "rivals Cloudflare", "better
  than `<WAF>`" — is earned only by a signed scorecard against a generic-WAF
  baseline on the same scenarios. The baseline is CRS on Coraza. No scorecard, no
  claim.

**Forbidden claim vocabulary (plan §13.6).** The product never says: universal
detection or prevention; zero or near-zero false positives/negatives; complete
MITRE coverage; permanent protection; "fully protected"; "all threats blocked"; or
`protected` as a state. Coverage is stated as measured and growing, with named
limitations.

## Consequences

- The edge layer is commodity and swappable; the moat is the per-actor reasoning and
  the replayable certificate, not an owned network. Fallbacks exist if a CloudFront
  feature is missing (per-host distributions, or a public ALB with a per-tenant
  header).
- Virtual patching is positioned honestly: it mitigates at the edge and says so,
  rather than claiming the underlying flaw is closed.
- Marketing and UI copy are constrained by the benchmark gate and the forbidden-term
  lint, so a comparative claim cannot ship ahead of the measurement that earns it.
- Because the edge is explicitly not an enforcement point, protection decisions and
  their evidence stay anchored at the unit, where the oracle and certificate live.

## References

- Plan §0.1 (E3), §6 (virtual patching chain, path 1b), §13.5 (ten questions),
  §13.6 (differentiators and forbidden claims).
- ADR 0003 (engines), ADR 0005 (evidence), `../DEPLOYMENT.md` (the honest promise).
