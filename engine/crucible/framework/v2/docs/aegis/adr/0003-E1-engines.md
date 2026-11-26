# ADR 0003 — Engines SIGIL operates and how they are chosen (E1)

**Status:** Accepted

## Context

Under E1 (ADR 0001), SIGIL deploys, operates, updates and monitors every detection
and enforcement engine itself, behind typed adapters that declare what each can and
cannot observe or enforce. AEGIS is never shipped to the customer to run. This ADR
records which engines are selected, the bar each had to clear, and the rule that an
engine consumes resources only for a live connection. Licence posture is summarised
here and governed by the licence gate.

## Decision

**The E1 evaluation bar (plan §7).** Every candidate engine is assessed on:
capability; supported platforms; maturity; security history; resource footprint;
update cadence; failure modes; overlap with capability VIGIL already has (the
CRUCIBLE reuse map); prerequisites; licences (engine, dependencies and rule
content, assessed separately); and redistribution obligations. Each unverified
point is closed before the engine ships — upstream tags (`git ls-remote --tags`),
advisories, release dates and a TT-STG run.

**Per-connection runtime.** An engine runs only per active connection. Managed
rule sets (CRS) are offered to a tenant only when a benchmark shows the rules-on
arm beats the baseline for that tenant; the baseline arm is CRS on Coraza.

**Selected (plan §7 matrix).**

- **Edge / transport.** CloudFront + ACM + Shield (E3a, ADR 0004) replace the former
  SNI router and in-unit ACME; the cell ALB; the AEGIS gateway itself.
- **Inline inspection.** A Caddy front plus Coraza v3 in DetectionOnly mode — CRS
  hits are recorded as leads in typed `rule_refs`, never as standalone blocks. CRS
  4.x is selected but gated per tenant.
- **First-party intelligence.** The Detection Mirror (evaluated ahead of Sigma); the
  Domain 7/8 oracles; the virtual-patch compiler. First-party oracles, honeypot and
  canary ship via engine-config.
- **Signals.** Sigma v2 with SigmaHQ rules as a standalone process.
- **Runtime (path 3).** GuardDuty findings as the default; EDR vendor APIs as the
  preferred integration; Tetragon (observe-only) and Suricata as conditional,
  separate-process engines; Falco as ingest only. Runtime enforcement is
  unsupported. Zeek is not planned (no packet vantage beyond mirroring, which the
  Suricata EVE path already covers). IOC feeds are deferred (none licensed).

**Service use vs distribution (engineering analysis; counsel ruling tracked as an
open decision).** As a hosted service, permissive and copyleft licences (MIT, BSD,
Apache, GPL, LGPL) impose nothing on service use; AGPL §13 applies only to a
modified engine. SSPL, Elastic-2.0, Commons Clause and CC-BY-NC are denied for
service images. Distribution — and therefore stronger obligations — arises only for
the CloudFormation template, the (not-offered) customer kit, the forwarder/SDK and
rule content pushed to a customer's own CDN; pushed CRS- or Sigma-derived rules
carry their notices. The licence gate enforces this: every artefact is tagged with
its `use_mode`, unknown licences fail unless ledgered, and bundles carry licence
digests. It lands before the first third-party deploy, and R1 requires a licence
record for every deployed engine.

## Consequences

- Adding an engine later is append-only: a new provider record plus its licence
  entry, evaluated against the same bar — no rewrite of the adapter layer.
- Because engines are operated by SIGIL and run only per connection, footprint and
  failure modes are capacity-planned per tenant rather than assumed.
- The DetectionOnly / leads-not-blocks stance keeps third-party rule engines inside
  the prove-don't-guess doctrine: a CRS or Sigma hit raises suspicion but never
  alone produces a block.
- An engine is DONE only when operated end to end on TT-STG with its licence record
  and per-engine health in place (ADR 0001, ADR 0005).

## References

- Plan §7 (engines and licensing), §6 (connection paths), §8 (compute fairness).
- ADR 0001 (scope), ADR 0004 (competitive), ADR 0005 (evidence).
- `../AEGIS-CRUCIBLE-REUSE-MAP.md`, `../AEGIS-SIGNAL-CATALOG.md`.
