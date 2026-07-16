# FORGE RAMPART — signed charter, slice 1 (proof-carrying edge: certificate-per-block)

**Stage 0 of the FORGE recipe.** Operator signed off 2026-07-16 ("build slice 1").

## Context correction (exploration result)

RAMPART's design (`AEGIS-CRUCIBLE-package/rampart/`) describes a two-plane proof-carrying edge. Exploration
of the tree shows **Plane B's inline decision core already exists** in `framework/v2/aegis/gateway.py`
(`AegisGatewayHandler`: "inspect → block under enforce+confirmed → forward → relay", blocks ONLY on a fired
oracle `verdict.decision == "confirmed"`, mints a re-runnable `CertRef` per block, doubly-gated by
entitlement + kill-switch, fail-open). So slice 1 is **reuse-first and small**: it does NOT rebuild the edge;
it upgrades the block's evidence to RAMPART's actual differentiator.

## The defensive capability this slice proves

Every inline BLOCK the AEGIS gateway makes emits a **real, signed, offline-re-verifiable PCF v0.1
certificate** (`evidence/pcf.py`) — the same real evidence layer Phase A wired findings onto — instead of (or
alongside) the lighter `CertRef`. A third party can re-run the exact certificate: recompute the request
evidence digest, re-fire the same request-side oracle over the retained context, and confirm the block was
justified — with no trust in RAMPART. This retires the RAMPART prototype's standalone PCF-verify reimpl as
the reference the real layer now supersedes (honest-ledger note).

## Scope — slice 1

- A `rampart` seam that, given a gateway BLOCK verdict (a fired request-side oracle over a normalized
  request), builds + signs a **PCF certificate for the block** via the existing `evidence/` primitives
  (`build_certificate` / `sign_certificate` / `to_pcf`), and verifies it offline (`verify_pcf`).
- Reuse the EXISTING request-side oracles (`sql_injection_breakout` / `command_injection_breakout` /
  `nosql_injection_breakout` and the traversal/CRLF/etc. gateway checks) — **no new oracle kinds**.
- The block's PCF `claim.class` is the fired oracle's bug class; `oracle.binding` its canonical kind;
  `verdict.fired = true`; the retained `oracle_context` is the normalized-request evidence the oracle judged,
  so the certificate re-verifies by re-firing that oracle.

## The mandatory benign twin (must NOT block / must produce NO certificate)

A benign request the gateway ALLOWS — encoded dots inside a real filename, a benign deep path, a benign
header/query (the prototype's 7/7 FP-controlled set) — produces **no block and no certificate**. A
certificate exists only for a genuinely-fired oracle. (Near-zero-FP is inherited from the oracles, already
dual-attested; slice 1 must not weaken it.)

## Non-goals — slice 1 (deferred / out of scope)

- The reverse-proxy TRANSPORT (TLS termination, ACME auto-cert, forward-to-origin) — a deployment slice.
- Plane A (agentless assessment driving the engine against an authorized origin) — a later slice; and when
  RUN it is charter-bound exactly like CRUCIBLE owner-testing.
- Any NEW detection oracle, any detection-evasion / stay-hidden capability, any offensive primitive
  (defensive-only, non-waivable).

## Invariants (inherited, non-negotiable)

Block ONLY on a fired oracle (prove-don't-guess inline; nothing below a fired oracle is blocked); every block
is a re-runnable certificate; `make gate` byte-identical (the PCF binding is off the scan/engage/benchmark
path, lazy-imported); determinism (no wall-clock/RNG in the cert bytes); fail-closed on tamper / fail-OPEN on
availability (a gateway error never spuriously blocks); charter-bound (RAMPART protects only authorized
sites); sovereign (offline verify, national trust root).

## Merge bar

The standing dual gate — RED-PEN **and** an independent `adversarial-sweep` — plus `make gate`
byte-identical, CHRONICLER ledger, and human approval. No self-merge.
