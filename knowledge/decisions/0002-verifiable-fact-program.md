# ADR 0002 — The Verifiable-Fact program: a remediation is a re-verifiable FACT

- **Status:** Accepted (implementation complete for the flagship + OOB tiers; one refinement deferred)
- **Scope:** VIGIL (`/home/kali/vigil`, repo `thuram-nana/vigil-sovereign`)
- **Prose knowledge:** [`../kb/verifiable-fact.md`](../kb/verifiable-fact.md) · **specs:**
  [`../../docs/proof-carrying-finding/`](../../docs/proof-carrying-finding/)

## Context

VIGIL already proved *"this bug is real"* (oracle-confirmed, signed, offline-re-verifiable FACTs). The open gap
was the other half of the lifecycle: *"this bug is really fixed."* A remediation was a status field you had to
trust. The operator's brief: turn a remediation claim into a **portable object whose truth a third party
re-derives by re-execution** — witnessed, time-anchored, continuously re-proven, and (for out-of-band classes)
self-authenticating — built as **reviewed security engineering, not wiring** (a security protocol, formal state
semantics, identity/authorization design, witness trust assumptions, negative-proof controls, and adversarial
interoperability testing).

## Decision

Build the program **design-first** (spec → adversarially-reviewed code), each slice `build → red-pen with
runnable PoCs → fix to convergence → CI-green → squash-merge`. The result:

- **The negative proof** — `vigil remediate --prove`: a four-state machine (**REMEDIATED / STILL_VULNERABLE /
  INCONCLUSIVE / REFUSED**) where a fix is *earned by oracle silence*, gated by controls (positive-control twin
  must fire, liveness, per-family repeat policy) and a **fail-closed certifiable-family allowlist**.
- **The F0–F4 freshness gradient**, with a fundamental asymmetry stated honestly: STILL_VULNERABLE reaches
  genuine **F2** (fresh nonce in the sink's matched error line); a REMEDIATED verdict caps at **F1** (a fixed
  sink's traversal is unprovable — an F2-demanding verifier gets INCONCLUSIVE, never a false F2).
- **A live re-drive adapter** (real gated HTTP, genuine F2, a live positive control), **observed-TLS-SPKI**
  target binding, a **continuous witnessed no-later-than-T attestation series** (signed chain + anti-rollback
  floor), an **OOB dishonest-producer tier** (secret token + independent signed collector receipt), a
  **standalone VIGIL-free verifier**, an end-to-end lifecycle demo, and the explicit **`TRUST-GRADIENT.md`**.

## Locked operator decisions

- **State the trust gradient explicitly; never overclaim beyond what the deterministic layer enforces.** The
  honesty *is* the product.
- **F2 semantics (2026-08): reclassify — a REMEDIATED (silent) verdict caps at F1.** #192 originally credited
  `F2_PATH_TRAVERSED` to a silent verdict from a merely-reflected nonce; the operator confirmed the fix —
  reflection is not sink-traversal (per the operator's own "a bare nonce echo ≠ vulnerable code path
  exercised"), so F2 is credited only to a firing trial whose fresh nonce is in the matched error line.
- **Differential-remediation implementation: DEFERRED (2026-08).** The design-first spec (#203) is merged, but
  the adversarial review showed the honest gain is narrow — a matched-decoy differential closes only a
  *blocking* payload-discriminating WAF; a *sanitizing* WAF, a param-stripping edge, and producer byte-forgery
  remain disclosed residuals, and its STILL_VULNERABLE is a safe over-approximation, not an unforgeable proof.
  The spec captures the design; the residual stays disclosed in `TRUST-GRADIENT.md`. Revisit if a
  blocking-WAF-fronted origin enters the threat model.

## Consequences / lessons (recorded so they aren't relearned)

- **Design-first review catches soundness holes for the cost of a doc edit, not a revert** — #203's false-
  `REMEDIATED` hole (an in-flight sanitizing WAF) was caught before any adapter code existed.
- **A positional fact (bytes present somewhere) is not a causal proof (the sink processed it / the app received
  the param); dress it as one and it forges** — the root cause of the #202 BLOCK+HIGH+LOW, and of #203's
  narrowed unforgeability claim.
- **An inline comment on the code counts as a claim** — the honesty sweep must cover comments, not just
  docstrings and docs (#202's third red-pen pass).
- **A universal property claim must carry the protocol/transport precondition the code actually requires** —
  the #201 TLS-SPKI-is-HTTPS-only fix.
- **For a security gate, an allowlist beats a blocklist** — the certifiable-family gate (a blocklist failed
  unsafe on unaudited new oracle kinds).

## Merged

PRs **#186–#202** (implementation) + **#203** (differential-remediation design spec). Every crypto/composition
slice red-penned to convergence. See [`../kb/verifiable-fact.md`](../kb/verifiable-fact.md) for the full detail.
