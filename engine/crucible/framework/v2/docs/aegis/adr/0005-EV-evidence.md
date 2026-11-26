# ADR 0005 — The evidence and DONE-record model (EV)

**Status:** Accepted

## Context

E1 (ADR 0001) makes DONE mean "proven end to end through VIGIL on staging." That
proof needs to be a durable, signed artefact an auditor can re-verify — not a green
CI badge. The existing claims registry cannot carry it: `validate_claim` requires
the proving job to be a *required* PR check that collects the proof file, and a
TT-STG run is a dispatched/scheduled job, so a registry entry could never point at
it. The registry therefore stays unchanged, and a separate evidence record carries
the end-to-end demonstration. This ADR records that evidence model and the validator
every claimed protection must answer.

## Decision

**The AS-25 record — a run record plus a signed binding (plan §13.3).**

- **Run record.** The existing verification-manifest tool produces a
  `vigil-verification-manifest/1` record; its `check()` re-derives case counts from
  the bound JUnit output and rejects any skip of a covered term. This machinery is
  reused unchanged.
- **Binding** (`vigil-aegis-tt-demonstration-v1`) ties the run to the slice and the
  world it ran in: slice and `claim_ids`; run and commit; manifest, JUnit and suite
  digests; the build manifest (`artifacts VALID`); the topology (`class: iac` with a
  digest — only infrastructure-as-code topology counts); the subject paths and
  digest; the tenants; the UI legs actually exercised (`route, screen, session`);
  the required case classes (`positive, benign, benign_same_shape, negative,
  cross_tenant, failure_class`); and `no_skip_terms` ⊇ {TT-B, cross-uid, browser,
  isolation, tenant}.
- **Signing.** Domain-tagged Ed25519 under the staging trust root, by a dedicated TT
  evidence key held in the staging control plane (KMS-wrapped) — **never a CI runner
  key**, and never the production root. An optional keyless cosign bundle may be
  added for third parties. The trust root lives at
  `docs/evidence/aegis-tt/trust-root.json`.
- **Verifier.** A collected test checks the signature under a non-production root,
  that digests match and `check()` passes, that claims are valid under the unchanged
  validator, that every case class is present and every UI route is in the Gate-5
  census, that artifacts are VALID, and that staleness is computed by subject/
  topology digest. Staleness is a *state*, not a CI failure — but CI **does** fail if
  anything is labelled "demonstrated" without a current IaC record.
- **Publication.** A pull request containing only passing records, merged by the
  owner. Failed runs go to private operations, never to the public repository.
- **Projection.** A capability-matrix status file carries each claim's
  `demonstrated_by` and its state, with a drift test.

**The ten-question validator (plan §13.5).** A claimed protection is only accepted
once all ten are answered from the record and the protection contract: Observe?
Detects? Evidence (offline certificate)? Authorized (epoch/capabilities + release +
token)? Enforce where (the unit — not the edge)? Took effect (receipt + an
independent probe)? Prevented (within tested coverage)? Legitimate operation still
OK (same-shape benign corpus)? Blind spots (stated limitations and trust
assumptions)? Re-check when (lease, staleness, condition binding)?

## Consequences

- DONE is a signed, offline-re-verifiable fact, decoupled from the required-check
  registry, which keeps the registry's invariant intact.
- The evidence key is scoped to staging and is not a runner key, so a compromised CI
  runner cannot forge a demonstration, and a staging record can never be mistaken
  for production authority.
- **Stated limits.** An AS-25 record is SIGIL attesting its own staging run. It is
  not production behaviour and not third-party assurance; the record says so.
- Honesty is enforced mechanically: a stale or missing record downgrades the
  capability's displayed state, and "demonstrated" without a current IaC record
  fails the build.

## References

- Plan §13.2 (why the registry cannot hold DONE), §13.3 (the AS-25 record),
  §13.5 (ten questions), §13.7 (states), §4.7 (publication: fixed state only).
- ADR 0001 (scope/DONE), ADR 0004 (verified-outcome differentiator).
