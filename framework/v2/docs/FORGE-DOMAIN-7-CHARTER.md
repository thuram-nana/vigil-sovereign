# FORGE Domain 7 — Identity Posture (`IDENTITY_POSTURE`) — signed charter, slice 1

**Stage 0 of the FORGE recipe.** Signed by the operator 2026-07-16. Slice 1 builds **two** predicates;
`wildcard_grant` and `dormant_privileged` are DEFERRED to a follow-up charter (a narrowing decision, not a
preset).

## The defensive fact this domain proves

A published identity-provider configuration export provably carries an identity-posture weakness that a
compliant configuration cannot — proven by **deterministic re-derivation over the export's literal fields**,
never a scanner's or IdP's say-so. A confirmed finding emits a real signed **PCF v0.1** certificate
(`evidence/pcf.py`) that re-verifies offline (by construction, via the additive-oracle pattern).

## The proof it emits (slice-1 predicates)

Each is a pure comparison over strict-typed retained fields; a compliant identity leaves each unsatisfied.

1. **`privileged_without_mfa`** — fires iff `privileged is True` (a producer attestation) **and**
   `mfa_enrolled is False`. If MFA status is absent/unknown the oracle REFUSES (a missing field is NOT proof
   MFA is absent — the "failed parse ≠ absence" discipline). Benign twin: a privileged identity with
   `mfa_enrolled is True` → silent.
2. **`stale_credential`** — fires iff `never_rotated is True`, **or** both `age_days` and `max_age_days` are
   integers and `age_days >= max_age_days`. The threshold (`max_age_days`) is the operator's rotation policy,
   supplied per credential; absent/non-integer age or threshold → REFUSE (the oracle chooses no policy).
   Benign twin: a credential with `age_days < max_age_days` → silent.

## The mandatory benign twin (must be SILENT end-to-end)

A compliant identity — `privileged: true, mfa_enrolled: true` with `age_days < max_age_days` — produces ZERO
facts through the real producer path.

## Non-goals — REFUSE, never assert

- **Anomaly / behavioral detection** (impossible-travel, unusual-login, entropy/risk scoring). Probabilistic;
  cannot be a near-zero-FP FACT. Out of scope, exactly as Domain 10 refused message-level DKIM.
- **Cloud resource IAM.** Over-broad grants on AWS/GCP/Azure *resources* stay with the existing `POLICY_PATH`
  / `CLOUD_POSTURE` oracles. Domain 7 is the IdP's OWN identity/role model only — no overlap.
- **Privilege inference.** The oracle never guesses "privileged" from role names; it requires the producer
  attestation `privileged: true`.
- **Live IdP calls.** Offline over a retained export only — no Okta/Entra/LDAP API, no auth attempt, no mail.

## Trust boundaries (to be recorded in `V2-LIMITATIONS.md` at stage 10)

- `privileged`, `mfa_enrolled`, `never_rotated` are read by STRICT identity (`is True` / `is False`), never
  coerced — a truthy `"false"`/`1` is dropped, not laundered (the Domain-10 bool-laundering lesson).
- `privileged` is a PRODUCER ATTESTATION, not derived by the oracle (analogous to Domain 10's `is_org_domain`
  / the absent PSL).
- `max_age_days` is producer-supplied POLICY, not an oracle-chosen threshold.
- `age_days` is a retained integer the producer computed — NO wall-clock in the proof path (determinism).

## Sovereignty / gate

Sensor Tier-1, `capability=None`, `egress_hosts=()`, offline local-JSON export only. `IDENTITY_POSTURE` is
`OracleKind` #31, held OUT of the frozen `_ALL_ORACLES` (stays 15), reachable only via its
`identity_misconfiguration` `BUG_CLASS_ORACLES` row keyed on an `identity_control` context field no
benchmark/scan/engage finding carries — so `make gate` stays byte-identical.

## Merge bar (the now-standing dual gate)

RED-PEN attestation **and** an independent `adversarial-sweep` attestation (FORGE §3 stage 9, both required),
`make gate` byte-identical, CHRONICLER ledger, and human approval. No self-merge.
