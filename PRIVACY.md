# Privacy & evidence-retention position

This document states the **real** position on the third-party credential material VIGIL captures
during an authorized engagement, how long it is retained, and how it can be erased. It is true of
the shipped code (see the decision record `knowledge/decisions/0008-crypto-shred-erasure-for-append-only-evidence.md`
and the mechanism in `engine/crucible/framework/v2/common/crypto_shred.py` /
`engine/crucible/framework/v2/agents/evidence_erasure.py`).

## What is captured

During a live engagement the executor archives the HTTP evidence needed to prove a finding:

- `request.http` — the request line and headers, **including** `Authorization` / `Cookie` request
  lines when the target requires them (credential *header names* are masked in the human-readable
  dump per `common/redact.py`, but the request as sent may still authenticate with a real token);
- `response.http` and `response.body` — the raw response, kept **byte-faithful** because
  over-masking a body would destroy the very proof a finding rests on;
- small credential-adjacent excerpts can also be reflected into the append-only event spine
  (`ResultPayload.body_excerpt`, `ObservationPayload.raw_excerpt`).

These live under `targets/<slug>/evidence/<action_id>/` (owner-only, 0600) and in the append-only
SQLite spine (`framework/v2/.blackboard/store.sqlite`, owner-only).

## Retention

The event spine is **append-only by design** (SQLite triggers + a governance-signed hash chain):
it is a tamper-evident audit log and is **never** silently deleted or edited. Evidence is retained
for the life of the engagement record so findings remain independently re-verifiable.

## Erasure (right to erasure)

Because the spine is append-only, credential material is erased by **crypto-shredding**, not
deletion:

- credential-bearing material is sealed under a **per-engagement key** (AES-256-GCM) held in a
  shreddable keystore that lives **outside** the append-only spine
  (`framework/v2/.evidence-keys/`, override with `CRUCIBLE_EVIDENCE_KEYS_DIR`);
- an erasure request destroys that key:

  ```
  python3 -m framework.v2 erase-evidence --engagement <slug> --reason "<request ref>" --yes
  ```

- after the key is destroyed, any **sealed** ciphertext — on disk, or **in any off-host backup copy of
  the ciphertext** — is cryptographically unrecoverable, while every append-only row is byte-for-byte
  unchanged and the audit chain still verifies. A signed tombstone is appended to the spine recording
  that (and when) erasure happened.

> **Honest scope (what is and is not sealed today).** The on-disk evidence archive is sealed at erasure
> and crypto-shredded. The sealing primitive (`crypto_shred.seal_text`) can also seal a credential
> excerpt destined for the append-only spine (`ResultPayload.body_excerpt`,
> `ObservationPayload.raw_excerpt`), **but seal-at-capture is not yet wired into the live executor**
> (staged as a follow-up with the reporter/redaction work). Until it is, excerpts already written to the
> spine are stored in plaintext and are **not** made unrecoverable by crypto-shredding — do not rely on
> erasing them. The DEK keystore (`framework/v2/.evidence-keys/`) **must never be replicated to the same
> off-host location as the ciphertext**, or a backup could resurrect a shredded key.
>
> **Sealed at rest today (Wave-A2 — proof-path re-verifiable context ONLY).** The offline-re-verifiable
> `oracle_context` the **proof path** persists (`proofs/reverifiable.json`, written by
> `proof.run._persist_runtime_reverifiable` / `_persist_reverifiable`) now **seals** its load-bearing
> secret-bearing fields at persist time under the per-engagement DEK: the exposure secret-signature arm's
> `observed_evidence.{secret_value, secret_assignment, body}` and the error-signature arm's
> `error_observed` / `error_control` raw response bytes. They are recoverable **in-engagement** (the local
> DEK) for offline re-verify / remediation and are crypto-shredded on erasure; the entry carries a
> `sealed_engagement` stamp the re-verify and remediation consumers key the unseal by. A client bundle /
> audit package **unseals** in-engagement before it ships (a deliberate disclosure), so it stays
> third-party-verifiable; the run's own `reverifiable.json` stays sealed at rest.
>
> **Named residual — scanner-path `error_observed` is still plaintext.** The scanner's own error-based
> injection check writes the full raw probe response body into `error_observed` **unsealed** to its
> `--reverifiable-out` (`scanner/checks.py` → `scanner/cli.py`), so the SAME class of raw response bytes
> remains in plaintext at rest on the **scan/console** path (and in the `findings.json` / SARIF / HTML it
> feeds). Sealing that artifact is deferred: `--reverifiable-out` is a byte-reproducible re-verification
> input and a random-nonce seal would break its determinism + byte-identity, so it needs its own slice with
> a deterministic-shape unseal-before-hash reader. Do not read the Wave-A2 sealing as covering the scanner
> path.

Erasure is **irreversible** and **per-engagement**: it cannot be undone, and it affects only the
named engagement. The command is destructive and default-denies without `--yes`.

## Honest limitations

- **Seal-at-capture is not yet the default.** Today the on-disk archive is turned into ciphertext at
  *erasure* time. Crypto-shredding an off-host backup is therefore fully effective for backups taken
  **after** an erasure/seal; a backup taken while evidence was still plaintext may still contain that
  plaintext. Making the live executor seal credential material **at capture** (so plaintext never
  reaches disk or a backup) is a planned follow-up tracked with the redaction work (W6-5 #456) and the
  off-host backup work (W7-2 #460); it is deferred because it changes the byte-identity of every
  evidence file and must ship together with the readers and the evidence manifest.
- **Wave-A2 sealing is proof-path only; two named residuals.** (1) The scan/console **report render**
  path (`report.adapt` → `findings.json` → `report.grounding.grade_finding` for `technical.md`/SARIF/JSON
  and the findings hub) does not yet carry `sealed_engagement` onto its `FindingPayload`, so a proof-sink
  FACT surfaced through THAT path grades as a *lead* — a **conservative under-claim**, never a false fact.
  Follow-up: thread the slug through adapt + `FindingPayload` (omit-when-empty) and unseal in
  `grade_finding`. (2) At rest the stored `signed_certificate` digest is over the **plaintext** context
  while the retained context is sealed; this is benign because every consumer that checks binding
  (`proof.bundle.export_bundle`, `evidence.build_audit_package`) **unseals in-engagement first**, and
  `framework.v2 verify` re-fires without a binding check. A NEW binding consumer pointed at a sealed
  `proofs/reverifiable.json` must unseal first (as those two now do) or it will fail BINDING/REPRODUCTION.
- **The Data Processing Agreement (W14-2 #504) and the claims registry (W0-3 #398)** are maintained in
  their own issues; they cite this document and ADR-0008 as the source of truth for the erasure
  mechanism.
