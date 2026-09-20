# Data ground truth

Where sensitive data actually lives on disk, what form it is in, and what can be done to it. This is
the operator's factual map — kept true of the code, cross-checked by
`engine/crucible/framework/v2/agents/tests/test_evidence_erasure.py`.

<!-- CLAIM:W14-3 -->
This map is generated from `docs/data-ground-truth/data-stores.json` and verified against the code that defines each on-disk store; CI fails when a store the code writes to is not described here or in the out-of-scope table below.

<!-- BEGIN GENERATED data-ground-truth (source: docs/data-ground-truth/data-stores.json; regenerate: python3 docs/data-ground-truth/gen_data_ground_truth.py) -->
| Data | Location | Contains credentials? | At-rest form | Mutable? | Erasure |
|------|----------|-----------------------|--------------|----------|---------|
| HTTP evidence archive | `targets/<slug>/evidence/<action_id>/` (`request.http`, `response.http`, `response.body`) | **Yes** — `Authorization`/`Cookie` request lines; raw response bodies | plaintext (0600); credential header *names* masked in `.http` dumps per `common/redact.py`; raw `response.body` byte-faithful | filesystem (not append-only) | **crypto-shred** — sealed in place under the per-engagement DEK, then the DEK is destroyed (`erase-evidence`) |
| Event spine | `framework/v2/.blackboard/store.sqlite` | Possibly — small excerpts (`ResultPayload.body_excerpt`, `ObservationPayload.raw_excerpt`) | plaintext unless sealed via `crypto_shred.seal_text`; **append-only** (SQLite triggers + signed hash chain) | **No** — append-only; supersede-only | credential excerpts sealed under the DEK become unrecoverable when the DEK is shredded; the row itself is never deleted (a tombstone is appended) |
| Evidence DEK keystore | `framework/v2/.evidence-keys/<slug>.dek` (override: `CRUCIBLE_EVIDENCE_KEYS_DIR`) | the keys, not the data | 32-byte AES-256 key, 0600, gitignored | yes — **shreddable** (this is the point) | destroying a `.dek` crypto-shreds that engagement's sealed evidence everywhere it was copied |
| Governance / entitlement material | `framework/v2/.entitlement/`, `framework/v2/.authority/`, `framework/v2/.authority-root/` | trust roots, signed grants, kill-switch, governance authority root | owner-only, gitignored | operator-provisioned | out of scope for evidence erasure |
<!-- END GENERATED data-ground-truth -->

## Framework state stores deliberately not in this credential map

Every other hidden on-disk store the framework creates is enumerated below with the reason it is not
part of the credential map above. This table is generated too: a new on-disk sink the code grows that
is neither documented above nor accounted for here turns the build red (see the drift guard,
`docs/tests/test_data_ground_truth_drift.py`).

<!-- BEGIN GENERATED data-ground-truth-oos (source: docs/data-ground-truth/data-stores.json) -->
| On-disk store | Resolver | Why it is not in the credential map above |
|---------------|----------|-------------------------------------------|
| `.crucible-v2.log` | `crucible_v2_log` | per-engagement structured audit log; every event passes through common/redact.scrub_log_event before write, so it is not a raw-credential archive |
| `.dryrun` | `dryrun_dir` | dry-run planning artifacts; no live target capture is performed in dry-run, so no credentials come to rest here |
| `.improve` | `improve_dir` | self-improvement-loop gaps and reviewable proposals about the framework itself; never target credentials or captured evidence |
| `.intake-authorizations.txt` | `authorization_ledger` | the operator's own intake-authorization records (attestations that a target may be tested); not target data or credentials |
| `.memory` | `memory_dir` | cross-engagement learning priors / world-model; stores derived signal (archetypes, embeddings, outcomes), not raw captured HTTP or credential headers |
| `.planner-state.json` | `planner_state` | engagement planner checkpoint (phase/step cursor); no captured HTTP or credential material |
<!-- END GENERATED data-ground-truth-oos -->

## The append-only / erasure relationship (the W16-8 collision, resolved)

The spine is append-only so it can be a tamper-evident audit log; captured evidence holds real
credentials. Deleting evidence rows to satisfy an erasure request would break append-only and the
signed hash chain. The resolution (ADR-0008) is **crypto-shredding**: keep the encryption key
*outside* the append-only store and erase by destroying the key. Consequences, guarantees, and the
one honest residual (seal-at-capture is not yet the default) are in `PRIVACY.md` and the ADR. The DPA
(W14-2 #504) and the claims registry (W0-3 #398) cite those as the source of truth.
