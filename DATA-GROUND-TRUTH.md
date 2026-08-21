# Data ground truth

Where sensitive data actually lives on disk, what form it is in, and what can be done to it. This is
the operator's factual map — kept true of the code, cross-checked by
`engine/crucible/framework/v2/agents/tests/test_evidence_erasure.py`.

| Data | Location | Contains credentials? | At-rest form | Mutable? | Erasure |
|------|----------|-----------------------|--------------|----------|---------|
| HTTP evidence archive | `targets/<slug>/evidence/<action_id>/` (`request.http`, `response.http`, `response.body`) | **Yes** — `Authorization`/`Cookie` request lines; raw response bodies | plaintext (0600); credential header *names* masked in `.http` dumps per `common/redact.py`; raw `response.body` byte-faithful | filesystem (not append-only) | **crypto-shred** — sealed in place under the per-engagement DEK, then the DEK is destroyed (`erase-evidence`) |
| Event spine | `framework/v2/.blackboard/store.sqlite` | Possibly — small excerpts (`ResultPayload.body_excerpt`, `ObservationPayload.raw_excerpt`) | plaintext unless sealed via `crypto_shred.seal_text`; **append-only** (SQLite triggers + signed hash chain) | **No** — append-only; supersede-only | credential excerpts sealed under the DEK become unrecoverable when the DEK is shredded; the row itself is never deleted (a tombstone is appended) |
| Evidence DEK keystore | `framework/v2/.evidence-keys/<slug>.dek` (override: `CRUCIBLE_EVIDENCE_KEYS_DIR`) | the keys, not the data | 32-byte AES-256 key, 0600, gitignored | yes — **shreddable** (this is the point) | destroying a `.dek` crypto-shreds that engagement's sealed evidence everywhere it was copied |
| Governance / entitlement material | `framework/v2/.entitlement/`, `framework/v2/.authority/` | trust roots, signed grants, kill-switch | owner-only, gitignored | operator-provisioned | out of scope for evidence erasure |

## The append-only / erasure relationship (the W16-8 collision, resolved)

The spine is append-only so it can be a tamper-evident audit log; captured evidence holds real
credentials. Deleting evidence rows to satisfy an erasure request would break append-only and the
signed hash chain. The resolution (ADR-0008) is **crypto-shredding**: keep the encryption key
*outside* the append-only store and erase by destroying the key. Consequences, guarantees, and the
one honest residual (seal-at-capture is not yet the default) are in `PRIVACY.md` and the ADR. The DPA
(W14-2 #504) and the claims registry (W0-3 #398) cite those as the source of truth.
