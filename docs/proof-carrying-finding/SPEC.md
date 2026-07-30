# Proof-Carrying Finding — wire spec (v0.1)

This is the published, implementation-independent specification of the public artifacts in a
VIGIL proof bundle, and of the algorithm a third party runs to check one **without trusting or
running VIGIL**. The JSON Schemas in `schemas/` describe the shapes; this document pins the
*bytes* and the *checks*. The reference implementation is `verify_pcf.py` in this directory — it
imports only the Python standard library and one Ed25519 library (`cryptography`), no VIGIL code.

The bytes described here are the same ones VIGIL's own code produces and verifies
(`vigil_core.canonical`, `vigil_core.crypto`, `vigil_core.chain`,
`framework.v2.evidence.{models,certify,pcf}`). The reference verifier is derived from **this
spec**, not from those modules, and the conformance test proves the two agree byte-for-byte.

---

## 1. Canonical JSON

Every digest and every signature is taken over **canonical JSON**:

```
canonical_json(x) = json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

That is: keys sorted recursively, no insignificant whitespace, non-ASCII emitted literally as
UTF-8 (not `\uXXXX`). Numbers use the language's shortest round-trippable form (all values in these
artifacts are integers, booleans, or floats in `[0,1]`).

```
sha256_hex(b)      = hex(sha256(b))              # 64 lowercase hex chars, no prefix
digest_payload(x)  = sha256_hex(canonical_json(x))
```

## 2. Domain separation

Signatures are **not** taken over the bare canonical bytes; they are taken over the bytes under a
one-byte-terminated domain tag, so a signature for one artifact class can never be replayed as
another:

```
EVIDENCE_DOMAIN         = b"crucible-evidence-v1\x00"          # note the trailing NUL
evidence_signing_bytes(payload) = EVIDENCE_DOMAIN + canonical_json(payload)
```

Both the certificate signature and the chain-head signature use `evidence_signing_bytes`. In the
PCF wire format the same tag appears as `signature.domain = "crucible-evidence-v1"`.

## 3. Ed25519 m-of-n threshold

`verify_threshold(message, signatures, trust_root)`:

1. Index the trust root's authorizers by `key_id`.
2. Walk the signatures **in order**, skipping any repeated `key_id` (a key counts once).
3. For each remaining signature whose `key_id` is a trust-root authorizer, verify the Ed25519
   signature (base64 → 64 raw bytes) against that authorizer's public key over `message`.
4. The threshold is satisfied iff the count of **distinct valid** authorizers `>= trust_root.threshold`.

**Weak-key rejection (mandatory).** Before a public key is used, reject it fail-closed if it is:

- **non-canonical**: `(int.from_bytes(raw32, "little") & (2^255 - 1)) >= 2^255 - 19` (a y-coordinate
  `>= p` has several byte encodings for one point — a key-identity ambiguity); or
- a **small-order point** (libsodium's `ge25519_has_small_order` blocklist — a low-order public key
  admits a keyless forgery: `R = identity, S = 0` verifies for any message). The last byte is
  compared sign-bit-agnostically (`& 0x7f`).

Neither is ever produced by a legitimate keygen; both are attacker-supplied trust-root poison.

## 4. EvidenceCertificate

Shape: `schemas/evidence-certificate.schema.json`. The certificate is deterministic (no
wall-clock). Its serialized form **drops** `report_claims`, `oracle_version`, and `how_to_verify`
when they are empty, so a certificate built without them is byte-identical to a pre-additive one.

```
cert_digest = digest_payload(certificate)         # the object exactly as it appears on the wire
```

A `SignedEvidence` is `{certificate, signatures}`; the signatures cover
`evidence_signing_bytes(certificate)`.

**Binding.** The certificate carries `oracle_context_digest`. Given the retained oracle_context
(from `reverifiable.json`, keyed by `finding_ref`, or from `evidence.oracle_context.value` in a PCF
cert), a verifier requires `digest_payload(oracle_context) == oracle_context_digest`. This is why a
signature cannot be lifted onto different evidence.

**Artifacts.** Each `ArtifactRef{path, sha256, size}` is re-checked by hashing the file at
`evidence_root / path`. The path is re-confined at verify time: reject absolute paths, any `..`
component, and (after joining) any symlink escape outside `evidence_root`.

## 5. Chain and signed head

Shapes: `schemas/chain.schema.json`.

```
entry_hash(seq, prev_hash, cert_digest) = sha256_hex(canonical_json(
    {"cert_digest": cert_digest, "prev_hash": prev_hash, "seq": seq}))
GENESIS_PREV = "0" * 64
```

`verify_chain(entries)`: starting from `GENESIS_PREV` (or the head's `base_prev_hash` for a re-based
window), each entry's `prev_hash` must equal the running previous `entry_hash`, each `entry_hash`
must recompute, and `seq` must be contiguous.

**Head signing payload.** Drop `signatures`; then, **iff `schema_version < 2`**, drop the six v2
members `base_seq, base_prev_hash, base_count, cumulative_merkle_root, snapshot_seq, prev_head_hash`.
Sign/verify `evidence_signing_bytes(that payload)`. (This makes a v1 head byte-identical to a
pre-v2 head.)

`verify_head(head, entries, trust_root, prev_highwater)`:

1. `verify_chain(entries)` passes.
2. `head.head_hash == last entry_hash` (or `GENESIS_PREV` if empty).
3. `head.last_seq == last entry seq` (or `head.base_seq` if empty).
4. `head.entry_count == head.base_count + len(entries)`.
5. `verify_threshold(evidence_signing_bytes(head_payload), head.signatures, trust_root)` holds.
6. Anti-rollback: if a `prev_highwater` is supplied, `head.last_seq >= prev_highwater`.

**Cert-set binding.** The chain's `cert_digest` sequence MUST equal the certificates' own
`cert_digest`s, in order. A suppressed / injected / reordered certificate breaks this even if the
chain still links.

## 6. Trust-root fingerprint (the out-of-band anchor)

```
trust_root_fingerprint(trust_root) = "sha256:" + digest_payload(trust_root)   # PUBLIC keys only
```

`trust-root.json` shipped inside a bundle is only a **convenience copy**. Authenticity is anchored
by comparing this fingerprint to a value the operator publishes through a channel **independent of
the bundle** (their website, a signed email). A conforming verifier that is given a pin refuses the
bundle on any mismatch **before** doing crypto. Without a pin, a successful verify proves internal
consistency + binding + chain, but **not** authenticity — whoever handed you the bundle could have
re-signed it under their own key and shipped a matching root.

## 7. What "verified offline" proves — and what it does not

A conforming **standalone** verifier (this spec's reference) checks, over stdlib + Ed25519 only:

- **fingerprint** — the trust root matches the operator's out-of-band pin;
- **authentic** — each certificate's m-of-n Ed25519 signature validates against the pinned root;
- **bound** — each `oracle_context_digest` matches the retained oracle_context;
- **artifacts** — each raw file re-hashes to its recorded digest (confined to the evidence tree);
- **chained** — the hash chain + signed head bind the whole certificate set (no
  suppress/inject/reorder), anchored + not rolled back.

It does **not** re-run the oracle. **Reproduction** — re-executing the deterministic oracle over the
retained `oracle_context` to reconfirm the verdict, plus the `oracle_version` staleness check and the
claim-grounding check — is framework-specific (it requires the oracle bodies) and is performed by the
VIGIL verifier (`python -m framework.v2 evidence verify` / `pcf-verify`). Authenticity, binding,
integrity, and chain are fully checkable standalone; reproduction is the one layer that needs VIGIL.

A single flipped byte anywhere — a signature, a certificate field, a chain entry, a raw artifact, or
the retained oracle_context — flips a standalone verify to NOT SOUND.
