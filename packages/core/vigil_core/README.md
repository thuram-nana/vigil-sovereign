# vigil-core

The shared, tamper-evident integrity substrate for the VIGIL monorepo — the single source of truth for the
signed hash-chain, canonical JSON, Ed25519 (+ m-of-n threshold) crypto, and the trust-root / chain models.

Both engines depend on it: SIGIL (`apps/sigil`) re-exports it from `sigil.reuse` and keeps its
offense-free-by-construction guard on top; CRUCIBLE (`engine/crucible`) imports its primitives in place of
the former `framework/v2/{evidence,entitlement}` copies. Adopting this core breaks **no** prior signature:
the v2 `SignedChainHead` is version-conditional (a `schema_version < 2` head signs byte-identically to a
pre-v2 head) and the `crucible-evidence-v1\x00` signing domain tag is unchanged.

Dependency-minimal (cryptography + pydantic) and namespace-pure (imports no `framework.*` / `strix.*` /
`sigil.*`).
