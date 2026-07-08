"""
framework.v2.evidence — cryptographic evidence integrity.

Turns CRUCIBLE's already-replayable finding certificates into *provable* ones. A
finding retains a pure, re-runnable `oracle_context`; this package adds an
authenticated wrapper (`EvidenceCertificate`) that governance authorisers SIGN, a
per-file artifact manifest that binds the raw bytes the oracle saw, and a hash-linked
`chain` that makes the whole evidence log tamper-evident.

`verify_certificate` proves four independent things — authenticity (m-of-n signature),
binding (the signature is for THIS oracle_context, by digest), artifact integrity, and
reproduction (the existing pure-oracle re-run) — so a finding is provable to a third
party with no trust in the tool that produced it.

Reuses the platform's existing crypto substrate verbatim: `entitlement.crypto` (Ed25519
threshold), the domain-separated canonical-bytes discipline, and `verify.reverify`.
Signing is provisioning-only; the runtime only ever verifies. Everything is additive —
findings without a certificate re-verify exactly as before.
"""

from .canonical import canonical_json, digest_payload, evidence_signing_bytes, sha256_hex
from .models import (
    ArtifactRef,
    ChainEntry,
    EvidenceCertificate,
    ReportClaim,
    SignedChainHead,
    SignedEvidence,
)
from .claims import canonical_fact_sentence, claims_for_finding, decompose_prose
from .manifest import manifest_dir, verify_manifest
from .certify import (
    BundleVerification,
    EvidenceVerification,
    build_certificate,
    sign_certificate,
    verify_bundle,
    verify_certificate,
)
from .chain import append_entry, build_chain, sign_head, verify_chain, verify_head

__all__ = [
    "canonical_json", "digest_payload", "evidence_signing_bytes", "sha256_hex",
    "ArtifactRef", "EvidenceCertificate", "SignedEvidence", "ChainEntry", "SignedChainHead",
    "ReportClaim", "claims_for_finding", "decompose_prose", "canonical_fact_sentence",
    "manifest_dir", "verify_manifest",
    "EvidenceVerification", "BundleVerification", "build_certificate", "sign_certificate",
    "verify_certificate", "verify_bundle",
    "append_entry", "build_chain", "sign_head", "verify_chain", "verify_head",
]
