"""
evidence.certify — build, sign, and independently verify an evidence certificate.

This is where "prove-don't-guess" gains a cryptographic spine. A finding already retains
a replayable `oracle_context`; this layer authenticates it. `verify_certificate` checks
FOUR independent things, and a certificate is sound only if all hold:

  1. AUTHENTICITY  — an m-of-n governance signature over the certificate's canonical
     bytes (reusing the entitlement trust-root threshold verify).
  2. BINDING       — the certificate's `oracle_context_digest` matches the sha256 of the
     oracle_context presented, so the signature cannot be lifted onto different evidence.
  3. ARTIFACT INTEGRITY — every raw file in the manifest still hashes to its recorded
     digest (the bytes the oracle saw are unaltered).
  4. REPRODUCTION  — the pure oracle re-fires over the oracle_context and matches the
     claimed verdict (the existing `verify.reverify` contract).

Signing is provisioning-only (governance authorisers, offline); the runtime only ever
verifies. The whole layer is ADDITIVE: findings without a certificate re-verify exactly
as before.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ..entitlement.crypto import sign, verify_threshold
from ..entitlement.models import Signature, TrustRoot
from ..verify.reverify import reverify_context
from .canonical import digest_payload, evidence_signing_bytes
from .chain import verify_chain, verify_head
from .manifest import manifest_dir, verify_manifest
from .models import ChainEntry, EvidenceCertificate, SignedChainHead, SignedEvidence


def build_certificate(
    finding: dict,
    *,
    engagement_slug: str = "",
    seq: int = 0,
    evidence_root: Path | None = None,
    action_id: str | None = None,
) -> EvidenceCertificate:
    """Build an (unsigned) certificate from a serialized finding carrying an
    `oracle_context`. If an evidence dir is given, its raw artifacts are manifested by
    per-file sha256 and bound into the certificate."""
    oracle_context = finding.get("oracle_context") or {}
    artifacts = []
    if evidence_root is not None and action_id:
        artifacts = manifest_dir(Path(evidence_root) / action_id, root=Path(evidence_root))
    return EvidenceCertificate(
        engagement_slug=engagement_slug,
        finding_ref=str(finding.get("check_id") or finding.get("finding_slug")
                        or finding.get("bug_class") or "finding"),
        bug_class=str(finding.get("bug_class", "")),
        surface=str(finding.get("insertion_point") or finding.get("param") or ""),
        confirmed_by=str(finding.get("confirmed_by", "")),
        confidence=float(finding.get("confidence", 0.0) or 0.0),
        oracle_context_digest=digest_payload(oracle_context),
        artifacts=artifacts,
        seq=seq,
    )


def sign_certificate(cert: EvidenceCertificate, signers: list[tuple[str, str]]) -> SignedEvidence:
    """Sign a certificate with governance authorisers (PROVISIONING ONLY — never the
    runtime). ``signers`` is a list of (key_id, private_key_b64)."""
    msg = evidence_signing_bytes(cert.model_dump(mode="json"))
    signatures = [Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers]
    return SignedEvidence(certificate=cert, signatures=signatures)


class EvidenceVerification(BaseModel):
    """The layered verdict on one signed certificate. ``ok`` requires ALL layers."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    authentic: bool = False        # m-of-n signature over the certificate
    bound: bool = False            # oracle_context_digest matches the presented context
    artifacts_ok: bool = True      # every manifested raw file still hashes correctly
    reproduced: bool = False       # the pure oracle re-fires and matches the claim
    valid_signers: tuple[str, ...] = ()
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.authentic and self.bound and self.artifacts_ok and self.reproduced


def verify_certificate(
    signed: SignedEvidence,
    *,
    oracle_context: dict,
    trust_root: TrustRoot,
    evidence_root: Path | None = None,
) -> EvidenceVerification:
    """Independently verify a signed certificate against the oracle_context it claims to
    authenticate. Checks authenticity + binding + artifact integrity + reproduction."""
    cert = signed.certificate

    thr = verify_threshold(
        evidence_signing_bytes(cert.model_dump(mode="json")), signed.signatures, trust_root)

    bound = digest_payload(oracle_context) == cert.oracle_context_digest

    artifacts_ok = True
    artifact_note = ""
    if cert.artifacts:
        if evidence_root is None:
            # FAIL CLOSED: a certificate that CLAIMS artifacts is not sound unless those
            # artifacts were actually checked — never pass an unchecked manifest.
            artifacts_ok = False
            artifact_note = "; artifacts CLAIMED but NOT checked (no evidence_root) — refusing to pass"
        else:
            results = verify_manifest(cert.artifacts, root=Path(evidence_root))
            bad = [f"{p}: {note}" for p, ok, note in results if not ok]
            artifacts_ok = not bad
            if bad:
                artifact_note = "; artifacts FAILED: " + ", ".join(bad)

    rr = reverify_context(
        oracle_context, bug_class=cert.bug_class,
        claimed_confirmed_by=cert.confirmed_by, claimed_confidence=cert.confidence,
        ref=cert.finding_ref)

    reason = (f"signature: {thr.reason}; "
              f"binding: {'oracle_context matches digest' if bound else 'DIGEST MISMATCH — signature is for different evidence'}; "
              f"reproduction: {rr.note}{artifact_note}")
    return EvidenceVerification(
        finding_ref=cert.finding_ref, authentic=thr.satisfied, bound=bound,
        artifacts_ok=artifacts_ok, reproduced=rr.ok, valid_signers=thr.valid_signers,
        reason=reason)


class BundleVerification(BaseModel):
    """The verdict on a whole evidence bundle. ``ok`` requires that the chain covers
    EXACTLY the certificates present (nothing suppressed/injected/reordered), every
    certificate is individually sound, and the chain is anchored + not rolled back."""

    model_config = ConfigDict(extra="forbid")

    certificate_results: list[EvidenceVerification] = Field(default_factory=list)
    cert_set_bound: bool = False   # chain digests == the certificates' digests, in order
    chain_ok: bool = False
    chain_note: str = ""

    @property
    def ok(self) -> bool:
        return (bool(self.certificate_results) and self.cert_set_bound and self.chain_ok
                and all(r.ok for r in self.certificate_results))


def verify_bundle(
    certificates: list[SignedEvidence],
    chain: list[ChainEntry],
    head: SignedChainHead | None,
    *,
    contexts: dict[str, dict],
    trust_root: TrustRoot,
    evidence_root: Path | None = None,
    prev_highwater: int | None = None,
) -> BundleVerification:
    """Verify a bundle as a WHOLE. Beyond per-certificate soundness, this binds the
    certificate SET to the hash chain (the chain's digests must equal the certificates'
    digests, in order) so a certificate cannot be silently deleted, injected, or
    reordered while leaving a valid-looking chain — and applies the monotonic
    anti-rollback high-water on the signed head."""
    cert_digests = [sc.certificate.cert_digest for sc in certificates]
    chain_digests = [e.cert_digest for e in chain]
    cert_set_bound = cert_digests == chain_digests

    results = [
        verify_certificate(sc, oracle_context=contexts.get(sc.certificate.finding_ref, {}),
                           trust_root=trust_root, evidence_root=evidence_root)
        for sc in certificates]

    if head is not None:
        chain_ok, chain_note = verify_head(head, chain, trust_root, prev_highwater=prev_highwater)
    else:
        chain_ok, chain_note = verify_chain(chain)
        chain_note += " (UNSIGNED head — not anchored to governance)"

    if not cert_set_bound:
        chain_note += (f"; CERT-SET MISMATCH: {len(cert_digests)} certificate(s) vs "
                       f"{len(chain_digests)} chain entr(ies) — a certificate was "
                       f"suppressed, injected, or reordered")
    return BundleVerification(certificate_results=results, cert_set_bound=cert_set_bound,
                              chain_ok=chain_ok, chain_note=chain_note)
