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
from .models import (
    ChainEntry,
    EvidenceCertificate,
    PathCertificate,
    PathStep,
    ReportClaim,
    SignedChainHead,
    SignedEvidence,
)


def trust_root_fingerprint(trust_root: TrustRoot) -> str:
    """A stable, content-addressed fingerprint of a trust root's PUBLIC governance material (its threshold +
    authoriser public keys). The verifier compares this against a value the operator publishes OUT-OF-BAND —
    that comparison, not the copy of trust-root.json shipped alongside a bundle, is what anchors authenticity.
    Two byte-identical trust roots share a fingerprint; adding/removing/altering any key changes it."""
    return "sha256:" + digest_payload(trust_root.model_dump(mode="json"))


def build_certificate(
    finding: dict,
    *,
    engagement_slug: str = "",
    seq: int = 0,
    evidence_root: Path | None = None,
    action_id: str | None = None,
    report_claims: "list[ReportClaim] | None" = None,
) -> EvidenceCertificate:
    """Build an (unsigned) certificate from a serialized finding carrying an
    `oracle_context`. If an evidence dir is given, its raw artifacts are manifested by
    per-file sha256 and bound into the certificate. ``report_claims`` (optional) binds
    atomic report sentences INTO the certificate so the signature covers them and
    ``verify_certificate`` re-admits each — sorted for deterministic canonical bytes."""
    oracle_context = finding.get("oracle_context") or {}
    artifacts = []
    if evidence_root is not None and action_id:
        artifacts = manifest_dir(Path(evidence_root) / action_id, root=Path(evidence_root))
    claims = sorted(report_claims, key=lambda c: (c.sentence, c.bug_class)) if report_claims else None
    # Stamp the PCF oracle id@version at mint time (over the kind that fired), so the signature covers it
    # and a verifier can detect a later oracle-body change. Empty when confirmed_by is unset/unknown —
    # then the field is dropped from the canonical form and the cert serialises exactly as before.
    from ..verify.oracle_version import oracle_version as _oracle_version
    ov = _oracle_version(str(finding.get("confirmed_by", "")))
    return EvidenceCertificate(
        schema_version=2 if claims else 1,   # claim-bearing certs are schema v2
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
        report_claims=claims,
        oracle_version=ov,
    )


def build_path_certificate(attack_path, *, backing_cert_digests: list[str],
                           engagement_slug: str = "", seq: int = 0) -> PathCertificate:
    """Build a (chain-anchored) certificate binding a derived attack path to the
    confirmed-finding certificates its hops depend on. ``attack_path`` is duck-typed (the
    ``scanner.orchestrator.AttackPath``: ``.steps`` of src/edge/dst/technique + a
    ``.destination``), so the evidence layer stays decoupled from the reasoning layer.
    ``backing_cert_digests`` are the ``cert_digest``s of the findings the caller determined
    established the path (e.g. by walking the world-model path edges' finding provenance);
    they are de-duplicated and sorted for deterministic canonical bytes."""
    steps = [PathStep(src=s.src, edge=s.edge, dst=s.dst, technique=getattr(s, "technique", ""))
             for s in getattr(attack_path, "steps", [])]
    dest = getattr(attack_path, "destination", "") or (steps[-1].dst if steps else "")
    return PathCertificate(
        engagement_slug=engagement_slug, destination=dest, steps=steps,
        backing_cert_digests=sorted(set(backing_cert_digests or [])), seq=seq)


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
    claims_grounded: bool = True   # every fact-bound report sentence re-admits as a fact
    valid_signers: tuple[str, ...] = ()
    reason: str = ""

    @property
    def ok(self) -> bool:
        return (self.authentic and self.bound and self.artifacts_ok and self.reproduced
                and self.claims_grounded)


def _claims_grounded(cert: EvidenceCertificate, oracle_context: dict) -> tuple[bool, str]:
    """5th layer: every report sentence bound into the certificate as a fact
    (``render_as == "fact"``) must have its DECLARED bug_class re-admit through the veracity
    firewall against the authenticated oracle_context. Because a proof is bound to its
    subject (P3), a claim declaring a class the evidence does not prove — a relabelled claim
    — does NOT ground and fails the certificate closed. Fail-closed: a fact claim that
    cannot be re-grounded (e.g. an empty/altered context) is not sound.

    Scope, stated honestly: this checks the declared CLASS re-executes, not the sentence's
    natural language. A deterministic gate does no entailment, so free prose is bound as
    labelled analyst commentary (no obligation); the only fact producers emit via
    evidence.claims is the canonical structured statement, which re-grounds by construction.
    The signature over the whole certificate makes every bound sentence's TEXT tamper-evident
    regardless of its render_as."""
    fact_claims = [rc for rc in (cert.report_claims or []) if rc.render_as == "fact"]
    if not fact_claims:
        return (True, "no fact-bound report claims")
    from ..veracity.claims import Claim
    from ..veracity.firewall import admit
    from ..veracity.tokens import GroundingToken
    for rc in fact_claims:
        claim = Claim(text=rc.sentence, source="report", bug_class=rc.bug_class, tokens=[
            GroundingToken.oracle(oracle_context, bug_class=rc.bug_class,
                                  confirmed_by=cert.confirmed_by or None,
                                  confidence=cert.confidence)])
        if not admit(claim).is_fact:
            return (False, f"a fact-bound report sentence declares bug_class "
                           f"{rc.bug_class!r} but that class does not re-verify against the "
                           f"evidence: {rc.sentence!r}")
    return (True, f"{len(fact_claims)} fact-bound report sentence(s) re-grounded")


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

    claims_grounded, claims_note = _claims_grounded(cert, oracle_context)

    reason = (f"signature: {thr.reason}; "
              f"binding: {'oracle_context matches digest' if bound else 'DIGEST MISMATCH — signature is for different evidence'}; "
              f"reproduction: {rr.note}; claims: {claims_note}{artifact_note}")
    return EvidenceVerification(
        finding_ref=cert.finding_ref, authentic=thr.satisfied, bound=bound,
        artifacts_ok=artifacts_ok, reproduced=rr.ok, claims_grounded=claims_grounded,
        valid_signers=thr.valid_signers, reason=reason)


class PathVerification(BaseModel):
    """The verdict on one derived attack-path certificate. ``ok`` requires that every
    finding certificate the path is bound to is present in the bundle AND itself verified —
    a path with no reproducing evidence under it can never pass as a proven route."""

    model_config = ConfigDict(extra="forbid")

    destination: str = ""
    backing_bound: bool = False
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.backing_bound


class BundleVerification(BaseModel):
    """The verdict on a whole evidence bundle. ``ok`` requires that the chain covers
    EXACTLY the certificates present (nothing suppressed/injected/reordered), every
    certificate is individually sound, the chain is anchored + not rolled back, and every
    derived attack path is bound to backing findings that themselves verified."""

    model_config = ConfigDict(extra="forbid")

    certificate_results: list[EvidenceVerification] = Field(default_factory=list)
    path_results: list[PathVerification] = Field(default_factory=list)
    cert_set_bound: bool = False   # chain digests == (finding + path) certs' digests, in order
    chain_ok: bool = False
    chain_note: str = ""

    @property
    def ok(self) -> bool:
        return (bool(self.certificate_results) and self.cert_set_bound and self.chain_ok
                and all(r.ok for r in self.certificate_results)
                and all(p.ok for p in self.path_results))


def _verify_paths(path_certs: list[PathCertificate], verified_finding_digests: set[str],
                  *, head_anchored: bool) -> list[PathVerification]:
    """Fail-closed: a path is sound only if (0) a VALID governance-signed chain head anchors
    it, (1) it cites ≥1 backing finding certificate, AND (2) every backing digest resolves
    to a finding certificate that itself verified. Requirement (0) is load-bearing: unlike
    finding certificates, path certificates are NOT individually signed — the signed head is
    their only governance anchor, so without it an attacker could fabricate an arbitrary
    route, rebuild the (unsigned) chain to match, and it would otherwise pass. A path with no
    anchor, no backing, or citing an absent/unverified finding is an unsupported route."""
    out: list[PathVerification] = []
    for pc in path_certs:
        backing = set(pc.backing_cert_digests)
        if not head_anchored:
            out.append(PathVerification(destination=pc.destination, backing_bound=False,
                reason="path certificate is not anchored by a valid governance-signed chain "
                       "head — an unsigned/absent head cannot rule out a fabricated route, refused"))
        elif not backing:
            out.append(PathVerification(destination=pc.destination, backing_bound=False,
                reason="path cites NO backing finding certificate — an unsupported route, refused"))
        elif backing - verified_finding_digests:
            out.append(PathVerification(destination=pc.destination, backing_bound=False,
                reason=f"path cites backing certificate(s) absent or unverified: "
                       f"{sorted(backing - verified_finding_digests)}"))
        else:
            out.append(PathVerification(destination=pc.destination, backing_bound=True,
                reason=f"all {len(backing)} backing finding certificate(s) present and verified"))
    return out


def verify_bundle(
    certificates: list[SignedEvidence],
    chain: list[ChainEntry],
    head: SignedChainHead | None,
    *,
    contexts: dict[str, dict],
    trust_root: TrustRoot,
    evidence_root: Path | None = None,
    prev_highwater: int | None = None,
    path_certs: list[PathCertificate] | None = None,
) -> BundleVerification:
    """Verify a bundle as a WHOLE. Beyond per-certificate soundness, this binds the
    certificate SET to the hash chain (the chain's digests must equal the certificates'
    digests, in order) so a certificate cannot be silently deleted, injected, or
    reordered while leaving a valid-looking chain — and applies the monotonic
    anti-rollback high-water on the signed head.

    ``path_certs`` (derived attack paths, anti-hallucination P4c) are anchored in the SAME
    chain AFTER the finding certificates: their digests extend the chain-set binding, and
    each path is verified to be backed by finding certificates that themselves verified —
    so a fabricated or under-supported path fails the bundle CLOSED."""
    path_certs = path_certs or []
    cert_digests = [sc.certificate.cert_digest for sc in certificates]
    path_digests = [pc.cert_digest for pc in path_certs]
    chain_digests = [e.cert_digest for e in chain]
    # the chain must cover the finding certs THEN the path certs, in that order.
    cert_set_bound = (cert_digests + path_digests) == chain_digests

    results = [
        verify_certificate(sc, oracle_context=contexts.get(sc.certificate.finding_ref, {}),
                           trust_root=trust_root, evidence_root=evidence_root)
        for sc in certificates]

    if head is not None:
        chain_ok, chain_note = verify_head(head, chain, trust_root, prev_highwater=prev_highwater)
    else:
        chain_ok, chain_note = verify_chain(chain)
        chain_note += " (UNSIGNED head — not anchored to governance)"

    # Path certificates are NOT individually signed; a VALID signed head is their only
    # governance anchor. Verify chain/head FIRST, then anchor the paths on it — so a
    # fabricated route in an unsigned (or invalidly-signed) bundle fails closed rather than
    # riding an attacker-rebuilt chain.
    verified_finding_digests = {
        sc.certificate.cert_digest for sc, r in zip(certificates, results) if r.ok}
    path_results = _verify_paths(path_certs, verified_finding_digests,
                                 head_anchored=(head is not None and chain_ok))

    if not cert_set_bound:
        chain_note += (f"; CERT-SET MISMATCH: {len(cert_digests)} finding + {len(path_digests)} "
                       f"path certificate(s) vs {len(chain_digests)} chain entr(ies) — a "
                       f"certificate was suppressed, injected, or reordered")
    return BundleVerification(certificate_results=results, path_results=path_results,
                              cert_set_bound=cert_set_bound, chain_ok=chain_ok, chain_note=chain_note)
