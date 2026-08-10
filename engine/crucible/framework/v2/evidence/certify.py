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
from .canonical import digest_payload, evidence_signing_bytes, sha256_hex
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
    artifact_sha256: str = "",
    collector_id: str = "",
    collector_version: str = "",
    resource_scope: "dict[str, str] | None" = None,
    capture_time_epoch: int | None = None,
    capture_method: str = "",
    requested_scope: str = "",
    returned_scope: str = "",
    completeness: str = "",
    collector_signature: str = "",
    artifact_recheck_required: bool = False,
    artifact_encoding: str = "",
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
        how_to_verify=_cert_how_to_verify(finding),
        # criterion-9 additive fields (deterministic, dropped-when-empty → byte-identical when absent):
        # the external tool identity that produced the proposal, and a declared freshness/TTL policy.
        tool_version=str(finding.get("tool_version", "") or ""),
        freshness_ttl_seconds=int(finding.get("freshness_ttl_seconds", 0) or 0),
        # D2 (Wave #4) artifact-identity / scope / freshness / completeness binding (dropped-when-empty →
        # byte-identical when a caller passes none). capture_time_epoch is caller/time-anchor supplied; no
        # wall-clock default is injected (that would break determinism/byte-identity).
        artifact_sha256=artifact_sha256,
        collector_id=collector_id,
        collector_version=collector_version,
        resource_scope=resource_scope,
        capture_time_epoch=capture_time_epoch,
        capture_method=capture_method,
        requested_scope=requested_scope,
        returned_scope=returned_scope,
        completeness=completeness,
        collector_signature=collector_signature,
        artifact_recheck_required=bool(artifact_recheck_required),
        artifact_encoding=artifact_encoding,
    )


def _cert_how_to_verify(finding: dict) -> str:
    """A deterministic, human per-finding 'how to verify / patch' note for the certificate — derived from the
    finding's OWN surface + firing oracle + class remediation via the report.howto primitives (reused, so the
    cert and the report describe verification identically). Pure; any failure yields "" (dropped from the
    canonical form → byte-identical). Import is lazy to avoid a report<->evidence module cycle."""
    try:
        from ..report.howto import VERIFY_COMMAND, finding_specific_remediation, parse_surface
    except Exception:  # noqa: BLE001 — howto unavailable ⇒ no note (byte-identical, never fatal)
        return ""
    try:
        surface = str(finding.get("insertion_point") or finding.get("param")
                      or finding.get("surface") or "").strip()
        method, location, param = parse_surface(surface or None)
        oracle = str(finding.get("confirmed_by", "")).strip() or "the deterministic oracle"
        where = location or surface or "the affected surface"
        param_note = f" (parameter `{param}`)" if param else ""
        remediation = finding_specific_remediation(finding)
        return (
            f"Verify: re-run this finding's retained proof offline with `{VERIFY_COMMAND}` over the "
            f"reverifiable material — the `{oracle}` oracle re-fires over the captured bytes and reports OK "
            f"when it reproduces. Surface: {where}{param_note}. Fix: {remediation}"
        )
    except Exception:  # noqa: BLE001 — a malformed finding ⇒ no note (fail-open to byte-identical)
        return ""


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


# The certificate schema versions this verifier understands. An unknown version fails CLOSED (the verifier
# cannot assert soundness over a shape it does not model). v1 = base, v2 = report-claim-bearing.
SUPPORTED_SCHEMA_VERSIONS = frozenset({1, 2})


class EvidenceVerification(BaseModel):
    """The layered verdict on one signed certificate. ``ok`` (SOUNDNESS) requires authenticity + binding +
    artifact integrity + reproduction + claim grounding + a known schema. Two orthogonal signals are
    reported but NOT folded into ``ok`` — a certificate stays cryptographically sound past them:
      * ``oracle_version_current`` — the stamped oracle version matches the CURRENT oracle body. False means
        the oracle code changed since mint (the reproduction below re-ran the CURRENT oracle, so ``reproduced``
        tells you whether the finding still holds); it is NOT a soundness failure — rejecting every old cert
        after an upgrade would destroy long-term reproducibility.
      * ``currently_fresh`` — present-tense posture validity against an AUTHENTICATED time (a verified RFC3161
        anchor's genTime vs the declared TTL). ``None`` when no authenticated time was supplied (freshness is
        then simply NOT asserted — a TTL without an authenticated start cannot expire). Authenticity survives
        expiration; only present-tense freshness goes stale."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    authentic: bool = False        # m-of-n signature over the certificate (+ the pinned trust-root, if given)
    bound: bool = False            # oracle_context_digest matches the presented context
    artifacts_ok: bool = True      # every manifested raw file still hashes correctly
    primary_artifact_ok: bool = True  # BLOCK #3: when the cert requires it, sha256(raw artifact) == artifact_sha256
    reproduced: bool = False       # the pure oracle re-fires and matches the claim
    claims_grounded: bool = True   # every fact-bound report sentence re-admits as a fact
    schema_ok: bool = True         # the certificate schema version is one this verifier models
    oracle_version_current: bool = True   # stamped oracle version == current (else: oracle body changed)
    currently_fresh: "bool | None" = None  # posture validity vs an authenticated time (None = not asserted)
    valid_signers: tuple[str, ...] = ()
    # D2 (Wave #4): the non-empty artifact-identity / scope / freshness / completeness fields the certificate
    # binds. SURFACED for the caller (freshness/scope decisions are the caller's) — it does NOT gate ``.ok``.
    # Because these ride the signed certificate bytes, they are authentic whenever ``authentic`` is True.
    bound_identity: dict = Field(default_factory=dict)
    reason: str = ""

    @property
    def ok(self) -> bool:
        # SOUNDNESS — authenticity/binding/artifacts/reproduction/grounding/known-schema. Deliberately NOT
        # gated on oracle_version_current (reproducibility) or currently_fresh (a separate posture signal).
        return (self.authentic and self.bound and self.artifacts_ok and self.primary_artifact_ok
                and self.reproduced and self.claims_grounded and self.schema_ok)


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
    expected_trust_root_fingerprint: str | None = None,
    now: int | None = None,
    anchor_gen_time: int | None = None,
    artifact_bytes: bytes | None = None,
) -> EvidenceVerification:
    """Independently verify a signed certificate against the oracle_context it claims to authenticate.
    Checks authenticity + binding + artifact integrity + reproduction + claim grounding + a known schema.

    ``expected_trust_root_fingerprint`` (STRONGLY recommended): the out-of-band-published
    ``trust_root_fingerprint`` the operator trusts. When given, a ``trust_root`` whose fingerprint does not
    match it is REFUSED (``authentic=False``) BEFORE any signature check — so a bundle that ships its own
    attacker-generated trust root cannot self-authenticate. When ``None``, the caller is asserting the
    ``trust_root`` came from trusted verifier configuration (the legacy contract).

    ``now`` + ``anchor_gen_time`` (the genTime of a SEPARATELY-VERIFIED RFC3161 time anchor — the caller,
    which has the RFC3161 verifier, checks ``signed.time_anchor``'s signature and passes its genTime here):
    together they evaluate ``currently_fresh`` against the cert's declared ``freshness_ttl_seconds``. Absent
    an authenticated time, ``currently_fresh`` stays ``None`` (freshness NOT asserted — never silently fresh).
    """
    cert = signed.certificate

    # 0. TRUST-ROOT PIN (fail-closed): if the operator published a fingerprint out-of-band, the supplied
    #    trust root MUST match it — otherwise an attacker-supplied trust-root.json would self-authenticate.
    tr_pinned = True
    tr_note = ""
    if expected_trust_root_fingerprint is not None:
        actual_fp = trust_root_fingerprint(trust_root)
        want = expected_trust_root_fingerprint if expected_trust_root_fingerprint.startswith("sha256:") \
            else "sha256:" + expected_trust_root_fingerprint
        tr_pinned = (actual_fp == want)
        if not tr_pinned:
            tr_note = f"; TRUST-ROOT PIN MISMATCH — expected {want}, got {actual_fp} (refusing)"

    thr = verify_threshold(
        evidence_signing_bytes(cert.model_dump(mode="json")), signed.signatures, trust_root)

    # schema allowlist — an unknown certificate shape fails closed.
    schema_ok = cert.schema_version in SUPPORTED_SCHEMA_VERSIONS

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

    # BLOCK #3 — PRIMARY ARTIFACT RE-CHECK. When the certificate opted into a gating artifact binding
    # (artifact_recheck_required), verification RECOMPUTES sha256 over the supplied raw artifact bytes and
    # cross-checks it against the signed artifact_sha256. A signed digest alone only proves the cert CONTAINS a
    # digest; recomputing from the bytes proves the cert is bound to THOSE bytes — so swapping the artifact (a
    # 1-byte change) fails. FAIL CLOSED when the bytes are not supplied (a re-checkable artifact that is never
    # re-checked is not sound) or when artifact_sha256 is absent (nothing to bind to).
    primary_artifact_ok = True
    primary_note = ""
    if cert.artifact_recheck_required:
        if not cert.artifact_sha256:
            primary_artifact_ok = False
            primary_note = "; primary artifact re-check REQUIRED but no artifact_sha256 bound — refusing to pass"
        elif artifact_bytes is None:
            primary_artifact_ok = False
            primary_note = ("; primary artifact re-check REQUIRED but the raw artifact bytes were NOT supplied "
                            "— refusing to pass (fail-closed)")
        else:
            recomputed = sha256_hex(artifact_bytes)
            if recomputed != cert.artifact_sha256:
                primary_artifact_ok = False
                primary_note = (f"; primary artifact MISMATCH — recomputed sha256 {recomputed} != bound "
                                f"{cert.artifact_sha256} (the artifact bytes were altered or swapped)")

    rr = reverify_context(
        oracle_context, bug_class=cert.bug_class,
        claimed_confirmed_by=cert.confirmed_by, claimed_confidence=cert.confidence,
        ref=cert.finding_ref)

    claims_grounded, claims_note = _claims_grounded(cert, oracle_context)

    # ORACLE-VERSION drift (informational, NOT gating): compare the stamped id@version to the CURRENT oracle
    # body. Only flag when BOTH are known and differ — a legacy cert with no stamp ("") or a frozen
    # deployment that cannot compute a current version ("") can't be compared, so it is not flagged.
    from ..verify.oracle_version import oracle_version as _oracle_version
    current_ov = _oracle_version(cert.confirmed_by) if cert.confirmed_by else ""
    oracle_version_current = not (cert.oracle_version and current_ov and cert.oracle_version != current_ov)
    ov_note = ("" if oracle_version_current
               else f"; ORACLE-VERSION CHANGED since mint (stamped {cert.oracle_version}, current "
                    f"{current_ov}) — reproduction re-ran the current oracle")

    # FRESHNESS (3-state posture validity): only against an AUTHENTICATED time. None when no verified anchor
    # genTime + now were supplied — a TTL without an authenticated start cannot expire, so freshness is NOT
    # asserted (never silently 'fresh'). A 0 TTL means 'no declared expiry' → always fresh once anchored.
    currently_fresh: bool | None = None
    fresh_note = ""
    if now is not None and anchor_gen_time is not None:
        if cert.freshness_ttl_seconds <= 0:
            currently_fresh, fresh_note = True, "; freshness: no declared TTL (anchored, non-expiring)"
        else:
            age = int(now) - int(anchor_gen_time)
            currently_fresh = age <= cert.freshness_ttl_seconds
            fresh_note = (f"; freshness: {'FRESH' if currently_fresh else 'STALE'} "
                          f"(age {age}s vs TTL {cert.freshness_ttl_seconds}s)")

    authentic = thr.satisfied and tr_pinned
    schema_note = "" if schema_ok else f"; UNKNOWN schema_version {cert.schema_version} (refusing)"
    bound_identity = cert.bound_identity
    identity_note = (f"; identity: {sorted(bound_identity)}" if bound_identity else "; identity: none bound")
    reason = (f"signature: {thr.reason}; "
              f"binding: {'oracle_context matches digest' if bound else 'DIGEST MISMATCH — signature is for different evidence'}; "
              f"reproduction: {rr.note}; claims: {claims_note}"
              f"{artifact_note}{primary_note}{tr_note}{schema_note}{ov_note}{fresh_note}{identity_note}")
    return EvidenceVerification(
        finding_ref=cert.finding_ref, authentic=authentic, bound=bound,
        artifacts_ok=artifacts_ok, primary_artifact_ok=primary_artifact_ok, reproduced=rr.ok,
        claims_grounded=claims_grounded, schema_ok=schema_ok, oracle_version_current=oracle_version_current,
        currently_fresh=currently_fresh, valid_signers=thr.valid_signers, bound_identity=bound_identity,
        reason=reason)


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
    head_anchored: bool = False    # a VALID governance-signed chain head anchors the chain (not just an
                                   # internally-consistent UNSIGNED chain) — REQUIRED for ``ok``
    refs_unique: bool = True       # finding_refs are unique (so per-ref context lookup cannot collide)
    single_engagement: bool = True  # every certificate/path shares ONE engagement (no cross-engagement mix)
    chain_note: str = ""

    @property
    def ok(self) -> bool:
        # A bundle is sound only when a VALID SIGNED HEAD anchors the chain. Without head_anchored, an
        # internally-consistent UNSIGNED chain (verify_chain True) with individually-signed finding certs
        # could otherwise pass — the anti-rollback/anchoring guarantee would be a claim, not a fact.
        return (bool(self.certificate_results) and self.cert_set_bound and self.chain_ok
                and self.head_anchored and self.refs_unique and self.single_engagement
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
    expected_trust_root_fingerprint: str | None = None,
    now: int | None = None,
    anchor_gen_times: dict[str, int] | None = None,
    artifact_bytes_by_ref: dict[str, bytes] | None = None,
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
    anchor_gen_times = anchor_gen_times or {}
    cert_digests = [sc.certificate.cert_digest for sc in certificates]
    path_digests = [pc.cert_digest for pc in path_certs]
    chain_digests = [e.cert_digest for e in chain]
    # the chain must cover the finding certs THEN the path certs, in that order.
    cert_set_bound = (cert_digests + path_digests) == chain_digests

    # finding_refs must be UNIQUE — the per-ref context lookup below would otherwise hand two certificates
    # the same context (a collision an attacker could exploit to bind a context to the wrong certificate).
    refs = [sc.certificate.finding_ref for sc in certificates]
    refs_unique = len(set(refs)) == len(refs)

    # SINGLE-ENGAGEMENT — components from two DIFFERENT NAMED engagements cannot be assembled into one
    # bundle. Empty ("") slugs are discarded so a uniform legacy bundle (findings default to "") under a
    # named head still passes. KNOWN BOUND (red-pen LOW, tracked in DEFERRED-INFRA): an empty-slug cert can
    # therefore ride a named bundle — defense-in-depth only, since it still requires a governance-signed
    # head over the mixed chain (compromised governance is already out of model).
    engagements = ({sc.certificate.engagement_slug for sc in certificates}
                   | {pc.engagement_slug for pc in path_certs}
                   | ({head.engagement_slug} if head is not None and getattr(head, "engagement_slug", None) else set()))
    engagements.discard("")
    single_engagement = len(engagements) <= 1

    # A posture certificate that opted into the gating artifact re-check (artifact_recheck_required) needs its
    # raw artifact bytes at verify or it fails CLOSED. The bundle supplies them per finding_ref via
    # artifact_bytes_by_ref (the bundle carries the raw artifacts); a cert that did not opt in ignores it.
    _ab = artifact_bytes_by_ref or {}
    results = [
        verify_certificate(
            sc, oracle_context=contexts.get(sc.certificate.finding_ref, {}),
            trust_root=trust_root, evidence_root=evidence_root,
            expected_trust_root_fingerprint=expected_trust_root_fingerprint,
            now=now, anchor_gen_time=anchor_gen_times.get(sc.certificate.finding_ref),
            artifact_bytes=_ab.get(sc.certificate.finding_ref))
        for sc in certificates]

    if head is not None:
        chain_ok, chain_note = verify_head(head, chain, trust_root, prev_highwater=prev_highwater)
    else:
        chain_ok, chain_note = verify_chain(chain)
        chain_note += " (UNSIGNED head — not anchored to governance)"
    # a VALID governance-signed head is what anchors the whole bundle (anti-rollback + no fabricated route).
    head_anchored = head is not None and chain_ok

    # Path certificates are NOT individually signed; a VALID signed head is their only
    # governance anchor. Verify chain/head FIRST, then anchor the paths on it — so a
    # fabricated route in an unsigned (or invalidly-signed) bundle fails closed rather than
    # riding an attacker-rebuilt chain.
    verified_finding_digests = {
        sc.certificate.cert_digest for sc, r in zip(certificates, results) if r.ok}
    path_results = _verify_paths(path_certs, verified_finding_digests, head_anchored=head_anchored)

    if not cert_set_bound:
        chain_note += (f"; CERT-SET MISMATCH: {len(cert_digests)} finding + {len(path_digests)} "
                       f"path certificate(s) vs {len(chain_digests)} chain entr(ies) — a "
                       f"certificate was suppressed, injected, or reordered")
    if not refs_unique:
        chain_note += "; DUPLICATE finding_ref(s) — refusing (per-ref context lookup would collide)"
    if not single_engagement:
        chain_note += f"; CROSS-ENGAGEMENT bundle — refusing (engagements: {sorted(engagements)})"
    return BundleVerification(certificate_results=results, path_results=path_results,
                              cert_set_bound=cert_set_bound, chain_ok=chain_ok, head_anchored=head_anchored,
                              refs_unique=refs_unique, single_engagement=single_engagement,
                              chain_note=chain_note)
