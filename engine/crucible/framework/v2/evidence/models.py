"""
evidence.models — the typed shapes of a signed, hash-linked evidence certificate.

An `EvidenceCertificate` is the *authenticated* wrapper around a finding's already-
replayable `oracle_context`: it binds the finding's identity, a DIGEST of the exact
oracle_context the oracle adjudicated, and a manifest of the raw on-disk artifacts (by
per-file sha256) into one canonical object that governance authorisers sign. A
`SignedEvidence` carries that certificate plus the m-of-n signatures.

The `ChainEntry` / `SignedChainHead` pair makes the evidence log tamper-evident: each
entry hash-links to its predecessor, and a signed head anchors the whole chain, so a
silently deleted or reordered certificate breaks the chain and a rewritten head fails
its signature (with a monotonic `last_seq` as anti-rollback).

Nothing here changes the unsigned path — a certificate is an ADDITIVE layer over the
existing oracle_context, and the runtime only ever VERIFIES (signing is provisioning).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer
from vigil_core import ChainEntry, Signature, SignedChainHead


from vigil_core.models import _GENESIS_PREV  # shared genesis


class ReportClaim(BaseModel):
    """One report sentence bound into a certificate. Signing the certificate signs the
    sentence too, so its text is tamper-evident; ``verify_certificate`` additionally
    re-admits each ``render_as == "fact"`` claim through the veracity firewall against the
    authenticated oracle_context.

    What that fact check DOES enforce: the declared ``bug_class`` must re-verify against the
    evidence — a claim declaring a class the evidence does not prove (a relabelled claim)
    fails the certificate closed (a proof is bound to its subject, P3). What it does NOT do:
    entailment over the sentence's natural language — a deterministic gate cannot read
    English, so free prose is bound as labelled ``analyst-commentary`` (retained,
    tamper-evident, but never asserted as a machine-verified fact), and the only fact a
    certificate asserts is the canonical STRUCTURED statement (see evidence.claims), which
    re-grounds by construction. ``render_as`` is the producer's claim; verify recomputes the
    truth of a fact claim and never trusts the label for grounding.

    Deterministic (no wallclock, stable field set) so it does not perturb canonical bytes."""

    model_config = ConfigDict(extra="forbid")

    sentence: str
    bug_class: str = ""
    render_as: str = "analyst-commentary"   # producer's claim; verify re-derives fact truth


class ArtifactRef(BaseModel):
    """One raw evidence file, bound by digest so a certificate proves WHICH bytes it
    was judged on."""

    model_config = ConfigDict(extra="forbid")

    path: str                          # relative to the engagement evidence root
    sha256: str
    size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def _relative_and_confined(cls, v: str) -> str:
        # reject at PARSE time so a hostile bundle with an escaping artifact path fails
        # to load at all (defense in depth alongside the verify-time confinement).
        from pathlib import PurePosixPath, PureWindowsPath
        if not v or PurePosixPath(v).is_absolute() or PureWindowsPath(v).is_absolute():
            raise ValueError(f"artifact path must be relative, got {v!r}")
        if any(part == ".." for part in PurePosixPath(v).parts):
            raise ValueError(f"artifact path must not contain '..', got {v!r}")
        return v


class EvidenceCertificate(BaseModel):
    """The signable, verifiable claim about ONE confirmed finding. Everything here is
    deterministic (no wallclock — `seq` is the monotonic order), so its canonical bytes
    are stable across producer and verifier."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    engagement_slug: str = ""
    finding_ref: str                   # check_id / finding slug
    bug_class: str = ""
    surface: str = ""                  # insertion point / param
    confirmed_by: str = ""             # oracle kind that fired
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    oracle_context_digest: str         # sha256 of the canonical oracle_context
    artifacts: list[ArtifactRef] = Field(default_factory=list)
    seq: int = Field(ge=0, default=0)
    # Atomic report sentences bound into (and thus signed with) this certificate. Kept
    # None/empty by default so an existing certificate serialises BYTE-IDENTICALLY (see
    # the serializer below) — no existing signature or digest changes. When present, the
    # governance signature and the chain digest cover it automatically (the whole model is
    # signed), so a flipped sentence breaks authenticity, and verify re-admits each one.
    report_claims: list[ReportClaim] | None = None
    # PCF oracle id@version: the content-derived version of the oracle that fired, captured at MINT time
    # and thus SIGNED. A verifier compares it to the current oracle version to detect a stale proof (the
    # oracle body changed since issue). Kept "" by default and dropped from the canonical form when empty
    # (see the serializer), so a certificate built without a stamped version — and every existing evidence
    # bundle — serialises BYTE-IDENTICALLY, keeping its signature valid.
    oracle_version: str = ""
    # A human-readable, per-finding "how to verify / test / patch" note (deterministic, derived from the
    # finding's own surface + firing oracle + class remediation). Signed when present, so it travels with the
    # certificate tamper-evident. Kept "" by default and dropped from the canonical form when empty (below),
    # so a certificate built without it — and every existing evidence bundle — serialises BYTE-IDENTICALLY,
    # keeping its signature valid.
    how_to_verify: str = ""

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        """Drop the additive ``report_claims`` / ``oracle_version`` / ``how_to_verify`` members from the
        canonical form when they are empty, so a certificate built without them hashes/signs exactly as it did
        before those fields existed (default-safety: no existing evidence bundle changes bytes)."""
        data = handler(self)
        if not data.get("report_claims"):
            data.pop("report_claims", None)
        if not data.get("oracle_version"):
            data.pop("oracle_version", None)
        if not data.get("how_to_verify"):
            data.pop("how_to_verify", None)
        return data

    @property
    def cert_digest(self) -> str:
        """sha256 of this certificate's canonical bytes — the chain links on this."""
        from .canonical import digest_payload
        return digest_payload(self.model_dump(mode="json"))


class SignedEvidence(BaseModel):
    """An evidence certificate + the governance signatures over its canonical bytes."""

    model_config = ConfigDict(extra="forbid")

    certificate: EvidenceCertificate
    signatures: list[Signature] = Field(default_factory=list)


class PathStep(BaseModel):
    """One hop of a derived attack path: a typed edge established by a technique."""

    model_config = ConfigDict(extra="forbid")

    src: str
    edge: str
    dst: str
    technique: str = ""


class PathCertificate(BaseModel):
    """A DERIVED attack path bound to the confirmed-finding certificates its hops depend on.

    A forward-reasoning attack path (attacker → crown jewel) is a CLAIM about what the
    confirmed facts compose into — it is only as sound as the findings under it. This
    certificate records the ordered hops and the ``backing_cert_digests`` (the cert_digests
    of the finding ``EvidenceCertificate``s the caller cites as the path's support).

    What ``verify_bundle`` then PROVES, precisely: (1) the path is tamper-evident and
    anchored — its digest rides the same signed chain head, so altering a hop or the
    backing list breaks the chain; and (2) every cited backing finding is present in the
    bundle AND itself verified, so a path with no reproducing evidence, or leaning on an
    absent/unverified finding, fails CLOSED. What it does NOT do: re-derive that those
    findings CAUSALLY establish these specific hops — that hop↦finding linkage is the
    reasoning layer's assertion (a deterministic bundle check cannot re-run pathsearch),
    exactly as the report gate cannot do natural-language entailment. So the guarantee is
    "the route's cited support is real and reproduces," not "the machine re-proved the route."

    Deterministic (no wallclock; ``seq`` is the order; backing digests are sorted), so its
    canonical bytes are stable across producer and verifier."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    engagement_slug: str = ""
    destination: str = ""              # crown-jewel node the path reaches
    steps: list[PathStep] = Field(default_factory=list)
    backing_cert_digests: list[str] = Field(default_factory=list)  # sorted; the findings under the path
    seq: int = Field(ge=0, default=0)

    @property
    def cert_digest(self) -> str:
        """sha256 of this path certificate's canonical bytes — what the chain links on."""
        from .canonical import digest_payload
        return digest_payload(self.model_dump(mode="json"))


