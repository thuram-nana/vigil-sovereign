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

from ..entitlement.models import Signature

_GENESIS_PREV: str = "0" * 64


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

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        """Drop ``report_claims`` from the canonical form when it is empty, so a
        certificate built without bound sentences hashes/signs exactly as it did before
        this field existed (default-safety: no existing evidence bundle changes bytes)."""
        data = handler(self)
        if not data.get("report_claims"):
            data.pop("report_claims", None)
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


class ChainEntry(BaseModel):
    """One link in the tamper-evident evidence log. ``entry_hash`` chains prev+cert+seq;
    a break anywhere is detectable by recomputation."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=0)
    prev_hash: str = _GENESIS_PREV
    cert_digest: str
    entry_hash: str


class SignedChainHead(BaseModel):
    """The signed anchor of the evidence chain. ``head_hash`` is the last entry's hash;
    ``last_seq`` is monotonic (anti-rollback). Signed by the governance trust root."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    engagement_slug: str = ""
    last_seq: int = Field(ge=0)
    entry_count: int = Field(ge=0)
    head_hash: str
    signatures: list[Signature] = Field(default_factory=list)
