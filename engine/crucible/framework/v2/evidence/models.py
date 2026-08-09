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

from typing import Any, ClassVar, Literal

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
    # A CLOSED label set (pydantic rejects any other value at construction — fail-closed): a typo or an
    # unexpected value like "verified"/"machine-fact" cannot slip through as neither-fact-nor-commentary and
    # be mis-rendered downstream. "fact" is re-derived by verify (the label is never trusted for grounding).
    render_as: Literal["fact", "analyst-commentary"] = "analyst-commentary"


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
    # The external TOOL that produced the PROPOSAL this FACT re-drove (e.g. "nmap 7.99", "sslscan 2.1.5"),
    # captured at MINT and thus SIGNED (criterion 9). HONEST BOUND: this is the producer's ASSERTED version
    # string, not a proof of which binary ran — a stronger sensor identity (executable/image/SBOM digest +
    # invocation args) is a future enhancement (Phase 0.4). It is NOT a source of truth for the finding: the
    # FACT rests on the runner-owned oracle re-drive, not the tool. Deterministic; "" for a non-tool finding.
    # Dropped from the canonical form when empty (below) → byte-identical for every existing certificate.
    tool_version: str = ""
    # A DECLARED validity window in seconds (a freshness/TTL policy), captured at MINT and SIGNED. 0 = no
    # declared expiry. The actual "as-of" time is the external RFC3161 time anchor carried as a SIDECAR on
    # SignedEvidence (never in these deterministic signed bytes, so the cert stays byte-stable — the split
    # the posture certificate uses). A verifier holding the anchor refuses a FACT older than the TTL.
    freshness_ttl_seconds: int = 0
    # ---- D2 (Wave #4): artifact identity + scope + freshness + completeness binding -----------------
    # A posture FACT must prove WHICH artifact, of WHAT scope, captured WHEN, and whether the capture was
    # COMPLETE — else a valid m-of-n signature could ride over an obsolete, partial, or unrelated artifact
    # and still "verify". These OPTIONAL fields bind that provenance INTO the signed certificate, so the
    # governance signature covers them (a flipped value breaks authenticity) and a verifier can decide
    # freshness/scope for itself. Every field is dropped from the canonical form when empty (serializer
    # below), so a certificate minted without any of them — and every existing evidence bundle — serialises
    # BYTE-IDENTICALLY and keeps its signature valid. They are SURFACED by ``verify_certificate``
    # (``bound_identity``) but do NOT gate ``.ok`` (an honest, non-gating binding is still tamper-evident
    # once signed; a caller acts on the surfaced provenance itself).
    artifact_sha256: str = ""          # sha256 of the primary artifact the finding is about
    collector_id: str = ""             # which collector/sensor captured the evidence
    collector_version: str = ""        # its content/version tag (stale-collector detection)
    # {provider, account, project, subscription, cluster, region, resource} — only the keys that apply.
    resource_scope: dict[str, str] | None = None
    capture_time_epoch: int | None = Field(default=None, ge=0)  # unix seconds; caller/time-anchor supplied
    capture_method: str = ""           # how it was captured, e.g. "api:list" / "http:probe"
    requested_scope: str = ""          # the scope the collector was ASKED to cover
    returned_scope: str = ""           # the scope the collector actually returned
    completeness: str = ""             # "complete" | "partial" | "unknown"  (else "")
    collector_signature: str = ""      # opaque collector-side signature over the raw capture, if any

    # The additive D2 members whose empty value is dropped for byte-identity (canonical bytes sort keys, so
    # order-independent — listed once here so the serializer and the ``bound_identity`` view agree).
    _D2_FIELDS: ClassVar[tuple[str, ...]] = (
        "artifact_sha256", "collector_id", "collector_version", "resource_scope",
        "capture_time_epoch", "capture_method", "requested_scope", "returned_scope",
        "completeness", "collector_signature",
    )

    @field_validator("completeness")
    @classmethod
    def _completeness_enum(cls, v: str) -> str:
        allowed = {"", "complete", "partial", "unknown"}
        if v not in allowed:
            raise ValueError(f"completeness must be one of {sorted(allowed - {''})} or empty, got {v!r}")
        return v

    @field_validator("resource_scope")
    @classmethod
    def _scope_keys_allowlisted(cls, v: "dict[str, str] | None") -> "dict[str, str] | None":
        # A schema allowlist so a hostile bundle cannot smuggle arbitrary signed key/values in under the
        # guise of "scope"; values must be strings so the canonical bytes are deterministic.
        if v is None:
            return v
        allowed = {"provider", "account", "project", "subscription", "cluster", "region", "resource"}
        bad = set(v) - allowed
        if bad:
            raise ValueError(f"resource_scope keys must be within {sorted(allowed)}, got extra {sorted(bad)}")
        for k, val in v.items():
            if not isinstance(val, str):
                raise ValueError(f"resource_scope[{k!r}] must be a string, got {type(val).__name__}")
        return v

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        """Drop the additive ``report_claims`` / ``oracle_version`` / ``how_to_verify`` / ``tool_version`` /
        ``freshness_ttl_seconds`` members AND every empty D2 identity/scope/freshness/completeness member
        from the canonical form when empty, so a certificate built without them hashes/signs exactly as
        before those fields existed (no existing evidence bundle changes bytes)."""
        data = handler(self)
        if not data.get("report_claims"):
            data.pop("report_claims", None)
        if not data.get("oracle_version"):
            data.pop("oracle_version", None)
        if not data.get("how_to_verify"):
            data.pop("how_to_verify", None)
        if not data.get("tool_version"):
            data.pop("tool_version", None)
        if not data.get("freshness_ttl_seconds"):
            data.pop("freshness_ttl_seconds", None)
        for k in self._D2_FIELDS:
            if not data.get(k):        # None / "" / {} / 0 are all "absent" for canonical bytes
                data.pop(k, None)
        return data

    @property
    def bound_identity(self) -> "dict[str, Any]":
        """The non-empty D2 artifact-identity / scope / freshness / completeness fields bound into this
        certificate. Surfaced by ``verify_certificate``; purely descriptive (never gates ``.ok``)."""
        out: "dict[str, Any]" = {}
        for k in self._D2_FIELDS:
            val = getattr(self, k)
            if val:
                out[k] = val
        return out

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
    # OPTIONAL external RFC3161 time-anchor SIDECAR (the as-of "timestamp" for criterion 9): an
    # independently-signed third-party token over this certificate's cert_digest, so the FACT's freshness
    # is trustworthy WITHOUT putting a wallclock into the deterministic signed cert (the cert stays
    # byte-stable; the anchor is verified separately, exactly as the posture certificate does). ``None`` by
    # default and dropped from the canonical form (below), so a SignedEvidence without an anchor serialises
    # BYTE-IDENTICALLY to before this field existed. The governance signatures cover only the certificate,
    # not this sidecar — the anchor is self-authenticating (its own RFC3161 signature binds the digest).
    time_anchor: dict | None = None

    @model_serializer(mode="wrap")
    def _ser(self, handler):
        data = handler(self)
        if not data.get("time_anchor"):
            data.pop("time_anchor", None)
        return data


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


