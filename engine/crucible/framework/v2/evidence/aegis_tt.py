"""
evidence.aegis_tt — the AEGIS TT-STG DONE record (AS-25 / decision D33).

A green CI badge is not a DONE record. ADR 0005 (EV) makes DONE mean "proven end to end
through VIGIL on staging", and that proof has to be a durable, signed artefact an auditor
can re-verify offline — decoupled from the required-check claims registry, which (by
design, plan §13.2) can never point at a dispatched/scheduled TT-STG run.

This module builds that artefact: a **signed binding** (``vigil-aegis-tt-demonstration/1``)
over a verification-manifest run. The binding ties the run to the slice and the world it
ran in — slice and ``claim_ids``; the commit; the manifest, JUnit and suite digests; the
signed build manifest (``artifacts VALID``); the IaC topology digest; the subject paths
and digest; the tenants; the UI legs actually exercised; the required case classes; and
the ``no_skip_terms`` that must never be skipped — and ``verify_demonstration`` re-checks
every one of those offline. A single flipped byte anywhere in the bound manifest changes
its digest and fails the binding; a flipped byte in the signed record fails the signature.

Reuse, not reinvention (doctrine: wire, don't rebuild):

  * Ed25519 m-of-n threshold verify is ``entitlement.crypto`` (the vendored vigil_core
    substrate) — ``sign`` / ``verify_threshold`` verbatim, never a hand-rolled primitive.
  * Canonical bytes are the domain-separated discipline from ``evidence.canonical``
    (``canonical_json`` / ``sha256_hex``). This binding gets its **own** domain tag so a
    demonstration record can never be confused with an evidence certificate.
  * ``TrustRoot`` / ``AuthorizerKey`` / ``Signature`` are the existing entitlement models.

Determinism (doctrine: no wallclock / global-RNG on a signed or decision path):

  * Building and signing a binding read only their inputs — no clock, no RNG.
  * ``verify_demonstration`` is a pure function of its arguments. Staleness is computed by
    comparing the record's subject / topology digests to *caller-supplied* current digests
    (plan §13.3: "staleness by subject/topology digest"); there is no ``datetime.now()``
    on the path. Staleness is a reported STATE, never a verification failure.

Fail-closed (doctrine: unverifiable ⇒ no authority): every check defaults to False and
``ok`` is their conjunction. A production trust root, an unprovisioned root, a missing
case class, empty UI legs, a skipped no-skip term, or non-VALID build artifacts all deny
the record. This is SIGIL attesting its own staging run — not production behaviour and not
third-party assurance; the record says so in ``limits``.

The signing half (``build_demonstration`` / ``sign_demonstration``) is PROVISIONING only;
the runtime and CI only ever verify. Everything here is additive and default-off: nothing
imports this module on an authority path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

# Integrity primitives come from the shared core (vigil_core) directly — the single source of
# truth the evidence/entitlement shims themselves re-export. Imported from the source (not through
# the dynamic re-export shim) so they resolve statically; this is the same engine↔core reuse as
# framework.v2.report.dossier (`from vigil_core import sign`). The TrustRoot / Signature pydantic
# MODELS stay on the entitlement layer, matching evidence.certify.
from vigil_core.canonical import canonical_json, sha256_hex
from vigil_core.crypto import sign, verify_threshold

from ..entitlement.models import Signature, TrustRoot

# The binding schema id and the human-facing binding name from plan §13.3 / ADR 0005.
DEMONSTRATION_SCHEMA: Final[str] = "vigil-aegis-tt-demonstration/1"
BINDING_NAME: Final[str] = "vigil-aegis-tt-demonstration-v1"

# The verification-manifest schema this binding is allowed to cover (tools/verification_manifest.py).
MANIFEST_SCHEMA: Final[str] = "vigil-verification-manifest/1"

# Domain tag for the demonstration-binding signing bytes. DISTINCT from the evidence-certificate
# domain (``crucible-evidence-v1\x00`` in evidence.canonical) on purpose: domain separation means a
# signature minted over an evidence certificate can never verify as a demonstration binding, or the
# reverse. Never change without a schema bump + migration — it invalidates every existing signature.
_AEGIS_TT_DOMAIN: Final[bytes] = b"vigil-aegis-tt-demonstration-v1\x00"

# The TT-STG trust-root doc wrapper schema (docs/evidence/aegis-tt/trust-root.json).
TRUST_ROOT_DOC_SCHEMA: Final[str] = "vigil-aegis-tt-trust-root/1"

# Terms that must NEVER be skipped in a run a demonstration binds (plan §13.3:
# ``no_skip_terms ⊇ {TT-B, cross-uid, browser, isolation, tenant}``). The control tenant
# (TT-B), the cross-uid isolation, the browser leg and the tenant boundary are exactly the
# behaviours a "green while the meaningful half skipped" run would quietly drop.
REQUIRED_NO_SKIP_TERMS: Final[frozenset[str]] = frozenset(
    {"TT-B", "cross-uid", "browser", "isolation", "tenant"}
)

# The six required case classes (plan §13.3 / §13.8). Each must be present (count >= 1).
REQUIRED_CASE_CLASSES: Final[tuple[str, ...]] = (
    "positive", "benign", "benign_same_shape", "negative", "cross_tenant", "failure_class",
)

# The standing, honest limit stamped into every record (ADR 0005 "Stated limits").
DEFAULT_LIMITS: Final[str] = (
    "SIGIL attesting its own staging (TT-STG) run. Not production behaviour and not "
    "third-party assurance."
)


# --------------------------------------------------------------------------------------
# The binding document (the signed core) and its sub-documents.
# --------------------------------------------------------------------------------------
class UiLeg(BaseModel):
    """One UI leg actually exercised: a route, the screen it rendered, the session it ran under."""
    model_config = ConfigDict(extra="forbid")
    route: str = Field(min_length=1)
    screen: str = Field(min_length=1)
    session: str = Field(min_length=1)


class RequiredCases(BaseModel):
    """Count of each required case class the run exercised. The verifier requires every count >= 1."""
    model_config = ConfigDict(extra="forbid")
    positive: int = Field(ge=0)
    benign: int = Field(ge=0)
    benign_same_shape: int = Field(ge=0)
    negative: int = Field(ge=0)
    cross_tenant: int = Field(ge=0)
    failure_class: int = Field(ge=0)


class BuildRef(BaseModel):
    """The signed build manifest this run's artifacts came from. ``artifacts`` must read ``VALID``."""
    model_config = ConfigDict(extra="forbid")
    build_id: str = Field(min_length=1)
    artifacts: str = Field(min_length=1, description='Artifact state from the build manifest; "VALID" to pass.')


class TopologyRef(BaseModel):
    """The topology the run ran against. Only infrastructure-as-code topology counts (``kind == "iac"``)."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    # Serialized as "class" (plan §13.3 ``topology{class: iac, digest}``); ``kind`` is the Python name
    # because ``class`` is a reserved word. Signing always goes through ``_signing_payload`` with
    # by_alias=True so the bytes carry "class", and verify uses the same path — they cannot diverge.
    # ``Literal["iac"]`` makes the IaC-only invariant STRUCTURAL: ``build_demonstration`` (and any
    # load of a serialized record) refuses a non-"iac" topology at construction, fail-closed, before
    # any signature is minted. A demonstration exists only to attest an IaC-provisioned run, so there
    # is no legitimate non-iac record to foreclose. ``verify_demonstration`` re-checks this anyway, so
    # a record built past validation (``model_construct``) is still denied at verify time.
    kind: Literal["iac"] = Field(alias="class")
    digest: str = Field(min_length=1)


class SubjectRef(BaseModel):
    """The subject under test: the paths exercised and a digest over them. Drives staleness."""
    model_config = ConfigDict(extra="forbid")
    paths: list[str] = Field(min_length=1)
    digest: str = Field(min_length=1)


class AegisTtDemonstration(BaseModel):
    """The signed binding core (``vigil-aegis-tt-demonstration/1``).

    This is the exact document the trust-root authorisers sign. Every field is bound: the
    manifest is bound by ``manifest_sha256`` (a digest over the WHOLE verification manifest),
    with ``junit_sha256`` / ``suite_digest`` / ``commit`` re-stated for precise error
    attribution. ``model_config`` forbids extra keys so a record with a stray field is refused
    at load, before any signature check."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_id: str = Field(default=DEMONSTRATION_SCHEMA, alias="schema")
    binding: str = Field(default=BINDING_NAME)
    slice_id: str = Field(min_length=1, alias="slice")
    claim_ids: list[str] = Field(default_factory=list)
    commit: str = Field(min_length=1)

    # The run, bound by digest. ``manifest_sha256`` covers the whole manifest; the rest are specific.
    manifest_sha256: str = Field(min_length=1)
    junit_sha256: str = Field(min_length=1)
    suite_digest: str = Field(min_length=1)

    build: BuildRef
    topology: TopologyRef
    subject: SubjectRef
    tenants: list[str] = Field(min_length=1)
    ui_legs: list[UiLeg] = Field(default_factory=list)
    required_cases: RequiredCases
    no_skip_terms: list[str] = Field(default_factory=list)
    limits: str = Field(default=DEFAULT_LIMITS, min_length=1)


class SignedDemonstration(BaseModel):
    """A demonstration binding plus the authoriser signatures over its canonical, domain-tagged bytes."""
    model_config = ConfigDict(extra="forbid")
    demonstration: AegisTtDemonstration
    signatures: list[Signature] = Field(default_factory=list)


# --------------------------------------------------------------------------------------
# Signing bytes — the single source of truth both sign and verify go through.
# --------------------------------------------------------------------------------------
def _signing_payload(demo: AegisTtDemonstration) -> dict[str, Any]:
    """The JSON object that gets canonicalised and signed. by_alias=True so the bytes carry the
    wire keys ("schema", "slice", topology "class"). Centralised so sign and verify cannot diverge."""
    return demo.model_dump(mode="json", by_alias=True)


def demonstration_signing_bytes(demo: AegisTtDemonstration) -> bytes:
    """The exact bytes signed/verified: the demonstration domain tag + canonical JSON of the binding."""
    return _AEGIS_TT_DOMAIN + canonical_json(_signing_payload(demo))


# --------------------------------------------------------------------------------------
# Build + sign (PROVISIONING ONLY — never the runtime or CI).
# --------------------------------------------------------------------------------------
def manifest_digest(manifest: dict[str, Any]) -> str:
    """sha256 over the WHOLE verification manifest in canonical form. This is what the binding
    covers: any change to any field of the manifest changes this digest, so the binding is void
    unless the manifest it is presented with is byte-for-byte (content-for-content) the one bound."""
    return sha256_hex(canonical_json(manifest))


def build_demonstration(
    *,
    manifest: dict[str, Any],
    slice_id: str,
    claim_ids: list[str],
    build: BuildRef,
    topology: TopologyRef,
    subject: SubjectRef,
    tenants: list[str],
    ui_legs: list[UiLeg],
    required_cases: RequiredCases,
    no_skip_terms: list[str] | None = None,
    limits: str = DEFAULT_LIMITS,
) -> AegisTtDemonstration:
    """Build a binding from a loaded verification manifest + the world it ran in.

    The run digests (``manifest_sha256``, ``junit_sha256``, ``suite_digest``, ``commit``) are
    DERIVED from ``manifest`` here, never passed in, so a binding can only ever describe the
    manifest it was built from. Deterministic: no clock, no RNG — the same inputs give the same
    binding, hence the same signing bytes.

    ``no_skip_terms`` defaults to exactly the required set; a caller may pass a superset."""
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(f"manifest is not a {MANIFEST_SCHEMA} record (got {manifest.get('schema')!r})")
    commit = str(manifest.get("commit") or "")
    if not commit:
        raise ValueError("manifest has no commit — cannot bind a run with no commit")
    junit_sha256 = str(manifest.get("junit_sha256") or "")
    if not junit_sha256:
        raise ValueError("manifest has no junit_sha256 — the JUnit artifact is what makes counts checkable")
    suite_digest = str((manifest.get("suite") or {}).get("node_digest") or "")
    if not suite_digest:
        raise ValueError("manifest has no suite.node_digest — the suite identity is unbound")
    terms = list(no_skip_terms) if no_skip_terms is not None else sorted(REQUIRED_NO_SKIP_TERMS)
    return AegisTtDemonstration(
        slice=slice_id,
        claim_ids=list(claim_ids),
        commit=commit,
        manifest_sha256=manifest_digest(manifest),
        junit_sha256=junit_sha256,
        suite_digest=suite_digest,
        build=build,
        topology=topology,
        subject=subject,
        tenants=list(tenants),
        ui_legs=list(ui_legs),
        required_cases=required_cases,
        no_skip_terms=terms,
        limits=limits,
    )


def sign_demonstration(
    demo: AegisTtDemonstration, signers: list[tuple[str, str]]
) -> SignedDemonstration:
    """Sign a binding with TT evidence authorisers (PROVISIONING ONLY). ``signers`` is a list of
    (key_id, private_key_b64). The private key lives KMS-wrapped in the staging control plane and
    is never a CI runner key (plan §13.3); this helper exists for provisioning and for tests."""
    msg = demonstration_signing_bytes(demo)
    signatures = [Signature(key_id=kid, signature_b64=sign(priv, msg)) for kid, priv in signers]
    return SignedDemonstration(demonstration=demo, signatures=signatures)


# --------------------------------------------------------------------------------------
# The trust-root doc wrapper (docs/evidence/aegis-tt/trust-root.json).
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustRootDoc:
    """A loaded TT-STG trust-root doc: the staging authoriser set plus its environment and status.

    ``trust_root`` is None when the doc is ``unprovisioned`` (no staging key provisioned yet, e.g.
    before the AS-26 key ceremony). A None trust root cannot verify anything — fail-closed."""
    environment: str
    status: str
    trust_root: TrustRoot | None

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def is_usable(self) -> bool:
        """True iff this root may verify records: provisioned, non-production, with authorisers."""
        return self.status == "provisioned" and not self.is_production and self.trust_root is not None


def load_trust_root_doc(data: dict[str, Any]) -> TrustRootDoc:
    """Parse a trust-root doc wrapper. The wrapper (schema, environment, status) carries the
    non-production marker the pydantic ``TrustRoot`` cannot (it forbids extra fields); an
    unprovisioned doc (empty authorisers) yields ``trust_root=None`` rather than raising, so the
    committed-but-unprovisioned staging root loads and is honestly flagged unusable."""
    if data.get("schema") != TRUST_ROOT_DOC_SCHEMA:
        raise ValueError(f"not a {TRUST_ROOT_DOC_SCHEMA} doc (got {data.get('schema')!r})")
    environment = str(data.get("environment") or "")
    status = str(data.get("status") or "")
    authorizers = data.get("authorizers") or []
    trust_root: TrustRoot | None = None
    if authorizers:
        trust_root = TrustRoot(
            schema_version=int(data.get("schema_version", 1)),
            threshold=int(data.get("threshold", 1)),
            authorizers=authorizers,
        )
    return TrustRootDoc(environment=environment, status=status, trust_root=trust_root)


def load_trust_root_doc_file(path: Path) -> TrustRootDoc:
    """Load a trust-root doc from a JSON file on disk."""
    import json
    return load_trust_root_doc(json.loads(path.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------------------
# The offline verifier — a pure function of its arguments. Fail-closed.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class DemonstrationVerification:
    """The structured verdict on one demonstration record. ``ok`` is the conjunction of the HARD
    checks; ``stale`` is a reported state and never contributes to ``ok``."""
    authentic: bool
    non_production: bool
    manifest_bound: bool
    run_ok: bool
    cases_present: bool
    legs_nonempty: bool
    routes_in_census: bool
    no_skip_ok: bool
    artifacts_valid: bool
    topology_is_iac: bool
    valid_signers: tuple[str, ...]
    stale: bool
    reasons: tuple[str, ...]
    ok: bool


def _manifest_skip_hits(manifest: dict[str, Any], term: str) -> list[str]:
    """Skipped tests in ``manifest`` whose node id or reason mentions ``term`` (case-insensitive).
    Mirrors tools/verification_manifest.py ``check(no_skip_covering=...)`` so the binding's
    no-skip claim is re-checked against the run, not merely declared on the binding."""
    hits: list[str] = []
    for skip in manifest.get("skips", []) or []:
        haystack = f"{skip.get('test', '')} {skip.get('reason', '')}".lower()
        if term.lower() in haystack:
            hits.append(str(skip.get("test", "?")))
    return hits


def verify_demonstration(
    signed: SignedDemonstration,
    *,
    manifest: dict[str, Any],
    trust_root: TrustRoot,
    environment: str,
    census_routes: set[str] | None = None,
    current_subject_digest: str | None = None,
    current_topology_digest: str | None = None,
    expected_trust_root_fingerprint: str | None = None,
) -> DemonstrationVerification:
    """Re-verify a demonstration record OFFLINE and deterministically.

    ``manifest`` is the verification manifest the record claims to bind (the same JSON the run
    wrote). ``trust_root`` + ``environment`` come from the loaded trust-root doc. ``census_routes``,
    when given, is the Gate-5 route census the UI legs must be drawn from — it is INJECTED rather
    than imported, so this engine-side verifier never reaches across the two-env boundary into the
    SIGIL UI layer that owns the census. The current subject/topology digests, when given, drive
    staleness (a state, not a failure).

    Every check defaults False and ``ok`` is their conjunction, so an unverifiable record denies."""
    reasons: list[str] = []
    demo = signed.demonstration

    # 1. Non-production root. A production trust root (or a production ``environment``) must never
    #    verify a staging demonstration — a staging record can never carry production authority.
    non_production = environment.lower() != "production"
    if not non_production:
        reasons.append(f"trust root environment is {environment!r} — a demonstration needs a non-production root")

    # 2. Trust-root fingerprint pin (optional but recommended): the out-of-band root the verifier trusts.
    fingerprint_ok = True
    if expected_trust_root_fingerprint is not None:
        actual = trust_root_fingerprint(trust_root)
        want = expected_trust_root_fingerprint
        want = want if want.startswith("sha256:") else "sha256:" + want
        if actual != want:
            fingerprint_ok = False
            reasons.append(f"trust-root fingerprint {actual} does not match the pinned {want}")

    # 3. Authenticity: m-of-n Ed25519 under the trust root, over the domain-tagged canonical bytes.
    msg = demonstration_signing_bytes(demo)
    thr = verify_threshold(msg, signed.signatures, trust_root)
    authentic = thr.satisfied and fingerprint_ok
    if not thr.satisfied:
        reasons.append(f"signature threshold not met: {thr.reason}")

    # 4. Manifest binding: the record covers the WHOLE manifest. Recompute the digest over the
    #    manifest presented and require it to equal the bound value — a 1-byte flip anywhere in the
    #    manifest changes this digest and voids the binding. JUnit / suite / commit re-checked for
    #    precise attribution (they are already inside manifest_sha256; this names which field moved).
    manifest_bound = True
    if manifest.get("schema") != MANIFEST_SCHEMA:
        manifest_bound = False
        reasons.append(f"manifest is not a {MANIFEST_SCHEMA} record")
    if manifest_digest(manifest) != demo.manifest_sha256:
        manifest_bound = False
        reasons.append("manifest digest does not match the binding (the bound manifest was altered or swapped)")
    if str(manifest.get("junit_sha256") or "") != demo.junit_sha256:
        manifest_bound = False
        reasons.append("bound junit_sha256 does not match the manifest")
    if str((manifest.get("suite") or {}).get("node_digest") or "") != demo.suite_digest:
        manifest_bound = False
        reasons.append("bound suite_digest does not match the manifest suite identity")
    if str(manifest.get("commit") or "") != demo.commit:
        manifest_bound = False
        reasons.append("bound commit does not match the manifest commit")

    # 5. Run quality: the bound run actually passed, on a clean tree.
    run_ok = True
    counts = manifest.get("counts") or {}
    if manifest.get("exit_status") != 0:
        run_ok = False
        reasons.append(f"the bound run FAILED (exit {manifest.get('exit_status')})")
    if manifest.get("dirty"):
        run_ok = False
        reasons.append("the bound run was on a DIRTY tree — it does not describe the committed state")
    if counts.get("failed"):
        run_ok = False
        reasons.append(f"the bound run had {counts.get('failed')} failing test(s)")
    if counts.get("error"):
        run_ok = False
        reasons.append(f"the bound run had {counts.get('error')} erroring test(s)")

    # 6. All six required case classes present (count >= 1 each).
    rc = demo.required_cases
    missing_cases = [c for c in REQUIRED_CASE_CLASSES if getattr(rc, c) < 1]
    cases_present = not missing_cases
    if missing_cases:
        reasons.append(f"required case class(es) absent: {', '.join(missing_cases)}")

    # 7. UI legs non-empty, and every route drawn from the Gate-5 census (when the census is supplied).
    legs_nonempty = bool(demo.ui_legs)
    if not legs_nonempty:
        reasons.append("no UI legs — a demonstration must exercise at least one route through VIGIL")
    routes_in_census = True
    if census_routes is not None:
        off_census = sorted({leg.route for leg in demo.ui_legs} - census_routes)
        if off_census:
            routes_in_census = False
            reasons.append(f"UI route(s) not in the Gate-5 census: {', '.join(off_census)}")

    # 8. No-skip discipline: the binding declares the required terms AND the run skipped none of them.
    declared = {t.lower() for t in demo.no_skip_terms}
    missing_terms = sorted(t for t in REQUIRED_NO_SKIP_TERMS if t.lower() not in declared)
    no_skip_ok = not missing_terms
    if missing_terms:
        reasons.append(f"no_skip_terms missing required term(s): {', '.join(missing_terms)}")
    for term in REQUIRED_NO_SKIP_TERMS:
        hits = _manifest_skip_hits(manifest, term)
        if hits:
            no_skip_ok = False
            reasons.append(f"a skipped test covers {term!r} (claim rests on behaviour that did not run): "
                           + "; ".join(hits))

    # 9. Build artifacts VALID.
    artifacts_valid = demo.build.artifacts == "VALID"
    if not artifacts_valid:
        reasons.append(f"build artifacts are {demo.build.artifacts!r}, not VALID")

    # 10. IaC topology — the invariant this whole record exists to attest (ADR 0005 / plan §13.3:
    #     "proven ... through VIGIL on staging" against infrastructure-as-code). The run must have
    #     executed against an IaC topology; a non-IaC one (e.g. a dev's local docker-compose,
    #     ``kind="local-docker-compose"``) can never back a demonstration, or the record would attest
    #     to a run on an environment that does not describe staging. Fail-closed and independent of the
    #     ``Literal["iac"]`` construction constraint, so a record built past validation is still denied.
    topology_is_iac = demo.topology.kind == "iac"
    if not topology_is_iac:
        reasons.append(f"topology class is {demo.topology.kind!r}, not \"iac\" — "
                       "a demonstration must bind a run on an IaC-provisioned topology")

    # Staleness (a STATE, computed by subject/topology digest — never a failure, never a clock).
    stale = False
    if current_subject_digest is not None and current_subject_digest != demo.subject.digest:
        stale = True
        reasons.append("STALE: the subject digest has moved since this record was signed")
    if current_topology_digest is not None and current_topology_digest != demo.topology.digest:
        stale = True
        reasons.append("STALE: the IaC topology digest has moved since this record was signed")

    ok = (
        authentic and non_production and manifest_bound and run_ok and cases_present
        and legs_nonempty and routes_in_census and no_skip_ok and artifacts_valid
        and topology_is_iac
    )
    return DemonstrationVerification(
        authentic=authentic, non_production=non_production, manifest_bound=manifest_bound,
        run_ok=run_ok, cases_present=cases_present, legs_nonempty=legs_nonempty,
        routes_in_census=routes_in_census, no_skip_ok=no_skip_ok, artifacts_valid=artifacts_valid,
        topology_is_iac=topology_is_iac, valid_signers=thr.valid_signers, stale=stale,
        reasons=tuple(reasons), ok=ok,
    )


def trust_root_fingerprint(trust_root: TrustRoot) -> str:
    """sha256 fingerprint of a trust root — the out-of-band value an operator pins. Matches the
    discipline of ``evidence.certify.trust_root_fingerprint`` (digest over the canonical model)."""
    return "sha256:" + sha256_hex(canonical_json(trust_root.model_dump(mode="json")))


# --------------------------------------------------------------------------------------
# Status projection (docs/capability-matrix/aegis-saas-status.json — plan §13.7).
# --------------------------------------------------------------------------------------
# The five capability states (plan §13.7 "Five states"). The first two are DERIVABLE from a
# record's verification; the last three are slice-level facts authored into the projection file.
STATE_IMPLEMENTED_AND_DEMONSTRATED: Final[str] = "implemented_and_demonstrated"
STATE_IMPLEMENTED_NOT_VALIDATED: Final[str] = "implemented_not_validated"
STATE_PARTIALLY_IMPLEMENTED: Final[str] = "partially_implemented"
STATE_UNSUPPORTED: Final[str] = "unsupported"
STATE_BLOCKED: Final[str] = "blocked"

CAPABILITY_STATES: Final[tuple[str, ...]] = (
    STATE_IMPLEMENTED_AND_DEMONSTRATED,
    STATE_IMPLEMENTED_NOT_VALIDATED,
    STATE_PARTIALLY_IMPLEMENTED,
    STATE_UNSUPPORTED,
    STATE_BLOCKED,
)


def project_state(verification: DemonstrationVerification | None) -> str:
    """Project a claim's displayed state from its demonstration verification (plan §13.7 rows 1-2).

    A claim reads ``implemented_and_demonstrated`` ONLY with a verified, current (non-stale)
    record. No record, an invalid record, or a stale record downgrades to
    ``implemented_not_validated`` — this is the §13.3 honesty invariant made mechanical: nothing
    can display "demonstrated" without a current IaC record. The remaining three states
    (partially / unsupported / blocked) are slice-level facts, not derivable from a single record,
    and are authored into the projection file."""
    if verification is not None and verification.ok and not verification.stale:
        return STATE_IMPLEMENTED_AND_DEMONSTRATED
    return STATE_IMPLEMENTED_NOT_VALIDATED
