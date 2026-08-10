"""mesh_cicd_posture — VIGIL-direct service-mesh + CI/CD posture FACT capability (Wave #4 Phase-A, slice A2).

Two more FACT-capable families that need NO external tool: VIGIL parses the target's OWN PRIMARY config
artifact — an Istio / Linkerd mesh manifest, or a GitHub-Actions workflow — for a CONCRETE insecure achieved
state, then drives the deterministic ``mesh_posture`` / ``cicd_posture`` oracle over the RETAINED control.
A control whose achieved state the oracle PROVABLY re-derives as insecure mints a signed, offline-re-verifiable
FACT; anything else is INCONCLUSIVE (never a labelled-clean negative). An istioctl / actionlint / checkov run
is only a PROPOSER of where to look — its "permissive / allow-all / unpinned" say-so never mints a FACT; VIGIL's
own parse + the oracle re-derivation is the sole authority (the criterion-6 firewall).

EVIDENCE AUTHORITY: the claim is a bounded statement about the ARTIFACT VIGIL parsed — "this manifest declares
PERMISSIVE mTLS" / "this workflow pins a mutable third-party action" — NEVER "the live mesh accepts plaintext".
The mesh/workflow bytes are the primary artifact; there is no live-infra channel here.

ADMISSION, not a direct mint (Phase-D BLOCKER-1). This module DOES NOT call ``oracle_adapter.confirm_and_certify``
— doing so would let a verdict reach a certificate with no capability check ever running, and the
``mesh_posture.declared_configuration`` / ``cicd_posture.workflow_construct`` branches are declared ``clean_capable:
false`` in ``docs/capability-matrix/evidence-branches.json`` (an incomplete config export cannot prove ABSENCE),
so a conclusive non-fire must be demoted to INCONCLUSIVE rather than escape as ``Outcome.CLEAN``. Instead —
mirroring ``web_redrive`` / ``sbom`` — it runs the oracle to obtain ``(fired, conclusive)``, attributes the
outcome to the ONE registered branch via ``verdict.admit(...)``, then lets ``oracle_adapter.certify_admitted``
mint ONLY what admission returned as a FACT. Admission decides, minting executes.

provenance="reproduced": the evidence is re-derived by VIGIL from the operator-supplied config bytes — a
non-LLM channel — so the anti-hallucination gate admits it (never "llm"). D2 provenance is bound into the cert
(``artifact_sha256`` of the raw bytes, ``collector_id``, ``capture_method``, ``completeness="partial"``).

RESOURCE-GOVERNED PARSING: the raw YAML/JSON bytes are parsed with ``live.safe_parse`` (safe_json / safe_yaml +
ParseBudget) — never raw ``yaml.load`` / ``json.loads`` on operator bytes — and the PARSED STRUCTURE (never the
raw text) is handed to the ingest, so a malformed / oversized / bomb artifact is a typed error, not a crash.

FATAL-2: every framework import (the ingest, the oracle-signal, the admission/mint) is FUNCTION-LOCAL
(``# noqa: PLC0415``); module-level imports are stdlib + the sovereign ``safe_parse`` / ``verdict`` only, so
importing this module co-loads no offense engine.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .safe_parse import ParseBudget, ParseResult, safe_json, safe_yaml

# The two registered evidence branches this capability produces (docs/capability-matrix/evidence-branches.json).
# Both fact_capable:true (a proven insecure achieved-state is a FACT), clean_capable:false (an INCOMPLETE config
# export cannot prove the ABSENCE of a misconfiguration — CLEAN needs a completeness proof = blocking_work).
_MESH_BRANCH = "mesh_posture.declared_configuration"
_CICD_BRANCH = "cicd_posture.workflow_construct"


@dataclass
class PostureResult:
    """The outcome of a mesh/CI-CD posture pass over ONE primary config artifact.

    ``facts``/``leads``/``inconclusive`` are AdapterResults; ``admissions`` is the (branch_id, verdict, reason)
    audit trail; ``contexts`` maps finding_ref -> oracle_context for offline re-verification; ``parse_outcome``
    is the safe_parse verdict for the raw bytes (``"ok"`` / ``"error"`` / ``"inconclusive"``)."""

    family: str                                   # "mesh_posture" | "cicd_posture"
    artifact_sha256: str
    controls: int = 0                             # controls the ingest recognised (LEAD candidates)
    parse_outcome: str = "ok"
    parse_reason: str = ""
    facts: list = field(default_factory=list)         # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)         # AdapterResult status=="lead", outcome not inconclusive/clean
    inconclusive: list = field(default_factory=list)  # AdapterResult outcome=="inconclusive" — NEVER clean
    admissions: list = field(default_factory=list)    # (branch_id, verdict, reason) — the admission audit trail
    contexts: dict = field(default_factory=dict)      # finding_ref -> oracle_context (offline re-verify)
    notes: list = field(default_factory=list)
    artifact_bytes: bytes = b""                        # raw artifact bytes the FACTs bind (BLOCK #3 re-check)

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self) -> str:
        """The conservative composition over every admitted branch outcome (see verdict.compose).

        An EMPTY set of admissions (nothing examined — a malformed artifact, or a config with no recognised
        mesh/workflow control) composes to INCONCLUSIVE, NOT CLEAN: nothing examined is not the same as
        nothing found. Neither branch is CLEAN-capable, so CLEAN can never appear here regardless."""
        from .verdict import compose  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)
        return compose([v for _branch, v, _reason in self.admissions]).value


# --------------------------------------------------------------------------------------------------
# Resource-governed parse: safe_json first (a JSON array / object is inert + dep-free), then safe_yaml.
# The PARSED STRUCTURE is what the ingest sees — never the raw operator bytes. A single safe_parse call
# handles a lone resource, a JSON/YAML array of resources, and a Kubernetes ``List`` wrapper; multi-document
# ``---`` YAML streams are an honest residual (export as a JSON array or a List wrapper).
# --------------------------------------------------------------------------------------------------
def _safe_parse_structure(raw: str | bytes, budget: ParseBudget | None = None) -> ParseResult:
    """Parse ``raw`` under ``budget`` WITHOUT ever raising on operator bytes. Tries JSON (dep-free, inert)
    then SAFE YAML; returns the first ``ok`` ParseResult, else the LAST failure (so an oversized/bomb/malformed
    artifact surfaces its typed reason). Never uses raw ``yaml.load`` / ``json.loads`` (charter rule 6)."""
    budget = budget or ParseBudget()
    j = safe_json(raw, budget)
    if j.ok:
        return j
    y = safe_yaml(raw, budget)
    if y.ok:
        return y
    # Prefer the YAML verdict: a config artifact that is not JSON is almost always YAML, so its typed reason
    # (oversize / too_deep / alias_bomb / unsafe_tag / malformed / yaml_unavailable) is the honest one.
    return y


def _raw_bytes(raw: str | bytes) -> bytes:
    """The exact bytes the artifact_sha256 is computed over — so verify can recompute them (BLOCK #3). A str
    input is UTF-8 canonical text; bytes are the exact input."""
    return raw.encode("utf-8", "surrogatepass") if isinstance(raw, str) else bytes(raw or b"")


def _sha256_hex(raw: str | bytes) -> str:
    return hashlib.sha256(_raw_bytes(raw)).hexdigest()


def _artifact_binding(raw: str | bytes) -> dict:
    """The BLOCK #3 artifact re-check binding fields shared by the mesh + cicd mint paths."""
    return {"artifact_recheck_required": True,
            "artifact_encoding": "canonical_text" if isinstance(raw, str) else "bytes"}


def _oracle_signal(oracle_context: dict, bug_class: str) -> "tuple[bool, bool]":
    """Run the deterministic posture oracle over the retained context and return ``(fired, conclusive)``
    WITHOUT minting anything — so admission sees the oracle's answer BEFORE any certificate exists (mirrors
    ``sbom._oracle_signal`` / ``web_redrive._oracle_signal``).

      * ``fired``      — an oracle fired at/above the verifier threshold: the retained control PROVABLY
                         carries an insecure achieved state (permissive/disabled mTLS, an allow-all authz
                         policy, an unauthenticated Linkerd inbound, an unpinned third-party action, a
                         pwn-request, or a script-injection sink).
      * ``conclusive`` — the oracle rendered a DECISIVE verdict. Even were a non-fire conclusive, both
                         branches are ``clean_capable: false``, so admission returns INCONCLUSIVE — the CLEAN
                         escape this slice closes.

    All framework imports are function-local (FATAL-2)."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": bug_class, "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    return fired, conclusive


def _adjudicate(
    *,
    res: PostureResult,
    branch: str,
    bug_class: str,
    controls: list,
    oracle_context_of,
    check_id_of,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    binding: dict,
) -> None:
    """Shared admission loop: for each recognised control, run the oracle, admit against ``branch``, and mint
    ONLY what admission returned as a FACT. ``controls`` reaching here were parsed from the artifact, so the
    ``artifact_parsed`` precondition holds by construction."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import admit  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)

    res.controls = len(controls)
    from vigil_core.canonical import digest_payload  # noqa: PLC0415 (shared integrity core; FATAL-2-safe)
    for idx, control in enumerate(controls):
        oracle_context = oracle_context_of(control)
        # A FULL-sha256 canonical digest over the control's STRUCTURAL LOCATION (parse ordinal `loc`) and its
        # retained oracle context disambiguates controls the identity string cannot tell apart — two dangerous
        # constructs in ONE job (two unpinned actions / two script-injection sinks) share the same
        # `cicd:{workflow}:{rule}:{job}`; two same-identity mesh resources share the same
        # `mesh:{provider}:{kind}:{ns}/{name}`. `loc` also keeps two IDENTICAL controls at DIFFERENT source
        # positions distinct (reviewer BLOCK #3). Full 256-bit (not a 48-bit prefix) + canonical (reject-non-JSON,
        # no default=str). Without it their finding_refs collide and res.contexts (last-writer-wins) hands one
        # genuine FACT the other control's context, breaking offline re-verify (red-pen MEDIUM). Order-stable
        # across a re-parse of the same bytes so the FACT re-verifies offline.
        _digest = digest_payload({"loc": idx, "cid": check_id_of(control), "ctx": oracle_context})
        finding = {
            "check_id": f"{check_id_of(control)}#{_digest}",
            "bug_class": bug_class,
            "oracle_context": oracle_context,
        }
        # ADMISSION DECIDES, MINTING EXECUTES.
        fired, conclusive = _oracle_signal(oracle_context, bug_class)
        admitted = admit(branch, fired=fired, conclusive=conclusive, observed={"artifact_parsed": True})
        res.admissions.append((branch, admitted.verdict.value, admitted.reason))
        r = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                             provenance="reproduced", binding=binding)
        if r.is_fact:
            # Only a FACT re-verifies; storing a NON-firing lead's context here let it overwrite a genuine
            # FACT's retained context on any finding_ref collision (red-pen MEDIUM — aggravated the mesh
            # collision). Retain context for facts alone.
            res.contexts[r.finding_ref] = oracle_context
            res.facts.append(r)
        elif r.outcome == "inconclusive":
            res.inconclusive.append(r)   # oracle refuted the control / non-conclusive → NEVER labelled clean
        else:
            res.leads.append(r)          # a genuine LEAD (e.g. unmapped class / unsupported)


def mesh_posture_verify(
    config: str | bytes,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    collector_id: str = "mesh-config",
    budget: ParseBudget | None = None,
) -> PostureResult:
    """Parse an Istio / Linkerd mesh manifest (the PRIMARY config artifact) and — THROUGH ADMISSION — mint a
    signed FACT for every control whose RETAINED achieved state the ``mesh_posture`` oracle PROVES insecure
    (permissive/disabled mTLS, an allow-all AuthorizationPolicy, or an all-unauthenticated Linkerd inbound).

    The bytes are resource-governed-parsed (safe_json / safe_yaml); a malformed / oversized / bomb artifact
    yields a typed ``parse_outcome != "ok"`` and NO facts (never a crash). The parsed STRUCTURE is handed to
    ``verify.mesh_posture.ingest_mesh_config`` (never the raw text). Near-zero-FP is the oracle's: a STRICT
    PeerAuthentication, a scoped/deny policy, and ``requestPrincipals: ["*"]`` (JWT-gated, not allow-all) do
    NOT fire. Returns a :class:`PostureResult`; the FACT re-verifies offline via ``verify_certificate``."""
    from framework.v2.verify.mesh_posture import ingest_mesh_config, mesh_posture_context  # noqa: PLC0415

    sha = _sha256_hex(config)
    res = PostureResult(family="mesh_posture", artifact_sha256=sha)
    res.artifact_bytes = _raw_bytes(config)
    parsed = _safe_parse_structure(config, budget)
    res.parse_outcome, res.parse_reason = parsed.outcome, parsed.reason
    if not parsed.ok:
        res.notes.append(f"mesh config did not parse: {parsed.outcome}:{parsed.reason}")
        return res   # nothing examined → family_verdict() is INCONCLUSIVE, never CLEAN

    controls = ingest_mesh_config(parsed.value)
    binding = {
        "artifact_sha256": sha, "collector_id": collector_id,
        "capture_method": "artifact:istio-linkerd", "completeness": "partial",
        **_artifact_binding(config),
    }

    def _ctx(control):
        return mesh_posture_context(control)

    def _cid(control):
        return (f"mesh:{control.get('provider', '?')}:{control.get('resource_kind', '?')}:"
                f"{control.get('namespace', '') or '-'}/{control.get('name', '') or '?'}")

    _adjudicate(res=res, branch=_MESH_BRANCH, bug_class="mesh_misconfiguration", controls=controls,
                oracle_context_of=_ctx, check_id_of=_cid, engagement_slug=engagement_slug,
                signers=signers, binding=binding)
    return res


def cicd_posture_verify(
    workflow: str | bytes,
    *,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    name: str = "workflow",
    collector_id: str = "cicd-workflow",
    budget: ParseBudget | None = None,
) -> PostureResult:
    """Parse a GitHub-Actions workflow (the PRIMARY config artifact) and — THROUGH ADMISSION — mint a signed
    FACT for every control the ``cicd_posture`` oracle PROVES dangerous (an unpinned third-party action, a
    pwn-request, or a script-injection sink).

    The bytes are resource-governed-parsed (safe_json / safe_yaml); a malformed / oversized / bomb artifact
    yields a typed ``parse_outcome != "ok"`` and NO facts (never a crash). The parsed STRUCTURE is handed to
    ``verify.cicd_posture.ingest_workflow`` (never the raw text). Near-zero-FP is the oracle's: a first-party
    ``actions/checkout@v4``, a SHA-pinned action, a plain ``pull_request`` base checkout, and a ``run`` whose
    only ``${{ }}`` is a quoted literal do NOT fire. Returns a :class:`PostureResult`; the FACT re-verifies
    offline via ``verify_certificate``."""
    from framework.v2.verify.cicd_posture import cicd_posture_context, ingest_workflow  # noqa: PLC0415

    sha = _sha256_hex(workflow)
    res = PostureResult(family="cicd_posture", artifact_sha256=sha)
    res.artifact_bytes = _raw_bytes(workflow)
    parsed = _safe_parse_structure(workflow, budget)
    res.parse_outcome, res.parse_reason = parsed.outcome, parsed.reason
    if not parsed.ok:
        res.notes.append(f"workflow did not parse: {parsed.outcome}:{parsed.reason}")
        return res   # nothing examined → family_verdict() is INCONCLUSIVE, never CLEAN

    # ingest_workflow accepts a dict (the parsed structure); it re-parses a str itself, but we NEVER hand it
    # raw operator text — a non-mapping parse (a bare list / scalar) ingests to zero controls, not a crash.
    structure = parsed.value if isinstance(parsed.value, dict) else None
    controls = ingest_workflow(structure, name=name) if structure is not None else []
    binding = {
        "artifact_sha256": sha, "collector_id": collector_id,
        "capture_method": "artifact:github-actions", "completeness": "partial",
        **_artifact_binding(workflow),
    }

    def _ctx(control):
        return cicd_posture_context(control)

    def _cid(control):
        return (f"cicd:{control.get('workflow', name)}:{control.get('rule', '?')}:"
                f"{control.get('job', '') or '-'}")

    _adjudicate(res=res, branch=_CICD_BRANCH, bug_class="cicd_misconfiguration", controls=controls,
                oracle_context_of=_ctx, check_id_of=_cid, engagement_slug=engagement_slug,
                signers=signers, binding=binding)
    return res
