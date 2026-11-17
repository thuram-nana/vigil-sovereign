"""
redpen.engine — the Red-Pen adversarial reproduction engine (offense plane, design §7.2).

The map -> attack -> refute-by-reproduction -> certify pipeline for a reviewed diff/tree:

  1. **Map.** Threat-model the changed paths deterministically (no model): read the changed files from the
     local checkout and build a bounded, per-lens context string. The engine holds NO GitHub token — R3
     hands it a local checkout + the changed paths.
  2. **Attack.** Fan out one request per lens (authn/authz, injection, crypto/secrets, business logic,
     data exposure, SSRF/egress, deserialisation, concurrency, supply chain/CI, IaC/cloud, LLM, test
     honesty) through an INJECTED ``Reviewer``-style seam. Each lens proposes candidates (file, line,
     bug_class, a sandbox PoC). The seam is the ONLY place a model is consulted; tests inject a
     deterministic fake, and the live gateway-backed reviewer is wired later (R3, the live flip waits).
     A lens that RAISES is logged and SKIPPED — it never aborts the run and never promotes a finding.
  3. **Refute by reproduction.** Each candidate's PoC runs in the S5 sandbox and must FIRE twice
     (:mod:`redpen.reproduce`).
  4. **Certify.** A twice-fired candidate's captured bytes are translated to a ``FindingContext`` and a
     FACT is minted via ``confirm_and_certify(provenance="reproduced")`` — but ONLY for the offline/static
     oracle set (O-1); everything else is a LEAD (:mod:`redpen.certify`).

Master flag ``VIGIL_REDPEN_ENABLED`` (default OFF, keyless env read in the offense plane, mirroring
``kernel.metered``): with it off :func:`run_redpen` returns an inert empty report BEFORE consulting the
reviewer, touching the sandbox, or importing ``framework`` — the engine is byte-identically absent.

FATAL-2: all ``framework`` work happens behind the certify seam, which lazy-imports; this module imports
only stdlib and the sibling redpen modules (themselves import-clean). No ``sigil`` import.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

from .certify import CertifyResult, certify_candidate
from .reproduce import DEFAULT_REPRO_TIMEOUT, DEFAULT_RUNS_REQUIRED, Reproduction, reproduce_candidate

# ---- the master flag (keyless, offense-plane; mirrors kernel.metered's env read) --------------------

REDPEN_ENABLED_ENV = "VIGIL_REDPEN_ENABLED"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def redpen_enabled() -> bool:
    """True iff the Red-Pen engine is switched on (``VIGIL_REDPEN_ENABLED`` ∈ {1,true,yes,on}). Default
    OFF: unset / empty / any other value is OFF, and :func:`run_redpen` is then inert (no reviewer call,
    no sandbox, no ``framework`` import). Keyless: it reads an env flag, never a secret — FATAL-2 clean."""
    return (os.environ.get(REDPEN_ENABLED_ENV) or "").strip().lower() in _TRUTHY


# ---- the lenses (design §7.2 §2) --------------------------------------------------------------------

DEFAULT_LENSES: tuple[str, ...] = (
    "authn_authz", "injection", "crypto_secrets", "business_logic", "data_exposure",
    "ssrf_egress", "deserialization", "concurrency_races", "supply_chain_ci", "iac_cloud",
    "llm_prompt_injection", "test_honesty",
)

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def _norm_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    return s if s in _SEVERITIES else "medium"


# ---- the model seam (Reviewer pattern — mirror analysis.review_loop) --------------------------------

@dataclass(frozen=True)
class LensCandidate:
    """One attack candidate a lens proposes. The engine NEVER trusts these fields to assert a defect —
    they only DIRECT a sandbox reproduction and an oracle adjudication, which are the authorities."""

    lens: str
    bug_class: str
    channel: str                             # a redpen.certify channel (request_payload/process/error_signature/...)
    poc_command: str = ""                    # the shell command run inside the sandbox
    fire_markers: tuple[str, ...] = ()       # substrings whose presence in captured output = "fired"
    fire_mode: str = "any"                   # "any" | "all"
    request_value: str = ""                  # the decoded request payload (request-side channel)
    param: str = ""                          # the parameter name / role
    control_value: str = ""                  # an optional benign control (error-signature channel)
    title: str = ""
    file: str = ""
    line: int = 0
    severity: str = "medium"
    finding_ref: str = ""
    verified_by_oracle: bool = False         # a DAA-sourced flag — DELIBERATELY NEVER gated on (O-1).


@dataclass(frozen=True)
class LensRequest:
    """What the engine hands the reviewer for one lens: the lens name and the mapped threat-model context
    for the reviewed change. Carries no secret and no token."""

    lens: str
    checkout_path: str
    changed_paths: tuple[str, ...]
    diff_context: str


@dataclass(frozen=True)
class LensResponse:
    """What a reviewer returns for one lens: the candidates it proposes (possibly none)."""

    candidates: tuple[LensCandidate, ...] = ()


# A reviewer takes one LensRequest and returns a LensResponse. The default is NOT built here — the live,
# gateway-backed reviewer waits (R3); R1 requires an injected seam and tests pass a deterministic fake.
RedPenReviewer = Callable[[LensRequest], LensResponse]


# ---- report model (what R3 consumes) ----------------------------------------------------------------

@dataclass(frozen=True)
class RedPenFact:
    """A reproduced + oracle-confirmed + signed finding from the O-1 FACT-eligible set. R3 posts these."""

    bug_class: str
    confirmed_by: str
    severity: str
    finding_ref: str
    reason: str
    lens: str
    file: str = ""
    line: int = 0
    confidence: float = 0.0
    signed: Any = None


@dataclass(frozen=True)
class RedPenLead:
    """Everything else — honest, retained, dashboard-only, NEVER posted as a finding."""

    bug_class: str
    severity: str
    finding_ref: str
    reason: str
    lens: str
    file: str = ""
    line: int = 0
    confirmed_by: str = ""
    outcome: str = ""


@dataclass(frozen=True)
class SkippedLens:
    """A lens whose reviewer RAISED — recorded so the skip is auditable; the run continues."""

    lens: str
    reason: str


@dataclass(frozen=True)
class RedPenReport:
    """The engine's output. ``enabled`` is False (and everything empty) when the flag is off."""

    enabled: bool
    facts: tuple[RedPenFact, ...] = ()
    leads: tuple[RedPenLead, ...] = ()
    skipped_lenses: tuple[SkippedLens, ...] = ()
    candidates_seen: int = 0


# ---- map: deterministic threat-model of the changed paths (no model) --------------------------------

_MAX_FILE_BYTES = 20_000          # per changed file, bounded so the context stays small
_MAX_CONTEXT_FILES = 50


def _map_diff(checkout_path: Path, changed_paths: Sequence[str]) -> str:
    """Build a bounded, DETERMINISTIC context string over the changed files for the reviewer to reason on.
    Reads only files WITHIN the checkout (a path escaping it is skipped); never executes anything, never
    reaches the network. The model does the real threat modelling — this just assembles the material."""
    root = checkout_path.resolve()
    parts: list[str] = [f"Reviewed change: {len(changed_paths)} changed path(s)."]
    for rel in list(changed_paths)[:_MAX_CONTEXT_FILES]:
        p = (root / rel)
        try:
            rp = p.resolve()
            rp.relative_to(root)                       # refuse a path escaping the checkout
        except (ValueError, OSError):
            parts.append(f"- {rel}: (outside checkout — skipped)")
            continue
        try:
            text = rp.read_text(encoding="utf-8", errors="replace")[:_MAX_FILE_BYTES] if rp.is_file() else ""
        except OSError:
            text = ""
        parts.append(f"--- {rel} ({len(text)} bytes) ---\n{text}")
    return "\n".join(parts)


# ---- the orchestrator -------------------------------------------------------------------------------

def run_redpen(
    *,
    checkout_path: "str | os.PathLike",
    changed_paths: Sequence[str],
    reviewer: RedPenReviewer,
    engagement_slug: str,
    signers: "Sequence[tuple[str, str]]",
    workspace: "Optional[str | os.PathLike]" = None,
    sandbox: Any = None,
    confirm: Any = None,
    lenses: "Optional[Sequence[str]]" = None,
    seq: int = 0,
    verifier: Any = None,
    timeout: float = DEFAULT_REPRO_TIMEOUT,
    runs_required: int = DEFAULT_RUNS_REQUIRED,
) -> RedPenReport:
    """Run the Red-Pen reproduction pipeline over a reviewed checkout. This is the entry point R3 calls.

    ``checkout_path`` + ``changed_paths`` are the LOCAL checkout and the paths the review changed (R3
    provides them; the engine holds no GitHub token). ``reviewer`` is the injected model seam (one
    :class:`LensResponse` per :class:`LensRequest`). ``signers`` are the governance authorisers (empty is
    refused fail-closed when a FACT is attempted). ``workspace`` is the sandbox's confined writable dir
    (default: the checkout). ``sandbox`` / ``confirm`` are injectable seams for tests (default: the real
    ``run_sandboxed`` / ``confirm_and_certify``).

    Returns a :class:`RedPenReport`. With ``VIGIL_REDPEN_ENABLED`` off it returns an inert empty report
    (``enabled=False``) WITHOUT consulting the reviewer, touching the sandbox, or importing ``framework``.
    """
    if not redpen_enabled():
        # Inert: the engine is byte-identically absent when the flag is off. The reviewer is not called,
        # the sandbox is not touched, no framework is imported.
        return RedPenReport(enabled=False)

    root = Path(checkout_path)
    ws = Path(workspace) if workspace is not None else root
    changed = tuple(str(p) for p in (changed_paths or ()))
    lens_names = tuple(lenses) if lenses is not None else DEFAULT_LENSES

    diff_context = _map_diff(root, changed)

    facts: list[RedPenFact] = []
    leads: list[RedPenLead] = []
    skipped: list[SkippedLens] = []
    seen = 0

    for lens in lens_names:
        request = LensRequest(lens=lens, checkout_path=str(root), changed_paths=changed,
                              diff_context=diff_context)
        try:
            response = reviewer(request)
            candidates = tuple(getattr(response, "candidates", ()) or ())
        except Exception as exc:  # noqa: BLE001 — a lens failure is logged and SKIPPED, never fatal/promoted.
            skipped.append(SkippedLens(lens=lens, reason=f"{type(exc).__name__}: {exc}"))
            continue

        for candidate in candidates:
            seen += 1
            fact, lead = _process_candidate(
                candidate, workspace=ws, engagement_slug=engagement_slug, signers=signers, seq=seq,
                verifier=verifier, sandbox=sandbox, confirm=confirm, timeout=timeout,
                runs_required=runs_required)
            if fact is not None:
                facts.append(fact)
            if lead is not None:
                leads.append(lead)

    return RedPenReport(
        enabled=True, facts=tuple(facts), leads=tuple(leads), skipped_lenses=tuple(skipped),
        candidates_seen=seen)


def _process_candidate(
    candidate: LensCandidate,
    *,
    workspace: Path,
    engagement_slug: str,
    signers: "Sequence[tuple[str, str]]",
    seq: int,
    verifier: Any,
    sandbox: Any,
    confirm: Any,
    timeout: float,
    runs_required: int,
) -> "tuple[Optional[RedPenFact], Optional[RedPenLead]]":
    """Reproduce one candidate, then certify it. Returns (fact|None, lead|None). A candidate NOT
    reproduced twice never reaches certification — it is an honest LEAD; a reproduced candidate is a FACT
    only when the O-1 oracle gate in :func:`certify_candidate` confirms it."""
    sev = _norm_severity(getattr(candidate, "severity", "medium"))
    ref = str(getattr(candidate, "finding_ref", "") or getattr(candidate, "bug_class", "") or "finding")
    lens = str(getattr(candidate, "lens", "") or "")

    repro: Reproduction = reproduce_candidate(
        candidate, workspace=workspace, sandbox=sandbox, timeout=timeout, runs_required=runs_required)

    if repro.status != "reproduced":
        # Not reproduced twice (flake / no fire / sandbox unavailable / error) — honest LEAD, never a FACT.
        return (None, RedPenLead(
            bug_class=candidate.bug_class, severity=sev, finding_ref=ref,
            reason=repro.reason or f"not reproduced ({repro.status})", lens=lens,
            file=candidate.file, line=candidate.line, outcome=repro.status))

    result: CertifyResult = certify_candidate(
        candidate, repro, engagement_slug=engagement_slug, signers=signers, seq=seq, verifier=verifier,
        confirm=confirm)

    if result.is_fact:
        return (RedPenFact(
            bug_class=result.bug_class, confirmed_by=result.confirmed_by, severity=sev,
            finding_ref=result.finding_ref, reason=result.reason, lens=lens, file=candidate.file,
            line=candidate.line, confidence=result.confidence, signed=result.signed), None)

    return (None, RedPenLead(
        bug_class=result.bug_class, severity=sev, finding_ref=result.finding_ref, reason=result.reason,
        lens=lens, file=candidate.file, line=candidate.line, confirmed_by=result.confirmed_by,
        outcome=result.outcome))
