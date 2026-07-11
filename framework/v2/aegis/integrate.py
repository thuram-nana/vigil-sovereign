"""
aegis.integrate — the AEGIS → engagement adapter (an ADDITIONAL, opt-in sink).

``pipeline.detect`` writes only to its own per-actor ``ActorGraph.world`` and returns a
``Verdict``. This module is the seam that lets a caller ALSO fold that verdict into the shared
ENGAGEMENT ``WorldModel`` and — when a spine sink is attached — onto the immutable event stream,
so the unified ``report`` / ``evidence`` tools compose the defensive dual alongside the offensive
scanner's findings. It NEVER changes ``detect``'s default behaviour: ``project_verdict_to_world``
is a function the caller opts into after ``detect`` returns.

What it projects, honestly graded (prove-don't-guess preserved):

  * a CONFIRMED verdict → a strong per-actor belief ``Observation`` on the world-model (via
    ``intel.project.project_observation``) PLUS a ``finding`` event carrying the verdict's OWN
    retained certificate (``oracle_context`` + ``verified_by_oracle=True``). The report grader
    RE-EXECUTES that certificate; only if the AEGIS oracle re-fires does it render as a FACT. No
    new oracle is added — AEGIS's four classes already live in ``BUG_CLASS_ORACLES``.
  * a LEAD verdict → a weak belief ``Observation`` PLUS a lead-graded ``finding`` event (no
    ``oracle_context``), which the report renders as an unconfirmed lead, never a fact.
  * a CLEAR verdict → nothing (there is no reportable detection).

The world-model NODE provenance from ``project_observation`` is the ``intel:`` (belief) tier in
BOTH cases — a belief is never a fact — while the verdict's own tier label
(``grounded:aegis:*`` for confirmed, ``intel:aegis:*`` for a lead) rides on the observation's
``attrs['verdict_provenance']`` and the emitted finding event's certificate. That is the honest
expression of "grounded for confirmed, intel for leads": the belief accrues, the CERTIFICATE is
the fact.

Determinism: a pure function of the verdict + the world's current high-water seq (never
wallclock, never rng). ``seq`` may be supplied to pin world-model time explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..intel.models import (
    Credibility,
    IntelSourceKind,
    Observation,
    Polarity,
    Reliability,
    SourceReliability,
)
from ..intel.project import project_observation
from ..intel.refs import EntityRef
from ..verify.verifier import normalize_bug_class
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import NodeKind
from .models import Verdict

# AEGIS attack_class → the inbound telemetry surface that produced it (the source_kind the AEGIS
# sensors mint). Any unknown/aliased class falls back to the request-telemetry surface.
_CLASS_SOURCE_KIND = {
    "prompt_injection": IntelSourceKind.LLM_INTERACTION,
    "system_prompt_disclosure": IntelSourceKind.LLM_INTERACTION,
    "automated_access": IntelSourceKind.REQUEST_TELEMETRY,
    "credential_stuffing": IntelSourceKind.AUTH_TELEMETRY,
}

# Coarse, class-level severity for the report header. This is NOT the grade — the report's
# fact/lead grade (re-executed oracle vs none) tells the operator whether it is proven.
_CLASS_SEVERITY = {
    "prompt_injection": "High",
    "system_prompt_disclosure": "High",
    "credential_stuffing": "High",
    "automated_access": "Medium",
}

# A confirmed detection is a re-verifiable oracle proof → an A/1 source (a strong belief update);
# a lead is the same C/3 tier the AEGIS sensors mint (real, but never a fact on its own).
_FACT_RELIABILITY = SourceReliability(reliability=Reliability.A, credibility=Credibility.C1)
_LEAD_RELIABILITY = SourceReliability(reliability=Reliability.C, credibility=Credibility.C3)


@dataclass(frozen=True)
class VerdictProjection:
    """The outcome of projecting one verdict.

    ``projected`` — the belief observation was applied to the world-model.
    ``observation`` — the minted lead/belief ``Observation`` (None for a clear verdict).
    ``finding_event_id`` — the spine ``finding`` event id (None when no sink, or a clear verdict).
    """

    projected: bool
    observation: Observation | None = None
    finding_event_id: int | None = None


def _actor_node_id_from_contributing(contributing: list[str]) -> str:
    """Recover the actor's world-model node id from a contributing obs_id.

    A contributing id is minted (aegis/sensors.py::_mint) as
    ``f"aegis:{source_kind}:{seq}:{subject.node_id}|{claim}"`` — ``source_kind`` and ``seq`` carry
    no ``:``, so the subject node id is everything after the third ``:`` of the part before ``|``.
    Pure string parsing; deterministic; returns "" when nothing parses."""
    for obs_id in contributing:
        head = obs_id.split("|", 1)[0]
        parts = head.split(":", 3)
        if len(parts) == 4 and parts[0] == "aegis":
            return parts[3]
    return ""


def _actor_ref(verdict: Verdict, actor: "EntityRef | str | None") -> EntityRef:
    """The world-model SESSION node the verdict is ABOUT. An explicit ``actor`` (EntityRef, a
    ``session:<key>`` node id, or a bare key) wins; otherwise it is recovered from the verdict's
    own ``contributing`` observation ids. Falls back to a deterministic ``unknown`` key."""
    if isinstance(actor, EntityRef):
        return actor
    if isinstance(actor, str) and actor.strip():
        raw = actor.strip()
        key = raw.split(":", 1)[1] if raw.startswith("session:") else raw
        return EntityRef(kind=NodeKind.SESSION, key=key or "unknown")
    node_id = _actor_node_id_from_contributing(list(verdict.contributing or []))
    key = node_id.split(":", 1)[1] if node_id.startswith("session:") else node_id
    return EntityRef(kind=NodeKind.SESSION, key=key or "unknown")


def _confirmed_finding_payload(verdict: Verdict, subject: EntityRef) -> dict:
    """A FindingPayload-shaped dict for a CONFIRMED verdict, carrying the verdict's OWN retained
    certificate so the report grader re-executes it and renders a FACT (only if the oracle
    re-fires). ``critique_status='confirmed'`` + ``verified_by_oracle=True`` mark the proof."""
    cert = verdict.certificate
    assert cert is not None  # Verdict's model validator guarantees this for decision=='confirmed'
    return {
        "finding_slug": (f"aegis-{verdict.attack_class}-{cert.cert_id.split(':')[-1]}")[:120],
        "title": f"{verdict.attack_class} confirmed by AEGIS",
        "severity": _CLASS_SEVERITY.get(normalize_bug_class(verdict.attack_class), "Medium"),
        "bug_class": verdict.attack_class,
        "surface": subject.node_id,
        "summary": (
            f"AEGIS confirmed {verdict.attack_class} for actor {subject.node_id} via oracle "
            f"{cert.confirmed_by}; offline-re-runnable certificate {cert.cert_id}."
        ),
        "critique_status": "confirmed",
        "critique_dryrun": False,
        "oracle_context": dict(cert.oracle_context),
        "verified_by_oracle": True,
        "confidence": float(cert.confidence),
        "oracle_kind": cert.confirmed_by,
        "oracle_rationale": (
            f"AEGIS {cert.confirmed_by} oracle re-fired over retained evidence (certificate "
            f"{cert.cert_id}); the veracity firewall admitted it as a fact."
        ),
    }


def _lead_finding_payload(verdict: Verdict, subject: EntityRef) -> dict:
    """A FindingPayload-shaped dict for a LEAD verdict: NO oracle_context, so the report grader
    renders it as an unconfirmed lead — never a fact. ``critique_status='llm_advisory'`` is the
    reportable-but-lead bucket (a lead is honestly a lead)."""
    canon = normalize_bug_class(verdict.attack_class)
    return {
        "finding_slug": (f"aegis-lead-{verdict.attack_class}-{subject.key}")[:120],
        "title": f"{verdict.attack_class} lead (AEGIS, unconfirmed)",
        "severity": _CLASS_SEVERITY.get(canon, "Info"),
        "bug_class": verdict.attack_class,
        "surface": subject.node_id,
        "summary": (
            f"AEGIS raised a LEAD for {verdict.attack_class} on actor {subject.node_id} "
            f"(belief only — no oracle fired). Verify before relying on it."
        ),
        "critique_status": "llm_advisory",
        "critique_dryrun": False,
        "oracle_context": None,
        "verified_by_oracle": False,
        "confidence": None,
        "oracle_kind": None,
        "oracle_rationale": "",
    }


def project_verdict_to_world(
    verdict: Verdict,
    world: WorldModel,
    *,
    sink: Any = None,
    seq: int | None = None,
    actor: "EntityRef | str | None" = None,
) -> VerdictProjection:
    """Project one AEGIS ``Verdict`` onto a shared engagement ``WorldModel`` and (with a spine
    ``sink``) emit a ``finding`` event for the unified report.

    Additive and opt-in: this is called AFTER ``detect`` returns; it does not touch ``detect`` or
    its ``ActorGraph.world``. A CLEAR verdict is a no-op. Best-effort on the spine — a sink write
    can never raise into the caller. Deterministic: ``seq`` (or the world's high-water + 1) stamps
    world-model time; no wallclock, no rng.

    Returns a :class:`VerdictProjection` (whether the world was touched, the observation, and the
    finding-event id)."""
    if verdict.decision == "clear":
        return VerdictProjection(projected=False)

    confirmed = verdict.decision == "confirmed"
    canon = normalize_bug_class(verdict.attack_class)
    source_kind = _CLASS_SOURCE_KIND.get(canon, IntelSourceKind.REQUEST_TELEMETRY)
    subject = _actor_ref(verdict, actor)

    # Deterministic world-model time: mirror engage's own seq_base derivation (never wallclock).
    if seq is None:
        seq = max((int(getattr(n, "last_seen", 0) or 0) for n in world.all_nodes()), default=0) + 1

    cert_id = verdict.certificate.cert_id if verdict.certificate is not None else ""
    # cert_id is a content hash (deterministic); the lead anchor is the actor+class → same
    # evidence mints the same obs_id, so re-projection collapses idempotently onto the same belief.
    anchor = cert_id if confirmed else f"lead:{subject.node_id}"
    obs = Observation(
        obs_id=(f"aegis:{anchor}:{canon}")[:512],
        source=f"aegis:{canon}",
        source_kind=source_kind,
        collector="aegis.integrate",
        subject=subject,
        attrs={
            "decision": verdict.decision,
            "attack_class": verdict.attack_class,
            "bug_class": verdict.attack_class,
            # the verdict's OWN tier label: grounded:aegis:* (confirmed) | intel:aegis:* (lead).
            "verdict_provenance": verdict.provenance,
            "cert_id": cert_id,
            "severity": _CLASS_SEVERITY.get(canon, "Info"),
        },
        source_reliability=_FACT_RELIABILITY if confirmed else _LEAD_RELIABILITY,
        confidence=float(verdict.confidence),
        polarity=Polarity.AFFIRMS,
        seq=int(seq),
        evidence=(
            f"AEGIS {verdict.decision} {verdict.attack_class}"
            + (f" (certificate {cert_id})" if cert_id else "")
        ),
    )
    applied = project_observation(world, obs, seq=int(seq))

    event_id: int | None = None
    if sink is not None:
        payload = (
            _confirmed_finding_payload(verdict, subject)
            if confirmed
            else _lead_finding_payload(verdict, subject)
        )
        try:
            event_id = sink.finding_event(payload)
        except Exception:
            event_id = None   # a spine write must never perturb the caller

    return VerdictProjection(projected=applied, observation=obs, finding_event_id=event_id)
