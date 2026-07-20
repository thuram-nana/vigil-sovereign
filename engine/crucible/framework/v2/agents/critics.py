"""
agents.critics — a panel of differentiated critics over a finding.

CRUCIBLE had exactly one critic (``CritiqueAgent``). A single reviewer sees a single failure
mode; a PANEL of critics, each looking through a different lens, turns their DISAGREEMENT into
a signal. This module adds that panel — deterministic lenses (replay-safe, no LLM cost, no
egress) whose verdicts are aggregated with abstain-on-disagreement.

Oracle authority is preserved at the type level: a critic verdict is ``endorse | object |
abstain`` — never ``confirm``. Critics can only advise, gate HARDER (object), or abstain; they
can NEVER promote a finding to a fact. Only a fired deterministic oracle confirms.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Protocol

_VERDICTS = ("endorse", "object", "abstain")
_SEVERITIES = ("info", "minor", "major", "critical")


@dataclass
class CriticVerdict:
    critic: str
    verdict: str                 # endorse | object | abstain (never "confirm")
    severity: str = "info"       # info | minor | major | critical
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in _VERDICTS:
            raise ValueError(f"critic verdict must be one of {_VERDICTS}, got {self.verdict!r} "
                             f"— a critic can never 'confirm' (only a fired oracle confirms)")
        if self.severity not in _SEVERITIES:
            raise ValueError(f"severity must be one of {_SEVERITIES}, got {self.severity!r}")


@dataclass
class PanelVerdict:
    verdict: str                 # endorse | object | abstain
    rationale: str = ""
    verdicts: list[CriticVerdict] = field(default_factory=list)
    agreement: float = 1.0
    entropy: float = 0.0


class Critic(Protocol):
    name: str
    def review(self, finding: Any) -> CriticVerdict: ...


# ---- concrete deterministic critics ----------------------------------------


def _get(f: Any, k: str, default: Any = None) -> Any:
    return f.get(k, default) if isinstance(f, dict) else getattr(f, k, default)


class GroundingCritic:
    """False-positive lens: re-execute the finding's own oracle. Endorse only if it re-grounds
    as a fact; object otherwise (a 'confirmed' finding whose proof no longer reproduces)."""

    name = "grounding"

    def review(self, finding: Any) -> CriticVerdict:
        try:
            from ..veracity import admit, claim_from_finding
            claim = claim_from_finding(finding, source="critic:grounding", match_confidence=False)
            admitted = admit(claim, world=None)
        except Exception:
            return CriticVerdict(self.name, "abstain", rationale="could not assess grounding")
        if admitted.is_fact:
            return CriticVerdict(self.name, "endorse", rationale="oracle re-fires (grounded fact)")
        return CriticVerdict(self.name, "object", severity="major",
                             rationale=f"does not re-ground under live re-execution: {admitted.reason}")


class ProvenanceCritic:
    """Deception lens: a finding that CLAIMS oracle verification must carry a re-verifiable
    oracle_context. verified_by_oracle=True with no retained proof is an unbacked assertion."""

    name = "provenance"

    def review(self, finding: Any) -> CriticVerdict:
        vbo = bool(_get(finding, "verified_by_oracle", False))
        oc = _get(finding, "oracle_context")
        if vbo and not oc:
            return CriticVerdict(self.name, "object", severity="major",
                                 rationale="claims oracle verification but carries no re-verifiable proof")
        return CriticVerdict(self.name, "endorse", rationale="provenance consistent")


class CalibrationCritic:
    """Calibration lens: a confirmed finding's confidence must be a real calibrated value,
    never the old hardcoded certainty. 1.0 (or >1) is a laundered number; None on a verified
    finding is missing calibration."""

    name = "calibration"

    def review(self, finding: Any) -> CriticVerdict:
        conf = _get(finding, "confidence")
        vbo = bool(_get(finding, "verified_by_oracle", False))
        if conf is not None and conf >= 1.0:
            return CriticVerdict(self.name, "object", severity="minor",
                                 rationale=f"confidence {conf} is a hardcoded certainty, not calibrated")
        if vbo and conf is None:
            return CriticVerdict(self.name, "abstain", rationale="verified but no calibrated confidence")
        return CriticVerdict(self.name, "endorse", rationale="confidence is calibrated / in-range")


def default_critics() -> list[Critic]:
    """The default deterministic panel."""
    return [GroundingCritic(), ProvenanceCritic(), CalibrationCritic()]


# ---- panel run + aggregation -----------------------------------------------


def run_panel(finding: Any, critics: list[Critic] | None = None) -> list[CriticVerdict]:
    """Every critic reviews the finding independently. Best-effort per critic (a crashing
    critic abstains rather than sinking the panel)."""
    out: list[CriticVerdict] = []
    for c in (critics if critics is not None else default_critics()):
        try:
            out.append(c.review(finding))
        except Exception:
            out.append(CriticVerdict(getattr(c, "name", "critic"), "abstain",
                                     rationale="critic raised — abstaining"))
    return out


def aggregate_panel(verdicts: list[CriticVerdict], *, entropy_gate: float = 0.5) -> PanelVerdict:
    """Aggregate heterogeneous critic verdicts into an advisory panel verdict.

    Rules (demote-only, oracle-authority-preserving): (1) any MAJOR/CRITICAL objection stands
    — a single strong objection demotes (fail-harder); (2) otherwise, if the critics DISAGREE
    (high categorical entropy over their verdicts), ABSTAIN — route to needs_evidence rather
    than assert; (3) otherwise the modal verdict. The panel result is never 'confirm'."""
    if not verdicts:
        return PanelVerdict("abstain", rationale="no critics ran")

    strong = [v for v in verdicts if v.verdict == "object" and v.severity in ("major", "critical")]
    if strong:
        return PanelVerdict("object", verdicts=verdicts, agreement=0.0,
                            rationale="; ".join(f"{v.critic}: {v.rationale}" for v in strong))

    counts = Counter(v.verdict for v in verdicts)
    modal, modal_n = counts.most_common(1)[0]
    agreement = modal_n / len(verdicts)
    from ..kernel.consistency import categorical_entropy
    entropy = categorical_entropy(dict(counts), n_samples=len(verdicts))
    if entropy > entropy_gate:
        return PanelVerdict("abstain", verdicts=verdicts, agreement=round(agreement, 4),
                            entropy=entropy, rationale="critics disagree — abstaining to needs_evidence")
    return PanelVerdict(modal, verdicts=verdicts, agreement=round(agreement, 4), entropy=entropy,
                        rationale=f"{modal_n}/{len(verdicts)} critics {modal}")


def _verdicts_about(bb: Any, engagement: Any, finding_event_id: int) -> list:
    """Every critic_verdict event posted ABOUT ``finding_event_id``, in id order — paged to
    exhaustion so a large log is never silently truncated (the N1/N3 lesson). X3: filters on the
    indexed ``parent_id`` (which ``MultiCriticAgent`` sets to the finding id) so this reads only
    the verdicts on THIS finding, not every verdict in the engagement — the panel quorum gate is
    O(verdicts-on-this-finding), not O(all-verdicts) per finding."""
    out: list = []
    since = 0
    while True:
        batch = bb.read(engagement=engagement, kinds=["critic_verdict"],
                        parent_id=finding_event_id, since_id=since, limit=5000)
        if not batch:
            break
        out.extend(batch)
        since = batch[-1].id
        if len(batch) < 5000:
            break
    return out


def panel_verdict_for(bb: Any, engagement: Any, finding_event_id: int,
                      *, entropy_gate: float = 0.5) -> PanelVerdict:
    """Read the critic_verdict events posted about ``finding_event_id`` and aggregate them
    into the panel verdict — the quorum gate a coordinator can consult before promotion. Reads
    the FULL verdict set for this finding (paged) so none is dropped by a limit. The
    ``target_event_id`` payload check is kept as a belt-and-suspenders over the indexed
    ``parent_id`` filter (both are the finding id), so a verdict posted with a divergent
    parent_id can never be mis-attributed."""
    rows = _verdicts_about(bb, engagement, finding_event_id)
    verdicts = [
        CriticVerdict(critic=r.payload["critic"], verdict=r.payload["verdict"],
                      severity=r.payload.get("severity", "info"),
                      rationale=r.payload.get("rationale", ""))
        for r in rows if r.payload.get("target_event_id") == finding_event_id
    ]
    return aggregate_panel(verdicts, entropy_gate=entropy_gate)


# ---- the panel as a schedulable agent (addable to the Coordinator) ----------


def _multi_critic_agent_base():
    # lazy base import so importing critics.py never drags in the agent stack
    from .base import Agent
    return Agent


class MultiCriticAgent(_multi_critic_agent_base()):  # type: ignore[misc]
    """A schedulable agent that runs the critic panel over each finding and posts one
    ``critic_verdict`` event per critic. Purely ADDITIVE: it can be added to the Coordinator's
    agent list without touching any existing agent; it only advises (posts verdicts), never
    promotes. The Coordinator (or any consumer) reads the quorum via ``panel_verdict_for``."""

    name = "multi-critic"

    def __init__(self, blackboard: Any, engagement_slug: str, *,
                 critics: list[Critic] | None = None) -> None:
        super().__init__(blackboard, engagement_slug)
        self._critics = critics if critics is not None else default_critics()

    def _unreviewed(self) -> list:
        # CURSOR-BASED: findings newer than what this agent has already reviewed. This both
        # bounds each tick and guarantees each finding is reviewed exactly once — a reviewed-
        # set derived from a (limit-capped) read of ALL verdicts would freeze its window on a
        # large log and re-review forever (never quiescing). Superseded findings are excluded.
        return self.bb.read(engagement=self.engagement_id, since_id=self._cursor, kinds=["finding"])

    def should_run(self) -> bool:
        return bool(self._unreviewed())

    def step(self) -> int:
        from .models import FindingPayload
        posted = 0
        highest = self._cursor
        for ev in self._unreviewed():
            highest = max(highest, ev.id)
            try:
                finding = FindingPayload.model_validate(ev.payload)
            except Exception:
                continue
            for v in run_panel(finding, self._critics):
                try:
                    self.bb.post(engagement=self.engagement_id, kind="critic_verdict",
                                 agent_name=self.name, parent_id=ev.id,
                                 payload={"critic": v.critic, "target_event_id": ev.id,
                                          "verdict": v.verdict, "severity": v.severity,
                                          "rationale": v.rationale})
                    posted += 1
                except Exception:
                    pass
        # advance PAST the findings reviewed this tick (only the finding ids — verdict events
        # have higher ids but are filtered out by kinds=["finding"] next tick regardless).
        self._cursor = highest
        return posted
