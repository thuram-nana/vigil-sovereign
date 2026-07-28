"""
knowledge_engine.evolve — the HONEST, BOUNDED self-evolve loop (K5).

What it actually is (state this plainly to the operator):
  * a DETERMINISTIC scan over DISCLOSED vuln leads → a horizon of `CapabilityGap`s, plus coverage-gap
    synthesis (disclosed bug classes the deterministic oracle substrate cannot yet adjudicate);
  * those gaps → DRAFT `improve.ImprovementProposal`s (described-only, `status=DRAFT`). It NEVER merges or
    applies anything — `improve.merge_gate.evaluate_merge` (capability + eval + m-of-n approvals) is the
    separate, human-applied gate, and K5 does not call it;
  * a `studied_enough` completion signal — true when every disclosed lead in scope has FIND/DETECT/PREVENT
    skills, every gap has a drafted proposal, and the OutcomeLedger has no open predictions;
  * predictions recorded in a slug-scoped `calibration.OutcomeLedger` on propose — the OUTCOME is recorded
    later (by a real engagement firing / not firing the mapped oracle), and `pairs()` feeds calibration.

What it is NOT: it does not forecast undiscovered CVEs, prove any vuln exists, fire an oracle, mint a FACT,
or self-apply a change. "Studied everything in scope" means "drafted everything for the disclosed leads",
not "the system is complete". "Gets smarter" = better-calibrated priors + more PROPOSED coverage, never
self-applied canon. All clocks are injected (`now`/`seq`) so the planning + ledger math stay deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .deeplearn import _bug_class_of, _safe_id

_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
_MODEL_VERSION = "k5-evolve-1"


def _norm_sev(sev) -> str:
    return _SEV.get(str(sev or "").strip().lower(), "medium")


def ledger_path(slug: str) -> Path:
    """The owner-only, slug-scoped OutcomeLedger path (0700 dir via the ledger's own secure_write on save)."""
    from ..common import paths
    safe = "".join(c for c in str(slug or "default") if c.isalnum() or c in "-_.") or "default"
    return Path(paths.v2_root()) / ".calibration" / f"{safe}.ledger.json"


def feed_to_horizon_items(vuln_leads: list[dict], *, now: datetime) -> list:
    """Disclosed VULNERABILITY leads → `HorizonItem`s (a deterministic, disclosure-only horizon — NOT a
    forecast of undiscovered CVEs). ``published_at`` is the injected ``now``."""
    from ..improve.models import HorizonItem
    items = []
    for lead in vuln_leads:
        vid = str(lead.get("id") or "").strip()
        if not vid:
            continue
        items.append(HorizonItem(
            id=vid, source="vuln-intel", summary=str(lead.get("summary") or vid)[:500],
            bug_class=_bug_class_of(lead), affected_archetypes=[],
            severity=_norm_sev(lead.get("severity")), references=[vid], published_at=now))
    return items


def coverage_gaps(vuln_leads: list[dict], *, now: datetime) -> list:
    """Coverage-gap synthesis: a disclosed bug class the deterministic oracle substrate CANNOT adjudicate
    (`not is_known_bug_class`) → one COVERAGE_GAP. This is exactly the class for which K3's DETECT drafts a
    gated oracle proposal — surfaced here as a gap so the self-evolve loop proposes real coverage for it."""
    from ..improve.models import CapabilityGap, GapKind
    from ..verify.verifier import is_known_bug_class, normalize_bug_class

    by_class: dict[str, list[str]] = {}
    for lead in vuln_leads:
        bc = _bug_class_of(lead)
        if not bc or is_known_bug_class(bc):
            continue                                   # covered (or unclassifiable) → not an oracle gap
        key = normalize_bug_class(bc)
        by_class.setdefault(key, []).append(str(lead.get("id") or ""))
    gaps = []
    for bc in sorted(by_class):
        gaps.append(CapabilityGap(
            id=f"gap-coverage-{bc}", kind=GapKind.COVERAGE_GAP, priority=70,
            title=f"No deterministic oracle for bug class {bc!r}",
            description=(f"Disclosed lead(s) name bug class {bc!r}, which the oracle substrate cannot yet "
                         f"adjudicate. Propose a REAL deterministic oracle (never a soft/LLM oracle)."),
            source="knowledge-engine", bug_class=bc, surface="",
            evidence=sorted({v for v in by_class[bc] if v})[:20], discovered_at=now))
    return gaps


@dataclass
class EvolvePlan:
    horizon_gaps: list = field(default_factory=list)
    coverage_gaps: list = field(default_factory=list)
    proposals: list = field(default_factory=list)     # DRAFT ImprovementProposals (never merged/applied)
    unlearned: list = field(default_factory=list)     # disclosed leads missing find/detect/prevent skills
    studied_enough: dict = field(default_factory=dict)


def _is_learned(vuln_id: str, skills_dir: Path) -> bool:
    try:
        sid = _safe_id(vuln_id)
    except ValueError:
        return False
    return all((Path(skills_dir) / cat / f"{sid}.md").is_file() for cat in ("find", "detect", "prevent"))


def plan_evolution(vuln_leads: list[dict], *, skills_dir: Path, now: datetime, ledger=None) -> EvolvePlan:
    """Compute the current evolution plan — PURE / read-only (writes no skills, mutates no ledger).

    Horizon gaps (from disclosed leads) + coverage gaps → DRAFT proposals; plus which disclosed leads are
    not yet deep-learned, and the ``studied_enough`` completion signal (done = all leads learned + all gaps
    drafted + no open predictions). ``ledger`` (optional) supplies the open-prediction count.
    """
    from ..improve.horizon import ingest_horizon
    from ..improve.patcher import draft_proposals

    horizon = ingest_horizon(feed_to_horizon_items(vuln_leads, now=now), now=now)
    coverage = coverage_gaps(vuln_leads, now=now)
    all_gaps = horizon + coverage
    proposals = draft_proposals(all_gaps, now=now)      # one DRAFT proposal per gap; never merged/applied

    ids = [str(v.get("id") or "").strip() for v in vuln_leads if str(v.get("id") or "").strip()]
    unlearned = [vid for vid in ids if not _is_learned(vid, skills_dir)]
    open_predictions = 0
    if ledger is not None:
        open_predictions = max(0, len(ledger) - ledger.resolved_count)

    undrafted = [g.id for g in all_gaps if not any(p.gap_ids and g.id in p.gap_ids for p in proposals)]
    done = (not unlearned) and (not undrafted) and open_predictions == 0 and bool(ids)
    remaining = {"unlearned_leads": unlearned, "undrafted_gaps": undrafted,
                 "open_predictions": open_predictions}
    return EvolvePlan(horizon_gaps=horizon, coverage_gaps=coverage, proposals=proposals,
                      unlearned=unlearned,
                      studied_enough={"done": done, "remaining": remaining,
                                      "note": ("drafted everything for the disclosed leads in scope — NOT "
                                               "'the system is complete'")})


def record_predictions(plan: EvolvePlan, ledger, *, base_seq: int = 0) -> int:
    """Record one calibration Prediction per drafted proposal (idempotent by finding_id). A prediction is a
    FORECAST that the proposed coverage will matter; ``oracle_confirmed=False`` — the OUTCOME is recorded
    later by a real engagement (firing / not firing the mapped oracle), never fabricated here. The
    ``raw_score`` is the underlying gap's priority ∈ [0,1]. Returns the number of new predictions added.
    Deterministic: seq = ``base_seq + index`` over id-sorted proposals."""
    from ..calibration.ledger import LedgerError
    from ..calibration.models import Prediction

    prio = {g.id: g.priority for g in (plan.horizon_gaps + plan.coverage_gaps)}
    existing = {p.finding_id for p in ledger.predictions()}
    added = 0
    for i, prop in enumerate(sorted(plan.proposals, key=lambda p: p.id)):
        fid = prop.id
        if fid in existing:
            continue
        gp = next((prio[gid] for gid in (prop.gap_ids or []) if gid in prio), 60)
        score = max(0.0, min(1.0, float(gp) / 100.0))    # gap priority → the [0,1] prediction prior
        feat = hashlib.sha256(f"{fid}|{prop.title}".encode()).hexdigest()[:16]
        try:
            ledger.add_prediction(Prediction(finding_id=fid, raw_score=score, feature_hash=feat,
                                             model_version=_MODEL_VERSION, oracle_confirmed=False),
                                  seq=base_seq + i)
            added += 1
        except LedgerError:
            continue                                     # duplicate/late race — append-only, skip
    return added
