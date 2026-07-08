"""
memory.recall — read-only query API for MLS.

Per FORGE PROTOCOL § 3.2: every recall result carries the engagement
IDs and finding IDs it was derived from. Hallucinated priors are a
fatal bug. The functions here only return data that is in the DB.

Similarity search uses cosine over the embeddings stored alongside
each row. For the small-scale workloads this framework targets
(hundreds of engagements), an in-process scan is sufficient and
simpler than a vector DB.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import embed
from .store import Store


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Provenance:
    """Where this recall result came from."""

    table: str
    row_id: int
    engagement_id: int | None
    engagement_slug: str | None


@dataclass
class SimilarTarget:
    score: float
    provenance: Provenance
    slug: str
    target_url: str
    archetype: str
    fingerprint: dict[str, Any]


@dataclass
class WinningHypothesis:
    score: float
    provenance: Provenance
    handle: str
    bug_class: str
    surface: str
    summary: str
    archetype: str
    # How ``score`` was derived, so a consumer never mistakes a placeholder for a measured
    # similarity: "cosine" = a real query-similarity score; "unranked" = no text query was
    # given, so rows are in recency order and ``score`` is a constant 1.0 placeholder, NOT a
    # similarity. Default "cosine" preserves the scored path's meaning.
    score_kind: str = "cosine"


@dataclass
class PayloadPrior:
    score: float                      # success rate within the matched archetype/class
    provenance: Provenance
    bug_class: str
    payload_text: str
    target_surface: str
    archetype: str
    outcome_count: int
    success_count: int


@dataclass
class DeadEndPrior:
    provenance: Provenance
    archetype: str
    technique: str
    surface: str
    reason: str


@dataclass
class PlaybookYield:
    playbook_id: str
    archetype: str
    finding_rate: float                # findings / engagement that ran it
    sample_size: int
    sources: list[Provenance] = field(default_factory=list)


# ---------------------------------------------------------------------------
# similar_targets
# ---------------------------------------------------------------------------


def similar_targets(
    store: Store,
    *,
    fingerprint: dict[str, Any] | None = None,
    text: str = "",
    limit: int = 5,
) -> list[SimilarTarget]:
    """Rank past engagements by cosine similarity to the query embedding."""
    if not text:
        text = json.dumps(fingerprint or {}, default=str)
    if not text.strip():
        return []
    q_vec = embed.get_embedder().embed(text)

    rows = store.fetchall(
        "SELECT id, slug, target_url, archetype, fingerprint_json, embedding "
        "FROM engagements WHERE embedding IS NOT NULL"
    )
    scored: list[SimilarTarget] = []
    for r in rows:
        v = embed.blob_to_vec(r["embedding"])
        score = embed.cosine(q_vec, v)
        if score <= 0.0:
            continue
        try:
            fp = json.loads(r["fingerprint_json"]) if r["fingerprint_json"] else {}
        except json.JSONDecodeError:
            fp = {}
        scored.append(SimilarTarget(
            score=score,
            provenance=Provenance(
                table="engagements", row_id=int(r["id"]),
                engagement_id=int(r["id"]), engagement_slug=r["slug"],
            ),
            slug=r["slug"],
            target_url=r["target_url"] or "",
            archetype=r["archetype"] or "",
            fingerprint=fp,
        ))
    scored.sort(key=lambda x: x.score, reverse=True)
    return scored[:limit]


# ---------------------------------------------------------------------------
# winning_hypotheses
# ---------------------------------------------------------------------------


def winning_hypotheses(
    store: Store,
    *,
    archetype: str = "",
    bug_class: str = "",
    text: str = "",
    limit: int = 10,
) -> list[WinningHypothesis]:
    """Confirmed hypotheses, ranked by similarity to query (or by recency)."""

    sql = (
        "SELECT h.id, h.handle, h.bug_class, h.surface, h.given_text, "
        "       h.if_text, h.then_text, h.because_text, h.embedding, "
        "       e.id AS eid, e.slug AS eslug, e.archetype AS earchetype "
        "FROM hypotheses h JOIN engagements e ON h.engagement_id = e.id "
        "WHERE h.status = 'confirmed' "
    )
    params: list[object] = []
    if archetype:
        sql += "AND e.archetype = ? "
        params.append(archetype)
    if bug_class:
        sql += "AND h.bug_class = ? "
        params.append(bug_class)

    rows = store.fetchall(sql, params)

    if text.strip():
        q_vec = embed.get_embedder().embed(text)
        scored = []
        for r in rows:
            v = embed.blob_to_vec(r["embedding"]) if r["embedding"] else []
            score = embed.cosine(q_vec, v) if v else 0.0
            scored.append((score, r))
        scored.sort(key=lambda t: t[0], reverse=True)
        rows = [r for _, r in scored[:limit]]
        scores = [s for s, _ in scored[:limit]]
        score_kind = "cosine"
    else:
        # no text query → recency order; the 1.0 is a placeholder, NOT a similarity score.
        scores = [1.0] * min(limit, len(rows))
        rows = rows[:limit]
        score_kind = "unranked"

    out: list[WinningHypothesis] = []
    for r, score in zip(rows, scores):
        summary = (
            f"GIVEN {r['given_text'] or '?'} | IF {r['if_text'] or '?'} "
            f"| THEN {r['then_text'] or '?'} | BECAUSE {r['because_text'] or '?'}"
        )
        out.append(WinningHypothesis(
            score=score,
            score_kind=score_kind,
            provenance=Provenance(
                table="hypotheses", row_id=int(r["id"]),
                engagement_id=int(r["eid"]), engagement_slug=r["eslug"],
            ),
            handle=r["handle"],
            bug_class=r["bug_class"] or "",
            surface=r["surface"] or "",
            summary=summary,
            archetype=r["earchetype"] or "",
        ))
    return out


# ---------------------------------------------------------------------------
# payload_priors
# ---------------------------------------------------------------------------


def payload_priors(
    store: Store,
    *,
    bug_class: str,
    archetype: str = "",
    limit: int = 10,
) -> list[PayloadPrior]:
    """Rank payloads for a (bug_class, archetype) pair by success-rate."""
    sql = (
        "SELECT id, archetype, target_surface, payload_text, outcome, engagement_id "
        "FROM payloads WHERE bug_class = ? "
    )
    params: list[object] = [bug_class]
    if archetype:
        sql += "AND archetype = ? "
        params.append(archetype)

    rows = store.fetchall(sql, params)

    # Group by payload_text (canonical) and aggregate.
    agg: dict[str, dict[str, Any]] = {}
    for r in rows:
        key = r["payload_text"]
        a = agg.setdefault(key, {
            "id": int(r["id"]),
            "archetype": r["archetype"] or "",
            "surface": r["target_surface"] or "",
            "engagement_id": r["engagement_id"],
            "successes": 0, "total": 0,
        })
        a["total"] += 1
        if r["outcome"] == "success":
            a["successes"] += 1

    out: list[PayloadPrior] = []
    for payload_text, a in agg.items():
        rate = (a["successes"] + 1) / (a["total"] + 2)  # Laplace
        out.append(PayloadPrior(
            score=rate,
            provenance=Provenance(
                table="payloads", row_id=a["id"],
                engagement_id=a["engagement_id"], engagement_slug=None,
            ),
            bug_class=bug_class,
            payload_text=payload_text,
            target_surface=a["surface"],
            archetype=a["archetype"],
            outcome_count=a["total"],
            success_count=a["successes"],
        ))
    out.sort(key=lambda x: (x.score, x.success_count), reverse=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# dead_end_priors
# ---------------------------------------------------------------------------


def dead_end_priors(
    store: Store,
    *,
    archetype: str = "",
    technique: str = "",
    text: str = "",
    limit: int = 10,
) -> list[DeadEndPrior]:
    """Past dead ends. If text given, rank by similarity; else by recency."""
    sql = "SELECT id, archetype, technique, surface, reason, embedding, engagement_id FROM dead_ends WHERE 1=1 "
    params: list[object] = []
    if archetype:
        sql += "AND archetype = ? "
        params.append(archetype)
    if technique:
        sql += "AND technique = ? "
        params.append(technique)

    rows = store.fetchall(sql + "ORDER BY recorded_at DESC", params)

    if text.strip():
        q_vec = embed.get_embedder().embed(text)
        scored = []
        for r in rows:
            v = embed.blob_to_vec(r["embedding"]) if r["embedding"] else []
            score = embed.cosine(q_vec, v) if v else 0.0
            scored.append((score, r))
        scored.sort(key=lambda t: t[0], reverse=True)
        rows = [r for _, r in scored[:limit]]
    else:
        rows = rows[:limit]

    return [
        DeadEndPrior(
            provenance=Provenance(
                table="dead_ends", row_id=int(r["id"]),
                engagement_id=r["engagement_id"], engagement_slug=None,
            ),
            archetype=r["archetype"] or "",
            technique=r["technique"],
            surface=r["surface"] or "",
            reason=r["reason"] or "",
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# playbook_yield
# ---------------------------------------------------------------------------


def playbook_yield(
    store: Store,
    *,
    playbook_id: str = "",
    archetype: str = "",
    limit: int = 20,
) -> list[PlaybookYield]:
    """Average findings yielded per engagement, grouped by playbook x archetype."""
    sql = (
        "SELECT playbook_id, archetype, "
        "       SUM(findings_yielded) AS total_yield, "
        "       COUNT(DISTINCT engagement_id) AS engagement_count "
        "FROM playbook_outcomes WHERE 1=1 "
    )
    params: list[object] = []
    if playbook_id:
        sql += "AND playbook_id = ? "
        params.append(playbook_id)
    if archetype:
        sql += "AND archetype = ? "
        params.append(archetype)
    sql += "GROUP BY playbook_id, archetype "
    sql += "ORDER BY total_yield DESC LIMIT ?"
    params.append(limit)

    rows = store.fetchall(sql, params)
    return [
        PlaybookYield(
            playbook_id=r["playbook_id"],
            archetype=r["archetype"] or "",
            finding_rate=(r["total_yield"] or 0) / (r["engagement_count"] or 1),
            sample_size=r["engagement_count"] or 0,
        )
        for r in rows
    ]
