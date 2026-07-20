"""
memory.recorder — write-only API.

Every other subsystem records through this module. Direct INSERTs
elsewhere defeat the audit invariant. Future agents (MAO, ACP) hook
into recorder.* on every blackboard event.

All functions are idempotent where the DB schema permits — replaying
the same event yields the same row.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from ..common import logging as v2log
from . import embed
from .store import Store


_log = v2log.get_logger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# engagements
# ---------------------------------------------------------------------------


def record_engagement_start(
    store: Store,
    *,
    slug: str,
    target_url: str = "",
    archetype: str = "",
    fingerprint: dict[str, Any] | None = None,
    business_context: str = "",
    posture: str = "TEST",
    started_at: str | None = None,
) -> int:
    fp_json = json.dumps(fingerprint or {}, default=str)
    text_for_embed = " ".join(
        x for x in (slug, target_url, archetype, business_context, fp_json) if x
    )
    emb = embed.get_embedder().embed_blob(text_for_embed)
    started = started_at or _now()

    cur = store.execute(
        """
        INSERT INTO engagements
          (slug, target_url, archetype, fingerprint_json, business_context,
           started_at, posture, embedding)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO UPDATE SET
            target_url       = excluded.target_url,
            archetype        = COALESCE(NULLIF(excluded.archetype, ''), engagements.archetype),
            fingerprint_json = COALESCE(NULLIF(excluded.fingerprint_json, '{}'), engagements.fingerprint_json),
            business_context = COALESCE(NULLIF(excluded.business_context, ''), engagements.business_context),
            posture          = excluded.posture,
            embedding        = excluded.embedding
        """,
        (slug, target_url, archetype, fp_json, business_context,
         started, posture, emb),
    )
    store.commit()
    eid = store.engagement_id(slug)
    _log.info("memory.engagement.started", slug=slug, id=eid, archetype=archetype)
    return eid


def record_engagement_end(store: Store, slug: str) -> None:
    store.execute(
        "UPDATE engagements SET ended_at=? WHERE slug=?",
        (_now(), slug),
    )
    store.commit()


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


def record_finding(
    store: Store,
    slug: str,                       # engagement slug
    *,
    finding_slug: str,
    title: str,
    severity: str,
    cvss_vector: str = "",
    cvss_base: float | None = None,
    bug_class: str = "",
    surface: str = "",
    summary: str = "",
    impact: str = "",
    discovered_at: str | None = None,
) -> int:
    eid = store.engagement_id(slug)
    text_for_embed = " ".join(
        x for x in (title, summary, impact, bug_class, surface) if x
    )
    emb = embed.get_embedder().embed_blob(text_for_embed)
    when = discovered_at or _now()

    cur = store.execute(
        """
        INSERT INTO findings
          (engagement_id, slug, title, severity, cvss_vector, cvss_base,
           bug_class, surface, summary, impact, embedding, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (eid, finding_slug, title, severity, cvss_vector, cvss_base,
         bug_class, surface, summary, impact, emb, when),
    )
    store.commit()
    fid = int(cur.lastrowid or 0)
    _log.info(
        "memory.finding.recorded",
        slug=finding_slug, severity=severity, bug_class=bug_class, id=fid,
    )
    return fid


# ---------------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------------


def record_hypothesis(
    store: Store,
    slug: str,
    *,
    handle: str,
    bug_class: str = "",
    surface: str = "",
    given: str = "",
    if_text: str = "",
    then_text: str = "",
    because: str = "",
    refute_on: str = "",
    cheap_test: str = "",
    status: str = "open",
    confidence: float | None = None,
    created_at: str | None = None,
) -> int:
    eid = store.engagement_id(slug)
    text_for_embed = " ".join(
        x for x in (bug_class, surface, given, if_text, then_text, because) if x
    )
    emb = embed.get_embedder().embed_blob(text_for_embed)
    when = created_at or _now()

    cur = store.execute(
        """
        INSERT INTO hypotheses
          (engagement_id, handle, bug_class, surface, given_text, if_text,
           then_text, because_text, refute_on, cheap_test, status, confidence,
           embedding, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(engagement_id, handle) DO UPDATE SET
            status     = excluded.status,
            confidence = excluded.confidence,
            embedding  = excluded.embedding
        """,
        (eid, handle, bug_class, surface, given, if_text, then_text,
         because, refute_on, cheap_test, status, confidence, emb, when),
    )
    store.commit()
    return int(cur.lastrowid or 0)


def update_hypothesis_status(
    store: Store,
    slug: str,
    handle: str,
    *,
    status: str,
    closed_at: str | None = None,
) -> None:
    eid = store.engagement_id(slug)
    closed = closed_at or _now() if status in ("confirmed", "refuted", "deferred") else None
    store.execute(
        "UPDATE hypotheses SET status=?, closed_at=? "
        "WHERE engagement_id=? AND handle=?",
        (status, closed, eid, handle),
    )
    store.commit()


# ---------------------------------------------------------------------------
# payloads
# ---------------------------------------------------------------------------


def record_payload(
    store: Store,
    slug: str | None,
    *,
    bug_class: str,
    payload_text: str,
    target_surface: str = "",
    archetype: str = "",
    outcome: str = "unknown",
    notes: str = "",
    used_at: str | None = None,
) -> int:
    eid: int | None
    if slug:
        eid = store.engagement_id(slug)
        # if archetype unspecified, fill from engagement
        if not archetype:
            row = store.fetchone(
                "SELECT archetype FROM engagements WHERE id=?", (eid,)
            )
            if row and row["archetype"]:
                archetype = row["archetype"]
    else:
        eid = None

    cur = store.execute(
        """
        INSERT INTO payloads
          (engagement_id, bug_class, payload_text, target_surface,
           archetype, outcome, notes, used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (eid, bug_class, payload_text, target_surface, archetype,
         outcome, notes, used_at or _now()),
    )
    store.commit()
    return int(cur.lastrowid or 0)


# ---------------------------------------------------------------------------
# dead ends
# ---------------------------------------------------------------------------


def record_dead_end(
    store: Store,
    slug: str | None,
    *,
    technique: str,
    archetype: str = "",
    surface: str = "",
    reason: str = "",
    recorded_at: str | None = None,
) -> int:
    eid = store.engagement_id(slug) if slug else None
    if slug and not archetype:
        row = store.fetchone(
            "SELECT archetype FROM engagements WHERE id=?", (eid,)
        )
        if row and row["archetype"]:
            archetype = row["archetype"]

    text = " ".join(x for x in (technique, surface, reason) if x)
    emb = embed.get_embedder().embed_blob(text)

    cur = store.execute(
        """
        INSERT INTO dead_ends
          (engagement_id, archetype, technique, surface, reason,
           embedding, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (eid, archetype, technique, surface, reason, emb,
         recorded_at or _now()),
    )
    store.commit()
    return int(cur.lastrowid or 0)


# ---------------------------------------------------------------------------
# playbook outcomes
# ---------------------------------------------------------------------------


def record_playbook_outcome(
    store: Store,
    slug: str,
    *,
    playbook_id: str,
    section: str = "",
    findings_yielded: int = 0,
    time_spent_minutes: int = 0,
    notes: str = "",
) -> int:
    eid = store.engagement_id(slug)
    row = store.fetchone(
        "SELECT archetype FROM engagements WHERE id=?", (eid,)
    )
    archetype = row["archetype"] if row else ""

    cur = store.execute(
        """
        INSERT INTO playbook_outcomes
          (playbook_id, section, engagement_id, archetype,
           findings_yielded, time_spent_minutes, notes, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (playbook_id, section, eid, archetype, findings_yielded,
         time_spent_minutes, notes, _now()),
    )
    store.commit()
    return int(cur.lastrowid or 0)
