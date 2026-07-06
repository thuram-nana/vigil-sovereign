"""
intel.store — the durable read/write API over the intel tables (schema v2).

A thin repository over a `memory.Store` sqlite connection. It preserves the full
JSON of every Observation and Entity so a run round-trips exactly, and keeps
flat, indexed columns for the queries the CLI, console, and planner need
("what cluster is this node in", "what did CT yield against this archetype").

Writes go through `IntelIngest` (the single writer). This module is the mechanism;
`IntelIngest` is the policy. Reads are open to the whole system.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..memory.store import Store
from .models import Observation
from .resolve import Entity, MergeEvent


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntelStore:
    """Repository over the intel_* tables. Construct from a `memory.Store`."""

    def __init__(self, store: Store) -> None:
        self._s = store

    # -- observations ---------------------------------------------------------

    def record_observation(self, obs: Observation, *, engagement_slug: str = "") -> None:
        rel = obs.relation.value if obs.relation else None
        obj = obs.object.node_id if obs.object else None
        ck = "|".join(obs.claim_key)
        self._s.execute(
            """INSERT INTO intel_observations
               (obs_id, engagement_slug, source, source_kind, collector, subject_node_id,
                relation, object_node_id, claim_key, polarity, confidence, reliability,
                seq, observed_at, obs_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(obs_id) DO UPDATE SET
                 confidence=excluded.confidence, reliability=excluded.reliability,
                 seq=excluded.seq, obs_json=excluded.obs_json""",
            (obs.obs_id, engagement_slug, obs.source, obs.source_kind.value, obs.collector,
             obs.subject.node_id, rel, obj, ck, obs.polarity.value, obs.confidence,
             obs.reliability(), obs.seq, obs.observed_at, obs.model_dump_json()),
        )

    def observations(self, *, engagement_slug: str | None = None,
                     source_kind: str | None = None,
                     subject_node_id: str | None = None) -> list[Observation]:
        sql = "SELECT obs_json FROM intel_observations WHERE 1=1"
        params: list[object] = []
        if engagement_slug is not None:
            sql += " AND engagement_slug=?"; params.append(engagement_slug)
        if source_kind is not None:
            sql += " AND source_kind=?"; params.append(source_kind)
        if subject_node_id is not None:
            sql += " AND subject_node_id=?"; params.append(subject_node_id)
        sql += " ORDER BY seq, obs_id"
        return [Observation.model_validate_json(r["obs_json"]) for r in self._s.fetchall(sql, params)]

    def observation_count(self, *, engagement_slug: str | None = None) -> int:
        if engagement_slug is None:
            row = self._s.fetchone("SELECT COUNT(*) AS n FROM intel_observations")
        else:
            row = self._s.fetchone(
                "SELECT COUNT(*) AS n FROM intel_observations WHERE engagement_slug=?",
                (engagement_slug,))
        return int(row["n"]) if row else 0

    # -- entities -------------------------------------------------------------

    def upsert_entity(self, ent: Entity, *, engagement_slug: str = "", seq: int = 0) -> None:
        self._s.execute(
            """INSERT INTO intel_entities
               (canonical_id, engagement_slug, tier, primary_kind, confidence,
                member_count, owned_by, seq, entity_json)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(engagement_slug, canonical_id) DO UPDATE SET
                 confidence=excluded.confidence, member_count=excluded.member_count,
                 owned_by=excluded.owned_by, seq=excluded.seq, entity_json=excluded.entity_json""",
            (ent.canonical_id, engagement_slug, ent.tier, ent.primary_kind.value,
             ent.confidence, len(ent.members), ",".join(ent.owned_by), seq, ent.model_dump_json()),
        )
        # refresh flattened membership + merge log for this cluster
        self._s.execute(
            "DELETE FROM intel_entity_members WHERE engagement_slug=? AND canonical_id=?",
            (engagement_slug, ent.canonical_id))
        for m in ent.members:
            self._s.execute(
                """INSERT OR REPLACE INTO intel_entity_members
                   (engagement_slug, canonical_id, member_node_id, member_kind, seq)
                   VALUES (?,?,?,?,?)""",
                (engagement_slug, ent.canonical_id, m.node_id, m.kind.value, seq))
        for ev in ent.merge_log:
            self._record_merge(ev, canonical_id=ent.canonical_id, engagement_slug=engagement_slug)

    def _record_merge(self, ev: MergeEvent, *, canonical_id: str, engagement_slug: str) -> None:
        self._s.execute(
            """INSERT INTO intel_merge_log
               (event_id, engagement_slug, canonical_id, a_node_id, b_node_id,
                trigger, total_llr_bits, probability, seq)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(engagement_slug, event_id) DO UPDATE SET
                 canonical_id=excluded.canonical_id, total_llr_bits=excluded.total_llr_bits,
                 probability=excluded.probability""",
            (ev.event_id, engagement_slug, canonical_id, ev.a.node_id, ev.b.node_id,
             ev.trigger.value, ev.total_llr_bits, ev.probability, ev.seq),
        )

    def entities(self, *, engagement_slug: str = "") -> list[Entity]:
        rows = self._s.fetchall(
            "SELECT entity_json FROM intel_entities WHERE engagement_slug=? "
            "ORDER BY confidence DESC, canonical_id", (engagement_slug,))
        return [Entity.model_validate_json(r["entity_json"]) for r in rows]

    def entity_for_node(self, node_id: str, *, engagement_slug: str = "") -> str | None:
        row = self._s.fetchone(
            "SELECT canonical_id FROM intel_entity_members "
            "WHERE engagement_slug=? AND member_node_id=?", (engagement_slug, node_id))
        return row["canonical_id"] if row else None

    # -- source-yield learning (Phase D) --------------------------------------

    def bump_source_yield(self, source_kind: str, *, archetype: str = "",
                          queries: int = 0, observations: int = 0,
                          entities: int = 0, findings: int = 0) -> None:
        self._s.execute(
            """INSERT INTO intel_source_yield
                 (source_kind, archetype, queries, observations_yielded,
                  entities_yielded, findings_downstream, last_updated)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(source_kind, archetype) DO UPDATE SET
                 queries = queries + excluded.queries,
                 observations_yielded = observations_yielded + excluded.observations_yielded,
                 entities_yielded = entities_yielded + excluded.entities_yielded,
                 findings_downstream = findings_downstream + excluded.findings_downstream,
                 last_updated = excluded.last_updated""",
            (source_kind, archetype, queries, observations, entities, findings, _now()),
        )

    def source_yield(self, source_kind: str, *, archetype: str = "") -> dict[str, int]:
        row = self._s.fetchone(
            "SELECT queries, observations_yielded, entities_yielded, findings_downstream "
            "FROM intel_source_yield WHERE source_kind=? AND archetype=?",
            (source_kind, archetype))
        if row is None:
            return {"queries": 0, "observations_yielded": 0, "entities_yielded": 0,
                    "findings_downstream": 0}
        return dict(row)

    def all_source_yield(self) -> list[dict]:
        rows = self._s.fetchall(
            "SELECT source_kind, archetype, queries, observations_yielded, "
            "entities_yielded, findings_downstream, last_updated "
            "FROM intel_source_yield ORDER BY source_kind, archetype")
        return [dict(r) for r in rows]

    def commit(self) -> None:
        self._s.commit()
