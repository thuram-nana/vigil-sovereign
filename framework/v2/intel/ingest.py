"""
intel.ingest — IntelIngest, the SINGLE WRITER.

Everything that mutates intel state flows through here, in one fixed order:

    observations ──▶ (1) durable log  ──▶ (2) project onto the world-model
                                        ──▶ (3) resolve entities
                                        ──▶ (4) persist entities + merge audit

Concentrating writes in one place is what keeps the substrate coherent: the
durable log, the in-memory belief graph, and the resolved entity set never
disagree about what was observed, because they are all derived from the same
batch in the same call. Projection is idempotent (Beta update is commutative) and
so is the store (upserts keyed by obs_id / canonical_id), so re-ingesting a batch
is safe — a crashed run resumes by replaying its observations.

`run_collectors` is the recon convenience: fetch a subject through a roster of
collectors (offline via a FixtureTransport, or gated-live via a
GuardedHttpTransport) and ingest whatever they return, discovering new subjects
along the way up to a bounded depth.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..worldmodel.graph import WorldModel
from .collectors.base import Collector
from .models import IntelSourceKind, Observation
from .project import project_observation
from .refs import EntityRef
from .resolve import Entity, ResolveResult, resolve
from .store import IntelStore
from .transport import Transport


class IngestResult(BaseModel):
    """What one ingest produced. ``applied`` observations changed belief; ``dropped``
    were reliability-0 (unknown stays unknown). ``entities`` is the freshly resolved
    clustering over everything ingested so far in this call."""

    model_config = ConfigDict(extra="forbid")

    applied: int = 0
    dropped: int = 0
    persisted: int = 0
    entities: list[Entity] = Field(default_factory=list)
    new_subjects: list[EntityRef] = Field(default_factory=list)
    per_source: dict[str, int] = Field(default_factory=dict)          # observations per source_kind
    queries_per_source: dict[str, int] = Field(default_factory=dict)  # collector invocations per source_kind
    entities_per_source: dict[str, int] = Field(default_factory=dict)  # distinct entities each source helped resolve


class IntelIngest:
    """The one object allowed to write intel state. Holds the world-model it
    projects onto; optionally holds an `IntelStore` for durability. Stateless
    across calls except for the accumulating world-model and observation set."""

    def __init__(
        self,
        world: WorldModel,
        *,
        store: IntelStore | None = None,
        engagement_slug: str = "",
    ) -> None:
        self.world = world
        self.store = store
        self.engagement_slug = engagement_slug
        self._observations: list[Observation] = []   # everything seen this session (for resolve)
        self._seen_obs_ids: set[str] = set()          # dedup: obs_ids are deterministic
        self._max_seq: int = 0                        # high-water mark on the monotonic clock

    def high_water(self) -> int:
        """The highest seq this ingest has projected. A downstream consumer sharing the
        world-model (e.g. finding projection) starts at ``high_water() + 1`` so the
        monotonic clock never inverts across the recon→scan handoff."""
        return self._max_seq

    # -- the core seam --------------------------------------------------------

    def ingest(self, observations: list[Observation], *, seq: int | None = None) -> IngestResult:
        """Persist → project → resolve → persist entities. Returns an IngestResult.

        ``seq`` overrides each observation's own seq when supplied (a batch stamped
        at one logical time); otherwise each observation carries its own."""
        applied = dropped = persisted = 0
        per_source: dict[str, int] = {}
        for obs in observations:
            if obs.obs_id in self._seen_obs_ids:
                continue   # re-ingesting the same observation is a no-op (idempotent):
                           # do NOT re-project (would falsely corroborate) or re-accumulate
                           # (would double-count SAME_AS/ANNOUNCES signals in resolve).
            self._seen_obs_ids.add(obs.obs_id)
            s = seq if seq is not None else obs.seq
            self._max_seq = max(self._max_seq, s)
            if self.store is not None:
                self.store.record_observation(obs, engagement_slug=self.engagement_slug)
                persisted += 1
            if project_observation(self.world, obs, seq=s):
                applied += 1
                per_source[obs.source_kind.value] = per_source.get(obs.source_kind.value, 0) + 1
            else:
                dropped += 1
            self._observations.append(obs)

        rr = self.resolve(seq=seq or 0)
        if self.store is not None:
            # sync the FULL current clustering (GC superseded canonical_ids) — resolve()
            # recomputes over all observations, so entities can merge across ingests.
            self.store.sync_entities(rr.entities, engagement_slug=self.engagement_slug, seq=seq or 0)
            self.store.commit()

        new_subjects = self._discover_subjects(observations)
        return IngestResult(applied=applied, dropped=dropped, persisted=persisted,
                            entities=rr.entities, new_subjects=new_subjects, per_source=per_source)

    def resolve(self, *, seq: int = 0) -> ResolveResult:
        """Re-run entity resolution over every observation ingested so far. Pure over
        the accumulated set — the resolver is order-independent and idempotent."""
        return resolve(self._observations, seq=seq)

    # -- recon convenience ----------------------------------------------------

    def run_collectors(
        self,
        seeds: list[EntityRef],
        collectors: list[Collector],
        transport: Transport,
        *,
        seq: int = 0,
        max_depth: int = 1,
        planner: "object | None" = None,
        priors: dict[str, float] | None = None,
    ) -> IngestResult:
        """Fetch ``seeds`` through ``collectors`` and ingest the results, following
        newly discovered subjects up to ``max_depth`` hops. Deterministic: subjects
        are processed in sorted order; ``seq`` advances per collector call so
        provenance is ordered. Bounded — never an unbounded crawl.

        When a ``planner`` (a ReconPlanner) is supplied, the collectors for each subject
        are run in the planner's VALUE-OF-INFORMATION order (highest expected information
        gain per cost first, using ``priors`` from source-yield learning), and completed
        (subject, collector) pairs are fed back as ``already_run`` so an exhausted source
        is damped. Without a planner the order is the roster order (still deterministic)."""
        seen: set[str] = set()
        already_run: set[tuple[str, str]] = set()
        frontier: list[tuple[int, EntityRef]] = [(0, s) for s in seeds]
        agg = IngestResult()
        queries: dict[str, int] = {}
        cur_seq = seq
        while frontier:
            # sort BEFORE popping so the very first subject (and every subject) is chosen
            # in deterministic (depth, node_id) order — provenance seqs then don't depend
            # on seed input order.
            frontier.sort(key=lambda t: (t[0], t[1].node_id))
            depth, subject = frontier.pop(0)
            if subject.node_id in seen or depth > max_depth:
                continue
            seen.add(subject.node_id)
            cols = [c for c in collectors if c.accepts(subject)]
            if planner is not None:
                # order this subject's collectors by value-of-information (desc)
                plan = planner.plan([subject], priors=priors, already_run=already_run)
                rank = {t.collector: t.eig_per_cost for t in plan.tasks}
                cols.sort(key=lambda c: (-rank.get(c.name, 0.0), c.name))
            batch: list[Observation] = []
            for c in cols:
                cur_seq += 1
                queries[c.source_kind.value] = queries.get(c.source_kind.value, 0) + 1
                batch.extend(c.collect(subject, transport, seq=cur_seq))
                already_run.add((subject.node_id, c.name))
            res = self.ingest(batch, seq=None)
            agg = _merge_results(agg, res)
            for ns in res.new_subjects:
                if ns.node_id not in seen:
                    frontier.append((depth + 1, ns))
        agg.entities = self.resolve(seq=cur_seq).entities
        agg.queries_per_source = queries
        agg.entities_per_source = self._attribute_entities(agg.entities)
        return agg

    def _attribute_entities(self, entities: list[Entity]) -> dict[str, int]:
        """Distinct entities each source helped resolve: a source is credited for an
        entity if any of the entity's members was observed by that source. The
        coverage signal for source-yield learning."""
        node_sources: dict[str, set[str]] = {}
        for o in self._observations:
            for ref in (o.subject, o.object):
                if ref is not None:
                    node_sources.setdefault(ref.node_id, set()).add(o.source_kind.value)
        counts: dict[str, int] = {}
        for ent in entities:
            srcs: set[str] = set()
            for m in ent.members:
                srcs |= node_sources.get(m.node_id, set())
            for s in srcs:
                counts[s] = counts.get(s, 0) + 1
        return counts

    # -- helpers --------------------------------------------------------------

    def _discover_subjects(self, observations: list[Observation]) -> list[EntityRef]:
        """New asset-tier subjects worth collecting on next (domains/hosts learned
        this batch) — deterministic, de-duplicated, owner-tier excluded."""
        out: dict[str, EntityRef] = {}
        for obs in observations:
            for ref in (obs.subject, obs.object):
                if ref is not None and ref.is_asset_tier and ref.kind.value in ("domain", "host"):
                    out[ref.node_id] = ref
        return [out[k] for k in sorted(out)]


def _merge_results(a: IngestResult, b: IngestResult) -> IngestResult:
    per = dict(a.per_source)
    for k, v in b.per_source.items():
        per[k] = per.get(k, 0) + v
    subj = {r.node_id: r for r in (a.new_subjects + b.new_subjects)}
    return IngestResult(
        applied=a.applied + b.applied, dropped=a.dropped + b.dropped,
        persisted=a.persisted + b.persisted, entities=b.entities or a.entities,
        new_subjects=[subj[k] for k in sorted(subj)], per_source=per)
