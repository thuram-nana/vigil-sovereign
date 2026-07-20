"""
intel.temporal — attack surface across time, with disappearance honesty.

Recon is not a snapshot; the surface moves. This module indexes Observations by
the world-model's monotonic ``seq`` and answers two questions:

  * **What changed between two points in time?** `TemporalIndex.delta(a, b)` →
    a `SurfaceDelta` of what APPEARED, what PERSISTED, what is STALE (present
    before, simply not re-checked), and what genuinely DISAPPEARED.

  * **When did we learn about X?** `timeline(node_id)` → the ordered record of
    first-seen / re-affirmation / refutation for one asset.

The load-bearing honesty rule is about DISAPPEARANCE. An asset is only reported
as disappeared when an ENUMERATIVE source — one whose query returns a COMPLETE
list (Certificate Transparency: every logged cert for an apex) — was RE-RUN over
the scope that contains the asset and did not list it. A point-query source's
silence (we simply didn't ask DNS again) is never evidence of absence: those
assets fall into STALE ("we don't currently know"), not DISAPPEARED. Claiming an
asset is gone because we stopped looking would be exactly the kind of guessing
this system refuses to do.
"""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field

from .models import IntelSourceKind, Observation

# The sources whose queries return a COMPLETE list, so an omission is meaningful.
# CT logs are append-only and enumerate every cert ever logged under an apex.
ENUMERATIVE_SOURCE_KINDS: frozenset[IntelSourceKind] = frozenset({
    IntelSourceKind.CERT_TRANSPARENCY,
})


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seq: int
    kind: str            # first_seen / reaffirmed / refuted
    source: str
    source_kind: IntelSourceKind
    truth_confidence: float


class SurfaceDelta(BaseModel):
    """What changed in the attack surface between two seqs. ``disappeared`` is only
    ever populated by an enumerative re-check; ``stale`` holds assets we last saw
    earlier but have NOT re-verified (honestly 'unknown', not 'gone')."""

    model_config = ConfigDict(extra="forbid")

    from_seq: int
    to_seq: int
    appeared: list[str] = Field(default_factory=list)
    persisted: list[str] = Field(default_factory=list)
    disappeared: list[str] = Field(default_factory=list)
    stale: list[str] = Field(default_factory=list)
    note: str = ""


class TemporalIndex:
    """Append-only index of Observations over ``seq``. Pure/read-only queries."""

    def __init__(self) -> None:
        self._obs: list[Observation] = []

    def record(self, obs: Observation) -> None:
        self._obs.append(obs)

    def extend(self, observations: list[Observation]) -> None:
        self._obs.extend(observations)

    @classmethod
    def from_observations(cls, observations: list[Observation]) -> "TemporalIndex":
        idx = cls()
        idx.extend(observations)
        return idx

    # -- presence -------------------------------------------------------------

    def _node_claims(self):
        """Node-claim observations (an asset EXISTS), sorted by seq — these carry
        the truth about presence; edge claims carry relationships."""
        return sorted((o for o in self._obs if o.relation is None),
                      key=lambda o: (o.seq, o.obs_id))

    def _latest_node_claim_truth(self, node_id: str, seq: int) -> float | None:
        """Truth of the latest node-claim for ``node_id`` at or before ``seq``; None
        if none exists (presence must then rest on an affirmed edge endpoint)."""
        best: tuple[int, float] | None = None
        for o in self._node_claims():
            if o.subject.node_id == node_id and o.seq <= seq:
                best = (o.seq, o.truth_confidence())
        return best[1] if best else None

    def _endpoint_affirmed_upto(self, node_id: str, seq: int) -> bool:
        for o in self._obs:
            if o.relation is not None and o.seq <= seq and o.truth_confidence() >= 0.5:
                for ref in (o.subject, o.object):
                    if ref is not None and ref.is_asset_tier and ref.node_id == node_id:
                        return True
        return False

    def _all_asset_ids(self) -> set[str]:
        ids: set[str] = set()
        for o in self._obs:
            for ref in (o.subject, o.object):
                if ref is not None and ref.is_asset_tier:
                    ids.add(ref.node_id)
        return ids

    def present_at(self, seq: int) -> set[str]:
        """Asset node_ids believed present as of ``seq`` (cumulative): the latest
        node-claim at or before ``seq`` affirms, OR it appears as an affirmed edge
        endpoint with no refuting node-claim. A later REFUTES node-claim removes it."""
        present: set[str] = set()
        for nid in self._all_asset_ids():
            t = self._latest_node_claim_truth(nid, seq)
            if t is not None:
                if t >= 0.5:
                    present.add(nid)
                # t < 0.5 → latest node-claim refutes → absent (do not add)
            elif self._endpoint_affirmed_upto(nid, seq):
                present.add(nid)
        return present

    def _affirmed_in_window(self, lo: int, hi: int) -> set[str]:
        """Assets with any AFFIRMING observation (node-claim or edge endpoint) in
        the window ``(lo, hi]`` — i.e. re-seen recently."""
        out: set[str] = set()
        for o in self._obs:
            if not (lo < o.seq <= hi) or o.truth_confidence() < 0.5:
                continue
            if o.relation is None:
                out.add(o.subject.node_id)
            else:
                for ref in (o.subject, o.object):
                    if ref is not None and ref.is_asset_tier:
                        out.add(ref.node_id)
        return out

    def _first_affirm_seq(self, node_id: str) -> int | None:
        seqs = [o.seq for o in self._obs if o.truth_confidence() >= 0.5 and (
            (o.relation is None and o.subject.node_id == node_id) or
            (o.relation is not None and node_id in {r.node_id for r in (o.subject, o.object) if r}))]
        return min(seqs) if seqs else None

    # -- enumerations (the disappearance authority) ---------------------------

    def _latest_enumeration(self, scope_apex: str, lo: int, hi: int) -> tuple[int, set[str]] | None:
        """The most recent enumerative sweep of ``scope_apex`` in ``(lo, hi]``: its
        seq and the COMPLETE set of asset node_ids it listed (affirming claims only).
        None if the scope was not enumerated in the window."""
        by_seq: dict[int, set[str]] = defaultdict(set)
        for o in self._obs:
            if (o.source_kind in ENUMERATIVE_SOURCE_KINDS and o.relation is None
                    and o.truth_confidence() >= 0.5
                    and lo < o.seq <= hi and str(o.attrs.get("apex", "")) == scope_apex):
                by_seq[o.seq].add(o.subject.node_id)
        if not by_seq:
            return None
        top = max(by_seq)
        return top, by_seq[top]

    def _enumerative_apexes(self) -> list[str]:
        return sorted({str(o.attrs.get("apex", "")) for o in self._obs
                       if o.source_kind in ENUMERATIVE_SOURCE_KINDS and o.attrs.get("apex")})

    # -- the delta ------------------------------------------------------------

    def delta(self, from_seq: int, to_seq: int) -> SurfaceDelta:
        """Change in the surface between two seqs, applying disappearance honesty.

        Each asset known-present at ``from_seq`` is classified by what happened in
        the window ``(from_seq, to_seq]``:
          * re-affirmed          → PERSISTED
          * dropped from a complete-list source that PREVIOUSLY listed it → DISAPPEARED
          * neither (not re-checked by a complete-list source that ever saw it) → STALE
        Assets first affirmed inside the window (and not already known) → APPEARED.

        Disappearance is a SET DIFFERENCE between two complete enumerative snapshots of
        the same scope: a baseline sweep at/ before ``from_seq`` that LISTED the asset,
        and a fresh sweep in the window that OMITS it. An asset a complete-list source
        never listed (e.g. one only ever seen via a point query, or an apex the source
        emits no node-claim for) can never be reported gone — its silence is STALE, not
        absence. Claiming otherwise would convert 'we stopped looking' into 'it's gone'."""
        if to_seq < from_seq:
            from_seq, to_seq = to_seq, from_seq
        before = self.present_at(from_seq)
        reaffirmed = self._affirmed_in_window(from_seq, to_seq)

        # Per scope, diff the baseline complete list (≤ from_seq) against the fresh one
        # (in window). Only assets the baseline LISTED and the fresh sweep DROPPED count.
        disappeared_set: set[str] = set()
        for apex in self._enumerative_apexes():
            base = self._latest_enumeration(apex, -1, from_seq)   # baseline complete snapshot
            fresh = self._latest_enumeration(apex, from_seq, to_seq)  # fresh complete snapshot
            if base is None or fresh is None:
                continue   # need BOTH snapshots to assert a set-difference; else no authority
            for nid in (base[1] - fresh[1]):
                if nid in before:
                    disappeared_set.add(nid)

        persisted: list[str] = []
        disappeared: list[str] = []
        stale: list[str] = []
        for nid in sorted(before):
            if nid in reaffirmed:
                persisted.append(nid)
            elif nid in disappeared_set:
                disappeared.append(nid)
            else:
                stale.append(nid)

        appeared = sorted(
            nid for nid in self._all_asset_ids()
            if nid not in before and (self._first_affirm_seq(nid) or 0) > from_seq
            and (self._first_affirm_seq(nid) or 0) <= to_seq)

        note = (f"{len(appeared)} appeared, {len(persisted)} persisted, "
                f"{len(disappeared)} disappeared (enumerative), {len(stale)} stale "
                f"(not re-checked — presence unknown, NOT assumed gone)")
        return SurfaceDelta(from_seq=from_seq, to_seq=to_seq, appeared=appeared,
                            persisted=persisted, disappeared=disappeared,
                            stale=stale, note=note)

    # -- per-asset timeline ---------------------------------------------------

    def timeline(self, node_id: str) -> list[TimelineEvent]:
        """The ordered learning history for one asset's existence claim."""
        events: list[TimelineEvent] = []
        seen = False
        for o in self._node_claims():
            if o.subject.node_id != node_id:
                continue
            t = o.truth_confidence()
            if not seen:
                kind, seen = "first_seen", True
            else:
                kind = "reaffirmed" if t >= 0.5 else "refuted"
            events.append(TimelineEvent(seq=o.seq, kind=kind, source=o.source,
                                        source_kind=o.source_kind, truth_confidence=round(t, 4)))
        return events
