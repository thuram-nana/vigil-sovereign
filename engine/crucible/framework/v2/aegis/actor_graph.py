"""
aegis.actor_graph — the per-actor Beta belief, via the reused projection keystone.

Each observation is projected onto a shared ``WorldModel`` through ``intel.project
.project_observation`` (unchanged), which accumulates a per-actor Beta(alpha, beta) belief —
corroboration raises ``belief_mean``, a REFUTES observation lowers it, order-independently.
That per-actor posterior is the thing a scalar risk score structurally cannot express.

The one genuinely new operational concern vs CRUCIBLE (which is batch-per-engagement) is a
CONTINUOUS stream: this graph adds bounded windowing/eviction so a long-running deployment's
memory stays bounded. Eviction is LRU over a per-actor observation counter; it never inflates
a belief and stays deterministic (no wallclock, no rng).
"""

from __future__ import annotations

from collections import OrderedDict

from ..intel.models import Observation
from ..intel.project import project_observation
from ..worldmodel.graph import WorldModel
from .models import BeliefRef


class ActorGraph:
    """A bounded, continuously-updated per-actor belief graph."""

    def __init__(self, world: WorldModel | None = None, *, max_actors: int = 4096) -> None:
        self.world = world if world is not None else WorldModel()
        self._max_actors = max(1, int(max_actors))
        # actor_node_id -> count of applied observations (LRU-ordered for eviction).
        self._counts: "OrderedDict[str, int]" = OrderedDict()

    def observe(self, obs: Observation) -> bool:
        """Project one observation; update the per-actor counter; evict the LRU actor if over
        the bound. Returns True if the projection applied (a reliability-0 source is dropped)."""
        applied = project_observation(self.world, obs)
        actor_id = obs.subject.node_id
        if applied:
            self._counts[actor_id] = self._counts.get(actor_id, 0) + 1
            self._counts.move_to_end(actor_id)
            self._evict()
        return applied

    def observe_all(self, observations: list[Observation]) -> int:
        return sum(1 for o in observations if self.observe(o))

    def belief(self, actor_id: str) -> BeliefRef | None:
        """The actor's current Beta posterior (mean + lower credible bound + observation
        count), or None if the actor is unknown to the graph."""
        node = self.world.get_node(actor_id)
        if node is None:
            return None
        return BeliefRef(mean=node.belief_mean, lcb=node.belief_lcb(),
                         n_observations=self._counts.get(actor_id, 0))

    def snapshot(self) -> list[tuple[str, BeliefRef]]:
        """Every tracked actor paired with its current belief, LRU order (most-recently-updated last).
        A read-only accessor for a status view — the alternative to reaching into the private ``_counts``.
        The caller holds any concurrency lock; the gateway serialises belief updates under its own
        ``_belief_lock``, so a snapshot taken under that lock is consistent."""
        out: list[tuple[str, BeliefRef]] = []
        for actor_id in list(self._counts.keys()):
            b = self.belief(actor_id)
            if b is not None:
                out.append((actor_id, b))
        return out

    def _evict(self) -> None:
        while len(self._counts) > self._max_actors:
            actor_id, _ = self._counts.popitem(last=False)  # least-recently-updated actor
            # Also drop the actor's node from the world-model, else the graph grows unbounded
            # despite the LRU cap — the belief cache and the graph must evict together.
            self.world.remove_node(actor_id)
