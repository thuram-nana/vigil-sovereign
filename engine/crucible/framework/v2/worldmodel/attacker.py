"""
worldmodel.attacker — the attacker's own state as first-class, persistent facts.

A world-model is only a *plan substrate* if it remembers what the attacker has
actually achieved. This module records the postconditions of confirmed
primitives — assets OWNED, credentials/sessions HELD, services REACHED — as
typed edges from a single canonical attacker PRINCIPAL node.

Two consequences fall out for free, and they are the point:

  * **Persistence.** Attacker state is just edges in the graph, so it round-trips
    through :mod:`worldmodel.store` with the rest of the world. A killed
    engagement reloads exactly the foothold it had — the state survives.

  * **Chaining.** Because the state is graph-native, :mod:`worldmodel.derivation`
    and :mod:`worldmodel.pathsearch` reason over it directly. Holding a
    credential that is VALID_ON a target lets the derivation engine conclude the
    attacker now OWNS that target — a follow-on edge unlocked by the recorded
    postcondition, exactly the chaining a flat finding list cannot do.

Everything here is deterministic: callers pass a monotonic ``seq`` (no wallclock),
and every asserted edge carries provenance so a path remains explainable.
"""

from __future__ import annotations

from .graph import WorldModel
from .models import Edge, EdgeKind, Node, NodeKind

# The single, stable id of the attacker principal whose out-edges ARE the
# attacker's state. One per engagement graph.
ATTACKER_ID = "attacker:self"


class AttackerState:
    """A thin, typed view over a :class:`WorldModel` for recording and querying
    what the attacker controls. It owns no state of its own — everything lives
    in the graph — so two views over the same (or a reloaded) world agree."""

    def __init__(self, world: WorldModel, attacker_id: str = ATTACKER_ID) -> None:
        self.world = world
        self.attacker_id = attacker_id

    # -- record postconditions ---------------------------------------------

    def ensure(self, *, seq: int, provenance: str = "attacker:init") -> str:
        """Idempotently add the attacker principal node. Returns its id."""
        self.world.add_node(
            Node(
                id=self.attacker_id,
                kind=NodeKind.PRINCIPAL,
                attrs={"role": "attacker"},
                provenance=provenance,
                confidence=1.0,
                first_seen=seq,
                last_seen=seq,
            )
        )
        return self.attacker_id

    def _record(
        self,
        kind: EdgeKind,
        target_id: str,
        *,
        seq: int,
        provenance: str,
        confidence: float,
    ) -> None:
        self.ensure(seq=seq, provenance="attacker:init")
        self.world.add_edge(
            Edge(
                src=self.attacker_id,
                dst=target_id,
                kind=kind,
                attrs={},
                provenance=provenance,
                confidence=confidence,
                first_seen=seq,
                last_seen=seq,
            )
        )

    def own(
        self, node_id: str, *, seq: int,
        provenance: str = "postcondition:own", confidence: float = 1.0,
    ) -> None:
        """Record that the attacker now controls ``node_id`` (a host / service /
        resource / assumed principal)."""
        self._record(EdgeKind.OWNS, node_id, seq=seq, provenance=provenance, confidence=confidence)

    def hold(
        self, credential_id: str, *, seq: int,
        provenance: str = "postcondition:credential", confidence: float = 1.0,
    ) -> None:
        """Record that the attacker now holds ``credential_id`` (a credential /
        session / token)."""
        self._record(EdgeKind.HOLDS, credential_id, seq=seq, provenance=provenance, confidence=confidence)

    def reach(
        self, service_id: str, *, seq: int,
        provenance: str = "postcondition:reach", confidence: float = 1.0,
    ) -> None:
        """Record that the attacker has reached ``service_id`` (a service /
        endpoint / network segment)."""
        self._record(EdgeKind.REACHED, service_id, seq=seq, provenance=provenance, confidence=confidence)

    # -- query state -------------------------------------------------------

    def _targets(self, kind: EdgeKind) -> list[str]:
        return sorted(
            e.dst for e in self.world.edges_of_kind(kind) if e.src == self.attacker_id
        )

    def owned(self) -> list[str]:
        """Node ids the attacker currently controls (deterministic order)."""
        return self._targets(EdgeKind.OWNS)

    def held(self) -> list[str]:
        """Credential/session/token ids the attacker currently holds."""
        return self._targets(EdgeKind.HOLDS)

    def reached(self) -> list[str]:
        """Service/endpoint/segment ids the attacker has reached."""
        return self._targets(EdgeKind.REACHED)


# ---------------------------------------------------------------------------
# Attacker-state derivation rules (the chaining the flat list cannot do)
# ---------------------------------------------------------------------------

from .derivation import EdgePattern, InteractionRule, NodeConstraint  # noqa: E402


OWN_VIA_HELD_CREDENTIAL = InteractionRule(
    name="own_via_held_credential",
    premises=[
        EdgePattern(src="A", dst="C", kind=EdgeKind.HOLDS),
        EdgePattern(src="C", dst="T", kind=EdgeKind.VALID_ON),
    ],
    conclusion=EdgePattern(src="A", dst="T", kind=EdgeKind.OWNS),
    where={"C": NodeConstraint(kind=NodeKind.CREDENTIAL)},
)
"""If the attacker HOLDS a credential C and C is VALID_ON target T, the attacker
now OWNS T. The postcondition of one primitive (credential obtained) unlocks the
next (target owned) — with confidence the product of the two supporting edges."""


REACH_VIA_OWNED_HOST = InteractionRule(
    name="reach_via_owned_host",
    premises=[
        EdgePattern(src="A", dst="H", kind=EdgeKind.OWNS),
        # REACHABLE_FROM(H, S): S is reachable *from* H.
        EdgePattern(src="H", dst="S", kind=EdgeKind.REACHABLE_FROM),
    ],
    conclusion=EdgePattern(src="A", dst="S", kind=EdgeKind.REACHED),
)
"""If the attacker OWNS host H and service S is reachable from H, the attacker has
REACHED S — owning a foothold extends reach to what that foothold can see."""


ATTACKER_RULES: list[InteractionRule] = [
    OWN_VIA_HELD_CREDENTIAL,
    REACH_VIA_OWNED_HOST,
]
"""Derivation rules that turn recorded attacker-state postconditions into the
follow-on edges an attacker would infer. Compose with ``derivation.DEFAULT_RULES``."""
