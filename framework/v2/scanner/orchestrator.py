"""
scanner.orchestrator — the self-directed autonomous engagement.

The scanner is the hands; ``worldmodel`` is the head's memory; ``knowledge`` holds
the moves. This ties them together so a run does not stop at a list of findings —
it *reasons forward* from them, and reports the multi-hop ATTACK PATHS that the
confirmed facts unlock, not just isolated escalations.

:class:`AutonomousCampaign` runs the loop:

  1. crawl + scan (the oracle-anchored WebScanCampaign),
  2. write each oracle-confirmed finding into a world-model attack graph and
     establish the topology + precondition it implies — an SSRF endpoint
     ``fetches_url`` and the attacker has REACHED it; an IDOR endpoint has broken
     ``auth`` and fronts a DATASTORE; a deserialization endpoint runs on a HOST —
  3. seed the internal resources a real engagement pivots toward, and the attacker
     principal,
  4. run the technique operators to a fixpoint (``knowledge.saturate``) so every
     chain the confirmed facts unlock is derived, and
  5. search the resulting graph for paths from the attacker to crown-jewel nodes
     (``worldmodel.pathsearch``) — the ranked, technique-annotated attack paths.

Every raw finding stays oracle-confirmed; the paths are sound derivations over
those confirmed facts, each hop carrying the technique that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import CATALOG, saturate
from ..worldmodel.attacker import ATTACKER_ID, AttackerState
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ..worldmodel.pathsearch import best_paths
from .campaign import ScanReport, WebScanCampaign, populate_worldmodel
from .checks import DEFAULT_CHECKS, Check, Send
from .insertion import InsertionKind

DEFAULT_INTERNAL_RESOURCES: tuple[tuple[str, dict[str, object]], ...] = (
    ("internal:cloud-metadata", {"internal": True, "detail": "169.254.169.254 instance metadata"}),
    ("internal:admin-host", {"internal": True, "detail": "internal admin service"}),
)

# crown-jewel node kinds an attack path aims for.
_CROWN_KINDS = (NodeKind.CLOUD_RESOURCE, NodeKind.DATASTORE, NodeKind.HOST)

# edge kinds an attacker can traverse when we search for a path.
_TRAVERSABLE = (
    EdgeKind.REACHED, EdgeKind.REACHABLE_FROM, EdgeKind.CAN_ASSUME, EdgeKind.HAS_GRANT,
    EdgeKind.SESSION_ON, EdgeKind.OWNS, EdgeKind.AUTHENTICATES_TO, EdgeKind.TRUSTS_FOR,
    EdgeKind.VALID_ON,
)

# operator ids that must be seeded with the attacker as their acting principal.
_ACTOR_SEEDED = ("credential-reuse", "token-replay", "deserialization-to-code-exec")


@dataclass
class ChainedConclusion:
    src: str
    edge: str
    dst: str
    technique: str

    def describe(self) -> str:
        return f"{self.src} --{self.edge}--> {self.dst}  (via {self.technique})"


@dataclass
class AttackPath:
    """A multi-hop route from the attacker to a crown-jewel node, each hop tagged
    with the technique (operator) that established it, or the finding for observed
    hops."""

    steps: list[ChainedConclusion]

    @property
    def destination(self) -> str:
        return self.steps[-1].dst if self.steps else ""

    @property
    def hops(self) -> int:
        return len(self.steps)

    def describe(self) -> str:
        chain = " -> ".join([self.steps[0].src, *[s.dst for s in self.steps]]) if self.steps else ""
        techs = ", ".join(dict.fromkeys(s.technique for s in self.steps))
        return f"{chain}   [{techs}]"


@dataclass
class AutonomousResult:
    scan_report: ScanReport
    chained_conclusions: list[ChainedConclusion] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    world: WorldModel | None = None

    @property
    def confirmed_findings(self) -> int:
        return len(self.scan_report.active_findings)


class AutonomousCampaign:
    """Self-directed engagement: crawl → scan → chain → attack paths."""

    def __init__(
        self,
        send: Send,
        *,
        checks: tuple[Check, ...] = DEFAULT_CHECKS,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        internal_resources: tuple[tuple[str, dict[str, object]], ...] = DEFAULT_INTERNAL_RESOURCES,
        max_pages: int = 100,
        max_depth: int = 6,
        max_audit_requests: int = 0,
    ) -> None:
        self._send = send
        self.checks = checks
        self.insertion_kinds = insertion_kinds
        self.internal_resources = internal_resources
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_audit_requests = max_audit_requests

    def run(self, seed_url: str) -> AutonomousResult:
        report = WebScanCampaign(
            self._send, checks=self.checks, insertion_kinds=self.insertion_kinds,
            enable_oob=True, targeted=True, max_pages=self.max_pages,
            max_depth=self.max_depth, max_audit_requests=self.max_audit_requests,
        ).run(seed_url)
        return self.chain_findings(report)

    def chain_findings(self, report: ScanReport) -> AutonomousResult:
        """Turn a scan report into an attack graph, chain the operators over the
        confirmed facts, and extract the attacker→crown-jewel paths. Split out from
        :meth:`run` so the reasoning is testable without a live scan."""
        world = WorldModel()
        populate_worldmodel(report, world, seq=1)
        seq = _Seq(2)

        attacker = AttackerState(world)
        attacker.ensure(seq=seq.next())

        for res_id, attrs in self.internal_resources:
            world.add_node(Node(id=res_id, kind=NodeKind.CLOUD_RESOURCE, attrs=dict(attrs),
                                provenance="orchestrator:seed", confidence=1.0,
                                first_seen=seq.peek(), last_seen=seq.next()))

        for f in report.active_findings:
            ep_id = f"endpoint:{f.param}"
            if world.get_node(ep_id) is None:
                continue
            # the attacker has reached this confirmed-vulnerable surface
            attacker.reach(ep_id, seq=seq.next(), provenance=f"finding:{f.bug_class}", confidence=f.confidence)
            self._establish_topology(world, ep_id, f.bug_class, f.confidence, seq)

        # chain: run the technique operators over the confirmed facts to a fixpoint
        seeds = {op_id: {"actor": ATTACKER_ID} for op_id in _ACTOR_SEEDED}
        saturate(CATALOG, world, seq_start=seq.next(), seeds=seeds)

        conclusions = [
            ChainedConclusion(src=e.src, edge=e.kind.value, dst=e.dst,
                              technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])))
            for e in world.all_edges() if e.provenance.startswith("operator:")
        ]

        paths = self._extract_paths(world)
        return AutonomousResult(scan_report=report, chained_conclusions=conclusions,
                                attack_paths=paths, world=world)

    # -- topology per finding class ---------------------------------------

    def _establish_topology(self, world: WorldModel, ep_id: str, bug_class: str, conf: float, seq: "_Seq") -> None:
        prov = f"finding:{bug_class}"
        if bug_class == "ssrf":
            _set_attr(world, ep_id, {"fetches_url": True}, prov, conf, seq)
        elif bug_class in ("idor", "bola", "broken_access_control"):
            _set_attr(world, ep_id, {"auth": False}, prov, conf, seq)
            ds = f"datastore:{ep_id}"
            world.add_node(Node(id=ds, kind=NodeKind.DATASTORE, attrs={"detail": "backing store"},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            _edge(world, ep_id, ds, EdgeKind.TRUSTS_FOR, prov, conf, seq)
        elif bug_class == "deserialization":
            _set_attr(world, ep_id, {"deserializes_untrusted": True}, prov, conf, seq)
            host = f"host:{ep_id}"
            world.add_node(Node(id=host, kind=NodeKind.HOST, attrs={"detail": "service host"},
                                provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
            # the operator wants an incoming REACHABLE_FROM(host -> endpoint)
            _edge(world, host, ep_id, EdgeKind.REACHABLE_FROM, prov, conf, seq)

    def _extract_paths(self, world: WorldModel) -> list[AttackPath]:
        if world.get_node(ATTACKER_ID) is None:
            return []
        paths: list[AttackPath] = []
        for p in best_paths(world, ATTACKER_ID, _CROWN_KINDS, k=8, edge_kinds=_TRAVERSABLE):
            steps = [
                ChainedConclusion(
                    src=e.src, edge=e.kind.value, dst=e.dst,
                    technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])),
                )
                for e in p.edges
            ]
            if steps:
                paths.append(AttackPath(steps=steps))
        return paths


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _Seq:
    """A tiny monotonic counter for the world-model's sequence ints."""

    def __init__(self, start: int) -> None:
        self._n = start

    def next(self) -> int:
        v = self._n
        self._n += 1
        return v

    def peek(self) -> int:
        return self._n


def _set_attr(world: WorldModel, node_id: str, attrs: dict[str, object], prov: str, conf: float, seq: "_Seq") -> None:
    node = world.get_node(node_id)
    if node is None:
        return
    world.add_node(Node(id=node_id, kind=node.kind, attrs=dict(attrs),
                        provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))


def _edge(world: WorldModel, src: str, dst: str, kind: EdgeKind, prov: str, conf: float, seq: "_Seq") -> None:
    world.add_edge(Edge(src=src, dst=dst, kind=kind, attrs={},
                        provenance=prov, confidence=conf, first_seen=seq.peek(), last_seen=seq.next()))
