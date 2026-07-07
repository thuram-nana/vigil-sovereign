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

import random
from dataclasses import dataclass, field

from ..knowledge import CATALOG, EXTENDED_CATALOG, saturate
from ..worldmodel.attacker import ATTACKER_ID, AttackerState
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from ..worldmodel.pathsearch import best_paths
from .campaign import ScanReport, WebScanCampaign, populate_worldmodel
from .checks import DEFAULT_CHECKS, Check, Send
from .detection_cost import path_detection_cost
from .insertion import InsertionKind
from .quantum_era import anneal_path_portfolio

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

# operator ids that must be seeded with the attacker as their acting principal
# (base catalog + the extended catalog's attacker-acting operators). saturate
# RAISES if a seed-requiring operator matches without its seed, so every such
# operator whose preconditions the graph can satisfy must be listed.
_ACTOR_SEEDED = (
    "credential-reuse", "token-replay", "deserialization-to-code-exec",
    "credential-leak-capture", "datastore-secret-extraction", "token-leak-capture",
)


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
    detection_cost: float = 0.0  # 0 = stealthy, 1 = loud (DEL telemetry accounting)
    value: float = 1.0           # reaching one crown jewel = 1 unit (portfolio value)

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
    # the quantum-inspired optimizer's pick: the most valuable set of paths whose
    # total detection cost fits the budget — the stealthiest way to the crown jewels.
    path_portfolio: list[AttackPath] = field(default_factory=list)
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
        detection_budget: float = 2.0,
    ) -> None:
        self._send = send
        self.detection_budget = detection_budget
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

    def chain_findings(
        self, report: ScanReport, *,
        world: WorldModel | None = None, seq_base: int = 1,
    ) -> AutonomousResult:
        """Turn a scan report into an attack graph, chain the operators over the
        confirmed facts, and extract the attacker→crown-jewel paths. Split out from
        :meth:`run` so the reasoning is testable without a live scan.

        ``world`` lets the caller pass a PRE-POPULATED graph — e.g. one an intel recon
        pass already projected assets onto — so findings accrete onto the SAME
        substrate rather than a fresh graph (attack-tier ids ``endpoint:*``/``finding:*``
        are disjoint from intel-tier ids ``domain:*``/``host:*``, so they coexist).
        ``seq_base`` is where finding projection starts on the monotonic clock; a caller
        that already spent seqs ``0..N`` on recon passes ``N+1`` so the clock never
        inverts. Defaults (``None``/``1``) reproduce the standalone behaviour exactly."""
        world = world if world is not None else WorldModel()
        populate_worldmodel(report, world, seq=seq_base)
        seq = _Seq(seq_base + 1)

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

        # passive findings feed chains too: a disclosed private key IS a credential
        # the attacker can capture, which the extended operators turn into account
        # takeover / a grant over a crown jewel.
        for pf in report.passive_findings:
            if pf.check_id == "info-private-key":
                self._establish_credential_exposure(world, pf.url, seq)

        # chain: run the base + extended technique operators over the confirmed
        # facts to a fixpoint. role-assumption grants over a caller-supplied crown
        # jewel; seed it with an internal resource so it can fire without raising.
        seeds: dict[str, dict[str, str]] = {op_id: {"actor": ATTACKER_ID} for op_id in _ACTOR_SEEDED}
        if self.internal_resources:
            seeds["role-assumption"] = {"resource": self.internal_resources[0][0]}
        saturate([*CATALOG, *EXTENDED_CATALOG], world, seq_start=seq.next(), seeds=seeds)

        conclusions = [
            ChainedConclusion(src=e.src, edge=e.kind.value, dst=e.dst,
                              technique=str(e.attrs.get("technique", e.provenance.split(":", 1)[-1])))
            for e in world.all_edges() if e.provenance.startswith("operator:")
        ]

        paths = self._extract_paths(world)
        # quantum-inspired: pick the most valuable path set within the detection
        # budget (simulated annealing over the 0/1 path-portfolio knapsack).
        portfolio: list[AttackPath] = []
        if paths:
            sel = anneal_path_portfolio(paths, budget=self.detection_budget, rng=random.Random(0))
            portfolio = list(sel.chosen)
        return AutonomousResult(scan_report=report, chained_conclusions=conclusions,
                                attack_paths=paths, path_portfolio=portfolio, world=world)

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

    def _establish_credential_exposure(self, world: WorldModel, url: str, seq: "_Seq") -> None:
        """A disclosed credential valid on a principal — the topology the
        credential-leak-capture → role-assumption chain consumes."""
        slug = ("".join(c for c in url if c.isalnum())[-16:]) or "x"
        cred, principal = f"credential:leaked:{slug}", f"principal:leaked:{slug}"
        prov = "finding:info-private-key"
        world.add_node(Node(id=cred, kind=NodeKind.CREDENTIAL, attrs={"exposed": True},
                            provenance=prov, confidence=0.9, first_seen=seq.peek(), last_seen=seq.next()))
        world.add_node(Node(id=principal, kind=NodeKind.PRINCIPAL, attrs={},
                            provenance=prov, confidence=0.9, first_seen=seq.peek(), last_seen=seq.next()))
        _edge(world, cred, principal, EdgeKind.VALID_ON, prov, 0.9, seq)

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
                cost = path_detection_cost([s.technique for s in steps])
                paths.append(AttackPath(steps=steps, detection_cost=round(cost, 3)))
        # stealthiest first — the DEL telemetry accounting lets the operator (or a
        # planner) prefer the least-detectable route to the same crown jewel.
        paths.sort(key=lambda ap: ap.detection_cost)
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
