"""
scanner.orchestrator — the self-directed autonomous engagement.

The scanner is the hands; ``worldmodel`` is the head's memory; ``knowledge`` holds
the moves. This ties them together so a run does not stop at a list of findings —
it *reasons forward* from them. A confirmed SSRF is not just "SSRF on /fetch"; it
means the server makes attacker-controlled outbound requests, which (via the
technique operators) means it can reach an internal-only resource such as cloud
metadata. That second conclusion is a chain the scanner alone cannot draw.

:class:`AutonomousCampaign` runs the full loop:

  1. crawl + scan (the existing oracle-anchored WebScanCampaign),
  2. write the oracle-confirmed findings into a world-model attack graph, and
     translate each into the precondition it establishes (SSRF ⇒ the endpoint
     ``fetches_url``; deserialization ⇒ it ``deserializes_untrusted``; …),
  3. seed the internal resources a real engagement cares about (metadata, an
     internal admin host),
  4. run the technique operators to a fixpoint (``knowledge.saturate``) so every
     chain that the confirmed facts unlock is derived,
  5. report the derived chains alongside the raw findings + the attack graph.

Every raw finding is still oracle-confirmed; the chains are sound derivations over
those confirmed facts, each carrying the operator (technique) that produced it, so
the escalation is explainable rather than asserted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..knowledge import CATALOG, saturate
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Node, NodeKind
from .campaign import ScanReport, WebScanCampaign, populate_worldmodel
from .checks import DEFAULT_CHECKS, Check, Send
from .insertion import InsertionKind

# Internal-only resources a real engagement pivots toward once server-side reach
# exists. Seeded as CLOUD_RESOURCE nodes so the SSRF-internal-reach operator can
# bind them. (id, attrs)
DEFAULT_INTERNAL_RESOURCES: tuple[tuple[str, dict[str, object]], ...] = (
    ("internal:cloud-metadata", {"internal": True, "detail": "169.254.169.254 instance metadata"}),
    ("internal:admin-host", {"internal": True, "detail": "internal admin service"}),
)

# bug_class a confirmed finding establishes -> the endpoint precondition it sets,
# which the technique operators then chain from.
_FINDING_PRECONDITIONS: dict[str, dict[str, object]] = {
    "ssrf": {"fetches_url": True},
    "deserialization": {"deserializes_untrusted": True},
}


@dataclass
class ChainedConclusion:
    """One escalation the operators derived from the confirmed findings."""

    src: str
    edge: str
    dst: str
    technique: str

    def describe(self) -> str:
        return f"{self.src} --{self.edge}--> {self.dst}  (chained via {self.technique})"


@dataclass
class AutonomousResult:
    scan_report: ScanReport
    chained_conclusions: list[ChainedConclusion] = field(default_factory=list)
    world: WorldModel | None = None

    @property
    def confirmed_findings(self) -> int:
        return len(self.scan_report.active_findings)


class AutonomousCampaign:
    """Self-directed engagement: crawl → scan → chain. Returns oracle-confirmed
    findings PLUS the escalations the technique operators derive from them, over a
    world-model attack graph."""

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
            self._send,
            checks=self.checks,
            insertion_kinds=self.insertion_kinds,
            enable_oob=True,
            targeted=True,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            max_audit_requests=self.max_audit_requests,
        ).run(seed_url)

        world = WorldModel()
        populate_worldmodel(report, world, seq=1)
        seq = 2

        # seed the internal resources a chain can reach toward
        for res_id, attrs in self.internal_resources:
            world.add_node(Node(
                id=res_id, kind=NodeKind.CLOUD_RESOURCE, attrs=dict(attrs),
                provenance="orchestrator:seed", confidence=1.0, first_seen=seq, last_seen=seq))
            seq += 1

        # translate each confirmed finding into the precondition it establishes,
        # so the operators can chain from it (upsert merges the attr onto the
        # endpoint node populate_worldmodel already created)
        for f in report.active_findings:
            attrs = _FINDING_PRECONDITIONS.get(f.bug_class)
            if not attrs:
                continue
            ep_id = f"endpoint:{f.param}"
            if world.get_node(ep_id) is not None:
                world.add_node(Node(
                    id=ep_id, kind=NodeKind.ENDPOINT, attrs=dict(attrs),
                    provenance=f"finding:{f.bug_class}", confidence=f.confidence,
                    first_seen=seq, last_seen=seq))
                seq += 1

        # chain: run the technique operators over the confirmed facts to a fixpoint
        saturate(CATALOG, world, seq_start=seq)

        conclusions: list[ChainedConclusion] = []
        for edge in world.all_edges():
            if edge.provenance.startswith("operator:"):
                conclusions.append(ChainedConclusion(
                    src=edge.src, edge=edge.kind.value, dst=edge.dst,
                    technique=str(edge.attrs.get("technique", edge.provenance.split(":", 1)[1])),
                ))

        return AutonomousResult(scan_report=report, chained_conclusions=conclusions, world=world)
