"""
scanner.campaign — the single autonomous web-scan entrypoint.

Everything else in this package is a stage; this ties them into one zero-manual
command. Given a seed URL and a ``send``, :class:`WebScanCampaign` crawls the
app, passively analyses every response, actively audits every discovered
endpoint across its insertion points, and returns one consolidated
:class:`ScanReport` — the crawl→scan→confirm loop as a product, not a library of
parts.

It also closes the loop back to the brain: :func:`populate_worldmodel` writes the
discovered endpoints and the oracle-confirmed findings into the ``worldmodel``
graph as ENDPOINT and FINDING nodes, so the planner can reason over — and chain
from — what the scanner found. The scanner is the hands; the world-model is where
the hands report to the head.

A shared audit-request budget bounds the whole campaign, and every request still
flows through the injected ``send`` (the scope/charter/kill-switch/egress-gated
executor in production), so an autonomous run is both bounded and authorized.
"""

from __future__ import annotations

import contextlib

from pydantic import BaseModel, ConfigDict, Field

from ..verify.oob import OOBReceiver
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from .checks import DEFAULT_CHECKS, Check, Send
from .crawler import Crawler, Scope
from .engine import AuditEngine, AuditFinding
from .insertion import InsertionKind
from .passive import PassiveFinding
from .targeting import select_checks


class ScanReport(BaseModel):
    """The consolidated result of one autonomous scan."""

    model_config = ConfigDict(extra="forbid")

    target: str
    pages_crawled: int = 0
    requests_discovered: int = 0
    requests_audited: int = 0
    audit_requests_sent: int = 0
    active_findings: list[AuditFinding] = Field(default_factory=list)
    passive_findings: list[PassiveFinding] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.active_findings) + len(self.passive_findings)

    def by_severity(self) -> dict[str, int]:
        """Passive findings carry a severity; active findings are all
        oracle-confirmed exploitable, counted as 'Confirmed'."""
        counts: dict[str, int] = {}
        for f in self.passive_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        if self.active_findings:
            counts["Confirmed"] = len(self.active_findings)
        return counts


class WebScanCampaign:
    """One-call autonomous scan: crawl → passive + active → report.

    ``insertion_kinds`` narrows the active sweep (default: all points).
    ``max_audit_requests`` caps total active traffic across the whole campaign
    (0 = unbounded); the crawl is bounded by ``max_pages`` / ``max_depth``."""

    def __init__(
        self,
        send: Send,
        *,
        scope: Scope | None = None,
        checks: tuple[Check, ...] = DEFAULT_CHECKS,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        max_pages: int = 100,
        max_depth: int = 6,
        max_audit_requests: int = 0,
        enable_oob: bool = True,
        targeted: bool = False,
    ) -> None:
        self._send = send
        self.scope = scope
        self.checks = checks
        self.insertion_kinds = insertion_kinds
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_audit_requests = max_audit_requests
        # A per-scan out-of-band receiver so the blind checks (SSRF/XXE/RCE/
        # deserialization) can confirm callbacks; loopback-only, torn down with
        # the scan. Off => those checks are skipped, never guessed.
        self.enable_oob = enable_oob
        # Prioritise checks per insertion point by parameter fingerprint, so the
        # budget is spent where a bug is plausible (scanner.targeting).
        self.targeted = targeted

    def run(self, seed_url: str) -> ScanReport:
        crawl = Crawler(
            self._send, scope=self.scope,
            max_pages=self.max_pages, max_depth=self.max_depth,
        ).crawl(seed_url)

        active: list[AuditFinding] = []
        audited = 0
        oob_cm = OOBReceiver() if self.enable_oob else contextlib.nullcontext(None)
        with oob_cm as oob:
            # One engine across the whole campaign, so its request counter enforces
            # a single shared active-traffic budget rather than a per-request one.
            engine = AuditEngine(self._send, max_requests=self.max_audit_requests, oob=oob)
            selector = select_checks if self.targeted else None
            for req in crawl.requests:
                active.extend(engine.audit(
                    req, checks=self.checks, insertion_kinds=self.insertion_kinds, selector=selector))
                audited += 1
                if self.max_audit_requests and engine.requests_sent >= self.max_audit_requests:
                    break  # budget spent; stop auditing further endpoints
            requests_sent = engine.requests_sent

        return ScanReport(
            target=seed_url,
            pages_crawled=len(crawl.pages),
            requests_discovered=len(crawl.requests),
            requests_audited=audited,
            audit_requests_sent=requests_sent,
            active_findings=active,
            passive_findings=crawl.passive_findings,
        )


def populate_worldmodel(report: ScanReport, world: WorldModel, *, seq: int) -> None:
    """Write a scan report into the world-model so the planner can reason over it.

    Each distinct audited surface becomes an ENDPOINT node; each oracle-confirmed
    active finding becomes a FINDING node with an EVIDENCES edge to its endpoint.
    Deterministic: the caller supplies the monotonic ``seq`` (no wallclock), node
    ids are derived from the surface/finding identity, and re-running upserts
    rather than duplicates."""
    endpoints: dict[str, str] = {}
    for f in report.active_findings:
        ep_id = f"endpoint:{f.param}"
        if ep_id not in endpoints:
            world.add_node(Node(
                id=ep_id, kind=NodeKind.ENDPOINT,
                attrs={"param": f.param, "target": report.target},
                provenance=f"scan:{report.target}", confidence=1.0,
                first_seen=seq, last_seen=seq,
            ))
            endpoints[ep_id] = ep_id

        finding_id = f"finding:{f.bug_class}:{f.insertion_point}"
        world.add_node(Node(
            id=finding_id, kind=NodeKind.FINDING,
            attrs={
                "bug_class": f.bug_class, "confirmed_by": f.confirmed_by,
                "confidence": f.confidence, "check": f.check_id,
            },
            provenance=f"oracle:{f.confirmed_by}", confidence=f.confidence,
            first_seen=seq, last_seen=seq,
        ))
        world.add_edge(Edge(
            src=finding_id, dst=ep_id, kind=EdgeKind.EVIDENCES, attrs={},
            provenance=f"oracle:{f.confirmed_by}", confidence=f.confidence,
            first_seen=seq, last_seen=seq,
        ))
