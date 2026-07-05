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
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..verify.oob import OOBReceiver
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from .checks import CorsActiveCheck, DEFAULT_CHECKS, Check, HostHeaderCheck, RequestCheck, Send
from .crawler import Crawler, Scope
from .domxss import DomXssCandidate, analyze_html
from .engine import AuditEngine, AuditFinding
from .graphql import GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
from .insertion import InsertionKind
from .jwt import JwtNoneCheck
from .learning import ContextualBandit
from .passive import PassiveFinding
from .targeting import select_checks

# The request-level arsenal: checks that operate on the WHOLE request/response
# (adding a hostile header, POSTing a probe query) rather than fuzzing one
# insertion point. Each confirms via its oracle on the real dangerous evidence,
# so a properly-configured server does not fire. Run once per host by the
# campaign (these are host/endpoint-level, not per-parameter).
DEFAULT_REQUEST_CHECKS: tuple[RequestCheck, ...] = (
    CorsActiveCheck(),
    HostHeaderCheck(),
    JwtNoneCheck(),
    GraphQLIntrospectionCheck(),
    GraphQLSuggestionsCheck(),
)


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
    # Static DOM-XSS source->sink flows over the crawled page corpus. These are
    # CANDIDATES (leads), never oracle-confirmed — kept strictly separate from
    # active_findings so the prove-don't-guess property is not diluted. Dynamic
    # confirmation needs a headless browser (the engage runner / Wave 6 path).
    dom_xss_candidates: list[DomXssCandidate] = Field(default_factory=list)

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
        request_checks: tuple[RequestCheck, ...] = DEFAULT_REQUEST_CHECKS,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
        max_pages: int = 100,
        max_depth: int = 6,
        max_audit_requests: int = 0,
        enable_oob: bool = True,
        targeted: bool = False,
        bandit: ContextualBandit | None = None,
        bandit_context: str = "default",
        bandit_path: Path | str | None = None,
        enable_domxss: bool = False,
    ) -> None:
        self._send = send
        self.scope = scope
        self.checks = checks
        # Request-level checks run once per host (CORS/host-header/JWT/GraphQL).
        self.request_checks = request_checks
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
        # Self-learning check ordering (scanner.learning). Explicit bandit wins;
        # else a persisted file is warm-started if present; else a fresh uniform
        # prior. The bandit only ORDERS effort (never drops a check), so coverage
        # is identical with or without it. Persisted at run end if a path is set.
        self._explicit_bandit = bandit
        self.bandit_context = bandit_context
        self.bandit_path = bandit_path
        # Opt-in static DOM-XSS source->sink analysis over crawled page bodies
        # (no extra traffic). Produces leads, not confirmed findings.
        self.enable_domxss = enable_domxss

    def _resolve_bandit(self) -> ContextualBandit:
        """The explicit bandit, else a warm-start from the persisted file if one
        exists, else a fresh uniform-prior bandit."""
        if self._explicit_bandit is not None:
            return self._explicit_bandit
        if self.bandit_path is not None:
            p = Path(self.bandit_path)
            if p.is_file():
                return ContextualBandit.load(p)
        return ContextualBandit()

    def run(self, seed_url: str) -> ScanReport:
        crawl = Crawler(
            self._send, scope=self.scope,
            max_pages=self.max_pages, max_depth=self.max_depth,
        ).crawl(seed_url)

        bandit = self._resolve_bandit()
        active: list[AuditFinding] = []
        audited = 0
        seen_hosts: set[str] = set()
        oob_cm = OOBReceiver() if self.enable_oob else contextlib.nullcontext(None)
        with oob_cm as oob:
            # One engine across the whole campaign, so its request counter enforces
            # a single shared active-traffic budget rather than a per-request one.
            engine = AuditEngine(
                self._send, max_requests=self.max_audit_requests, oob=oob,
                bandit=bandit, bandit_context=self.bandit_context)
            selector = select_checks if self.targeted else None
            for req in crawl.requests:
                # Request-level checks are host/endpoint-level, so run them once
                # per host (on the first request seen for that host) — not per
                # parameter, which would re-confirm the same host CORS/JWT N times.
                host = urlsplit(req.url).netloc
                point_request_checks = self.request_checks if host not in seen_hosts else ()
                seen_hosts.add(host)
                active.extend(engine.audit(
                    req, checks=self.checks, insertion_kinds=self.insertion_kinds,
                    selector=selector, request_checks=point_request_checks))
                audited += 1
                if self.max_audit_requests and engine.requests_sent >= self.max_audit_requests:
                    break  # budget spent; stop auditing further endpoints
            requests_sent = engine.requests_sent

        # Persist the learned posteriors so the next engagement warm-starts.
        if self.bandit_path is not None:
            bandit.save(self.bandit_path)

        # Opt-in static DOM-XSS leads over the crawled corpus (no extra traffic).
        candidates: list[DomXssCandidate] = []
        if self.enable_domxss:
            for page in crawl.pages:
                if page.body:
                    candidates.extend(analyze_html(page.body))

        return ScanReport(
            target=seed_url,
            pages_crawled=len(crawl.pages),
            requests_discovered=len(crawl.requests),
            requests_audited=audited,
            audit_requests_sent=requests_sent,
            active_findings=active,
            passive_findings=crawl.passive_findings,
            dom_xss_candidates=candidates,
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
