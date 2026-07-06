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

from ..verify.collaborator import RelayClient
from ..verify.oob import OOBReceiver
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from .checks import CorsActiveCheck, DEFAULT_CHECKS, Check, HostHeaderCheck, RequestCheck, Send
from .crawler import Crawler, Scope
from .domxss import DomXssCandidate, analyze_html
from .engine import AuditEngine, AuditFinding
from .fingerprint import Fingerprint, fingerprint
from .graphql import GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
from .insertion import HttpRequest, InsertionKind
from .jwt import JwtNoneCheck
from .learning import ContextualBandit
from .library import LibraryEntry, load_library, select_entries, split_checks
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
    # The target's detected technology stack (when library-driven scanning ran).
    # Drives which fingerprint-gated checks were selected.
    fingerprint: Fingerprint | None = None
    library_checks_run: int = 0
    # Static DOM-XSS source->sink flows over the crawled page corpus. These are
    # CANDIDATES (leads), never oracle-confirmed — kept strictly separate from
    # active_findings so the prove-don't-guess property is not diluted. Dynamic,
    # execution-CONFIRMED DOM-XSS (when the browser pass runs) lands in
    # active_findings with a dom_execution certificate instead.
    dom_xss_candidates: list[DomXssCandidate] = Field(default_factory=list)
    # Endpoints the SPA crawler observed the app call (method + absolute URL) —
    # the fetch/XHR surface a static crawl cannot see.
    discovered_endpoints: list[str] = Field(default_factory=list)

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
        oob_advertise_base_url: str | None = None,
        use_library: bool = False,
        library_entries: list[LibraryEntry] | None = None,
        oob_relay_url: str | None = None,
        oob_relay_secret: str | None = None,
        enable_browser_xss: bool = False,
        enable_spa_crawl: bool = False,
        max_browser_targets: int = 15,
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
        # Opt-in operator-hosted OOB relay: the callback base blind checks embed.
        # None => loopback-only (blind classes confirm only for co-resident
        # targets). The engage runner sets this only after checking the relay
        # host is on the charter allowlist.
        self.oob_advertise_base_url = oob_advertise_base_url
        # Opt-in remote OOB collaborator (verify.collaborator): when a relay URL is
        # given, blind checks confirm on REMOTE targets by polling the operator-
        # hosted relay instead of the loopback receiver. The engage runner sets
        # this only after checking the relay host is on the charter allowlist.
        self.oob_relay_url = oob_relay_url
        self.oob_relay_secret = oob_relay_secret
        # Opt-in dynamic browser passes (loopback `scan` path). A headless browser
        # navigates DIRECTLY (its requests do not flow through the injected gated
        # `send`), so these are scoped to contained targets — the remote `engage`
        # browser path is deferred until a CDP request-allowlist gates that egress.
        # No browser present => both are silently skipped (a browser never guesses).
        self.enable_browser_xss = enable_browser_xss
        self.enable_spa_crawl = enable_spa_crawl
        self.max_browser_targets = max_browser_targets
        # Data-driven coverage: fingerprint the target from the crawl and run the
        # declarative-library checks whose applicability predicate matches the
        # detected stack (scanner.library + scanner.fingerprint). Off by default
        # so the fixed DEFAULT_CHECKS path is unchanged. `library_entries` lets a
        # caller inject a check set; None loads the shipped library from disk.
        self.use_library = use_library
        self._library_entries = library_entries

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

    def _maybe_start_browser(self):
        """A started CdpBrowser when a dynamic pass is enabled and a browser
        exists, else None (the passes are then skipped — never guessed)."""
        if not (self.enable_browser_xss or self.enable_spa_crawl):
            return None
        from .cdp import CdpBrowser, cdp_available
        if not cdp_available():
            return None
        try:
            return CdpBrowser().start()
        except Exception:
            return None

    def _spa_discover(self, crawl, browser) -> tuple[list[str], list[HttpRequest]]:
        """Run the SPA crawler over a bounded set of crawled pages; return the
        observed endpoints (``METHOD absolute-url``) and, for in-scope GET
        endpoints carrying a query, extra requests to fold into the audit surface."""
        from urllib.parse import urljoin
        from .spa_crawler import crawl_spa

        endpoints: list[str] = []
        extra: list[HttpRequest] = []
        seen: set[tuple[str, str]] = set()
        for page in crawl.pages[: self.max_browser_targets]:
            try:
                result = crawl_spa(page.url, browser=browser)
            except Exception:
                continue
            for ep in result.endpoints:
                absu = urljoin(page.url, ep.url)
                key = (ep.method.upper(), absu)
                if key in seen:
                    continue
                seen.add(key)
                endpoints.append(f"{ep.method.upper()} {absu}")
                if ep.method.upper() == "GET" and urlsplit(absu).query:
                    if self.scope is None or self.scope.in_scope(absu):
                        extra.append(HttpRequest(method="GET", url=absu))
        return endpoints, extra

    def _browser_xss_pass(self, crawl, browser) -> list[AuditFinding]:
        """For a bounded set of crawled GET parameters, confirm DOM-XSS by real
        execution in the browser; return an AuditFinding (with a dom_execution
        certificate) per parameter that actually executed."""
        from urllib.parse import parse_qsl
        from ..verify.confirmation import confirm_finding
        from ..verify.verifier import OracleVerifier
        from .browser_xss import confirm_dom_xss

        findings: list[AuditFinding] = []
        verifier = OracleVerifier()
        tested = 0
        for req in crawl.requests:
            if req.method.upper() != "GET":
                continue
            for param, _ in parse_qsl(urlsplit(req.url).query):
                if tested >= self.max_browser_targets:
                    return findings
                tested += 1
                try:
                    results = confirm_dom_xss(req.url, param=param, browser=browser)
                except Exception:
                    continue
                for r in results:
                    if not r.executed:
                        continue
                    confirmed = confirm_finding(
                        finding={"bug_class": "dom_xss", "title": f"DOM-XSS via {param}",
                                 "severity": "High", "surface": req.url,
                                 "summary": "injected script executed in a real DOM"},
                        context=r.context, verifier=verifier)
                    if confirmed is None:
                        continue
                    kind = confirmed.confirmed_by
                    findings.append(AuditFinding(
                        check_id="browser-xss", bug_class="dom_xss",
                        insertion_point=f"query_value:{param}", param=param,
                        confidence=confirmed.confidence,
                        confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
                        rationale=confirmed.rationale,
                        oracle_context=r.context.model_dump(mode="json")))
                    break  # one confirmed execution per parameter is enough
        return findings

    def run(self, seed_url: str) -> ScanReport:
        crawl = Crawler(
            self._send, scope=self.scope,
            max_pages=self.max_pages, max_depth=self.max_depth,
        ).crawl(seed_url)

        bandit = self._resolve_bandit()

        # Dynamic browser passes (loopback scan path). Started once, shared by the
        # SPA discovery (before the audit) and the browser-XSS pass (after it).
        browser = self._maybe_start_browser()
        spa_endpoints: list[str] = []
        extra_requests: list[HttpRequest] = []
        try:
            if browser is not None and self.enable_spa_crawl:
                spa_endpoints, extra_requests = self._spa_discover(crawl, browser)

            # Data-driven coverage: fingerprint the target and add the library
            # checks whose applicability predicate matches the detected stack. The
            # checks are oracle-anchored exactly like the built-ins, so precision
            # is unaffected; coverage is scoped so a WordPress payload never fires
            # at a Spring app.
            fp: Fingerprint | None = None
            active_checks = self.checks
            library_request_checks: tuple = ()
            library_checks_run = 0
            if self.use_library:
                fp = fingerprint(crawl.pages)
                entries = self._library_entries if self._library_entries is not None else load_library()
                selected = select_entries(entries, fp.tokens)
                point_lib, request_lib = split_checks(selected)
                library_request_checks = tuple(request_lib)
                library_checks_run = len(point_lib) + len(request_lib)
                active_checks = tuple(self.checks) + tuple(point_lib)

            # SPA-discovered in-scope GET endpoints join the audit surface.
            all_requests = list(crawl.requests) + extra_requests

            active: list[AuditFinding] = []
            audited = 0
            seen_hosts: set[str] = set()
            if self.enable_oob and self.oob_relay_url:
                # Remote collaborator: poll the operator-hosted relay for interactions.
                oob_cm: object = RelayClient(self.oob_relay_url, self.oob_relay_secret or "")
            elif self.enable_oob:
                oob_cm = OOBReceiver(advertise_base_url=self.oob_advertise_base_url)
            else:
                oob_cm = contextlib.nullcontext(None)
            with oob_cm as oob:
                # One engine across the whole campaign, so its request counter
                # enforces a single shared active-traffic budget.
                engine = AuditEngine(
                    self._send, max_requests=self.max_audit_requests, oob=oob,
                    bandit=bandit, bandit_context=self.bandit_context)
                selector = select_checks if self.targeted else None
                for req in all_requests:
                    # Request-level checks are host/endpoint-level, so run them once
                    # per host (on the first request seen for that host) — not per
                    # parameter, which would re-confirm the same host CORS/JWT N times.
                    host = urlsplit(req.url).netloc
                    point_request_checks = (
                        tuple(self.request_checks) + library_request_checks
                        if host not in seen_hosts else ())
                    seen_hosts.add(host)
                    active.extend(engine.audit(
                        req, checks=active_checks, insertion_kinds=self.insertion_kinds,
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

            # Dynamic DOM-XSS confirmed by real execution in the browser — these
            # land in active_findings with a dom_execution certificate.
            if browser is not None and self.enable_browser_xss:
                active.extend(self._browser_xss_pass(crawl, browser))
        finally:
            if browser is not None:
                browser.stop()

        return ScanReport(
            target=seed_url,
            pages_crawled=len(crawl.pages),
            requests_discovered=len(crawl.requests),
            requests_audited=audited,
            audit_requests_sent=requests_sent,
            active_findings=active,
            passive_findings=crawl.passive_findings,
            dom_xss_candidates=candidates,
            discovered_endpoints=spa_endpoints,
            fingerprint=fp,
            library_checks_run=library_checks_run,
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
