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
import random
import re
import time
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..verify.collaborator import RelayClient
from ..verify.oob import OOBReceiver
from ..worldmodel.graph import WorldModel
from ..worldmodel.models import Edge, EdgeKind, Node, NodeKind
from .checks import CorsActiveCheck, DEFAULT_CHECKS, Check, HostHeaderCheck, RequestCheck, Send
from .crawler import Crawler, Scope
from .discovery import DiscoveredPath, JsSecret
from .domxss import DomXssCandidate, analyze_html
from .engine import AuditEngine, AuditFinding
from .fingerprint import Fingerprint, fingerprint
from .grammar import generate as grammar_generate, infer_grammar
from .graphql import GRAPHQL_DOS_CHECKS, GraphQLIntrospectionCheck, GraphQLSuggestionsCheck
from .insertion import HttpRequest, InsertionKind
from .jwt import JwtNoneCheck
from .learning import ContextualBandit
from .progress import ProgressSink
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
    # Wall-clock seconds the whole scan took (crawl + audit + any browser passes).
    # A performance datum for the comparative benchmark, not a scoring input.
    elapsed_s: float = 0.0
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
    # --- opt-in advanced web arsenal (enable_arsenal) — LEADS, never confirmed ---
    # These are populated only when the arsenal pass ran. Like dom_xss_candidates
    # they are strictly separated from active_findings: they record reachability /
    # references, not exploitability. The arsenal's oracle-CONFIRMED findings
    # (request smuggling, CSWSH, request race) land in active_findings with an
    # oracle_context certificate like any other confirmed finding — they are NOT
    # here. Empty on every default (arsenal-off) run.
    discovered_paths: list[DiscoveredPath] = Field(default_factory=list)
    js_secrets: list[JsSecret] = Field(default_factory=list)
    # Human-readable capability/reference leads the arsenal surfaced (an offered
    # h2c upgrade, mined ws:// endpoints, mined API refs) — context, not findings.
    arsenal_leads: list[str] = Field(default_factory=list)
    # Provenance-tagged GraphQL DoS/abuse leads (opt-in `enable_graphql_dos`): the
    # cost-limit and depth-when-introspection-off signals that are honestly LEADS,
    # not oracle-confirmed. The DoS checks' CONFIRMED findings (unbounded depth,
    # alias overloading, batching) land in active_findings like any other; these are
    # the strictly-separated leads. Empty on every default (dos-off) run.
    graphql_leads: list[str] = Field(default_factory=list)

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
        browser_allowed_hosts: set[str] | None = None,
        waf_adaptive: bool = False,
        grammar_fuzz: int = 0,
        grammar_fuzz_seed: int = 0,
        priors: "Iterable[object] | None" = None,
        progress: "ProgressSink | None" = None,
        enable_arsenal: bool = False,
        arsenal_authz: "Callable[[str], bool] | None" = None,
        arsenal_race_targets: "tuple[tuple[str, int], ...]" = (),
        arsenal_max_probes: int = 64,
        enable_graphql_dos: bool = False,
    ) -> None:
        self._send = send
        self.scope = scope
        self.checks = checks
        # OPT-IN live-progress sink (scanner.progress). Default None -> the run makes
        # NO calls (byte-for-byte the current behaviour, zero cost). When attached it
        # is invoked only on rare events (phase boundaries + confirmed findings, never
        # per-request), so a live view never perturbs scan efficiency.
        self._progress = progress
        # Opt-in adaptive WAF-bypass: filtered-but-plausible probes get a synthesized
        # bypassing form (see AuditEngine.waf_adaptive). Off by default (extra traffic).
        self.waf_adaptive = waf_adaptive
        # Opt-in grammar-aware fuzzing: induce a request grammar from the crawl and
        # synthesize this many structurally-valid NEW requests into the audit surface
        # — endpoints/params the static crawl never linked to. 0 = off. Deterministic
        # given grammar_fuzz_seed.
        self.grammar_fuzz = grammar_fuzz
        self.grammar_fuzz_seed = grammar_fuzz_seed
        # Opt-in cross-engagement TRANSFER: Beta priors (memory.priors.Prior-shaped:
        # bug_class/successes/attempts) from PAST engagements, folded into this run's
        # check-ordering bandit so it warm-starts biased toward what paid off before.
        # It only ORDERS effort (never drops a check), so coverage is unchanged.
        self._priors = priors
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
        # When set, the headless browser is launched with resolver-level egress
        # control: it can only reach these hosts (+ loopback). The engage runner
        # sets this to the charter's in-scope hosts so the remote browser path
        # cannot pull the browser off-scope. None => unrestricted (loopback scan).
        self._browser_allowed_hosts = browser_allowed_hosts
        # Data-driven coverage: fingerprint the target from the crawl and run the
        # declarative-library checks whose applicability predicate matches the
        # detected stack (scanner.library + scanner.fingerprint). Off by default
        # so the fixed DEFAULT_CHECKS path is unchanged. `library_entries` lets a
        # caller inject a check set; None loads the shipped library from disk.
        self.use_library = use_library
        self._library_entries = library_entries
        # Opt-in advanced web arsenal (default OFF → the default scan is byte-for-byte
        # unchanged). When on, an ADDITIVE post-audit pass runs the built-but-unwired
        # request-level modules — content/JS discovery (leads via the gated `send`),
        # HTTP request-smuggling detection, and Cross-Site WebSocket Hijacking — plus,
        # only when explicit race targets are supplied, the single-packet race engine.
        # Every arsenal finding is oracle-confirmed exactly like a built-in (a smuggle
        # is a fact only when the latency oracle fires on a real hang), so precision is
        # unaffected; the raw-socket modules that bypass the injected `send` are gated
        # host-by-host through `arsenal_authz` (fail-closed).
        self.enable_arsenal = enable_arsenal
        # Host authorization for the RAW-SOCKET arsenal (smuggling/CSWSH/race), which
        # speaks bytes on the wire directly and so does NOT flow through the injected
        # gated `send`. The engage runner sets this to the full authority/kill-switch/
        # scope/posture chain (no traffic); None → loopback-only (the `scan` discipline).
        # A gate that refuses (or errors) means NO probe leaves the box for that host.
        self._arsenal_authz = arsenal_authz
        # The single-packet race engine writes concurrent requests at an action and is
        # therefore DESTRUCTIVE — it is never fired blindly at a swept endpoint (that
        # would be both unsafe and false-positive-prone without a known atomicity limit).
        # It runs only against operator-supplied ``(action_path, max_allowed)`` targets,
        # each still host-gated. Empty (default) → the race engine never runs.
        self.arsenal_race_targets = tuple(arsenal_race_targets)
        # Bound the content-discovery probe count so an arsenal pass stays cheap.
        self.arsenal_max_probes = arsenal_max_probes
        # Opt-in GraphQL DoS/abuse pass (default OFF → the default scan, and the gate,
        # are byte-for-byte unchanged). When on, an ADDITIVE post-audit pass probes each
        # discovered GraphQL endpoint minimally (one bounded query per check: depth,
        # alias, batching, cost) through the gated `send`. Confirmed amplifications
        # (unbounded depth / alias overloading / batching) join active_findings with a
        # predicate-oracle certificate; the honest LEADS (cost, depth-when-introspection-
        # off) populate `graphql_leads`. Minimal by doctrine — it demonstrates the
        # absent guard, it does not flood.
        self.enable_graphql_dos = enable_graphql_dos

    def _resolve_bandit(self) -> ContextualBandit:
        """The explicit bandit, else a warm-start from the persisted file if one
        exists, else a fresh uniform-prior bandit — then folded with any
        cross-engagement transfer priors."""
        if self._explicit_bandit is not None:
            bandit = self._explicit_bandit
        elif self.bandit_path is not None and Path(self.bandit_path).is_file():
            bandit = ContextualBandit.load(Path(self.bandit_path))
        else:
            bandit = ContextualBandit()
        self._seed_transfer(bandit)
        return bandit

    def _seed_transfer(self, bandit: ContextualBandit) -> None:
        """Fold cross-engagement priors into this run's bandit: each prior's
        successes/attempts become Beta evidence on ``(this context, its bug_class)``,
        so a bug class that paid off in past engagements starts ranked higher. A
        prior without a ``bug_class`` is skipped — this never invents an arm.

        Transfer is a ONE-TIME COLD START. An arm that already carries evidence — real
        outcomes, OR a transfer already folded into a PERSISTED (``bandit_path``) bandit
        that was just loaded — is left untouched. Re-seeding it every run would re-inject
        the borrowed pseudo-counts, compounding unboundedly and diluting real learning
        (borrowed evidence must count for LESS than direct, never override repeated real
        disproof). ``observations == 0`` ⇔ the arm is still at the untouched Beta(1,1)
        prior, i.e. genuinely cold."""
        if not self._priors:
            return

        def _key(prior: object) -> tuple[str, str] | None:
            bug_class = getattr(prior, "bug_class", None)
            if not bug_class:
                return None
            arm = str(bug_class)
            if bandit.observations(self.bandit_context, arm) > 0.0:
                return None   # arm already has evidence — do not re-inject borrowed counts
            return (self.bandit_context, arm)

        bandit.seed_from_priors(self._priors, _key)

    def _grammar_requests(self, observed: list[HttpRequest]) -> list[HttpRequest]:
        """Synthesize up to ``grammar_fuzz`` structurally-valid, in-scope requests
        from a grammar induced over the crawled corpus. Deterministic (seeded rng);
        de-duplicated against the observed URLs and each other; scope-filtered so a
        synthesized request can never leave the authorized surface. Robust: an empty
        or ungeneralizable corpus simply yields nothing."""
        try:
            grammar = infer_grammar(observed)
        except Exception:
            return []
        if not grammar.templates:
            return []
        rng = random.Random(self.grammar_fuzz_seed)
        seen = {r.url for r in observed}
        out: list[HttpRequest] = []
        # bounded attempts so a low-entropy grammar cannot loop forever chasing new URLs
        for _ in range(self.grammar_fuzz * 8):
            if len(out) >= self.grammar_fuzz:
                break
            try:
                req = grammar_generate(grammar, rng)
            except Exception:
                break
            if req.url in seen:
                continue
            if self.scope is not None and not self.scope.in_scope(req.url):
                continue
            seen.add(req.url)
            out.append(req)
        return out

    def _maybe_start_browser(self):
        """A started CdpBrowser when a dynamic pass is enabled and a browser
        exists, else None (the passes are then skipped — never guessed)."""
        if not (self.enable_browser_xss or self.enable_spa_crawl):
            return None
        from .cdp import CdpBrowser, cdp_available
        if not cdp_available():
            return None
        try:
            return CdpBrowser(allowed_hosts=self._browser_allowed_hosts).start()
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

    # ---------------------------------------------------------------------
    # opt-in advanced web arsenal (enable_arsenal) — additive, gated, oracle-anchored
    # ---------------------------------------------------------------------

    def _arsenal_host_allowed(self, url: str) -> bool:
        """Fail-closed authorization for the RAW-SOCKET arsenal (smuggling / CSWSH /
        race), which sends bytes on the wire directly and so cannot ride the injected
        gated ``send``. With an ``arsenal_authz`` gate (the engage runner's full
        authority/kill-switch/scope/posture chain) the host must clear it; a refusal
        OR a gate error means no probe leaves the box. Without a gate (loopback
        ``scan``) only loopback hosts are allowed, mirroring the ``scan`` discipline —
        the raw-socket arsenal can never egress off-box unauthorized."""
        if self._arsenal_authz is not None:
            try:
                return bool(self._arsenal_authz(url))
            except Exception:
                return False   # fail closed on a gate error — never assume authorized
        host = (urlsplit(url).hostname or "").lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    @staticmethod
    def _arsenal_finding(confirmed, *, check_id: str, insertion_point: str,
                         param: str, endpoint: str, oracle_context: dict | None) -> AuditFinding:
        """Adapt an oracle-confirmed arsenal result into the same AuditFinding shape
        the built-in checks emit, retaining the serialized FindingContext as the
        re-verifiable certificate."""
        kind = confirmed.confirmed_by
        return AuditFinding(
            check_id=check_id, bug_class=confirmed.bug_class,
            insertion_point=insertion_point, param=param, endpoint=endpoint,
            confidence=confirmed.confidence,
            confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
            rationale=confirmed.rationale,
            oracle_context=oracle_context,
        )

    def _discovery_leads(self, seed_url: str, crawl) -> tuple[list[DiscoveredPath], list[JsSecret], list[str]]:
        """Content discovery (via the gated ``send``) + JS secret/endpoint mining over
        the already-crawled corpus (no extra traffic). All LEADS — reachability and
        references, never confirmed vulnerabilities. Deterministic; robust to a
        partial/absent corpus. Also surfaces mined ws:// endpoints as arsenal leads."""
        from .discovery import discover_content, mine_js

        leads: list[str] = []
        secrets: list[JsSecret] = []
        try:
            sp = urlsplit(seed_url)
            base = f"{sp.scheme}://{sp.netloc}/"
            paths = discover_content(base, self._send, max=self.arsenal_max_probes)
        except Exception:
            paths = []
        seen_secret: set[tuple[str, str]] = set()
        seen_lead: set[str] = set()
        for page in crawl.pages:
            body = page.body or ""
            if not body:
                continue
            try:
                mined = mine_js(body, base_url=page.url)
            except Exception:
                mined = None
            for s in (mined.secrets if mined is not None else []):
                key = (s.kind, s.value)
                if key not in seen_secret:
                    seen_secret.add(key)
                    secrets.append(s)
            # mine_js recognises http(s)/path endpoints; ws:// refs (the CSWSH surface)
            # need a direct scan, so surface them as leads here too.
            for ep in re.findall(r"wss?://[^\s'\"<>)]+", body):
                if ep not in seen_lead:
                    seen_lead.add(ep)
                    leads.append(f"ws-endpoint {ep}")
        return paths, secrets, leads

    def _http_origins(self, seed_url: str, crawl) -> list[tuple[str, int, str]]:
        """The distinct plain-HTTP origins the crawl touched (seed included), as
        ``(host, port, origin_url)``. Only ``http`` origins — the raw-socket
        smuggling/race probes speak cleartext, so ``https`` origins are skipped
        (documented limitation). Bounded and deterministic (first-seen order)."""
        origins: list[tuple[str, int, str]] = []
        seen: set[str] = set()
        urls = [seed_url] + [r.url for r in crawl.requests]
        for u in urls:
            sp = urlsplit(u)
            if sp.scheme != "http" or not sp.hostname:
                continue
            netloc = sp.netloc
            if netloc in seen:
                continue
            seen.add(netloc)
            origins.append((sp.hostname, sp.port or 80, f"http://{netloc}/"))
            if len(origins) >= 8:
                break
        return origins

    def _smuggling_findings(self, origins: list[tuple[str, int, str]]) -> tuple[list[AuditFinding], list[str]]:
        """Probe each authorized origin for HTTP request-smuggling desync and h2c
        capability. A ``detected`` desync is promoted to an oracle-confirmed
        AuditFinding (the latency oracle fired on a real hang); an offered h2c
        upgrade is a capability lead. Every origin clears ``_arsenal_host_allowed``
        first — an unauthorized host is never touched."""
        from .smuggling import detect, detect_h2c_upgrade
        from ..verify.adapter import FindingContext
        from ..verify.confirmation import confirm_finding

        findings: list[AuditFinding] = []
        leads: list[str] = []
        for host, port, origin_url in origins:
            if not self._arsenal_host_allowed(origin_url):
                continue
            try:
                results = detect(host, port)
            except Exception:
                results = []
            for r in results:
                if not r.detected:
                    continue
                ctx = FindingContext.from_http_responses(
                    {"status": 200, "body": "control"}, {"status": 200, "body": "control"},
                    bug_class="request_smuggling",
                    baseline_latency_ms=r.control_ms, mutated_latency_ms=r.probe_ms,
                    discriminator={"dimensions": ["latency"], "latency_threshold_ms": 1500.0})
                confirmed = confirm_finding(
                    {"bug_class": "request_smuggling", "title": f"{r.technique} desync",
                     "severity": "High", "surface": origin_url,
                     "summary": f"{r.technique} timing desync (connection hung on the probe)"},
                    ctx)
                if confirmed is None:
                    continue
                findings.append(self._arsenal_finding(
                    confirmed, check_id=f"smuggling-{r.technique}",
                    insertion_point=f"request:{r.technique}", param=r.technique,
                    endpoint=origin_url, oracle_context=ctx.model_dump(mode="json")))
            try:
                if detect_h2c_upgrade(host, port):
                    leads.append(f"h2c-upgrade offered at {origin_url} (escalate to an h2 tool)")
            except Exception:
                pass
        return findings, leads

    def _ws_candidates(self, seed_url: str, crawl, spa_endpoints: list[str]) -> list[str]:
        """In-scope ws:// / wss:// endpoints to test for CSWSH: mined from crawled
        page bodies and from any SPA-discovered ws endpoints, deduped, restricted to
        the seed host, bounded. No candidates → the WS checks simply do not run."""
        seed_host = urlsplit(seed_url).hostname or ""
        out: list[str] = []
        seen: set[str] = set()

        def _add(u: str) -> None:
            if len(out) >= 8 or u in seen:
                return
            h = urlsplit(u).hostname or ""
            if h and h == seed_host:
                seen.add(u)
                out.append(u)

        for page in crawl.pages:
            for m in re.findall(r"wss?://[^\s'\"<>)]+", page.body or ""):
                _add(m)
        for ep in spa_endpoints:
            token = ep.split(" ", 1)[-1]
            if token.startswith(("ws://", "wss://")):
                _add(token)
        return out

    def _cswsh_findings(self, ws_urls: list[str]) -> list[AuditFinding]:
        """Test each in-scope ws endpoint for Cross-Site WebSocket Hijacking: a
        handshake accepted from a FOREIGN origin (while the trusted origin also
        succeeds) means Origin is not validated. Oracle-confirmed via achieved-state;
        each endpoint clears ``_arsenal_host_allowed`` first."""
        from .websocket import CswshCheck
        from ..verify.adapter import FindingContext

        findings: list[AuditFinding] = []
        for ws_url in ws_urls:
            probe_url = ws_url.replace("ws://", "http://", 1).replace("wss://", "https://", 1)
            if not self._arsenal_host_allowed(probe_url):
                continue
            try:
                confirmed = CswshCheck(url=ws_url).probe()
            except Exception:
                continue
            if confirmed is None:
                continue
            ctx = FindingContext.from_state(
                {"cross_origin_ws_accepted": True}, {"cross_origin_ws_accepted": True},
                bug_class="cross_site_websocket_hijacking")
            findings.append(self._arsenal_finding(
                confirmed, check_id="cswsh", insertion_point=f"websocket:{ws_url}",
                param=ws_url, endpoint=ws_url, oracle_context=ctx.model_dump(mode="json")))
        return findings

    def _race_findings(self, seed_url: str) -> list[AuditFinding]:
        """Fire the single-packet race engine ONLY at operator-supplied
        ``(action_path, max_allowed)`` targets (never a blindly-swept endpoint). An
        action that overran its atomicity limit under the burst is promoted to an
        oracle-confirmed ``request_race`` finding. Each target's origin is host-gated."""
        from .race import race_burst
        from ..verify.adapter import FindingContext
        from ..verify.confirmation import confirm_finding

        if not self.arsenal_race_targets:
            return []
        sp = urlsplit(seed_url)
        base = f"{sp.scheme}://{sp.netloc}"
        findings: list[AuditFinding] = []
        for action_path, max_allowed in self.arsenal_race_targets:
            target_url = urljoin(base + "/", action_path.lstrip("/"))
            if not self._arsenal_host_allowed(target_url):
                continue
            try:
                result = race_burst(base, action_path, max_allowed=int(max_allowed))
            except Exception:
                continue
            if not result.over_run:
                continue
            ctx = FindingContext.from_predicate(
                {"action": action_path, "successes": result.successes, "max_allowed": int(max_allowed)},
                {"gt": [{"var": "successes"}, {"var": "max_allowed"}]},
                bug_class="request_race")
            confirmed = confirm_finding(
                {"bug_class": "request_race", "title": f"Limit-overrun race on {action_path}",
                 "severity": "High", "surface": f"POST {action_path}",
                 "summary": f"action succeeded {result.successes}x under a burst (limit {max_allowed})"},
                ctx)
            if confirmed is None:
                continue
            findings.append(self._arsenal_finding(
                confirmed, check_id="race", insertion_point=f"race:{action_path}",
                param=action_path, endpoint=target_url, oracle_context=ctx.model_dump(mode="json")))
        return findings

    def _arsenal_pass(
        self, seed_url: str, crawl, spa_endpoints: list[str],
    ) -> tuple[list[AuditFinding], list[DiscoveredPath], list[JsSecret], list[str]]:
        """Run the opt-in arsenal and return (confirmed findings, discovered-path
        leads, JS-secret leads, misc leads). Each sub-pass is best-effort and gated;
        a failure in one never sinks the scan. Oracle-confirmed findings flow back
        into active_findings; everything else is a clearly-separated lead."""
        active: list[AuditFinding] = []
        leads: list[str] = []
        paths, secrets, disc_leads = self._discovery_leads(seed_url, crawl)
        leads.extend(disc_leads)

        smug_findings, smug_leads = self._smuggling_findings(self._http_origins(seed_url, crawl))
        active.extend(smug_findings)
        leads.extend(smug_leads)

        active.extend(self._cswsh_findings(self._ws_candidates(seed_url, crawl, spa_endpoints)))
        active.extend(self._race_findings(seed_url))
        return active, paths, secrets, leads

    # ---------------------------------------------------------------------
    # opt-in GraphQL DoS/abuse pass (enable_graphql_dos) — additive, gated,
    # oracle-anchored for the confirmable classes, LEADs for the rest
    # ---------------------------------------------------------------------

    _GRAPHQL_PATH = re.compile(r"/graph(?:ql|iql|ql-explorer|ql-playground)/?$", re.I)

    def _graphql_endpoints(self, seed_url: str, crawl) -> list[str]:
        """The distinct GraphQL-looking endpoint URLs the crawl (and the seed)
        touched — path ends in ``/graphql`` (or a known variant). Deduped by
        scheme+host+path, scope-filtered, bounded. No candidates → the DoS pass
        simply does not run (a non-GraphQL app is never probed)."""
        out: list[str] = []
        seen: set[str] = set()
        urls = [seed_url] + [r.url for r in crawl.requests]
        for u in urls:
            sp = urlsplit(u)
            if not self._GRAPHQL_PATH.search(sp.path or ""):
                continue
            key = f"{sp.scheme}://{sp.netloc}{sp.path}"
            if key in seen:
                continue
            if self.scope is not None and not self.scope.in_scope(u):
                continue
            seen.add(key)
            out.append(key)
            if len(out) >= 8:
                break
        return out

    def _graphql_dos_pass(self, seed_url: str, crawl) -> tuple[list[AuditFinding], list[str]]:
        """Probe each discovered GraphQL endpoint for the DoS/abuse surface. A
        confirmed amplification (a fired predicate oracle) becomes an AuditFinding
        with a re-verifiable certificate; an honest signal that is not a proof
        (cost, or depth when introspection is off) becomes a provenance-tagged
        lead. Each probe is one bounded request through the gated ``send`` — a
        failing check never sinks the pass."""
        from ..verify.confirmation import confirm_finding

        findings: list[AuditFinding] = []
        leads: list[str] = []
        for endpoint in self._graphql_endpoints(seed_url, crawl):
            template = RequestTemplate(HttpRequest(method="POST", url=endpoint))
            for check in GRAPHQL_DOS_CHECKS:
                try:
                    result = check.probe_dos(template, self._send)
                except Exception:
                    continue
                if result.lead:
                    leads.append(f"graphql-dos {check.id} @ {endpoint}: {result.lead}")
                if result.context is None:
                    continue
                confirmed = confirm_finding(
                    {"bug_class": check.bug_class,
                     "title": f"{check.bug_class} at {endpoint}",
                     "severity": "High", "surface": endpoint,
                     "summary": f"{check.id} amplification accepted ({result.reason})"},
                    result.context)
                if confirmed is None:
                    continue
                kind = confirmed.confirmed_by
                findings.append(AuditFinding(
                    check_id=check.id, bug_class=check.bug_class,
                    insertion_point=f"request:{check.id}", param="(request)",
                    endpoint=endpoint, confidence=confirmed.confidence,
                    confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
                    rationale=confirmed.rationale,
                    oracle_context=result.context.model_dump(mode="json")))
        return findings, leads

    def run(self, seed_url: str) -> ScanReport:
        started = time.monotonic()
        if self._progress is not None:
            self._progress.phase("crawl", target=seed_url)
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

            # Grammar-aware fuzzing: induce a request grammar from what the crawl
            # observed and synthesize structurally-valid NEW requests (typed path
            # placeholders + observed params with type-appropriate values). These
            # reach endpoint/param shapes the static crawl never linked to, while
            # staying well-formed enough to exercise real handlers.
            if self.grammar_fuzz > 0:
                all_requests += self._grammar_requests(crawl.requests)

            if self._progress is not None:
                self._progress.phase("audit", surface=len(all_requests),
                                     pages=len(crawl.pages), discovered=len(crawl.requests))

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
                    bandit=bandit, bandit_context=self.bandit_context,
                    waf_adaptive=self.waf_adaptive)
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
                    new_findings = engine.audit(
                        req, checks=active_checks, insertion_kinds=self.insertion_kinds,
                        selector=selector, request_checks=point_request_checks)
                    if self._progress is not None:  # rare event: only on a confirmed finding
                        for f in new_findings:
                            self._progress.finding(f.bug_class, f.confirmed_by, f.param,
                                                   f.endpoint, f.confidence)
                    active.extend(new_findings)
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

            # Opt-in advanced arsenal (default OFF → this whole block is skipped and
            # the run is byte-identical). Additive: its oracle-confirmed findings join
            # active_findings; its leads populate the separate lead lists below.
            discovered_paths: list[DiscoveredPath] = []
            js_secrets: list[JsSecret] = []
            arsenal_leads: list[str] = []
            if self.enable_arsenal:
                a_findings, discovered_paths, js_secrets, arsenal_leads = self._arsenal_pass(
                    seed_url, crawl, spa_endpoints)
                active.extend(a_findings)

            # Opt-in GraphQL DoS/abuse pass (default OFF → skipped, run byte-identical).
            # Additive: confirmed amplifications join active_findings; honest leads
            # (cost / depth-when-introspection-off) populate the separate list below.
            graphql_leads: list[str] = []
            if self.enable_graphql_dos:
                gql_findings, graphql_leads = self._graphql_dos_pass(seed_url, crawl)
                active.extend(gql_findings)
        finally:
            if browser is not None:
                browser.stop()

        elapsed = round(time.monotonic() - started, 3)
        if self._progress is not None:
            self._progress.done(findings=len(active), requests_sent=requests_sent, elapsed_s=elapsed)

        return ScanReport(
            target=seed_url,
            pages_crawled=len(crawl.pages),
            requests_discovered=len(crawl.requests),
            requests_audited=audited,
            audit_requests_sent=requests_sent,
            elapsed_s=elapsed,
            active_findings=active,
            passive_findings=crawl.passive_findings,
            dom_xss_candidates=candidates,
            discovered_endpoints=spa_endpoints,
            discovered_paths=discovered_paths,
            js_secrets=js_secrets,
            arsenal_leads=arsenal_leads,
            graphql_leads=graphql_leads,
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
