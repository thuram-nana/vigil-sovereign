"""
framework.v2.engage — the authorized, gated, end-to-end engagement runner.

`scan` (Wave 1) is loopback-only because it issues traffic through a plain local
client. `engage` is its authorized-remote counterpart: it runs the SAME Wave-1
arsenal (crawl + point checks + request-level checks + self-learning bandit), but
every single request flows through the fail-closed safety stack in
`agents.http_executor.HttpExecutor` — authority/kill-switch -> scope -> destructive
-confirm -> per-engagement budget -> posture rate-limit -> egress allowlist. The
scanner's injected `send` IS the gated executor (`HttpExecutor.gated_fetch`), so
the docstring claim the campaign always made becomes literally true here.

Fail-closed by construction:
  * A tripped kill-switch or an out-of-scope seed is refused BEFORE any traffic
    (and every per-request gate still enforces it on every hop).
  * Confirmation stays with the oracle: each finding carries its serialized
    FindingContext (`oracle_context`) so it is independently re-verifiable
    (the Wave-3 `verify` re-verifier).
  * The opt-in operator-hosted OOB relay is used only after its host is checked
    against the charter scope; default stays loopback-only.

    python3 -m framework.v2 engage <slug> <https://authorized-target/seed>
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .agents.http_executor import HttpExecutor, PromptCallback, parse_posture, stdin_prompt_with_timeout
from .agents.scope_gate import validate_action
from .authority.killswitch import KillSwitch
from .scanner.campaign import ScanReport, WebScanCampaign
from .scanner.orchestrator import AttackPath, AutonomousCampaign, ChainedConclusion
from .worldmodel.graph import WorldModel

if TYPE_CHECKING:  # intel types are only referenced in annotations on the default path
    from .intel.predict import AssetHypothesis
    from .intel.resolve import Entity


class EngagementRefused(RuntimeError):
    """The engagement could not start: kill-switch tripped, seed out of scope, or
    a relay host not on the charter allowlist."""


@dataclass
class EngagementResult:
    """The full outcome of an engagement: the oracle-confirmed scan report AND the
    forward reasoning over it. The scan is the hands; ``attack_paths`` are what the
    confirmed facts unlock — the multi-hop routes from the attacker to a crown-jewel
    node, each hop tagged with the technique that established it. Chaining is pure
    reasoning over the report (it sends no traffic), and is best-effort: a chaining
    failure never sinks the engagement, so ``attack_paths`` may be empty while the
    report still stands."""

    report: ScanReport
    attack_paths: list[AttackPath] = field(default_factory=list)
    path_portfolio: list[AttackPath] = field(default_factory=list)
    chained_conclusions: list[ChainedConclusion] = field(default_factory=list)
    # Intelligence Engine (opt-in ``enable_recon``): the resolved asset inventory this
    # engagement observed/discovered, and the GATED prediction queue (where-to-look-next
    # hypotheses — never facts, never auto-scanned). ``world`` is the shared graph the
    # intel recon and the finding-chaining both project onto.
    entities: list["Entity"] = field(default_factory=list)
    predictions: list["AssetHypothesis"] = field(default_factory=list)
    world: WorldModel | None = None


def _no_send(request: object) -> dict:  # pragma: no cover - chaining never sends
    """A send that must never be called: chaining is pure reasoning over an already
    -collected report. If the reasoning ever tries to issue traffic, fail loudly
    rather than silently sending ungated requests."""
    raise RuntimeError("chaining must not issue traffic")


def _origin(url: str) -> str:
    p = urlsplit(url)
    if not p.scheme or not p.netloc:
        raise EngagementRefused(f"seed url must be absolute (scheme://host/...), got {url!r}")
    return f"{p.scheme}://{p.netloc}/"


def preflight(slug: str, seed_url: str) -> None:
    """Fail closed BEFORE any traffic: refuse a tripped kill-switch or an
    out-of-scope seed with a legible reason. The per-request gates still enforce
    this on every hop; this is an early, honest refusal."""
    ks = KillSwitch(slug)
    if ks.is_tripped():
        raise EngagementRefused(f"kill-switch tripped: {ks.reason()}")
    posture = parse_posture(slug)
    decision = validate_action(slug=slug, method="GET", target_url=seed_url, posture=posture)
    if not decision.allowed:
        raise EngagementRefused(
            f"seed out of scope ({decision.refusal_kind}): {decision.reason}")


def _intel_recon(world: WorldModel, slug: str, seed_url: str, *,
                 fixtures_dir: str | None, max_depth: int) -> object:
    """Best-effort intel recon bound to the run's SHARED world-model. Returns the
    `IntelIngest` (bound to ``world``) so the caller can finalize + read the seq
    high-water mark. Pre-scan collector discovery runs only when an offline fixtures
    dir is supplied, in the ReconPlanner's value-of-information order. Collectors query
    THIRD-PARTY sources (never the target), and nothing predicted is ever projected."""
    from .intel.collectors import DEFAULT_COLLECTORS
    from .intel.from_scan import host_ref
    from .intel.ingest import IntelIngest
    from .intel.planner import ReconPlanner
    from .intel.transport import FixtureTransport

    ingest = IntelIngest(world, engagement_slug=slug)
    host = urlsplit(seed_url).hostname or ""
    if fixtures_dir and host:
        ingest.run_collectors(
            [host_ref(host)], list(DEFAULT_COLLECTORS), FixtureTransport(fixtures_dir),
            seq=0, max_depth=max_depth, planner=ReconPlanner(list(DEFAULT_COLLECTORS)))
    return ingest


def _intel_finalize(ingest: object, report: ScanReport) -> tuple[list, list]:
    """Post-scan: register the target + fingerprinted stack the scan observed, resolve
    the asset inventory, and produce the GATED prediction queue. Predictions are never
    projected onto the world-model and never auto-scanned — a where-to-look-next queue."""
    from .intel.from_scan import observations_from_report
    from .intel.predict import AssetPredictor
    from .worldmodel.models import NodeKind

    ingest.ingest(observations_from_report(report, seq=ingest.high_water() + 1))  # type: ignore[attr-defined]
    entities = ingest.resolve(seq=ingest.high_water()).entities                    # type: ignore[attr-defined]
    domains = sorted({m.key for e in entities for m in e.members if m.kind is NodeKind.DOMAIN})
    predictions = AssetPredictor().predict(observed_domains=domains) if domains else []
    return entities, predictions


def run_engagement(
    slug: str,
    seed_url: str,
    *,
    request_budget: int = 200,
    max_pages: int = 100,
    max_audit_requests: int = 0,
    bandit_path: str | None = None,
    enable_domxss: bool = False,
    enable_oob: bool = True,
    enable_browser_xss: bool = False,
    enable_spa_crawl: bool = False,
    oob_advertise_base_url: str | None = None,
    oob_relay_url: str | None = None,
    oob_relay_secret: str | None = None,
    enable_chaining: bool = True,
    enable_recon: bool = False,
    recon_fixtures: str | None = None,
    recon_depth: int = 2,
    detection_budget: float = 2.0,
    waf_adaptive: bool = False,
    grammar_fuzz: int = 0,
    priors: object = None,
    prompt_callback: PromptCallback | None = None,
) -> EngagementResult:
    """Run one authorized engagement end to end and return an
    :class:`EngagementResult` — the oracle-confirmed :class:`ScanReport` plus the
    forward reasoning over it (the attack paths the confirmed facts unlock). Every
    request passes the full gate chain; raises EngagementRefused if the engagement
    may not start.

    With ``enable_chaining`` (default) the confirmed findings are written into a
    world-model and the technique operators are run to a fixpoint to extract
    attacker→crown-jewel attack paths. Chaining sends NO traffic and is best-effort:
    if it fails, the engagement still returns its report with empty paths."""
    preflight(slug, seed_url)

    # Any OOB callback base the target will contact — the advertise host or the
    # collaborator relay — must itself be on the charter allowlist.
    for label, relay in (("advertise", oob_advertise_base_url), ("relay", oob_relay_url)):
        if relay is None:
            continue
        posture = parse_posture(slug)
        d = validate_action(slug=slug, method="GET", target_url=relay, posture=posture)
        if not d.allowed:
            raise EngagementRefused(
                f"OOB {label} host not on charter allowlist ({d.refusal_kind}): {d.reason}")

    # The dynamic browser passes navigate DIRECTLY (not via the gated executor),
    # so on a remote target the browser is confined at the resolver layer to the
    # in-scope host — it cannot pull the browser off to third-party hosts.
    browser_allowed_hosts = {urlsplit(seed_url).hostname} if (enable_browser_xss or enable_spa_crawl) else None
    browser_allowed_hosts = {h for h in (browser_allowed_hosts or set()) if h}

    # The single run-owned world-model: intel recon projects assets onto it, and finding
    # chaining accretes attack facts onto the SAME graph (disjoint id namespaces). Built
    # even when recon is off, so chaining shares it and the result exposes it.
    world = WorldModel()
    ingest = None
    if enable_recon:
        try:
            ingest = _intel_recon(world, slug, seed_url,
                                  fixtures_dir=recon_fixtures, max_depth=recon_depth)
        except Exception:
            ingest = None   # recon is value-add; a recon failure never sinks the engagement

    ex = HttpExecutor(
        engagement_slug=slug,
        base_url=_origin(seed_url),
        auto_load_authority=True,
        request_budget=request_budget,
        prompt_callback=prompt_callback or stdin_prompt_with_timeout,
    )
    try:
        report = WebScanCampaign(
            ex.gated_fetch,
            max_pages=max_pages,
            max_audit_requests=max_audit_requests,
            enable_oob=enable_oob,
            enable_domxss=enable_domxss,
            enable_browser_xss=enable_browser_xss,
            enable_spa_crawl=enable_spa_crawl,
            browser_allowed_hosts=browser_allowed_hosts or None,
            bandit_path=bandit_path,
            bandit_context=slug,
            oob_advertise_base_url=oob_advertise_base_url,
            oob_relay_url=oob_relay_url,
            oob_relay_secret=oob_relay_secret,
            waf_adaptive=waf_adaptive,
            grammar_fuzz=grammar_fuzz,
            priors=priors,
        ).run(seed_url)
    finally:
        ex.close()

    # Post-scan intel: register the observed target + stack, resolve the asset
    # inventory, and produce the gated prediction queue. Best-effort.
    result = EngagementResult(report=report, world=world)
    if enable_recon and ingest is not None:
        try:
            result.entities, result.predictions = _intel_finalize(ingest, report)
        except Exception:
            pass
    # Findings project ABOVE the intel recon band on the shared clock, so the monotonic
    # world-model time never inverts across the recon→scan handoff.
    seq_base = (ingest.high_water() + 1) if (enable_recon and ingest is not None) else 1

    # Forward reasoning over the confirmed facts (no traffic). Best-effort: the
    # scan result is authoritative and must survive any chaining error.
    if enable_chaining:
        try:
            auto = AutonomousCampaign(
                _no_send, detection_budget=detection_budget,
            ).chain_findings(report, world=world, seq_base=seq_base)
            result.attack_paths = auto.attack_paths
            result.path_portfolio = auto.path_portfolio
            result.chained_conclusions = auto.chained_conclusions
        except Exception:
            # chaining is value-add; a reasoning failure never sinks the engagement
            pass
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 engage",
        description="Authorized, fully-gated end-to-end web engagement (the Wave-1 "
                    "arsenal through the charter/scope/kill-switch/egress stack).",
    )
    parser.add_argument("slug", help="Engagement slug (directs charter, scope, evidence, log).")
    parser.add_argument("seed_url", help="Absolute seed URL on an in-scope host.")
    parser.add_argument("--request-budget", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=100)
    parser.add_argument("--max-audit-requests", type=int, default=0)
    parser.add_argument("--bandit-file", default=None,
                        help="Persist/warm-start the self-learning check-ordering bandit.")
    parser.add_argument("--domxss", action="store_true", help="Also emit static DOM-XSS leads.")
    parser.add_argument("--browser-xss", action="store_true",
                        help="Confirm DOM-XSS by real execution in a headless browser "
                             "(browser confined to the in-scope host at the resolver layer).")
    parser.add_argument("--spa", action="store_true",
                        help="Run the SPA crawler to capture fetch/XHR endpoints (browser confined to scope).")
    parser.add_argument("--oob-relay", default=None,
                        help="Operator-hosted, charter-allowlisted OOB callback base URL to ADVERTISE "
                             "(tunnel model; hits delivered to a loopback receiver).")
    parser.add_argument("--oob-relay-url", default=None,
                        help="Operator-hosted OOB COLLABORATOR relay base URL to poll "
                             "(run `collaborator serve`; unlocks blind confirmation on remote targets).")
    parser.add_argument("--oob-relay-secret", default=None,
                        help="Shared secret for the collaborator relay's poll endpoint.")
    parser.add_argument("--no-chaining", action="store_true",
                        help="Skip the forward reasoning pass (do not derive attack paths "
                             "from the confirmed findings). Chaining sends no traffic.")
    parser.add_argument("--waf-adaptive", action="store_true",
                        help="On a filtered/blocked probe, synthesize a bypassing form "
                             "(evasion ladder, then a small GA) that still fires the oracle. "
                             "Spends extra requests; confirmation stays oracle-gated.")
    parser.add_argument("--grammar-fuzz", type=int, default=0, metavar="N",
                        help="Induce a request grammar from the crawl and audit N extra "
                             "structurally-valid synthesized requests (in-scope, deduped).")
    parser.add_argument("--recon", action="store_true",
                        help="Run the Intelligence Engine alongside the scan: resolve an "
                             "asset inventory into the shared world-model and produce a "
                             "GATED prediction queue. Sends no traffic to the target "
                             "(collectors query third-party sources; predictions are never "
                             "auto-scanned).")
    parser.add_argument("--recon-fixtures", default=None, metavar="DIR",
                        help="Offline collector fixtures dir for --recon (DNS/CT/RDAP/ASN). "
                             "Without it, --recon still registers the scanned target + stack.")
    args = parser.parse_args(argv)

    try:
        result = run_engagement(
            args.slug, args.seed_url,
            request_budget=args.request_budget,
            max_pages=args.max_pages,
            max_audit_requests=args.max_audit_requests,
            bandit_path=args.bandit_file,
            enable_domxss=args.domxss,
            enable_browser_xss=args.browser_xss,
            enable_spa_crawl=args.spa,
            oob_advertise_base_url=args.oob_relay,
            oob_relay_url=args.oob_relay_url,
            oob_relay_secret=args.oob_relay_secret,
            enable_chaining=not args.no_chaining,
            enable_recon=args.recon,
            recon_fixtures=args.recon_fixtures,
            waf_adaptive=args.waf_adaptive,
            grammar_fuzz=args.grammar_fuzz,
        )
    except EngagementRefused as e:
        print(f"engagement refused: {e}")
        return 2

    report = result.report
    print(f"engage {args.slug}  {report.target}")
    print(f"  pages crawled     : {report.pages_crawled}")
    print(f"  requests audited  : {report.requests_audited} ({report.audit_requests_sent} sent)")
    print(f"  confirmed findings: {len(report.active_findings)}")
    for f in report.active_findings:
        cert = "cert" if f.oracle_context else "no-cert"
        print(f"    [{f.confirmed_by}/{cert}] {f.bug_class} @ {f.insertion_point} (conf {f.confidence:.2f})")
    if report.passive_findings:
        print(f"  passive findings  : {len(report.passive_findings)}")
    if report.dom_xss_candidates:
        print(f"  dom-xss leads     : {len(report.dom_xss_candidates)} (candidates)")
    # Forward reasoning: the multi-hop attack paths the confirmed facts unlock.
    if result.attack_paths:
        print(f"  attack paths      : {len(result.attack_paths)} (attacker -> crown jewel)")
        for ap in result.attack_paths[:5]:
            print(f"    [{ap.detection_cost:.2f} detect] {ap.describe()}")
    elif result.chained_conclusions:
        print(f"  chained facts     : {len(result.chained_conclusions)} derived (no full path to a crown jewel)")
    # Intelligence Engine: the asset inventory + the gated prediction queue.
    if result.entities:
        owned = [e for e in result.entities if e.owned_by]
        print(f"  intel entities    : {len(result.entities)} resolved"
              + (f", {len(owned)} owner-attributed" if owned else ""))
        for e in result.entities[:5]:
            own = f" owned_by={e.owned_by}" if e.owned_by else ""
            print(f"    [{e.confidence:.2f}] {e.canonical_id} ({len(e.members)} refs){own}")
    if result.predictions:
        print(f"  predictions       : {len(result.predictions)} GATED (never auto-scanned)")
        for p in result.predictions[:5]:
            print(f"    [prior {p.prior:.2f}] {p.node_id} ({p.pattern}) — awaiting operator approval")
    return 0
