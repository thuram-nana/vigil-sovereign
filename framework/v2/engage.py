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
from urllib.parse import urlsplit

from .agents.http_executor import HttpExecutor, PromptCallback, parse_posture, stdin_prompt_with_timeout
from .agents.scope_gate import validate_action
from .authority.killswitch import KillSwitch
from .scanner.campaign import ScanReport, WebScanCampaign


class EngagementRefused(RuntimeError):
    """The engagement could not start: kill-switch tripped, seed out of scope, or
    a relay host not on the charter allowlist."""


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
    oob_advertise_base_url: str | None = None,
    prompt_callback: PromptCallback | None = None,
) -> ScanReport:
    """Run one authorized engagement end to end and return the ScanReport. Every
    request passes the full gate chain; raises EngagementRefused if the engagement
    may not start."""
    preflight(slug, seed_url)

    if oob_advertise_base_url is not None:
        # The relay URL is embedded in blind-check payloads and thus contacted by
        # the target — it must itself be in charter scope.
        posture = parse_posture(slug)
        d = validate_action(slug=slug, method="GET", target_url=oob_advertise_base_url, posture=posture)
        if not d.allowed:
            raise EngagementRefused(
                f"OOB relay host not on charter allowlist ({d.refusal_kind}): {d.reason}")

    ex = HttpExecutor(
        engagement_slug=slug,
        base_url=_origin(seed_url),
        auto_load_authority=True,
        request_budget=request_budget,
        prompt_callback=prompt_callback or stdin_prompt_with_timeout,
    )
    try:
        return WebScanCampaign(
            ex.gated_fetch,
            max_pages=max_pages,
            max_audit_requests=max_audit_requests,
            enable_oob=enable_oob,
            enable_domxss=enable_domxss,
            bandit_path=bandit_path,
            bandit_context=slug,
            oob_advertise_base_url=oob_advertise_base_url,
        ).run(seed_url)
    finally:
        ex.close()


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
    parser.add_argument("--oob-relay", default=None,
                        help="Operator-hosted, charter-allowlisted OOB callback base URL "
                             "(unlocks blind-class confirmation on remote targets).")
    args = parser.parse_args(argv)

    try:
        report = run_engagement(
            args.slug, args.seed_url,
            request_budget=args.request_budget,
            max_pages=args.max_pages,
            max_audit_requests=args.max_audit_requests,
            bandit_path=args.bandit_file,
            enable_domxss=args.domxss,
            oob_advertise_base_url=args.oob_relay,
        )
    except EngagementRefused as e:
        print(f"engagement refused: {e}")
        return 2

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
    return 0
