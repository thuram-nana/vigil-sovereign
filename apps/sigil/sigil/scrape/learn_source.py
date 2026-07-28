"""
scrape.learn_source — point-at-a-URL learning (K4), a thin wrapper over the sovereign WebResearcher.

The operator gives a URL (or a topic → the curated TRUSTED_LEARN_SOURCES); K4 scopes the crawl to that
host, fetches PUBLIC pages through the existing scope/robots/rate-limit/SSRF gate, and runs EVERY claim
through the identical demote-only ``consolidate.gate.admit``. So nothing a page asserts becomes a fact:
grounded claims serve a BYTE-VERBATIM source span, ungrounded claims are demoted to advisory, and a citation
outside the fetched window is rejected. No offense engine, no Strix web_search — this is the sovereign
scraper's own gated path. Bounded + STOP-able: a small page budget and a kill-switch ``cancel`` hook that
aborts the crawl between hops.
"""

from __future__ import annotations

from typing import Callable, Optional
from urllib.parse import urlsplit

from ..spine.store import SpineStore
from .frontier import Frontier
from .researcher import WebResearcher
from .scope import ScrapeScope

# Curated public documentation sources for topic-learning (when the operator gives WHAT to learn, not a
# URL). Concrete apex hosts only — the scope's `is_public_host` gate still applies. These are references,
# never the target.
TRUSTED_LEARN_SOURCES: tuple[str, ...] = (
    "owasp.org", "cheatsheetseries.owasp.org", "cwe.mitre.org", "capec.mitre.org",
    "attack.mitre.org", "nvd.nist.gov", "osv.dev",
)

# URL-learn is a bounded, synchronous fetch (the owner-action plane is synchronous, like `check_secret`'s
# probe). Keep the page budget small so it stays responsive; expansion is one hop from the seed.
_MAX_PAGES = 4
_MAX_DEPTH = 1


def _summarise(store: SpineStore, res, *, url: str, host: str) -> dict:
    """Read the composed `report` record `research_web` produced → the honest grounded/advisory summary.
    Grounded counts are verbatim-verified; advisory are demoted. Never promotes anything to a fact."""
    out: dict = {"url": url, "host": host, "notes": list(getattr(res, "notes", []) or [])}
    applied = getattr(res, "applied", None) or []
    if applied:
        rec = store.get(applied[-1])
        if rec is not None:
            p = rec.payload
            out.update({"report_seq": applied[-1], "pages_fetched": p.get("pages_fetched"),
                        "grounded": p.get("grounded"), "advisory": p.get("advisory"),
                        "skipped": p.get("skipped"), "text": p.get("text")})
    else:
        out["note"] = "report was not applied (kill-switch engaged or gate refused) — nothing learned"
    return out


def learn_from_url(store: SpineStore, url: str, *, question: str = "", synthesizer=None,
                   cancel: Optional[Callable[[], bool]] = None, max_pages: int = _MAX_PAGES) -> dict:
    """Learn from a single operator-supplied URL. Scopes the crawl to the URL's host (so it can never reach
    another site or an internal/metadata address — `ScrapeScope.admit`'s `is_public_host` gate), fetches at
    most ``max_pages`` public pages, and returns the demote-only grounded/advisory summary. Raises
    ValueError on a non-http(s) URL. ``cancel`` (e.g. the kill-switch) aborts the crawl between hops."""
    parts = urlsplit(url)
    host = (parts.hostname or "").strip().lower()
    if parts.scheme not in ("http", "https") or not host:
        raise ValueError("learn_from_url requires an http(s) URL")
    scope = ScrapeScope([host])                                  # single-host scope; deny-all otherwise
    frontier = Frontier(scope, max_pages=max_pages, max_depth=_MAX_DEPTH, cancel=cancel)
    q = question.strip() or f"security learning about {host}"
    res = WebResearcher(store).research_web(q, [url], scope, synthesizer=synthesizer, frontier=frontier)
    return _summarise(store, res, url=url, host=host)


def learn_from_topic(store: SpineStore, topic: str, *, synthesizer=None,
                     cancel: Optional[Callable[[], bool]] = None, max_pages: int = _MAX_PAGES) -> dict:
    """Learn about a topic from the curated TRUSTED_LEARN_SOURCES (used when the operator gives WHAT to
    learn, not a URL). Scoped to those public documentation hosts; same demote-only grounding."""
    topic = (topic or "").strip()
    if not topic:
        raise ValueError("learn_from_topic requires a topic")
    scope = ScrapeScope(list(TRUSTED_LEARN_SOURCES))
    frontier = Frontier(scope, max_pages=max_pages, max_depth=_MAX_DEPTH, cancel=cancel)
    seeds = [f"https://{h}/" for h in TRUSTED_LEARN_SOURCES]
    res = WebResearcher(store).research_web(topic, seeds, scope, synthesizer=synthesizer, frontier=frontier)
    out = _summarise(store, res, url="", host="trusted-sources")
    out["sources"] = list(TRUSTED_LEARN_SOURCES)
    return out
