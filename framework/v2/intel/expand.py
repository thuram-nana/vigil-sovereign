"""intel.expand — in-loop crawl/mine surface expansion (Phase-1 Slice 2).

A promoted root endpoint (``https://host/``) is testable in principle but exposes no query parameter to
inject into, so the single-check probe mints nothing from it. This closes that gap: it crawls a seed
endpoint — bounded, scope-bound, over the SAME gated send the probe uses — and returns the discovered
in-scope, fuzzable (param-bearing) URLs, which the caller mints as ENDPOINT nodes that flow through the
DiscoveryFrontier into the goal tree. This is what turns "promote the host" into "test the pages and
parameters actually on it" — the compounding step of the discoverer.

REUSE, not rebuild: the crawl is the existing :class:`scanner.crawler.Crawler` (BFS, cycle-safe) bound by
:meth:`scanner.crawler.Scope.from_seed` (same-host, path-prefix — the crawler's own egress boundary), and
the fuzzable requests it already extracts (links + forms → ``CrawlResult.requests``) are the discovered
surfaces. Deterministic (the crawler is BFS in document order, no wallclock / rng), best-effort (any
trouble → ``[]``), and invoked ONLY on the opt-in discover+expand path — off the byte-identical gate.

SAFETY: every fetch rides the injected gated send (production: ``HttpExecutor.gated_fetch`` — charter /
scope / egress / rate / kill-switch gated), and ``Scope.in_scope`` refuses any off-host or non-http link,
so the crawl cannot wander outside the seed's (already in-scope) host.
"""

from __future__ import annotations

from typing import Any

# Conservative in-loop bounds — a discovery crawl is a bounded peek, not a full site sweep (the operator
# raises them explicitly). Kept small so expansion cannot dominate the autonomous budget.
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_DEPTH = 3


def expand_endpoint(send: Any, seed_url: str, *, max_pages: int = DEFAULT_MAX_PAGES,
                    max_depth: int = DEFAULT_MAX_DEPTH) -> list[str]:
    """Crawl ``seed_url`` (bounded, scope-from-seed, over the gated ``send``) and return the discovered
    in-scope fuzzable URLs — deduped + sorted (deterministic). Best-effort: any error → ``[]``.

    Only fuzzable requests (those carrying a query the audit engine can inject into) are returned — a
    bare same-page link with no parameter is not a new testable surface for the value-injecting probe."""
    u = (seed_url or "").strip()
    if not (u.startswith("http://") or u.startswith("https://")):
        return []
    try:
        from ..scanner.crawler import Crawler, Scope
    except Exception:
        return []
    try:
        scope = Scope.from_seed(u)
        result = Crawler(send, scope=scope, max_pages=max(1, int(max_pages)),
                         max_depth=max(1, int(max_depth))).crawl(u)
    except Exception:
        return []
    urls: set[str] = set()
    for req in getattr(result, "requests", []) or []:
        r_url = getattr(req, "url", None)
        if not isinstance(r_url, str):
            continue
        # keep only surfaces that expose an injectable query (the promoted root itself, paramless, adds
        # no new testable value; the crawler's fuzzable requests that carry a query do).
        if "?" in r_url and r_url.split("?", 1)[1].strip():
            urls.add(r_url)
    return sorted(urls)
