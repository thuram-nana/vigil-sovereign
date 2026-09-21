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

import posixpath
from typing import Any
from urllib.parse import urlsplit

# Conservative in-loop bounds — a discovery crawl is a bounded peek, not a full site sweep (the operator
# raises them explicitly). Kept small so expansion cannot dominate the autonomous budget.
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_DEPTH = 3


def expand_endpoint(send: Any, seed_url: str, *, max_pages: int = DEFAULT_MAX_PAGES,
                    max_depth: int = DEFAULT_MAX_DEPTH) -> list[str]:
    """Crawl ``seed_url`` (bounded, scope-from-seed, over the gated ``send``) and return the discovered
    in-scope surfaces — deduped + sorted (deterministic). Best-effort: any error → ``[]``.

    From the HTML crawl, only fuzzable requests (those carrying a query the audit engine can inject into)
    are returned — a bare same-page link with no parameter is not a new testable surface for the value-
    injecting probe. In ADDITION (#799), the machine-readable surface maps the HTML crawler is blind to —
    ``/sitemap.xml`` and ``/openapi.json`` — are mined over the SAME gated ``send`` and their in-scope
    surfaces folded in under the same scheme/host/prefix containment filter, so an endpoint listed only in
    a sitemap or OpenAPI spec (never linked from a page) is still discovered and tested."""
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
    # Containment + OPSEC filter (review wcqss59lb): the shared Scope.in_scope binds the crawl to the
    # seed HOST but not the seed SCHEME, and its path-prefix test is a raw ``startswith`` on the
    # un-normalised path. So mint only surfaces that (a) keep the seed SCHEME (never downgrade https→http
    # — a TLS-seeded engagement must not emit or queue cleartext), (b) keep the seed HOST, and (c) whose
    # NORMALISED path stays under the seed's path-prefix subtree (a ``..`` cannot escape it). Belt-and-
    # suspenders in expand (does not touch the shared crawler); the per-request gate still re-authorises.
    seed = urlsplit(u)
    seed_scheme = seed.scheme.lower()
    seed_netloc = seed.netloc.lower()
    seed_prefix = seed.path.rsplit("/", 1)[0] + "/" if "/" in seed.path else "/"
    norm_prefix = posixpath.normpath(seed_prefix)   # "/app/" -> "/app"; "/" -> "/"

    def _under_prefix(path: str) -> bool:
        np = posixpath.normpath(path or "/")
        if norm_prefix == "/":
            return True
        return np == norm_prefix or np.startswith(norm_prefix + "/")

    def _contained(candidate: str) -> bool:
        """scheme + host + normalised-prefix containment (no https→http downgrade, same host,
        path under the seed subtree). The per-request gate still re-authorises every fetch."""
        try:
            csp = urlsplit(candidate)
        except Exception:
            return False
        if csp.scheme.lower() != seed_scheme:      # no scheme downgrade (https seed must not mint http)
            return False
        if csp.netloc.lower() != seed_netloc:      # same host+port as the seed (defense-in-depth)
            return False
        return _under_prefix(csp.path)             # normalised path must remain under the seed subtree

    urls: set[str] = set()
    for req in getattr(result, "requests", []) or []:
        r_url = getattr(req, "url", None)
        if not isinstance(r_url, str):
            continue
        # keep only surfaces that expose an injectable query (the promoted root itself, paramless, adds
        # no new testable value; the crawler's fuzzable requests that carry a query do).
        if not ("?" in r_url and r_url.split("?", 1)[1].strip()):
            continue
        if _contained(r_url):
            urls.add(r_url)

    # #799 — the HTML crawler is BLIND to machine-readable surface maps: an endpoint listed only in
    # /sitemap.xml or /openapi.json (never linked from a crawled page) is invisible to it. Mine both,
    # relative to the seed ORIGIN, over the SAME gated ``send`` (charter/scope/egress/rate/kill-switch),
    # and fold the in-scope surfaces they name into the returned set under the SAME containment filter.
    # SAFETY: sitemap is parsed by a plain <loc> regex — NOT an XML parser — so no external-entity /
    # billion-laughs expansion is possible from a hostile sitemap (XXE-proof by construction).
    seed_origin = f"{seed_scheme}://{seed_netloc}"
    for surface_path, kind in (("sitemap.xml", "xml"), ("openapi.json", "openapi")):
        try:
            for durl in _mine_surface_map(send, seed_origin, surface_path, kind):
                if _contained(durl):
                    urls.add(durl)
        except Exception:
            continue   # best-effort: a missing/hostile surface map never breaks expansion
    return sorted(urls)


def _mine_surface_map(send: Any, seed_origin: str, surface_path: str, kind: str) -> list[str]:
    """Fetch ``<seed_origin>/<surface_path>`` over the gated ``send`` and return the absolute in-scope-ish
    surfaces it names (containment is applied by the caller). ``kind`` picks the parser: ``xml`` reads
    sitemap ``<loc>`` entries by regex (no XML parser → no XXE); ``openapi`` reads the JSON ``paths`` keys
    (concrete paths only — templated ``/{id}`` surfaces are skipped, they are not fetchable URLs)."""
    import re
    from urllib.parse import urljoin

    from ..scanner.insertion import HttpRequest

    probe_url = f"{seed_origin}/{surface_path}"
    try:
        resp = send(HttpRequest(method="GET", url=probe_url))
    except Exception:
        return []
    if not isinstance(resp, dict) or int(resp.get("status", 0) or 0) != 200:
        return []
    body = resp.get("body", "") or ""
    if not isinstance(body, str) or not body.strip():
        return []

    out: list[str] = []
    if kind == "xml":
        # sitemap / sitemap-index: every <loc>…</loc>. Regex, NOT an XML parser (no external-entity /
        # billion-laughs expansion). A spec-compliant sitemap uses ABSOLUTE URLs, but many real apps emit
        # ROOT-RELATIVE locs (e.g. ``<loc>/records/search</loc>``); resolve those against the seed ORIGIN so
        # a relative-sitemap app's endpoints are still mined (the caller's scheme+host+prefix containment
        # filter re-checks every candidate, so a cross-origin or off-subtree <loc> is dropped regardless).
        for loc in re.findall(r"<loc>\s*([^<>\s]+)\s*</loc>", body, flags=re.IGNORECASE):
            loc = loc.strip()
            if loc.startswith("http://") or loc.startswith("https://"):
                out.append(loc)
            elif loc.startswith("/"):
                # ``urljoin`` resolves a root-relative ``/path`` against the seed origin, AND a
                # protocol-relative ``//host/path`` to that OTHER host (which the caller's containment
                # filter then drops) — so no lstrip, which would mangle ``//host`` into an in-host path.
                out.append(urljoin(seed_origin + "/", loc))
    elif kind == "openapi":
        import json
        try:
            doc = json.loads(body)
        except Exception:
            return []
        paths = doc.get("paths") if isinstance(doc, dict) else None
        if isinstance(paths, dict):
            for p in paths:
                if not isinstance(p, str) or not p.startswith("/"):
                    continue
                if "{" in p or "}" in p:           # templated → not a concrete fetchable URL
                    continue
                out.append(urljoin(seed_origin + "/", p.lstrip("/")))
    return out
