"""Frontier (Phase 8, WS-E E-i) — a bounded, scope-gated, VOI-priority crawl. Every candidate passes
ScrapeScope (deny-all + public-only) → robots (respected) → per-host rate limit → SSRF-gated
`fetch_raw` BEFORE a socket opens. Value-of-information ranking (question ↔ anchor+URL-path salient
overlap, minus a depth penalty) spends the page budget on the pages most likely to GROUND an answer,
not blind BFS. Hard caps (max_pages/depth/per-host) + a normalized `seen` set kill runaway crawls and
cycles. Every dropped URL is recorded (robots-skip / out-of-scope / per-host-cap / fetch-error) — a
silent cap would misrepresent coverage."""
from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..agents.sources import fetch_raw
from ..consolidate.gate import salient
from ..reuse import sha256_hex
from . import extract
from .ratelimit import RateLimiter
from .robots import RobotsCache
from .scope import ScrapeScope


def _norm_url(url: str) -> str:
    p = urlsplit(url)
    q = urlencode(sorted(parse_qsl(p.query)))
    return urlunsplit((p.scheme, p.netloc.lower(), p.path or "/", q, ""))     # drop fragment, sort query


def _voi(qtok: set, url: str, anchor: str, depth: int) -> float:
    path = urlsplit(url).path.replace("/", " ").replace("-", " ").replace("_", " ")
    cand = salient(anchor) | salient(path)
    return len(qtok & cand) - 0.5 * depth


@dataclass
class FetchedPage:
    url: str
    status: int
    text: str                      # readable (HTML-stripped) text — what a synthesizer sees
    raw: str                       # raw body (for extraction)
    content_hash: str
    depth: int
    links: List[dict] = field(default_factory=list)


class Frontier:
    def __init__(self, scope: ScrapeScope, *, rate: Optional[RateLimiter] = None,
                 robots: Optional[RobotsCache] = None, fetch: Callable = fetch_raw,
                 max_pages: int = 25, max_depth: int = 3, max_per_host: int = 15,
                 cancel: Optional[Callable[[], bool]] = None):
        self.scope = scope
        self.rate = rate or RateLimiter()
        self.robots = robots or RobotsCache()
        self._fetch = fetch
        self.max_pages, self.max_depth, self.max_per_host = max_pages, max_depth, max_per_host
        # Optional STOP hook (e.g. the kill-switch): checked between hops so a slow crawl aborts promptly.
        # Default None → no check → byte-identical to the prior crawl.
        self._cancel = cancel
        self.skips: List[Tuple[str, str]] = []

    def crawl(self, question: str, seeds: List[str]) -> List[FetchedPage]:
        qtok = salient(question)
        heap: list = []
        seen: set = set()
        per_host: dict = {}
        tie = itertools.count()
        for s in seeds:
            self._push(heap, qtok, s, "", 0, seen, tie)
        results: List[FetchedPage] = []
        while heap and len(results) < self.max_pages:
            if self._cancel is not None and self._cancel():
                self.skips.append(("", "stopped"))     # STOP tripped mid-crawl — abort, record it honestly
                break
            _score, _t, url, depth = heapq.heappop(heap)
            host = self.scope.admit(url)
            if host is None:
                self.skips.append((url, "out-of-scope")); continue
            if per_host.get(host, 0) >= self.max_per_host:
                self.skips.append((url, "per-host-cap")); continue
            if not self.robots.can_fetch(url):
                self.skips.append((url, "robots-disallow")); continue     # RESPECT, never fetch
            self.rate.acquire(host, host_min=self.robots.crawl_delay(url))
            res = self._fetch(url)
            if not res.ok:
                self.skips.append((url, res.reason)); continue
            per_host[host] = per_host.get(host, 0) + 1
            page_links = extract.links(url, res.raw)
            results.append(FetchedPage(url=url, status=res.status, text=extract.main_text(res.raw),
                                       raw=res.raw, content_hash=sha256_hex(res.raw.encode("utf-8", "ignore")),
                                       depth=depth, links=page_links))
            if depth < self.max_depth:
                for lk in page_links:
                    self._push(heap, qtok, lk["url"], lk.get("text", ""), depth + 1, seen, tie)
        # Honesty: record the budget truncation — discovered-but-unfetched URLs are NOT silently
        # dropped (red-pen BLOCK-2). Depth-horizon links are simply never enqueued (bounded by design).
        for _s, _t, url, _d in heap:
            self.skips.append((url, "max-pages-budget"))
        return results

    def _push(self, heap, qtok, url, anchor, depth, seen, tie):
        try:
            nu = _norm_url(url)
        except (ValueError, TypeError):
            return
        if nu in seen or not url.startswith(("http://", "https://")):
            return
        seen.add(nu)
        heapq.heappush(heap, (-_voi(qtok, url, anchor, depth), next(tie), url, depth))
