"""
scanner.browser_crawler — JS-aware (SPA) crawling via the headless browser.

The static crawler parses the HTML the server sent. Modern apps build most of
their navigation in JavaScript — a React/Vue router, a menu injected after load,
links assembled from a fetched JSON — none of which is in that initial HTML. Burp
solves this with an embedded Chromium; we already have one (``scanner.browser``).

The insight is that the crawler is built around a ``send`` callable, so JS-aware
crawling needs no new crawler: :func:`browser_send` renders each URL in headless
Chromium and returns the **post-JavaScript DOM** as the response body. Hand it to
the existing :class:`Crawler` and its link extraction now sees the rendered nav —
SPA routes, JS-injected ``<a href>``, forms built at runtime — that a static fetch
misses.

No browser present ⇒ ``browser_send`` returns an empty body (the crawl finds
nothing extra rather than guessing). Renders only operator-authorised URLs.
"""

from __future__ import annotations

from .browser import find_browser, render_dom
from .checks import Send
from .crawler import CrawlResult, Crawler, Scope
from .insertion import HttpRequest


def browser_send(*, browser: str | None = None, timeout: float = 25.0) -> Send:
    """A ``send`` that renders each request's URL in a headless browser and
    returns ``{status, body}`` where ``body`` is the post-JS DOM. Drop-in for the
    Crawler so it crawls the rendered app instead of the raw HTML."""
    exe = browser or find_browser()

    def send(req: HttpRequest) -> dict:
        dom = render_dom(req.url, browser=exe, timeout=timeout) if exe is not None else None
        return {"status": 200 if dom is not None else 0, "headers": [], "body": dom or ""}

    return send


class BrowserCrawler:
    """A JS-aware crawler: the same graph-based crawl, but every page is rendered
    in a headless browser first, so links that only exist after JavaScript runs
    are discovered. Falls back to finding nothing extra when no browser is present
    (check :func:`framework.v2.scanner.browser.find_browser`)."""

    def __init__(
        self,
        *,
        scope: Scope | None = None,
        browser: str | None = None,
        timeout: float = 25.0,
        max_pages: int = 100,
        max_depth: int = 6,
    ) -> None:
        self._crawler = Crawler(
            browser_send(browser=browser, timeout=timeout),
            scope=scope, max_pages=max_pages, max_depth=max_depth,
        )

    def crawl(self, seed_url: str) -> CrawlResult:
        return self._crawler.crawl(seed_url)
