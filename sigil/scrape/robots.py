"""RobotsCache (Phase 8, WS-E E-ii) — fetch, parse, and RESPECT robots.txt. Doctrine: respect, NEVER
evade — a Disallowed URL is dropped (recorded as a skip), never fetched, and the site's crawl-delay
raises our rate-limit floor. robots.txt is fetched via the SSRF-gated `sources.fetch_raw` (NOT
`RobotFileParser.read()`, which would make its own UN-vetted, un-pinned request — an SSRF hole).
Fail-closed on ambiguity: a 5xx/429/401/403/network robots → treat the whole host as disallow-all for
this run; a 404/empty robots → allow-all (standard). Cached per host for the run. Stdlib parser, no dep."""
from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

from ..agents.sources import UA, fetch_raw
from .scope import normalize_host

_ALLOW_ALL = "allow-all"
_DISALLOW_ALL = "disallow-all"


class RobotsCache:
    def __init__(self, *, fetch: Callable = fetch_raw, ua: str = UA):
        self._fetch = fetch
        self._ua = ua
        self._cache: dict = {}

    def _rules_for(self, scheme: str, host: str):
        key = (scheme, host)
        if key in self._cache:
            return self._cache[key]
        res = self._fetch(f"{scheme}://{host}/robots.txt")
        rules = self._classify(res)
        self._cache[key] = rules
        return rules

    def _classify(self, res):
        st = res.status
        if st == 0 or 500 <= st < 600 or st in (401, 403, 429):
            return _DISALLOW_ALL                       # ambiguous/blocked → fail-closed (polite + safe)
        if st == 404 or not (res.raw or "").strip():
            return _ALLOW_ALL                          # missing/empty robots → allowed (standard)
        if res.ok:
            rp = RobotFileParser()
            rp.parse((res.raw or "").splitlines())
            return rp
        return _ALLOW_ALL                              # other 4xx → allowed (RFC)

    def can_fetch(self, url: str) -> bool:
        p = urlsplit(url)
        rules = self._rules_for(p.scheme, normalize_host(p.hostname or ""))
        if rules == _DISALLOW_ALL:
            return False
        if rules == _ALLOW_ALL:
            return True
        return rules.can_fetch(self._ua, url)

    def crawl_delay(self, url: str) -> float:
        p = urlsplit(url)
        rules = self._rules_for(p.scheme, normalize_host(p.hostname or ""))
        if not isinstance(rules, RobotFileParser):
            return 0.0
        try:
            d = rules.crawl_delay(self._ua)
        except Exception:  # noqa: BLE001
            return 0.0
        return float(d) if d else 0.0
