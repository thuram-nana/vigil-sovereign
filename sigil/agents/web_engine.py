"""Web engine (Phase 8, WS-G G-iii) — HTTP-first, headless-browser fallback. `HttpEngine` reuses the
SSRF-gated, IP-pinned, correlatable-UA `sources.fetch_raw` for the light path. `detect_block` flags a
CAPTCHA / 403 / 429 / CF-challenge and is checked BEFORE the escalation decision, so "use the browser
to defeat a block" is structurally unreachable. `BrowserEngine` (lazy Playwright, locked-down, no
stealth/proxy/UA-rotation) is a documented off-by-default seam. `FakeEngine` is the deterministic
double + call spy for tests."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

_BLOCK = re.compile(r"recaptcha|hcaptcha|turnstile|cf-chl|just a moment|attention required|\bcaptcha\b", re.I)
_JS_APP = re.compile(r'id=["\'](root|app|__next)["\']', re.I)


@dataclass
class PageView:
    ok: bool
    status: int
    html: str
    url: str


@runtime_checkable
class WebEngine(Protocol):
    egresses: bool
    def fetch(self, url: str) -> PageView: ...
    def act(self, step: dict, resolved: dict) -> dict: ...


def detect_block(status: int, html: str) -> Optional[str]:
    """A block signal (STOP + surface as a positive control — never defeated). Runs BEFORE escalation."""
    if status in (403, 429):
        return f"http-{status}"
    if _BLOCK.search(html or ""):
        return "captcha/anti-automation"
    return None


def needs_js(html: str, *, min_text: int = 200) -> bool:
    """A MISSING-CAPABILITY signal (escalate to the browser) — deliberately DISJOINT from a block."""
    from .sources import _strip_html
    return len(_strip_html(html or "").strip()) < min_text and bool(_JS_APP.search(html or ""))


class HttpEngine:
    egresses = True

    def fetch(self, url: str) -> PageView:
        from .sources import fetch_raw
        r = fetch_raw(url)
        return PageView(r.ok, r.status, r.raw, url)

    def act(self, step: dict, resolved: dict) -> dict:
        """A simple static-form submit (urlencoded POST). Credentials arrive in `resolved` at the last
        instant and go ONLY into the POST body — never logged/returned."""
        import urllib.parse
        import urllib.request
        from .sources import UA, _NoRedirect, _PinnedHTTPHandler, _PinnedHTTPSHandler, _vetted_ip
        from urllib.parse import urlsplit
        url = step.get("url", "")
        ip = _vetted_ip(urlsplit(url).hostname or "")
        if ip is None:
            return {"ok": False, "reason": "ssrf-refused"}
        data = urllib.parse.urlencode(resolved).encode("utf-8")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedHTTPHandler(ip),
                                             _PinnedHTTPSHandler(ip), _NoRedirect)
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"User-Agent": UA, "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with opener.open(req, timeout=20) as r:
                return {"ok": 200 <= getattr(r, "status", 200) < 400, "status": getattr(r, "status", 200)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "reason": f"{type(e).__name__}"}


class FakeEngine:
    """Deterministic double + spy: `pages` = {url: (status, html)}; records every fetch/act."""
    egresses = True

    def __init__(self, pages: Optional[dict] = None):
        self.pages = pages or {}
        self.calls: list = []

    def fetch(self, url: str) -> PageView:
        self.calls.append(("fetch", url))
        st, html = self.pages.get(url, (404, ""))
        return PageView(200 <= st < 300, st, html, url)

    def act(self, step: dict, resolved: dict) -> dict:
        self.calls.append(("act", step.get("url"), sorted(resolved.keys())))   # keys only — never values
        return {"ok": True, "status": 200}
