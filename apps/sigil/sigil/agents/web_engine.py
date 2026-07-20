"""Web engine (Phase 8, WS-G G-iii) — HTTP-only. `HttpEngine` reuses the SSRF-gated, IP-pinned,
correlatable-UA `sources.fetch_raw` for the read path and pins the SAME vetted IP for the write path
(so the bytes that were block-checked/hashed and the endpoint that receives credentials are one
address — no DNS-rebinding split). `detect_block` is a BEST-EFFORT flag for a CAPTCHA / 403 / 429 /
CF-challenge; a DETECTED block STOPS + is surfaced as a positive control (it is not a guarantee that
every anti-automation page is recognised — a missed soft-block only ever means the actor proceeds as
approved, never that a block is defeated). This actor is HTTP-only: the ONLY engine implemented here
is `HttpEngine` over `sources.fetch_raw`. It has no browser engine and executes no JavaScript, and no
headless-render fallback exists anywhere on this path — so "use a browser to beat a block" is not a
capability this actor has, rather than a capability it declines to use. `FakeEngine` is the
deterministic double + call spy for tests."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

_BLOCK = re.compile(r"recaptcha|hcaptcha|turnstile|cf-chl|just a moment|attention required|\bcaptcha\b", re.I)


@dataclass
class PageView:
    ok: bool
    status: int
    html: str
    url: str
    resolved_ip: str = ""    # the vetted IP the read used — threaded into act() to bind the write to it


@runtime_checkable
class WebEngine(Protocol):
    egresses: bool
    def fetch(self, url: str) -> PageView: ...
    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict: ...


def detect_block(status: int, html: str) -> Optional[str]:
    """A best-effort block signal (STOP + surface as a positive control — never defeated). Runs BEFORE
    any action. Keys on 403/429 and a fixed anti-automation keyword set; it can MISS a soft-block."""
    if status in (403, 429):
        return f"http-{status}"
    if _BLOCK.search(html or ""):
        return "captcha/anti-automation"
    return None


class HttpEngine:
    egresses = True

    def fetch(self, url: str) -> PageView:
        from .sources import fetch_raw
        r = fetch_raw(url)
        return PageView(r.ok, r.status, r.raw, url, resolved_ip=r.resolved_ip)

    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict:
        """A simple static-form submit (urlencoded POST). Credentials arrive in `resolved` at the last
        instant and go ONLY into the POST body — never the URL, never logged/returned. The socket is
        pinned to `pinned_ip` when the caller supplies the IP its read already vetted (binding the write
        to the block-checked address); otherwise the IP is re-vetted here (fail-closed on private)."""
        import urllib.parse
        import urllib.request
        from urllib.parse import urlsplit
        from .sources import UA, _NoRedirect, _PinnedHTTPHandler, _PinnedHTTPSHandler, _vetted_ip
        url = step.get("url", "")
        ip = pinned_ip or _vetted_ip(urlsplit(url).hostname or "")
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
            return {"ok": False, "reason": f"{type(e).__name__}"}   # type name only — never the body/exception text


class FakeEngine:
    """Deterministic double + spy: `pages` = {url: (status, html)}; records every fetch/act (act records
    the field KEYS and the pinned IP only — never a value)."""
    egresses = True

    def __init__(self, pages: Optional[dict] = None, *, resolved_ip: str = "203.0.113.7"):
        self.pages = pages or {}
        self.resolved_ip = resolved_ip
        self.calls: list = []

    def fetch(self, url: str) -> PageView:
        self.calls.append(("fetch", url))
        st, html = self.pages.get(url, (404, ""))
        return PageView(200 <= st < 300, st, html, url, resolved_ip=self.resolved_ip)

    def act(self, step: dict, resolved: dict, *, pinned_ip: Optional[str] = None) -> dict:
        self.calls.append(("act", step.get("url"), sorted(resolved.keys()), pinned_ip))   # keys + IP only — never values
        return {"ok": True, "status": 200}
