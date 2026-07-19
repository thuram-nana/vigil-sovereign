"""Render provider (Phase 8, WS-E E-iii / shared with WS-G) — the JS-render seam, mirroring
`perception.vision.VisionModel`. Only ONE provider is IMPLEMENTED and shipped: `NullRenderer`, which
returns "" (no JS execution, no browser) — so SIGIL's scraper is HTTP-only in practice and a JS-heavy
page is an honest gap, never a silent partial read.

A headless-browser provider is DELIBERATELY NOT implemented: a real browser is a data-egress + attack
surface (it follows redirects, loads third-party subresources, and runs attacker JS — bypassing the
pinned-IP + no-redirect SSRF gate). Should one ever be added it must be off-by-default, owner-opt-in,
re-vet the host with `is_public_host`, run cookieless/credential-free with the correlatable UA, and
block private-IP subresource loads — and if that blocking can't be enforced it must stay disabled. That
is a design note for a future provider, NOT a shipped capability. `needs_js` is the missing-capability
signal that WOULD decide escalation (it is NOT a block signal)."""
from __future__ import annotations

import re
from typing import Optional, Protocol, runtime_checkable

_JS_APP_HINT = re.compile(r"<div[^>]+id=[\"'](root|app|__next)[\"']", re.I)


@runtime_checkable
class RenderProvider(Protocol):
    egresses: bool
    def render(self, url: str) -> str: ...   # returns rendered HTML, or "" on failure/unavailable


class NullRenderer:
    """The default: no JS rendering. Honest empty (never a fabricated render)."""
    egresses = False

    def render(self, url: str) -> str:
        return ""


def needs_js(html: str, *, min_text: int = 200) -> bool:
    """True when a page is a JS-app shell (near-empty server-rendered text but a root/app mount).
    A MISSING-CAPABILITY signal — deliberately disjoint from a block signal, so 'render to beat a
    block' is never a path."""
    from ..agents.sources import _strip_html
    text = _strip_html(html or "")
    return len(text.strip()) < min_text and bool(_JS_APP_HINT.search(html or ""))
