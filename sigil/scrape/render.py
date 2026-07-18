"""Render provider (Phase 8, WS-E E-iii / shared with WS-G) — the headless-browser seam for JS-heavy
pages, mirroring `perception.vision.VisionModel`. DEFAULT is `NullRenderer` (returns "" — an honest
gap on a headless box). A `HeadlessRenderer` is a DATA-EGRESS + ATTACK surface (a browser follows
redirects, loads third-party subresources, runs attacker JS — bypassing the pinned-IP + no-redirect
SSRF gate), so it is OFF BY DEFAULT, owner-opt-in, re-vets the host with `is_public_host`, runs
cookieless/credential-free with the correlatable UA, blocks private-IP subresource loads, and — if
that private-IP blocking cannot be enforced by the provider — stays a documented, disabled seam.
`needs_js` is the missing-capability signal that decides escalation (it is NOT a block signal)."""
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
