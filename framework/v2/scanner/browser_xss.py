"""
scanner.browser_xss — DOM-XSS confirmed by EXECUTION in a real browser.

Static DOM-XSS analysis (``scanner.domxss``) and reflection oracles find *leads*:
a source flows toward a sink, or a marker is reflected. Neither proves the script
runs — an encoded reflection, a sanitised sink, or a CSP can all defeat a payload
that "looked" injectable. This module proves it: it drives a headless browser
(``scanner.cdp``), injects a payload that — IF it executes — calls a unique CDP
binding with a canary, and confirms via the ``dom_execution`` oracle only when the
browser actually invoked that callback. That is the strongest XSS evidence there
is: real JavaScript execution observed in a real DOM.

The confirmation is a ``verify.FindingContext`` (``from_dom_execution``), so a
browser-confirmed DOM-XSS carries the same re-verifiable certificate every other
CRUCIBLE finding does. Requires a browser (``scanner.cdp.cdp_available``); with
none, callers skip the dynamic path — a browser check never guesses.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..verify.adapter import FindingContext
from .cdp import CdpBrowser, CdpError

# The binding a payload calls on execution. Only the driver registers it, so a
# call carrying the canary is unforgeable proof the injected script ran.
_BINDING = "__crucible_xss"

# Execution payloads. Each renders the canary and, if it reaches an executable
# position, calls the binding. Event-handler payloads (img/onerror, svg/onload)
# execute even when inserted via innerHTML (where a raw <script> would not); the
# breakout and javascript:-URI forms cover attribute and URL-sink contexts.
_PAYLOAD_TEMPLATES: tuple[str, ...] = (
    "<img src onerror=window.{b}('{c}')>",
    "<svg onload=window.{b}('{c}')>",
    "\"><img src onerror=window.{b}('{c}')>",
    "'><svg onload=window.{b}('{c}')>",
    "</script><img src onerror=window.{b}('{c}')>",
    "javascript:window.{b}('{c}')",
)


@dataclass
class DomXssResult:
    """One execution attempt: the payload, where it was injected, whether the
    browser ran it, and the re-verifiable oracle context."""

    payload: str
    canary: str
    injection: str
    executed: bool
    context: FindingContext
    bug_class: str = "dom_xss"


def _inject(url: str, payload: str, *, param: str | None, in_fragment: bool) -> str:
    """Render ``payload`` into ``url`` — into query parameter ``param`` (the app
    decodes it) or the URL fragment (for ``location.hash`` sinks, kept raw)."""
    parts = urlsplit(url)
    if in_fragment:
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, payload))
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    kept.append((param or "q", payload))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(kept), parts.fragment))


def confirm_dom_xss(
    url: str,
    *,
    param: str | None = None,
    in_fragment: bool = False,
    browser: CdpBrowser | None = None,
    payloads: tuple[str, ...] = _PAYLOAD_TEMPLATES,
    settle: float = 0.8,
) -> list[DomXssResult]:
    """Drive execution payloads into ``url`` (via query ``param`` or the fragment)
    in a real headless DOM and return one :class:`DomXssResult` per attempt.

    ``result.executed`` (and the ``dom_execution`` oracle over its ``context``) is
    True only when the browser actually ran the injected script. A shared
    ``browser`` may be passed to amortise launch cost; otherwise one is started and
    torn down here. Raises :class:`CdpError` only if no browser is available."""
    own = browser is None
    br = browser or CdpBrowser().start()
    results: list[DomXssResult] = []
    try:
        sess = br.session()
        sess.add_binding(_BINDING)
        for i, template in enumerate(payloads):
            canary = f"cxss{i:02d}{secrets.token_hex(4)}"
            payload = template.format(b=_BINDING, c=canary)
            target = _inject(url, payload, param=param, in_fragment=in_fragment)
            try:
                sess.navigate(target, settle=settle)
                calls = sess.binding_calls(_BINDING)
            except CdpError:
                calls = []
            ctx = FindingContext.from_dom_execution(calls, canary, bug_class="dom_xss")
            results.append(DomXssResult(
                payload=payload,
                canary=canary,
                injection=f"{'fragment' if in_fragment else 'query:' + (param or 'q')}",
                executed=any(canary in c for c in calls),
                context=ctx,
            ))
    finally:
        if own:
            br.stop()
    return results
