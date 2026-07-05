"""
scanner.browser — dynamic DOM-XSS confirmation via a headless browser.

Static analysis (``scanner.domxss``) finds source→sink *candidates*; only a real
DOM can prove one *fires*. This module drives headless Chromium/Chrome to render a
page with an injected payload and confirms execution by observing the browser's
post-JavaScript DOM — the dynamic half `domxss` deliberately left to a browser.

The confirmation distinguishes execution from mere reflection: the payload is an
``<img onerror>`` whose handler sets a unique attribute on ``<body>``. The raw
payload text always appears in the DOM (reflected); the *rendered attribute*
(``data-<marker>="FIRED"``) appears **only if the handler ran**. The side-effect
oracle looks for that rendered attribute — so a page that puts input in
``textContent`` (safe) does not fire.

Uses only stdlib ``subprocess`` + a Chromium/Chrome binary already on the host; no
CDP client, no npm, no Python browser SDK. If no browser is present, every entry
point returns None (the caller skips — never guesses). Drives the browser only to
operator-authorised URLs (loopback in tests).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import urllib.parse

from ..verify.confirmation import ConfirmedFinding, confirm_finding
from ..verify.adapter import FindingContext

_BROWSERS = ("chromium", "chromium-browser", "google-chrome-stable", "google-chrome", "chrome")


def find_browser() -> str | None:
    """Path to a usable headless Chromium/Chrome, or None."""
    for name in _BROWSERS:
        path = shutil.which(name)
        if path:
            return path
    return None


def render_dom(
    url: str,
    *,
    browser: str | None = None,
    timeout: float = 25.0,
    virtual_time_ms: int = 4000,
) -> str | None:
    """Render ``url`` in headless mode and return the post-JavaScript DOM as HTML
    (or None if no browser / it failed). ``virtual_time_ms`` lets scripts and
    timers run before the DOM is dumped."""
    exe = browser or find_browser()
    if exe is None:
        return None
    with tempfile.TemporaryDirectory(prefix="crucible-hb-") as profile:
        cmd = [
            exe, "--headless=new", "--dump-dom",
            "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
            "--no-first-run", "--no-default-browser-check", "--disable-extensions",
            f"--user-data-dir={profile}",
            f"--virtual-time-budget={int(virtual_time_ms)}",
            url,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603 (argv, no shell)
        except (subprocess.TimeoutExpired, OSError):
            return None
    return result.stdout or None


def scan_dom_xss(
    base_url: str,
    *,
    inject: str = "fragment",
    param: str | None = None,
    browser: str | None = None,
    token: str = "c1",
    timeout: float = 25.0,
) -> ConfirmedFinding | None:
    """Confirm DOM-XSS at ``base_url`` by injecting an execution-marker payload
    (into the URL ``fragment`` or a query ``param``), rendering in a real browser,
    and firing the side-effect oracle iff the handler's rendered attribute appears
    in the post-JS DOM. Returns the ConfirmedFinding, or None (not vulnerable / no
    browser)."""
    exe = browser or find_browser()
    if exe is None:
        return None

    marker = f"cruciblexss{token}"
    payload = f"<img src=x onerror=\"document.body.setAttribute('data-{marker}','FIRED')\">"
    encoded = urllib.parse.quote(payload, safe="")
    if inject == "fragment":
        url = f"{base_url}#{encoded}"
    else:
        if not param:
            raise ValueError("param is required when inject != 'fragment'")
        sep = "&" if "?" in base_url else "?"
        url = f"{base_url}{sep}{param}={encoded}"

    dom = render_dom(url, browser=exe, timeout=timeout)
    if dom is None:
        return None

    exec_marker = f'data-{marker}="FIRED"'  # the RENDERED attribute — proof of execution
    ctx = FindingContext.from_side_effect(exec_marker, dom, bug_class="dom_xss")
    return confirm_finding(
        {
            "bug_class": "dom_xss",
            "title": "DOM-based XSS (dynamic, browser-confirmed)",
            "severity": "High",
            "surface": f"{inject}:{param or 'location.hash'}",
            "summary": "an injected payload executed in a real browser DOM",
        },
        ctx,
    )
