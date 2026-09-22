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

# ---------------------------------------------------------------------------
# One shared headless-launch flag set for EVERY launcher in the scanner.
#
# Two jobs, both belonging to every launcher:
#
#   1. Headless / sandbox-tolerant operation (`--headless=new`, `--no-sandbox`,
#      `--disable-gpu`, `--disable-dev-shm-usage`, `--disable-extensions`,
#      `--no-first-run`).
#
#   2. NO phone-home / network discovery. A security tool's browser must not
#      beacon while a scan runs: the egress guard would flag it, exactly the
#      doctrine behind the nuclei `-no-interactsh` fix. At startup Chromium reaches
#      the network for GCM registration, DIAL/MediaRouter device discovery,
#      component/sync/domain-reliability beacons and safe-browsing lookups; those
#      are disabled here by flag and by `--disable-features`. On Chromium 150
#      `--disable-background-networking` ALONE is not sufficient, so the
#      DIAL/MediaRouter discovery (`MediaRouter,DialMediaRouteProvider`) and the
#      rest are disabled explicitly.
#
# Defined ONCE and imported by scanner.cdp (and used by render_dom below) so the
# CDP driver and the --dump-dom render carry the IDENTICAL set — the "a class-bug
# recurs at each unguarded launch site → one shared helper" lesson. None of these
# flags touch page JS execution, the DOM, or CDP bindings.
#
# Launch-site-specific flags are NOT here: `--dump-dom`/`--virtual-time-budget`
# (render_dom) and `--remote-debugging-port=0` (the CDP driver) are added by each
# site, and `--user-data-dir` is per-invocation.
OFFLINE_CHROME_FLAGS: tuple[str, ...] = (
    "--headless=new",                 # future-proof headless (NOT the deprecated --headless=old)
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--no-first-run",
    # --- no phone-home / no network discovery ---
    "--disable-background-networking",
    "--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider",
    "--disable-component-update",
    "--disable-sync",
    "--no-pings",
    "--no-default-browser-check",
    "--disable-domain-reliability",
    "--disable-default-apps",
    "--disable-client-side-phishing-detection",
)


def find_browser() -> str | None:
    """Path to an INSTALLED headless Chromium/Chrome, or None. Installed is not the same as usable — see
    :func:`browser_usable`."""
    for name in _BROWSERS:
        path = shutil.which(name)
        if path:
            return path
    return None


_USABLE: bool | None = None


def browser_usable(*, timeout: float = 25.0) -> bool:
    """Whether a headless browser is not merely INSTALLED but actually able to render.

    ``find_browser()`` only proves a binary is on PATH. A CI runner can ship Chrome that then fails to start
    (container sandbox, missing shared libraries, no writable profile dir), so a browser-dependent test
    guarded on ``find_browser() is None`` alone FAILS there instead of skipping — which is what happened the
    first time the scanner suite was wired into CI. This does one bounded smoke render of a ``data:`` URL and
    caches the answer for the process."""
    global _USABLE
    if _USABLE is None:
        try:
            dom = render_dom("data:text/html,<b id=probe>ok</b>", timeout=timeout, virtual_time_ms=0)
        except Exception:          # noqa: BLE001 — a probe must never break collection; treat as unusable
            dom = None
        _USABLE = bool(dom and "probe" in dom)
    return _USABLE


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
    # ignore_cleanup_errors: the browser can still be flushing its profile when we return, and a failed
    # rmtree used to escape as OSError("Directory not empty") — a render helper must never raise at teardown.
    with tempfile.TemporaryDirectory(prefix="crucible-hb-", ignore_cleanup_errors=True) as profile:
        cmd = [
            exe, *OFFLINE_CHROME_FLAGS, "--dump-dom",
            f"--user-data-dir={profile}",
        ]
        # `--virtual-time-budget=N` runs scripts/timers for N virtual ms before the
        # dump. A budget of 0 is degenerate: on Chromium 150 the DOM dump never
        # fires (the smoke render in browser_usable(), which passes 0, then hangs
        # until the subprocess timeout — the reason browser_usable() returned False
        # on a host with a working browser). Omit the flag for a non-positive budget
        # so those callers get a plain load-then-dump; real callers pass a positive
        # budget and keep virtual-time behaviour unchanged.
        vtb = int(virtual_time_ms)
        if vtb > 0:
            cmd.append(f"--virtual-time-budget={vtb}")
        cmd.append(url)
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
