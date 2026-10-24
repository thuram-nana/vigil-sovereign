"""
scanner.browser — headless-browser DOM rendering primitives.

Static analysis (``scanner.domxss``) finds source→sink *candidates*; only a real
DOM shows what actually renders after JavaScript runs. This module drives headless
Chromium/Chrome and returns the post-JavaScript DOM (``render_dom``), plus the
helpers to locate a usable browser (``find_browser``, ``browser_usable``) and the
shared offline launch flags (``OFFLINE_CHROME_FLAGS``). It is the dynamic
cross-check input for the static ``scanner.domxss`` candidates.

This module does NOT confirm DOM-XSS. A marker found in the rendered DOM is
substring detection — the exact false positive the ``DOM_EXECUTION`` oracle exists
to refuse (``dom_xss`` maps to ``DOM_EXECUTION`` only; the side-effect oracle is
never consulted for it). Proven DOM-XSS *execution* is confirmed by
``scanner.browser_xss``: an injected payload calls a unique CDP binding carrying a
per-probe canary — unforgeable proof the script ran — adjudicated by the
``DOM_EXECUTION`` oracle.

Uses only stdlib ``subprocess`` + a Chromium/Chrome binary already on the host; no
CDP client, no npm, no Python browser SDK. If no browser is present, every entry
point returns None (the caller skips — never guesses). Drives the browser only to
operator-authorised URLs (loopback in tests).
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile

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
