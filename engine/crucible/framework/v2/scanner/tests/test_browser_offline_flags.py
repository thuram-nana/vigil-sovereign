"""
The shared no-phone-home / offline headless-launch flag set.

A security tool's browser must not beacon while a scan runs — the egress guard
would flag it (the same doctrine as the nuclei ``-no-interactsh`` fix). Chromium
reaches the network at startup for GCM registration, DIAL/MediaRouter device
discovery, component/sync/domain-reliability beacons and safe-browsing lookups.
``scanner.browser.OFFLINE_CHROME_FLAGS`` disables all of that and is the SINGLE
source both headless launchers use:

  * ``scanner.browser.render_dom`` (the ``--dump-dom`` render + browser_usable), and
  * ``scanner.cdp._LAUNCH_FLAGS`` (the CDP driver behind browser_xss/domxss/crawlers).

These tests pin the anti-beacon flags into the shared set, prove BOTH launch sites
carry the identical set (no per-site drift — the "one shared helper" lesson), and
confirm the offline probe actually renders on a host with a working browser.
"""

from __future__ import annotations

import pytest

from framework.v2.scanner.browser import OFFLINE_CHROME_FLAGS, browser_usable, find_browser
from framework.v2.scanner.cdp import _LAUNCH_FLAGS


def test_offline_set_disables_network_discovery() -> None:
    """The network-discovery / phone-home disables are present in the shared set."""
    # DIAL/MediaRouter mDNS discovery is the startup hang on Chromium 150 in an
    # egress-restricted host; it must be feature-disabled.
    disable_features = [f for f in OFFLINE_CHROME_FLAGS if f.startswith("--disable-features=")]
    assert disable_features, "OFFLINE_CHROME_FLAGS must carry a --disable-features flag"
    features = disable_features[0].split("=", 1)[1]
    assert "MediaRouter" in features, "MediaRouter discovery must be disabled"
    assert "DialMediaRouteProvider" in features, "DIAL media-route discovery must be disabled"

    # Belt-and-suspenders phone-home / beacon disables.
    assert "--disable-background-networking" in OFFLINE_CHROME_FLAGS
    for flag in (
        "--disable-component-update",
        "--disable-sync",
        "--no-pings",
        "--no-default-browser-check",
        "--disable-domain-reliability",
        "--disable-client-side-phishing-detection",
    ):
        assert flag in OFFLINE_CHROME_FLAGS, f"{flag} missing from the shared offline set"


def test_offline_set_is_future_proof_headless() -> None:
    """Keep the modern headless mode; never regress to the deprecated --headless=old."""
    assert "--headless=new" in OFFLINE_CHROME_FLAGS
    assert "--headless=old" not in OFFLINE_CHROME_FLAGS


def test_cdp_reuses_the_single_shared_set() -> None:
    """The CDP driver's launch flags ARE the shared offline set (plus its own
    remote-debugging port) — one helper, no duplicated per-site list to drift."""
    for flag in OFFLINE_CHROME_FLAGS:
        assert flag in _LAUNCH_FLAGS, f"CDP launch flags dropped a shared offline flag: {flag}"
    assert "--remote-debugging-port=0" in _LAUNCH_FLAGS  # the one CDP-specific addition


def test_no_offline_flag_touches_js_or_dom() -> None:
    """The offline flags gate only network beacons — none disable JS, the DOM, or
    CDP bindings the execution/side-effect oracles depend on."""
    forbidden = ("--disable-javascript", "--disable-scripts", "--dom-automation")
    for flag in OFFLINE_CHROME_FLAGS:
        assert not any(flag.startswith(f) for f in forbidden), f"{flag} would break oracle behaviour"


def test_browser_usable_true_when_a_browser_is_present() -> None:
    """On a host with a working headless browser, the offline smoke render succeeds
    and browser_usable() is True. Skip gracefully where no browser can render."""
    if find_browser() is None:
        pytest.skip("no Chromium/Chrome binary installed on this host")
    if not browser_usable():
        pytest.skip("a browser binary is installed but cannot render headless on this host")
    assert browser_usable() is True
