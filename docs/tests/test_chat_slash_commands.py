"""S6 — composer slash-commands: type "/" for a discovery menu; a leading /command runs an EXISTING gated chat
action instead of sending a message. A slash is a shortcut, never a bypass; an unknown /token is sent as an
ordinary message (never swallowed).

Reads files only (docs-only CI job). The dispatch (known runs, unknown→send, /scan url-vs-path) is verified
against the real sliced registry in a headless jsdom harness.
"""
from __future__ import annotations
from pathlib import Path

APPJS = (Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")


def test_registry_maps_to_existing_actions():
    for cmd in ('"/scan"', '"/url"', '"/plan"', '"/research"', '"/model"', '"/fireteam"', '"/new"'):
        assert cmd in APPJS, f"slash command {cmd} missing"
    # they call existing gated helpers, not new powers
    assert "launchUrlScan(a)" in APPJS and "launchScan(a)" in APPJS and "requestFireteam()" in APPJS


def test_dispatch_and_send_integration():
    assert "function runSlash(msg)" in APPJS
    assert "if (!hit) return false;" in APPJS, "unknown /command must fall through to a normal message"
    assert 'if (msg && msg.charAt(0) === "/" && runSlash(msg)) { input.value = ""; hideSlash(); return; }' in APPJS


def test_discovery_menu_present():
    assert 'h("div.slash-menu"' in APPJS and "function updateSlash()" in APPJS
    assert 'input.addEventListener("input", updateSlash)' in APPJS
