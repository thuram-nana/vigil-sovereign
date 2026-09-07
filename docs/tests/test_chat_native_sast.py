"""Wave 5 — the chat can launch the DETERMINISTIC DAA codebase scan (`vigil codescan` — static rules →
signed spine, fix-enabled), distinct from the vendored Strix codebase mode.

Docs-only drift guard (reads files, no framework import): pins the end-to-end wiring across the three
layers so a rename cannot silently break the chat's source-review affordance.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CHAT = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "chat.py").read_text(encoding="utf-8")
ACTIONS = (REPO / "engine" / "crucible" / "framework" / "v2" / "console" / "actions.py").read_text(encoding="utf-8")


def test_actions_declares_sast_mode_and_runs_deterministic_codescan():
    assert '"sast"' in ACTIONS and 'mode == "sast"' in ACTIONS, "the sast launch branch is gone"
    # the branch runs the ENGINE's own deterministic DAA codebase scan (vigil codescan), not Strix, writing
    # the signed spine + capturing the findings report, and validates the path
    assert '"codescan"' in ACTIONS and '"--root"' in ACTIONS and '"--base-dir"' in ACTIONS
    assert 'capture_report=True' in ACTIONS, "the codescan findings must be captured to report.json"
    assert "source-review path does not exist" in ACTIONS, "the sast path must be validated"


def test_chat_offers_scan_sast_with_a_server_computed_target():
    assert '"scan_sast"' in CHAT, "scan_sast is not an allowed proposal"
    # the SAME security rule as scan_codebase: the filesystem target is server-computed, never the model's
    assert 'key = ("scan_sast", offer_target)' in CHAT
    assert 'spec["target"] = offer_target' in CHAT


def test_app_wires_the_scan_sast_chip_to_launchSast_with_mode_sast():
    assert "function launchSast(path)" in APPJS, "launchSast is gone"
    assert 'action === "scan_sast"' in APPJS and "launchSast(String(p.target" in APPJS
    # launchSast posts the native-review mode, distinct from launchScan's codebase (Strix) mode
    assert 'target: path, mode: "sast",' in APPJS
