"""Professional chat-screen layout: transcript (focus) → docked composer card → secondary context → collapsed
engine settings; a tidy sessions rail. Layout lives in CSS classes, not scattered inline styles.

Reads files only. Rendering is verified in a headless jsdom harness; this guards the structure + that the
system-wide engine controls are tucked into a collapsed disclosure (not dominating the top).
"""
from __future__ import annotations
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APPJS = (REPO / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")
CSS = (REPO / "packages" / "vigil-ui" / "components.css").read_text(encoding="utf-8")


def test_clean_main_column_order():
    # transcript, then the docked composer card, then context, then the collapsed engine settings
    assert "V.mount(host, [askBanner, list, dock, contextPanels, engineSettings]);" in APPJS
    assert 'h("div.chat-dock"' in APPJS and 'h("div.chat-context"' in APPJS


def test_engine_settings_are_collapsed_not_top_of_screen():
    assert 'h("details.chat-engine-settings"' in APPJS, "system-wide controls must be a collapsed disclosure"
    assert "system-wide (not this chat)" in APPJS


def test_run_options_are_a_compact_disclosure():
    assert 'h("details.chat-runopts"' in APPJS


def test_layout_is_class_driven_not_inline():
    # the shell + transcript no longer carry big inline style blobs
    assert 'h("div#chat-wrap", null,' in APPJS
    assert 'h("div#chat-list.dropzone.chat-transcript", null,' in APPJS
    for sel in ("#chat-wrap", ".chat-dock", ".chat-context", ".chat-engine-settings", ".chat-session", "#chat-list.chat-transcript"):
        assert sel in CSS, f"missing layout class {sel}"


def test_sidebar_is_tidied():
    assert 'h("div.chat-rail-cap", null, "Chats")' in APPJS
    assert 'h("button.chat-session"' in APPJS
