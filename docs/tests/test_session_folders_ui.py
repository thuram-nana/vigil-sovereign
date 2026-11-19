"""Session FOLDERS UI (``VIGIL_SESSION_FOLDERS``): the chat rail and the Sessions screen organise chats and
sessions into operator-named folders. Reads files only (the briefing job installs only pytest).

Pins that the UI (a) consumes every folder route, (b) asks through the focus-managed modal — never
``window.prompt`` / ``window.confirm``, (c) renders EXACTLY the pre-folders views while the feature is off
(a 404 from ``/api/folders`` is the off signal, remembered so the probe is made once), (d) drags a chat with
a private type that the attachment drop guard ignores and that a folder accepts exclusively, and (e) ships
the icons and styles it uses.
"""
from __future__ import annotations

import re
from pathlib import Path

UI = Path(__file__).resolve().parents[2] / "packages" / "vigil-ui"
APPJS = (UI / "app.js").read_text(encoding="utf-8")
UIJS = (UI / "ui.js").read_text(encoding="utf-8")
CSS = (UI / "components.css").read_text(encoding="utf-8")


def _between(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


# the shared folder helpers + the Sessions screen, and the chat rail's folder code (inside renderChat)
SHARED = _between(APPJS, "// ---- Session FOLDERS (VIGIL_SESSION_FOLDERS, default-OFF)", "function connectSession(s, rows)")
RAIL = _between(APPJS, "const CHAT_DRAG = ", "function renameChat(s)")


def test_every_folder_route_is_consumed():
    for route in ('OFF("/api/folders")', 'OFF("/api/folder/create")', 'OFF("/api/folder/rename")',
                  'OFF("/api/folder/delete")', 'OFF("/api/session/folder")'):
        assert route in APPJS, route


def test_folder_dialogs_use_the_modal_never_prompt_or_confirm():
    for block in (SHARED, RAIL):
        assert "window.prompt" not in block and "window.confirm" not in block
    assert 'folderNameDialog("New folder"' in SHARED and 'folderNameDialog("Rename folder"' in SHARED
    assert 'openModal("Delete folder"' in SHARED and 'openModal("Move ‘"' in SHARED


def test_a_404_is_the_off_signal_and_is_remembered():
    assert "e.status === 404" in SHARED and "FOLDERS_OFF = true" in SHARED
    assert "if (FOLDERS_OFF) return Promise.resolve({ on: false" in SHARED


def test_off_renders_the_pre_folders_views():
    # chat rail: with folders off a row is exactly [open, rename, delete] and drawSessions never branches
    assert ('if (!C.foldersOn) return h("div.chat-session-row" + (active ? ".on" : ""), null, '
            '[main, rn, del]);') in RAIL
    assert "if (C.foldersOn) { drawFolderedSessions(host); return; }" in RAIL
    # Sessions screen: no folder context ⇒ the extra card button is null and the grid is unchanged
    assert "if (fs && fs.on) { drawFolderedSessionList(host, rows, fs.folders || []); return; }" in SHARED
    assert 'ctx ? h("button.btn"' in SHARED and "return sessionCard(s, rows, null);" in SHARED


def test_deleting_a_folder_says_nothing_inside_is_deleted():
    assert "Nothing inside is deleted" in SHARED


def test_chat_drag_uses_a_private_type_the_file_drop_guard_ignores():
    m = re.search(r'const CHAT_DRAG = "([^"]+)";', RAIL)
    assert m and m.group(1) != "Files" and "/" in m.group(1)
    assert "e.dataTransfer.setData(CHAT_DRAG, s.id)" in RAIL
    assert "indexOf.call(types, CHAT_DRAG) !== -1" in RAIL and "if (!isChatDrag(e)) return;" in RAIL


def test_a_dangling_folder_renders_unfiled():
    assert "function folderIdIn(folders, fid)" in SHARED
    assert "function folderOf(s) { return folderIdIn(C.folders, s && s.folder); }" in RAIL


def test_icons_and_styles_ship():
    for name in ("folder:", '"folder-plus":', '"chev-right":', '"chev-down":'):
        assert name in UIJS, name
    for cls in (".chat-folder-h", ".chat-folder-t", ".chat-folder-item", ".drop-on", ".folder-pick",
                ".session-folder", ".session-folder-h", ".chat-rail-top"):
        assert cls in CSS, cls
