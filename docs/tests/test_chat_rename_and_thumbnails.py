"""S12 rename-via-modal (not window.prompt) + S11 image attachment thumbnails. Reads files only."""
from __future__ import annotations
from pathlib import Path
APPJS = (Path(__file__).resolve().parents[2] / "packages" / "vigil-ui" / "app.js").read_text(encoding="utf-8")

def test_rename_uses_a_modal_not_window_prompt():
    assert 'openModal("Rename chat"' in APPJS, "rename must use the modal"
    # the old window.prompt rename path is gone
    assert 'window.prompt("Rename chat:"' not in APPJS

def test_image_attachments_get_a_local_thumbnail():
    assert "a.previewUrl = URL.createObjectURL(f)" in APPJS, "no local object-URL thumbnail"
    assert 'h("img.att-thumb"' in APPJS, "thumbnail not rendered in the chip"
    assert 'f.type.indexOf("image/") === 0' in APPJS, "thumbnail should be gated to image types"
