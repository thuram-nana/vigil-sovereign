"""The operator console shows the owner's logo: `assemble_serve_dir` copies packages/vigil-ui/brand/ (image files
only, byte-for-byte) into the serve dir and counts them in the build id, the proxy serves them with their image
types, and the shipped console names its favicon and header mark from there.
"""
from __future__ import annotations

import os
import socket
import threading
import urllib.request
from pathlib import Path

import pytest

from vigil_integration import uiproxy

REPO = Path(__file__).resolve().parents[2]
KIT = REPO / "packages" / "vigil-ui"


def _src(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "tokens.css").write_text(":root{}", encoding="utf-8")
    (src / "components.css").write_text(".b{}", encoding="utf-8")
    for j in uiproxy.BUNDLE_JS:
        (src / j).write_text(f"/*{j}*/", encoding="utf-8")
    (src / "index.html").write_text('<body data-build="__VIGIL_BUILD__"></body>', encoding="utf-8")
    return src


def test_the_brand_images_are_copied_byte_for_byte_and_nothing_else(tmp_path):
    src = _src(tmp_path)
    b = src / "brand"
    b.mkdir()
    (b / "favicon.svg").write_bytes(b"<svg/>")
    (b / "mark.png").write_bytes(b"\x89PNG-bytes")
    (b / "favicon.ico").write_bytes(b"\x00\x00\x01\x00")
    (b / "notes.txt").write_text("not an image", encoding="utf-8")
    secret = tmp_path / "secret.svg"
    secret.write_text("outside", encoding="utf-8")
    os.symlink(secret, b / "link.svg")
    out = tmp_path / "o"
    uiproxy.assemble_serve_dir(src, out, token="T")
    assert sorted(p.name for p in (out / "brand").iterdir()) == ["favicon.ico", "favicon.svg", "mark.png"]
    for name in ("favicon.svg", "mark.png", "favicon.ico"):
        assert (out / "brand" / name).read_bytes() == (b / name).read_bytes()


def test_a_new_logo_is_a_new_build(tmp_path):
    src = _src(tmp_path)
    (src / "brand").mkdir()
    (src / "brand" / "favicon.svg").write_bytes(b"<svg>one</svg>")
    uiproxy.assemble_serve_dir(src, tmp_path / "a", token="T")
    (src / "brand" / "favicon.svg").write_bytes(b"<svg>two</svg>")
    uiproxy.assemble_serve_dir(src, tmp_path / "b", token="T")
    one = (tmp_path / "a" / ".build-id").read_text(encoding="utf-8")
    two = (tmp_path / "b" / ".build-id").read_text(encoding="utf-8")
    assert one and two and one != two
    assert f'data-build="{two}"' in (tmp_path / "b" / "index.html").read_text(encoding="utf-8")


def test_a_bundle_without_a_brand_dir_still_assembles(tmp_path):
    out = tmp_path / "o"
    uiproxy.assemble_serve_dir(_src(tmp_path), out, token="T")
    assert (out / "index.html").is_file() and not (out / "brand").exists()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture()
def console(tmp_path):
    serve = tmp_path / "serve"
    uiproxy.assemble_serve_dir(KIT, serve, token="T")          # the SHIPPED console kit
    port = _free_port()
    httpd = uiproxy.make_proxy_server("127.0.0.1", port, serve, token="owner-token")
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{port}", serve
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("path,ctype", [("/brand/favicon.svg", "image/svg+xml"), ("/brand/favicon.ico", "image/x-icon"),
                                        ("/brand/vigil-mark.svg", "image/svg+xml"),
                                        ("/brand/vigil-mark-white.svg", "image/svg+xml")])
def test_the_console_serves_the_logo_with_its_image_type(console, path, ctype):
    base, serve = console
    with urllib.request.urlopen(base + path, timeout=5) as r:  # noqa: S310 (loopback)
        assert r.status == 200
        assert r.headers.get("Content-Type") == ctype
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("Cache-Control") == "no-cache" and r.headers.get("ETag")
        body = r.read()
    assert body == (KIT / path.lstrip("/")).read_bytes()


def test_the_shipped_console_names_its_favicon_and_header_mark(console):
    _base, serve = console
    html = (serve / "index.html").read_text(encoding="utf-8")
    build = (serve / ".build-id").read_text(encoding="utf-8")
    assert f'<link rel="icon" href="brand/favicon.svg?v={build}" type="image/svg+xml" />' in html
    assert f'<link rel="icon" href="brand/favicon.ico?v={build}" sizes="any" />' in html
    app = (KIT / "app.js").read_text(encoding="utf-8")
    assert '"brand/vigil-mark-white.svg"' in app and '"brand/vigil-mark.svg"' in app
    assert 'h("span.logo", null, "V")' not in app                   # the old letter tile is gone
