"""The customer app is installable: manifest.webmanifest, the owner's icons and the page's install tags.

Checks (stdlib only; the PNG sizes are read from the files' own headers):
  1. the manifest: name VIGIL, start_url and scope RELATIVE (so the app installs at the customer origin's root
     in production and stays inside /customer/ under the console's dev mount), display standalone, theme and
     background colours equal to tokens.css --bg-0;
  2. its icons: 192 and 512 "any" plus a 512 "maskable", every file present, a PNG of exactly the declared size,
     the maskable one opaque (the owner's dark avatar keeps the mark inside the maskable safe circle);
  3. the page: the manifest link, theme-color for dark and light (tokens.css --bg-0), an opaque 180 px
     apple-touch-icon and the iOS tags — and still nothing inline, nothing external;
  4. the edge serves the manifest as application/manifest+json at a stable (never ?v=) URL with revalidation.
"""
from __future__ import annotations

import http.client
import json
import re
import struct
import threading
from pathlib import Path

from sigil.ui.custui import build_customer_server

APP = Path(__file__).resolve().parents[1] / "sigil" / "ui" / "customer_app"
MANIFEST = json.loads((APP / "manifest.webmanifest").read_text(encoding="utf-8"))
INDEX = (APP / "index.html").read_text(encoding="utf-8")


def _bg0() -> tuple[str, str]:
    """(dark, light) --bg-0 from tokens.css: the first definition, then the light theme's."""
    tokens = (APP / "tokens.css").read_text(encoding="utf-8")
    vals = re.findall(r"--bg-0:\s*(#[0-9a-fA-F]{6})", tokens)
    return vals[0].lower(), vals[1].lower()


def _png(path: Path) -> tuple[int, int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR", path
    w, h, _depth, colour = struct.unpack(">IIBB", data[16:26])
    return w, h, colour


def test_the_manifest_names_a_standalone_app_at_a_relative_root():
    m = MANIFEST
    assert m["name"] == "VIGIL" and m["short_name"] == "VIGIL"
    assert m["start_url"] == "./" and m["scope"] == "./"           # relative: the mount decides the origin path
    assert m["display"] == "standalone"
    dark, _light = _bg0()
    assert m["theme_color"].lower() == dark and m["background_color"].lower() == dark


def test_the_manifest_icons_are_the_owners_pngs_at_their_declared_sizes():
    icons = MANIFEST["icons"]
    got = {(i["sizes"], i["purpose"]) for i in icons}
    assert {("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")} <= got
    for i in icons:
        assert i["type"] == "image/png" and not i["src"].startswith(("/", "http", "data:"))
        w, h, colour = _png(APP / i["src"])
        assert f"{w}x{h}" == i["sizes"], i
        if i["purpose"] == "maskable":
            assert colour == 2, "the maskable icon must be opaque (no alpha)"


def test_the_page_carries_the_install_tags():
    dark, light = _bg0()
    assert '<link rel="manifest" href="manifest.webmanifest" />' in INDEX
    assert f'<meta name="theme-color" content="{dark}" media="(prefers-color-scheme: dark)" />' in INDEX
    assert f'<meta name="theme-color" content="{light}" media="(prefers-color-scheme: light)" />' in INDEX
    assert '<link rel="apple-touch-icon" href="brand/apple-touch-icon.png" />' in INDEX
    assert _png(APP / "brand" / "apple-touch-icon.png") == (180, 180, 2)        # opaque, 180 px
    for tag in ('name="apple-mobile-web-app-capable" content="yes"', 'name="mobile-web-app-capable" content="yes"',
                'name="apple-mobile-web-app-title" content="VIGIL"', 'name="apple-mobile-web-app-status-bar-style"'):
        assert tag in INDEX, tag
    for ref in re.findall(r'(?:href|src)="([^"]+)"', INDEX):
        assert (APP / ref).is_file(), f"index.html names a missing file {ref}"


def test_the_page_stays_csp_clean():
    assert "http://" not in INDEX and "https://" not in INDEX
    assert not re.search(r"<[a-zA-Z][^>]*\son[a-z]+\s*=", INDEX), "an inline on*= handler"
    assert not re.search(r"<[a-zA-Z][^>]*\sstyle\s*=", INDEX), "an inline style attribute"
    for attrs, body in re.findall(r"<script\b([^>]*)>(.*?)</script>", INDEX, re.DOTALL | re.IGNORECASE):
        assert "src=" in attrs and body.strip() == ""


def test_the_header_shows_the_owners_wordmark():
    app = (APP / "app.js").read_text(encoding="utf-8")
    for name in ("brand/vigil-wordmark-white.svg", "brand/vigil-wordmark.svg"):
        assert f'"{name}"' in app and (APP / name).is_file()


def test_the_edge_serves_the_manifest_with_its_type_at_a_stable_url(tmp_path):
    srv = build_customer_server(host="127.0.0.1", port=0, hop_key="k", provision_base="http://127.0.0.1:1",
                                sessions_dir=str(tmp_path / "s"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/manifest.webmanifest", headers={"Host": f"127.0.0.1:{port}"})
        r = c.getresponse()
        body = r.read()
        assert r.status == 200 and r.getheader("Content-Type") == "application/manifest+json"
        assert r.getheader("Cache-Control") == "no-cache" and r.getheader("ETag")
        assert json.loads(body) == MANIFEST
        c.request("GET", "/", headers={"Host": f"127.0.0.1:{port}"})
        page = c.getresponse().read().decode()
        assert 'href="manifest.webmanifest"' in page                  # never ?v= (its URL stays the same)
        assert re.search(r'data-build="[0-9a-f]{12}"', page)
    finally:
        srv.shutdown()
        srv.server_close()
