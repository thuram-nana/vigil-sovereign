"""The VIGIL brand set (packages/vigil-brand) is generated once, committed, and copied into each UI. This pins it:

* every asset brand.json names exists in generated/ and is what its entry says: a PNG of the stated pixel size with no
  alpha channel when it is marked opaque, an ICO holding exactly the stated sizes, an SVG with only the stated
  fills, a square viewBox where stated, and nothing active (no script, style, foreign content or link);
* each SVG is byte-for-byte what generate.py builds from the owner's master (a crop and a fill swap of its own
  path data), so a hand edit or a changed master shows up here;
* every UI copy is byte-identical to generated/, and generated/ holds nothing brand.json does not list;
* the server that serves each copy sends it with the Content-Type brand.json states.

Stdlib only: the PNG and ICO headers are read with `struct`; Pillow is needed only to regenerate.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import struct
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
BRAND = REPO / "packages" / "vigil-brand"
DIST = BRAND / "generated"
MANIFEST = json.loads((BRAND / "brand.json").read_text(encoding="utf-8"))
ASSETS = {a["name"]: a for a in MANIFEST["assets"]}
_SVG_NS = "{http://www.w3.org/2000/svg}"


def _generator():
    spec = importlib.util.spec_from_file_location("vigil_brand_generate", BRAND / "generate.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _png_chunks(data: bytes):
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    i = 8
    while i < len(data):
        (n,) = struct.unpack(">I", data[i:i + 4])
        kind = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + n]
        (crc,) = struct.unpack(">I", data[i + 8 + n:i + 12 + n])
        assert zlib.crc32(kind + body) & 0xFFFFFFFF == crc, f"bad CRC on {kind!r}"
        yield kind, body
        i += 12 + n


def png_info(data: bytes) -> tuple[int, int, int, set[bytes]]:
    """(width, height, colour type, chunk kinds)."""
    chunks = list(_png_chunks(data))
    kind, ihdr = chunks[0]
    assert kind == b"IHDR"
    w, h, _depth, colour = struct.unpack(">IIBB", ihdr[:10])
    assert chunks[-1][0] == b"IEND"
    return w, h, colour, {k for k, _ in chunks}


def ico_sizes(data: bytes) -> list[int]:
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    assert (reserved, kind) == (0, 1), "not an ICO"
    sizes = []
    for i in range(count):
        w, h = data[6 + 16 * i], data[7 + 16 * i]
        assert w == h, "a non-square favicon frame"
        sizes.append(w or 256)
    return sorted(sizes)


def svg_facts(data: bytes):
    root = ET.fromstring(data)
    assert root.tag == _SVG_NS + "svg"
    view = [float(v) for v in root.get("viewBox", "").split()]
    assert len(view) == 4 and view[2] > 0 and view[3] > 0
    fills, bad = set(), []
    for el in root.iter():
        local = el.tag.replace(_SVG_NS, "")
        if local in ("script", "style", "foreignObject", "image", "use", "a"):
            bad.append(local)
        for k, v in el.attrib.items():
            if k.lower().startswith("on") or k.endswith("href") or k == "style":
                bad.append(k)
            if k == "fill":
                fills.add(v.upper())
    return view, fills, bad


@pytest.mark.parametrize("name", sorted(ASSETS))
def test_each_asset_is_what_its_entry_says(name):
    a = ASSETS[name]
    data = (DIST / name).read_bytes()
    if a["type"] == "image/png":
        w, h, colour, kinds = png_info(data)
        assert [w, h] == a["size"], (name, w, h)
        if a.get("opaque"):
            assert colour in (0, 2) and b"tRNS" not in kinds, f"{name} carries an alpha channel"
    elif a["type"] == "image/x-icon":
        assert ico_sizes(data) == sorted(a["ico_sizes"])
    elif a["type"] == "image/svg+xml":
        view, fills, bad = svg_facts(data)
        assert not bad, f"{name} carries {bad}"
        assert fills == {f.upper() for f in a["fills"]}, (name, fills)
        if a.get("square"):
            assert view[2] == view[3], f"{name} is not square"
    else:
        pytest.fail(f"no check for {a['type']}")


def test_the_svgs_are_exactly_what_the_master_produces():
    built = _generator().svg_outputs((BRAND / "source" / "VIGIL_Logo.svg").read_text(encoding="utf-8"))
    svgs = {n for n, a in ASSETS.items() if a["type"] == "image/svg+xml"}
    assert set(built) == svgs
    for name, text in built.items():
        assert (DIST / name).read_bytes() == text.encode("utf-8"), f"generated/{name} is not the generated SVG"


def test_the_wordmark_keeps_every_path_of_the_master_and_only_swaps_the_fill():
    master = (BRAND / "source" / "VIGIL_Logo.svg").read_text(encoding="utf-8")
    gen = _generator()
    paths = gen.master_paths(master)
    for name in ("vigil-wordmark.svg", "vigil-wordmark-white.svg"):
        text = (DIST / name).read_text(encoding="utf-8")
        for d, _tx, _ty in paths:
            assert f'd="{d}"' in text, f"{name} lost a path of the master"
    mark = (DIST / "vigil-mark.svg").read_text(encoding="utf-8")
    assert mark.count("<path ") == 1 and f'd="{paths[0][0]}"' in mark          # the mark alone


def test_generated_holds_only_the_listed_assets():
    assert {p.name for p in DIST.iterdir()} == set(ASSETS)


@pytest.mark.parametrize("name,target", [(a["name"], t) for a in MANIFEST["assets"] for t in a["targets"]])
def test_every_ui_copy_is_byte_identical_to_generated(name, target):
    assert (REPO / target).read_bytes() == (DIST / name).read_bytes(), f"{target} drifted from generated/{name}"


def _uiproxy_static_types() -> dict:
    tree = ast.parse((REPO / "integration" / "vigil_integration" / "uiproxy.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_STATIC_TYPES" for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError("uiproxy._STATIC_TYPES not found")


def _served_type(target: str) -> str:
    """The Content-Type the server that owns `target` sends for its suffix (charset stripped)."""
    suffix = Path(target).suffix.lower()
    if target.startswith("apps/sigil/sigil/ui/public_site/"):
        from sigil.ui import pubui
        table = pubui._CTYPES
    elif target.startswith("apps/sigil/sigil/ui/customer_app/"):
        from sigil.ui import custui
        table = custui._APP_CTYPES
    elif target.startswith("packages/vigil-ui/"):
        table = _uiproxy_static_types()
    elif target.startswith("apps/sigil/sigil/bridge/webapp/"):
        from sigil.bridge import server as bridge_server
        table = bridge_server._STATIC_CTYPES
    else:
        raise AssertionError(f"{target}: no server is known to serve this tree — add it here")
    return table.get(suffix, "application/octet-stream").split(";")[0].strip()


@pytest.mark.parametrize("name,target", [(a["name"], t) for a in MANIFEST["assets"] for t in a["targets"]])
def test_each_copy_is_served_with_its_content_type(name, target):
    assert _served_type(target) == ASSETS[name]["type"], target


def test_the_checks_catch_a_wrong_png_and_a_wrong_svg():
    # negative controls for the parsers above
    png = (DIST / "icon-192.png").read_bytes()
    w, h, colour, _ = png_info(png)
    assert (w, h, colour) == (192, 192, 2)
    with pytest.raises(AssertionError):
        png_info(png[:19] + bytes([png[19] ^ 0x01]) + png[20:])               # a changed width fails the CRC
    _view, _fills, bad = svg_facts(b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1">'
                                   b'<script>x</script><path fill="#000" onload="x"/></svg>')
    assert "script" in bad and "onload" in bad
