#!/usr/bin/env python3
"""Regenerate the VIGIL brand set from the owner's masters and copy it into every UI that shows it.

Author-time only, like packages/vigil-ui/sync.sh: nothing runs this at deploy or at request time. The output
is committed, so every server keeps serving only files from its own tree.

    python3 packages/vigil-brand/generate.py          # rewrite generated/ and every target listed in brand.json

Inputs (source/, the owner's files, used as image data only):
  * VIGIL_Logo.svg               the wordmark: six filled paths (the mark, then V I G I L), one fill colour
  * vigil_avatar_on_dark_1024.png the white mark on #07090D, inside the maskable 80 % safe circle
  * favicon.ico                  the owner's favicon, copied unchanged

Outputs (generated/): the SVG variants are text built from the master's own path data (a crop and a fill swap, no
redrawing), so they need nothing beyond the standard library; the PNG sizes are resampled from the avatar with
Pillow, which is imported only for that step. apps/sigil/tests/test_brand_assets.py checks the committed set.
"""
from __future__ import annotations

import json
import math
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SOURCE = HERE / "source"
DIST = HERE / "generated"
MANIFEST = HERE / "brand.json"

MASTER_FILL = "#111827"        # the fill every path of VIGIL_Logo.svg carries
WHITE = "#FFFFFF"
AVATAR_BG = "#07090D"          # the background of vigil_avatar_on_dark_1024.png

_PATH_RE = re.compile(r'<path d="([^"]+)" fill="([^"]+)" transform="translate\(([-0-9.]+),([-0-9.]+)\)"\s*/>')
_NUM_RE = re.compile(r"-?\d*\.?\d+(?:[eE][-+]?\d+)?")


def master_paths(svg_text: str) -> list[tuple[str, float, float]]:
    """The master's paths as (d, tx, ty), in document order. The master uses only absolute M/C/Z commands."""
    out = []
    for d, fill, tx, ty in _PATH_RE.findall(svg_text):
        if fill.upper() != MASTER_FILL.upper():
            raise ValueError(f"unexpected fill {fill!r} in the master")
        if set(re.findall(r"[A-Za-z]", d)) - {"M", "C", "Z"}:
            raise ValueError("the master path uses a command other than absolute M/C/Z")
        out.append((d, float(tx), float(ty)))
    if len(out) != 6:
        raise ValueError(f"expected 6 paths (the mark and five letters), found {len(out)}")
    return out


def bbox(paths: list[tuple[str, float, float]]) -> tuple[float, float, float, float]:
    """(x0, y0, x1, y1) over every point, control points included. A cubic Bezier lies inside the hull of its
    control points, so this bounds the drawing (within a fraction of a unit on this master)."""
    xs: list[float] = []
    ys: list[float] = []
    for d, tx, ty in paths:
        nums = [float(n) for n in _NUM_RE.findall(d)]
        xs += [n + tx for n in nums[0::2]]
        ys += [n + ty for n in nums[1::2]]
    return min(xs), min(ys), max(xs), max(ys)


def _n(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def _path_tags(paths: list[tuple[str, float, float]], fill: str) -> str:
    return "\n".join(f'<path d="{d}" fill="{fill}" transform="translate({_n(tx)},{_n(ty)})"/>'
                     for d, tx, ty in paths)


def _svg(view: tuple[float, float, float, float], body: str) -> str:
    x, y, w, h = view
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{_n(x)} {_n(y)} {_n(w)} {_n(h)}" '
            f'width="{_n(w)}" height="{_n(h)}" role="img" aria-label="VIGIL"><title>VIGIL</title>\n{body}\n</svg>\n')


def wordmark_svg(paths, fill: str) -> str:
    """The full wordmark, cropped to the drawing with an 8-unit margin."""
    x0, y0, x1, y1 = bbox(paths)
    x0, y0, x1, y1 = math.floor(x0 - 8), math.floor(y0 - 8), math.ceil(x1 + 8), math.ceil(y1 + 8)
    return _svg((x0, y0, x1 - x0, y1 - y0), _path_tags(paths, fill))


def _square_around(mark, side: float) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = bbox(mark)
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    return round(cx - side / 2, 2), round(cy - side / 2, 2), side, side


def mark_svg(paths, fill: str) -> str:
    """The mark alone (the first path), centred in a square with a 12-unit margin."""
    mark = paths[:1]
    x0, y0, x1, y1 = bbox(mark)
    side = math.ceil(max(x1 - x0, y1 - y0) + 24)
    return _svg(_square_around(mark, side), _path_tags(mark, fill))


def favicon_svg(paths) -> str:
    """The white mark on the avatar's dark rounded square, the mark spanning about 74 % of the width — legible on
    light and dark browser chrome alike."""
    mark = paths[:1]
    x0, _y0, x1, _y1 = bbox(mark)
    side = math.ceil((x1 - x0) / 0.74)
    view = _square_around(mark, side)
    rect = (f'<rect x="{_n(view[0])}" y="{_n(view[1])}" width="{side}" height="{side}" '
            f'rx="{round(side * 0.22)}" fill="{AVATAR_BG}"/>')
    return _svg(view, rect + "\n" + _path_tags(mark, WHITE))


def svg_outputs(master_text: str) -> dict[str, str]:
    """Every SVG of the set, by generated name (pure text; the test rebuilds these and compares bytes)."""
    paths = master_paths(master_text)
    return {
        "vigil-wordmark.svg": wordmark_svg(paths, MASTER_FILL),
        "vigil-wordmark-white.svg": wordmark_svg(paths, WHITE),
        "vigil-mark.svg": mark_svg(paths, MASTER_FILL),
        "vigil-mark-white.svg": mark_svg(paths, WHITE),
        "favicon.svg": favicon_svg(paths),
    }


def _png_outputs() -> dict[str, bytes]:
    import io

    from PIL import Image  # author-time only

    src = Image.open(SOURCE / "vigil_avatar_on_dark_1024.png").convert("RGB")   # opaque: no alpha channel
    out = {}
    for name, px in (("icon-512.png", 512), ("icon-192.png", 192), ("apple-touch-icon.png", 180)):
        buf = io.BytesIO()
        src.resize((px, px), Image.Resampling.LANCZOS).save(buf, format="PNG", optimize=True)
        out[name] = buf.getvalue()
    return out


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    DIST.mkdir(exist_ok=True)
    blobs: dict[str, bytes] = {n: t.encode("utf-8")
                               for n, t in svg_outputs((SOURCE / "VIGIL_Logo.svg").read_text("utf-8")).items()}
    blobs.update(_png_outputs())
    blobs["favicon.ico"] = (SOURCE / "favicon.ico").read_bytes()
    names = {a["name"] for a in manifest["assets"]}
    if names != set(blobs):
        print(f"brand.json and the generator disagree: {sorted(names ^ set(blobs))}", file=sys.stderr)
        return 1
    for name, data in sorted(blobs.items()):
        (DIST / name).write_bytes(data)
    for asset in manifest["assets"]:
        for target in asset["targets"]:
            dest = REPO / target
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(DIST / asset["name"], dest)
            print(f"  {asset['name']:<26} -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
