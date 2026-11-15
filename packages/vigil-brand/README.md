# vigil-brand — the one source of the VIGIL logo

Every logo, favicon and app icon VIGIL serves comes from this folder.

| Path | What it is |
|---|---|
| `source/VIGIL_Logo.svg` | The owner's wordmark: six filled paths (the mark, then V I G I L), fill `#111827`. The repository copy ends with a newline (the end-of-file hook); nothing else differs. |
| `source/vigil_avatar_on_dark_1024.png` | The owner's avatar: the white mark on `#07090D`, inside the maskable 80 % safe circle. |
| `source/favicon.ico` | The owner's favicon (16, 32, 48 and 64 px), used unchanged. |
| `generate.py` | Builds `generated/` from `source/` and copies each asset to every target in `brand.json`. |
| `brand.json` | Each generated asset: its type, its pixel size or fill colours, and every UI copy of it. |
| `generated/` | The generated, committed set. |

## The generated set

| Asset | Made from | Used by |
|---|---|---|
| `vigil-wordmark.svg` | the master, cropped to the drawing | customer app header on a light theme |
| `vigil-wordmark-white.svg` | the master with the fill set to white | public site header; customer app header on a dark theme |
| `vigil-mark.svg`, `vigil-mark-white.svg` | the mark path alone, centred in a square | operator console header (light, dark) |
| `favicon.svg` | the white mark on the avatar's dark rounded square | favicon on the public site, the customer app, the console and the Companion |
| `favicon.ico` | `source/favicon.ico` | favicon for browsers without SVG favicons |
| `icon-192.png`, `icon-512.png` | the avatar, resampled (opaque RGB) | customer app and Companion manifests (`any`, and 512 also `maskable`) |
| `apple-touch-icon.png` | the avatar at 180 px (opaque RGB) | iOS home-screen icon |

The SVGs reuse the master's path data unchanged: only the `viewBox` and the fill differ. Each server serves only
files from its own tree, so the assets are copied into each UI (the same model as `packages/vigil-ui/sync.sh`).

## Regenerate

```
python3 packages/vigil-brand/generate.py
```

The SVG step needs only the standard library; the PNG step needs Pillow. Commit `generated/` and every target the
script lists. `apps/sigil/tests/test_brand_assets.py` fails when a copy differs from `generated/`, when a PNG or ICO
has the wrong size or an alpha channel where the entry says opaque, when an SVG is not the one the master
produces, or when a server would send an asset with the wrong `Content-Type`.
