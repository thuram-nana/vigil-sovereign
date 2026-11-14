"""Content-hashed static sites for the keyless edges: the public site (`pubui`) and the customer app (`custui`).

At startup an edge reads its whole content tree ONCE into a :class:`SiteSnapshot` and serves only those bytes
until it stops. The snapshot:

  * gives every asset a digest (the first 12 hex digits of its SHA-256) and rewrites each same-site
    ``href="…"`` / ``src="…"`` in the HTML pages that names a versionable asset (css, js, images, fonts, sounds)
    to ``…?v=<digest>``;
  * computes the BUILD id (a digest of every source file, plus any per-deployment values the edge substitutes),
    which the edge reports at ``/version.json`` and in ``X-Vigil-Build``, and writes it in place of
    ``__VIGIL_BUILD__`` in the pages;
  * applies an edge's own text templates (the customer app's service worker gets its build id and its shell
    list this way).

:meth:`SiteSnapshot.version_state` tells the edge how to answer a request for an asset:
  * ``immutable`` — the URL carries exactly ``?v=<this asset's current digest>``: the bytes behind that URL can
    never change, so it may be cached for a year;
  * ``mismatch`` — the URL carries some other ``v`` (a page from another build asked for its own bytes): the
    edge answers 404 + ``no-store``. Serving the current bytes under the old URL would let a cache keep them for
    a year under a name that promised different bytes;
  * ``plain`` — no ``v``: served with revalidation (an ETag), never as immutable.

Because the snapshot is taken once, a checkout that changes the files under a running edge changes nothing it
serves: it keeps serving one consistent build until it is replaced (the edge swap). stdlib only (FATAL-2).
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional
from urllib.parse import parse_qs, unquote, urlparse

#: Suffixes whose URLs carry ``?v=<digest>`` in the pages (their bytes are content-addressed).
VERSIONED_SUFFIXES = frozenset({".css", ".js", ".svg", ".png", ".ico", ".jpg", ".jpeg", ".webp", ".woff2",
                                ".wav"})
#: The cache policy of a URL whose ``v`` matches the current digest.
IMMUTABLE = "public, max-age=31536000, immutable"
#: The build placeholder an edge's pages and templates carry.
BUILD_PLACEHOLDER = "__VIGIL_BUILD__"

_REF_RE = re.compile(r'\b(href|src)="([^"]*)"')
_DEFAULT_MAX_TOTAL = 64 * 1024 * 1024

Template = Callable[[str, "SiteSnapshot"], str]


@dataclass(frozen=True)
class Asset:
    rel: str            # the path under the content root, '/'-separated
    body: bytes         # the exact bytes served
    ctype: str
    etag: str           # a strong ETag over `body`
    digest: str         # sha256(body)[:12]; the `?v=` value of a versioned asset
    versioned: bool     # its URLs in the pages carry ?v=<digest>


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def normalize_rel(urlpath: str) -> Optional[str]:
    """The content-root-relative path a URL path names, or None when it would leave the root. Percent-decoding
    happens here once; the result is only ever used as a key into the snapshot (never opened as a path)."""
    raw = unquote(urlpath)
    if "\x00" in raw or "\\" in raw:
        return None
    rel = posixpath.normpath("/" + raw.lstrip("/")).lstrip("/")
    if rel in ("", "."):
        return ""
    if rel == ".." or rel.startswith("../"):
        return None
    return rel


class SiteSnapshot:
    """Every file under ``root`` read once, digested, with the pages rewritten (see the module docstring)."""

    def __init__(self, root, ctypes: Mapping[str, str], *, max_file: int, max_total: int = _DEFAULT_MAX_TOTAL,
                 stable: tuple[str, ...] = (), templates: Optional[Mapping[str, Template]] = None,
                 html_values: Optional[Mapping[str, str]] = None) -> None:
        self.root = Path(root).resolve()
        self.too_large: set[str] = set()
        self._stable = frozenset(stable)
        values = dict(html_values or {})
        raw: dict[str, bytes] = {}
        total = 0
        for p in sorted(self.root.rglob("*")) if self.root.is_dir() else []:
            if not p.is_file():
                continue
            try:
                rp = p.resolve()
                rel = p.relative_to(self.root).as_posix()
            except (OSError, ValueError, RuntimeError):
                continue
            if rp != self.root and not rp.is_relative_to(self.root):
                continue                                   # a symlink out of the root is never served
            try:
                size = rp.stat().st_size
                if size > max_file:
                    self.too_large.add(rel)
                    continue
                data = rp.read_bytes()
            except OSError:
                continue
            total += len(data)
            if total > max_total:
                raise ValueError(f"the content under {self.root} exceeds {max_total} bytes")
            raw[rel] = data
        # The build: every source file (name + bytes) and every per-deployment value written into the pages.
        h = hashlib.sha256()
        for rel in sorted(raw):
            h.update(rel.encode("utf-8") + b"\0" + hashlib.sha256(raw[rel]).digest())
        for k in sorted(values):
            h.update(b"\1" + k.encode("utf-8") + b"\0" + values[k].encode("utf-8"))
        self.build = h.hexdigest()[:12]
        values[BUILD_PLACEHOLDER] = self.build

        def asset(rel: str, body: bytes) -> Asset:
            suffix = posixpath.splitext(rel)[1].lower()
            return Asset(rel=rel, body=body, ctype=ctypes.get(suffix, "application/octet-stream"),
                         etag='"' + hashlib.sha256(body).hexdigest()[:32] + '"', digest=_digest(body),
                         versioned=suffix in VERSIONED_SUFFIXES and rel not in self._stable)

        templates = dict(templates or {})
        pages = {rel for rel in raw if rel.lower().endswith(".html")}
        self._assets: dict[str, Asset] = {rel: asset(rel, raw[rel]) for rel in raw
                                          if rel not in pages and rel not in templates}
        for rel in sorted(pages):
            text = raw[rel].decode("utf-8", errors="replace")
            self._assets[rel] = asset(rel, self._rewrite_page(rel, text, values).encode("utf-8"))
        for rel, render in sorted(templates.items()):
            if rel in raw:
                text = raw[rel].decode("utf-8", errors="replace")
                self._assets[rel] = asset(rel, render(text, self).encode("utf-8"))

    # -- building --------------------------------------------------------------------------------------------
    def _resolve_ref(self, page_rel: str, url: str) -> Optional[str]:
        """The asset a page's same-site reference names, or None (an external, fragment or query URL, or no
        such asset)."""
        if not url or url.startswith(("#", "//", "data:")) or ":" in url.split("/", 1)[0] or "?" in url \
                or "#" in url:
            return None
        if url.startswith("/"):
            rel = normalize_rel(url)
        else:
            rel = normalize_rel(posixpath.join(posixpath.dirname(page_rel), url))
        return rel or None

    def _rewrite_page(self, page_rel: str, text: str, values: Mapping[str, str]) -> str:
        for k, v in values.items():
            text = text.replace(k, v)

        def sub(m: "re.Match[str]") -> str:
            rel = self._resolve_ref(page_rel, m.group(2))
            a = self._assets.get(rel) if rel else None
            if a is None or not a.versioned:
                return m.group(0)
            return f'{m.group(1)}="{m.group(2)}?v={a.digest}"'

        return _REF_RE.sub(sub, text)

    # -- serving ---------------------------------------------------------------------------------------------
    def get(self, rel: Optional[str]) -> Optional[Asset]:
        return self._assets.get(rel) if rel is not None else None

    def __contains__(self, rel: object) -> bool:
        return rel in self._assets

    def versioned_refs(self, page_rel: str) -> list[str]:
        """The ``?v=`` URLs a page names, as written in the page (used for a service worker's shell list)."""
        a = self._assets.get(page_rel)
        if a is None:
            return []
        return [u for _k, u in _REF_RE.findall(a.body.decode("utf-8", errors="replace")) if "?v=" in u]

    @staticmethod
    def version_state(asset: Asset, query: str) -> str:
        """``immutable`` | ``mismatch`` | ``plain`` for a request of ``asset`` with this query string."""
        if not asset.versioned:
            return "plain"                                 # pages, the manifest, the service worker: no v at all
        q = parse_qs(query or "", keep_blank_values=True)
        if "v" not in q:
            return "plain"
        if list(q) == ["v"] and q["v"] == [asset.digest]:
            return "immutable"
        return "mismatch"


def request_query(path: str) -> str:
    return urlparse(path).query


def not_modified(if_none_match: str, etag: str) -> bool:
    """True when an If-None-Match header names ``etag`` (or is ``*``)."""
    if not if_none_match:
        return False
    tags = [t.strip() for t in if_none_match.split(",")]
    return "*" in tags or etag in tags or ("W/" + etag) in tags
