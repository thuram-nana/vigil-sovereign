"""Structured extraction (Phase 8, WS-E E-iii) — beyond HTML-strip, stdlib `html.parser` only (no
dep, matching `sources.py`). `links` (absolute URL + anchor text, for the VOI frontier), `tables`
(row/col structure), `main_text` (readable text, reusing `_strip_html`), `entities` (salient +
capitalized-run heuristic). DISCIPLINE: links/tables/entities are NAVIGATION + advisory metadata —
they are NEVER served as a grounded fact unless a verbatim quote grounds them through the veracity
gate."""
from __future__ import annotations

from html.parser import HTMLParser
from typing import List, Tuple
from urllib.parse import urljoin

from ..agents.sources import _strip_html
from ..consolidate.gate import salient


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []      # (href, anchor_text)
        self._href = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href, self._buf = href, []

    def handle_data(self, data):
        if self._href is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())[:200]))
            self._href = None


def links(base_url: str, html: str) -> List[dict]:
    """Absolute links + anchor text. Relative hrefs resolved against `base_url`; junk schemes dropped."""
    p = _LinkParser()
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 — malformed HTML must not crash a crawl
        pass
    out = []
    for href, text in p.links:
        try:
            absu = urljoin(base_url, href)
        except ValueError:
            continue
        if absu.startswith(("http://", "https://")):
            out.append({"url": absu, "text": text})
    return out


class _TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables: List[List[List[str]]] = []
        self._t = self._r = None
        self._buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._t = []
        elif tag == "tr" and self._t is not None:
            self._r = []
        elif tag in ("td", "th") and self._r is not None:
            self._buf = []

    def handle_data(self, data):
        if self._r is not None:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._r is not None:
            self._r.append(" ".join("".join(self._buf).split()))
            self._buf = []
        elif tag == "tr" and self._r is not None:
            self._t.append(self._r); self._r = None
        elif tag == "table" and self._t is not None:
            self.tables.append(self._t); self._t = None


def tables(html: str) -> List[List[List[str]]]:
    p = _TableParser()
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001
        pass
    return p.tables


def main_text(html: str) -> str:
    return _strip_html(html or "")


def entities(text: str, *, limit: int = 40) -> List[str]:
    """Advisory candidate entities: salient tokens + capitalized runs. NOT facts."""
    import re
    caps = re.findall(r"\b([A-Z][\w'-]+(?:\s+[A-Z][\w'-]+){0,3})\b", text or "")
    out: List[str] = []
    seen = set()
    for c in caps:
        k = c.lower()
        if k not in seen and len(c) >= 3:
            seen.add(k); out.append(c)
    for t in sorted(salient(text or "")):
        if t not in seen:
            seen.add(t); out.append(t)
    return out[:limit]
