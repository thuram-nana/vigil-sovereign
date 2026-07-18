"""Source reading for SCHOLAR — a URL (web fetch, HTML stripped) or a local file/doc path → text.
Kept small + dependency-free (urllib + a crude tag strip); a richer extractor is a later add."""
from __future__ import annotations

import re
import urllib.request
from pathlib import Path

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


def _strip_html(html: str) -> str:
    html = _SCRIPT.sub(" ", html)
    return _WS.sub(" ", _TAG.sub(" ", html)).strip()


def read_source(ref: str, *, timeout: int = 20, max_chars: int = 20000) -> str:
    """Return the text of a source. `http(s)://…` is fetched + HTML-stripped; anything else is a
    local path. Never raises — returns '' on failure (SCHOLAR treats an unreadable source as no
    evidence, never a fabricated one)."""
    try:
        if ref.startswith(("http://", "https://")):
            req = urllib.request.Request(ref, headers={"User-Agent": "SIGIL-SCHOLAR/1.0 (authorized owner research)"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "ignore")
            return _strip_html(raw)[:max_chars]
        return Path(ref).read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:  # noqa: BLE001 — an unreadable source is simply empty evidence
        return ""
