"""Source reading for SCHOLAR — a URL (web fetch, HTML stripped) or a local file/doc path → text.
Kept small + dependency-free (urllib + a crude tag strip); a richer extractor is a later add.

SSRF GATE (Phase 6, closes the carried debt): a URL whose host resolves to a private, loopback,
link-local, or otherwise non-public address is REFUSED before any request leaves the machine — so
SCHOLAR cannot be steered at `169.254.169.254`, `localhost`, or an internal `10.x`/`192.168.x`
service. Redirects are NOT auto-followed (a public URL cannot bounce SCHOLAR onto an internal host).
A refused/unreadable source is simply empty evidence, never a fabricated one."""
from __future__ import annotations

import ipaddress
import re
import socket
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


def _strip_html(html: str) -> str:
    html = _SCRIPT.sub(" ", html)
    return _WS.sub(" ", _TAG.sub(" ", html)).strip()


def is_public_host(host: str) -> bool:
    """True iff EVERY address `host` resolves to is a public unicast address. Fail-closed: an
    unresolvable host, or one with any private/loopback/link-local/reserved/multicast address, is
    NOT public (blocks SSRF and DNS-rebinding-to-internal)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for *_, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow 3xx — a public URL must not be able to redirect SCHOLAR onto an internal host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def read_source(ref: str, *, timeout: int = 20, max_chars: int = 20000) -> str:
    """Return the text of a source. `http(s)://…` is SSRF-gated then fetched + HTML-stripped; anything
    else is a local path. Never raises — returns '' on failure or refusal."""
    try:
        if ref.startswith(("http://", "https://")):
            host = urlsplit(ref).hostname or ""
            if not is_public_host(host):
                return ""       # SSRF gate: non-public target → no request leaves the machine
            req = urllib.request.Request(ref, headers={"User-Agent": "SIGIL-SCHOLAR/1.0 (authorized owner research)"})
            with _OPENER.open(req, timeout=timeout) as r:
                raw = r.read().decode("utf-8", "ignore")
            return _strip_html(raw)[:max_chars]
        return Path(ref).read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:  # noqa: BLE001 — an unreadable source is simply empty evidence
        return ""
