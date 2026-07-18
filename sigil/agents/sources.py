"""Source reading for SCHOLAR — a URL (web fetch, HTML stripped) or a local file/doc path → text.
Kept small + dependency-free (urllib + a crude tag strip); a richer extractor is a later add.

SSRF GATE (Phase 6, closes the carried debt + red-pen SSRF-REBIND-TOCTOU): the host is resolved
ONCE; every resolved address must be public (not private/loopback/link-local/reserved/multicast/
unspecified — IPv4 and IPv6, incl. IPv4-mapped IPv6); and the connection is then PINNED to that exact
vetted IP, so a rebinding DNS that flips to an internal address between the check and the fetch cannot
steer SCHOLAR onto `169.254.169.254`/`localhost`/an internal service. Redirects are not followed. A
refused/unreadable source is simply empty evidence, never a fabricated one."""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

# One stable, CORRELATABLE User-Agent (OBSIDIAN OPSEC §VI: identifiable, NOT evasive — never rotated).
UA = "SIGIL-SCHOLAR/1.0 (authorized owner research)"

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")
_SCRIPT = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)


def _strip_html(html: str) -> str:
    html = _SCRIPT.sub(" ", html)
    return _WS.sub(" ", _TAG.sub(" ", html)).strip()


def _vetted_ip(host: str) -> Optional[str]:
    """Resolve `host`; return ONE address to pin iff EVERY resolved address is public unicast, else
    None. Fail-closed: an unresolvable host, or any private/loopback/link-local/reserved/multicast/
    unspecified/IPv4-mapped-internal address, yields None."""
    if not host:
        return None
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    if not infos:
        return None
    chosen = None
    for family, _t, _p, _c, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return None
        # unwrap IPv4-mapped/compat IPv6 (::ffff:127.0.0.1) so an internal v4 can't hide as v6
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        # Reject anything NOT globally routable — `not is_global` also closes RFC 6598 CGNAT/shared
        # space 100.64.0.0/10 (incl. the Alibaba metadata IP 100.100.100.200) and other non-global
        # ranges the explicit list misses (red-pen BLOCK-1). The explicit checks stay as defense-in-depth.
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified or not ip.is_global):
            return None
        if chosen is None:
            chosen = sockaddr[0]
    return chosen


def is_public_host(host: str) -> bool:
    return _vetted_ip(host) is not None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    pinned_ip: Optional[str] = None

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip or self.host, self.port),
                                              self.timeout, self.source_address)
        if getattr(self, "_tunnel_host", None):
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    pinned_ip: Optional[str] = None

    def connect(self):
        sock = socket.create_connection((self.pinned_ip or self.host, self.port),
                                        self.timeout, self.source_address)
        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()
            sock = self.sock
        # SNI + certificate validation still use the ORIGINAL hostname, not the pinned IP.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, ip):
        super().__init__()
        self._ip = ip

    def http_open(self, req):
        ip = self._ip

        def factory(host, **kw):
            c = _PinnedHTTPConnection(host, **kw)
            c.pinned_ip = ip
            return c
        return self.do_open(factory, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, ip):
        super().__init__()
        self._ip = ip

    def https_open(self, req):
        ip = self._ip

        def factory(host, **kw):
            c = _PinnedHTTPSConnection(host, **kw)
            c.pinned_ip = ip
            return c
        return self.do_open(factory, req, context=self._context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow 3xx — a public URL must not redirect SCHOLAR onto an internal host."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class FetchResult:
    """The outcome of a raw SSRF-gated fetch. `raw` preserves newlines (robots/extraction need line
    structure); `status` is surfaced (unlike `read_source`, which swallows to '') so a caller can do
    robots/backoff on 429/503. `status == 0` = network error / SSRF-refused (nothing left the box)."""
    ok: bool
    status: int
    raw: str
    url: str
    headers: dict = field(default_factory=dict)
    reason: str = ""


def fetch_raw(ref: str, *, timeout: int = 20, max_bytes: int = 2_000_000) -> FetchResult:
    """SSRF-gated raw GET (Phase 8 shared): resolve-once, verify-all-public, PIN the vetted IP, refuse
    redirects, correlatable UA. Surfaces the HTTP status and preserves the raw body. Never raises. A
    non-public/unresolvable host → ok=False, status=0 (no request leaves the machine)."""
    if not ref.startswith(("http://", "https://")):
        return FetchResult(False, 0, "", ref, reason="not-http")
    host = urlsplit(ref).hostname or ""
    ip = _vetted_ip(host)
    if ip is None:
        return FetchResult(False, 0, "", ref, reason="ssrf-refused")
    # ProxyHandler({}) disables env http_proxy/https_proxy so routing can't be diverted (N3); the
    # pinned handlers force the socket to the vetted IP regardless.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         _PinnedHTTPHandler(ip), _PinnedHTTPSHandler(ip), _NoRedirect)
    req = urllib.request.Request(ref, headers={"User-Agent": UA})
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(max_bytes).decode("utf-8", "ignore")
            return FetchResult(True, getattr(r, "status", 200), raw, ref, headers=dict(r.headers))
    except urllib.error.HTTPError as e:                 # 3xx-not-followed / 4xx / 5xx — surface the code
        body = ""
        try:
            body = e.read(max_bytes).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001
            pass
        return FetchResult(False, e.code, body, ref, headers=dict(e.headers or {}), reason=f"http-{e.code}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return FetchResult(False, 0, "", ref, reason=f"neterr:{type(e).__name__}")


def read_source(ref: str, *, timeout: int = 20, max_chars: int = 20000) -> str:
    """Return the text of a source. `http(s)://…` is SSRF-gated (via `fetch_raw`) then HTML-stripped;
    anything else is a local path. Never raises — returns '' on failure or refusal."""
    if ref.startswith(("http://", "https://")):
        res = fetch_raw(ref, timeout=timeout)
        return _strip_html(res.raw)[:max_chars] if res.ok else ""
    try:
        return Path(ref).read_text(encoding="utf-8", errors="ignore")[:max_chars]
    except Exception:  # noqa: BLE001 — an unreadable source is simply empty evidence
        return ""
