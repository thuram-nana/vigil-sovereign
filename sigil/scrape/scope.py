"""ScrapeScope (Phase 8, WS-E E-i) — the domain allowlist that bounds where SCRIBE may crawl. Mirrors
`agents/operator_scope.OperatorScope`: EMPTY allowlist = deny-all (fail-closed); the owner explicitly
authorizes each domain (their own or ones they're authorized to research). A candidate URL is admitted
iff (1) scheme ∈ {http,https}, (2) the host is public unicast (`sources.is_public_host` — the SSRF
gate, so no internal host is ever in scope), (3) the normalized host matches the allowlist (exact host
by default; opt-in eTLD+1 to include subdomains). Returns the NORMALIZED host actually vetted so the
rate limiter/robots key on the same string a fetch will use (no check/use drift, no confusable split)."""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlsplit

from ..agents.sources import is_public_host


def normalize_host(host: str) -> str:
    """Lowercase, IDNA-encode, strip a trailing dot + any userinfo/port. Stable key for scope/limit."""
    host = (host or "").strip().lower().rstrip(".")
    if "@" in host:                       # defensive: userinfo should be in netloc not hostname, but strip anyway
        host = host.rsplit("@", 1)[-1]
    host = host.split(":", 1)[0]
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


def _registrable_suffix(host: str) -> str:
    """A crude eTLD+1 (last two labels). Good enough for owner-declared domains; not a public-suffix list."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class ScrapeScope:
    def __init__(self, allowed_domains: Optional[List[str]] = None, *, include_subdomains: bool = False):
        self.allowed = {normalize_host(d) for d in (allowed_domains or [])}
        self.include_subdomains = include_subdomains

    def admit(self, url: str) -> Optional[str]:
        """Return the normalized host iff the URL is in scope AND public, else None (deny-all if empty)."""
        try:
            parts = urlsplit(url)
        except ValueError:
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return None
        host = normalize_host(parts.hostname)
        if not host or not self.allowed or not is_public_host(parts.hostname):
            return None
        if host in self.allowed:
            return host
        if self.include_subdomains and _registrable_suffix(host) in {_registrable_suffix(a) for a in self.allowed}:
            return host
        return None
