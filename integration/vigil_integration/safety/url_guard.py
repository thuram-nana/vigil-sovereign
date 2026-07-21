"""
url_guard — application-layer SSRF / metadata pre-filter for URLs (VIGIL-FUSION F1).

An app-layer fast-path that sits **behind, never in place of** the P6 host egress gate (the netns +
nftables deny-default drop that already blocks IMDS/metadata/RFC1918 at L3/L4 and re-checks every
resolved connection IP to defeat DNS rebinding). This module guards *URLs* the agent or the reasoning
layer are about to use — an operator-configured Claude inference endpoint, or an agent fetch/crawl
target — by:

  * requiring an ``http``/``https`` scheme (rejecting ``file:``/``gopher:``/… SSRF smuggling);
  * blocking known cloud-metadata hostnames;
  * resolving the host FIRST and rejecting the URL if ANY resolved A/AAAA record is on the egress
    denylist (delegated to ``vigil_gateway.denylist`` — a single source of truth for the always-denied
    ranges, with embedded-IPv4 unwrap, so ``::ffff:169.254.169.254`` can't slip past);
  * optionally rejecting plaintext HTTP to a public host (a config/secret-leak channel for an
    inference endpoint).

Fail-closed: an unparseable URL, an unresolvable host (when resolution is required), or a denied
resolved IP → refused. Delegating IP classification to the gateway avoids a second, drift-prone copy
of the SSRF ranges.

VIGIL note: this can only DENY — it is a pre-filter, not an authority; the egress gate is the L3/L4
enforcer and the conjunctive gate authorizes the action.

Import-clean at module load (stdlib only); ``vigil_gateway.denylist`` is imported lazily on first use
(present in the offense env) so the safety package imports anywhere.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Callable, Iterable, Optional
from urllib.parse import urlsplit

# Known cloud-metadata hostnames (the IPs — 169.254.169.254, 100.100.100.200, fd00:ec2::254 — are
# already caught by the egress denylist; these cover the hostname aliases).
_METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.goog", "metadata",
    "instance-data", "instance-data.ec2.internal",
})

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class UnsafeURLError(RuntimeError):
    """A URL was refused by the SSRF/metadata pre-filter — it must not be fetched. Fail-closed."""


def _egress_denied() -> Callable[..., tuple[bool, str]]:
    """Resolve ``vigil_gateway.denylist.is_egress_denied`` lazily; the offense env provides it."""
    try:
        from vigil_gateway.denylist import is_egress_denied  # type: ignore
    except Exception as exc:  # pragma: no cover - misconfiguration in a non-offense env
        raise RuntimeError(
            "url_guard requires vigil_gateway.denylist (the P6 egress denylist) on the path; "
            "it is the single source of truth for the always-denied ranges. Missing: " + repr(exc)
        ) from exc
    return is_egress_denied


def _resolve_ips(host: str, port: int) -> list[str]:
    """All A/AAAA addresses ``host`` resolves to (deduped). An IP literal returns itself. Empty on
    resolution failure (caller fails closed)."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in out:
            out.append(addr)
    return out


def is_safe_url(
    url: str,
    *,
    allowed_ips: Optional[Iterable[str]] = None,
    require_tls_on_public: bool = True,
    resolve: Optional[Callable[[str, int], list[str]]] = None,
) -> tuple[bool, str]:
    """Return ``(safe, reason)`` for using ``url``. ``allowed_ips`` are charter-authorized concrete
    IPs that may lift the *private* egress tier (never the hard-deny tier). ``resolve`` is injectable
    for tests. Fail-closed on every ambiguity."""
    if not isinstance(url, str) or not url.strip():
        return False, "empty or non-string URL (fail-closed)"
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        return False, f"unparseable URL: {exc} (fail-closed)"
    scheme = (parts.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"scheme {scheme!r} is not http/https (fail-closed)"
    host = (parts.hostname or "").lower().strip("[]")
    if not host:
        return False, "URL has no host (fail-closed)"
    if host in _METADATA_HOSTS:
        return False, f"{host!r} is a cloud-metadata hostname (blocked)"
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        return False, "invalid port (fail-closed)"

    resolver = resolve or _resolve_ips
    ips = resolver(host, port)
    if not ips:
        return False, f"host {host!r} did not resolve to any IP (fail-closed)"

    is_egress_denied = _egress_denied()
    allow = list(allowed_ips or ())
    for ip in ips:
        denied, why = is_egress_denied(ip, allow)
        if denied:
            return False, f"resolved IP {ip} for {host!r} is denied: {why}"

    if require_tls_on_public and scheme == "http":
        # Plaintext to a public host leaks config/secrets; all resolved IPs are non-denied (public
        # or explicitly-allowed private). Allow http ONLY to explicitly-allowlisted (internal) IPs.
        allow_set = set(str(a) for a in allow)
        if not all(ip in allow_set for ip in ips):
            return False, f"plaintext http to a public host {host!r} is refused (use https)"

    return True, "allowed"


def assert_safe_url(url: str, **kwargs) -> None:
    """Raise :class:`UnsafeURLError` fail-closed unless ``url`` passes :func:`is_safe_url`."""
    safe, reason = is_safe_url(url, **kwargs)
    if not safe:
        raise UnsafeURLError(reason)
