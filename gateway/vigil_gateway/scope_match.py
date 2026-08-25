"""scope_match — the charter-scope MATCHING predicate, as a STDLIB-ONLY fallback for the gateway container.

The gateway reuses CRUCIBLE's audited ``framework.v2.common.ethics`` matching semantics when framework is
importable (the host-run path, single source of truth). But the egress gateway also runs as a **stdlib-only
container** (no framework, no engine/crucible on the path — see gateway/Dockerfile), and the per-connection
L7 check (`proxy.py` → `ScopeSource.matches`) MUST work there. Before this module existed, ``matches`` raised
``ModuleNotFoundError`` inside the container, so the proxy could never confirm a host in scope and every
in-scope destination was denied — the gateway was structurally deny-all regardless of the injected scope
(B2 red-pen BLOCK).

These four functions are **ported verbatim** from ``framework.v2.common.ethics`` (they are pure — `ipaddress`
/ `re` / `urllib.parse` only, no `vigil_core`/framework dependency). ``scope_source._gate`` prefers the
framework originals and falls back to these; ``test_scope_match_parity`` asserts the two implementations agree
over a corpus so they can never silently drift. NOTE: charter *parsing* (`parse_scope`) is deliberately NOT
ported — reading a signed charter is the launcher's host-side job (it injects the resolved hosts via
``VIGIL_GATEWAY_SCOPE_HOSTS``); the container only ever MATCHES against an already-parsed static scope.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_URL_AUTHORITY_RE = re.compile(
    r"^(?P<userinfo>[^@/?#]*@)?(?P<hostport>[^/?#]*)(?P<tail>[/?#].*)?$", re.DOTALL
)


def bracket_bare_ipv6(url: str) -> str:
    """Return ``url`` with a bare (unbracketed) IPv6 authority wrapped in ``[]`` so ``urlparse`` extracts the
    host correctly; a no-op for every other input."""
    scheme, sep, rest = url.partition("://")
    if not sep:
        return url
    m = _URL_AUTHORITY_RE.match(rest)
    if m is None:
        return url
    hostport = m.group("hostport") or ""
    if not hostport or hostport.startswith("["):
        return url  # empty, or already bracketed — leave untouched
    try:
        if ipaddress.ip_address(hostport).version != 6:
            return url  # IPv4 or (with a port present) not a bare literal
    except ValueError:
        return url  # a hostname or host:port — unchanged
    return f"{scheme}://{m.group('userinfo') or ''}[{hostport}]{m.group('tail') or ''}"


def extract_hostname(target_url: str) -> "str | None":
    """The hostname of a URL or bare host, correct for IPv6 literals (bracketed or bare)."""
    raw = target_url if "://" in target_url else "https://" + target_url
    return urlparse(bracket_bare_ipv6(raw)).hostname


def _as_ipv6(value: str) -> "ipaddress.IPv6Address | None":
    """The canonical IPv6 address ``value`` denotes, else None (IPv4, a hostname, or unparseable)."""
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except (ValueError, AttributeError):
        return None
    return ip if ip.version == 6 else None


def host_matches_scope(host: str, scope_entries: "list[str]") -> bool:
    """Match a hostname against scope entries: literal, ``*.`` wildcard (incl. the apex), and canonical IPv6
    literal. Ported verbatim from ``framework.v2.common.ethics.host_matches_scope`` (kept in lock-step by
    ``test_scope_match_parity``)."""
    h = host.lower().strip().rstrip(".")
    if not h:
        return False
    h_v6 = _as_ipv6(h)
    for raw in scope_entries:
        e = raw.lower().strip().strip("`").rstrip(".")
        if not e:
            continue
        if e in {"n/a", "n\\/a", "none"}:  # tolerate sentinels operators write when a row doesn't apply
            continue
        if h_v6 is not None:
            e_v6 = _as_ipv6(e)
            if e_v6 is not None and e_v6 == h_v6:
                return True
            continue  # an IP host never falls through to wildcard/string logic
        if e.startswith("*."):
            base = e[2:]
            if h == base or h.endswith("." + base):
                return True
        elif h == e:
            return True
    return False
