"""
scope_source — the charter scope, as the gateway sees it.

The gateway does NOT reinvent scope parsing. It reuses CRUCIBLE's audited, single-file
ethics gate (``framework.v2.common.ethics``): ``parse_scope`` (the literal host list from
the signed charter), ``host_matches_scope`` (literal / ``*.`` wildcard / canonical IPv6),
and ``extract_hostname`` (IPv6-correct). Every existing CRUCIBLE gate (egress_guard,
scope_gate, authority/gate, intel/transport) delegates to the same predicate, so wrapping
it here keeps one source of truth for "in scope". This module puts it behind a small
interface so the proxy and the nftables renderer share that notion, and so tests can
inject a static scope without a charter on disk.

``resolved_allowed_ips()`` best-effort resolves the concrete scope hosts (literal
hostnames and IP literals — not wildcards) to a set of IPs. That set is advisory for the
static nftables allow-set and authoritative-as-an-*exception* for the proxy's private-IP
re-check: a resolved connection IP in a private range is only allowed if it is exactly one
of these charter-authorized IPs. DNS is dynamic, so the proxy re-checks every connection's
resolved IP at request time (see proxy.py) — the static set is never the sole gate.
"""

from __future__ import annotations

import socket
import sys
from abc import ABC, abstractmethod
from pathlib import Path


def _bootstrap_crucible_import():
    """Import CRUCIBLE's ethics gate, adding engine/crucible to sys.path if needed.

    The gateway is offense-side infrastructure; reusing ``framework`` is intended. The
    package is path-based (not pip-installed), so locate engine/crucible relative to this
    file (repo_root/engine/crucible) and insert it if the plain import fails.
    """
    try:
        from framework.v2.common.ethics import (  # type: ignore
            extract_hostname,
            host_matches_scope,
            parse_scope,
        )
        return parse_scope, host_matches_scope, extract_hostname
    except ImportError:
        repo_root = Path(__file__).resolve().parents[2]
        crucible = repo_root / "engine" / "crucible"
        if crucible.is_dir() and str(crucible) not in sys.path:
            sys.path.insert(0, str(crucible))
        from framework.v2.common.ethics import (  # type: ignore
            extract_hostname,
            host_matches_scope,
            parse_scope,
        )
        return parse_scope, host_matches_scope, extract_hostname


_GATE: tuple | None = None


def _gate():
    """Lazily import CRUCIBLE's ethics gate on first use, so importing this module (and the
    pure denylist path that pulls the package ``__init__``) does not require the CRUCIBLE
    package to be present — only actually evaluating scope does."""
    global _GATE
    if _GATE is None:
        _GATE = _bootstrap_crucible_import()
    return _GATE


class ScopeSource(ABC):
    """The gateway's view of the active charter scope."""

    @abstractmethod
    def hosts(self) -> list[str]:
        """The literal scope entries (hostnames, wildcard domains, IP literals)."""

    def matches(self, host: str) -> bool:
        """True iff ``host`` is inside the charter scope (CRUCIBLE semantics)."""
        if not host:
            return False
        _, host_matches_scope, _ = _gate()
        return host_matches_scope(host, self.hosts())

    def matches_url(self, url: str) -> bool:
        """True iff the hostname of ``url`` is in scope. Fail-closed on unparseable."""
        _, _, extract_hostname = _gate()
        host = extract_hostname(url)
        if not host:
            return False
        return self.matches(host)

    def resolved_allowed_ips(self, *, resolver=socket.getaddrinfo) -> frozenset[str]:
        """Best-effort concrete IPs for non-wildcard scope entries.

        Wildcard entries (``*.example.com``) are skipped — there is no single host to
        resolve; the proxy validates such hosts per-request. Resolution failures are
        skipped (a name that will not resolve authorises nothing). ``resolver`` is
        injectable for hermetic tests.
        """
        ips: set[str] = set()
        for raw in self.hosts():
            entry = raw.strip().strip("`").rstrip(".")
            if not entry or entry.startswith("*.") or entry.lower() in {"n/a", "none"}:
                continue
            try:
                infos = resolver(entry, None)
            except (socket.gaierror, OSError, UnicodeError):
                continue
            for info in infos:
                sockaddr = info[4]
                if sockaddr and sockaddr[0]:
                    ips.add(sockaddr[0])
        return frozenset(ips)


class StaticScopeSource(ScopeSource):
    """A fixed scope list — for injection and hermetic tests."""

    def __init__(self, hosts: list[str]):
        self._hosts = list(hosts)

    def hosts(self) -> list[str]:
        return list(self._hosts)


class CharterScopeSource(ScopeSource):
    """Scope read live from a signed charter via CRUCIBLE ``parse_scope(slug)``.

    Reads the charter each call so a mid-engagement re-sign is picked up. Raising
    behaviour (missing charter) is CRUCIBLE's — the gateway does not soften it.
    """

    def __init__(self, slug: str):
        self.slug = slug

    def hosts(self) -> list[str]:
        parse_scope, _, _ = _gate()
        return parse_scope(self.slug)
