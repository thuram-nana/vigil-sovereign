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


def _local_gate():
    """The STDLIB-ONLY fallback used inside the gateway container (no framework, no engine/crucible on the
    path). ``host_matches_scope`` + ``extract_hostname`` are ported verbatim in ``scope_match`` and kept in
    lock-step with CRUCIBLE's originals by ``test_scope_match_parity``. ``parse_scope`` (reading a signed
    charter) is NOT ported — that is the launcher's host-side job (it injects the resolved hosts via
    ``VIGIL_GATEWAY_SCOPE_HOSTS``), so the container only ever MATCHES against an already-parsed static scope;
    a container-side ``CharterScopeSource`` (which would call parse_scope) is never constructed. If one ever
    were, this raises rather than silently mis-parsing."""
    from . import scope_match

    def _parse_scope_unavailable(_slug: str):
        raise RuntimeError(
            "charter parsing (parse_scope) requires the CRUCIBLE ethics gate, which is not present in the "
            "stdlib-only gateway container; scope must be injected as VIGIL_GATEWAY_SCOPE_HOSTS by the "
            "host-side launcher (see gateway/README.md B2). The container matches, it does not parse.")

    return _parse_scope_unavailable, scope_match.host_matches_scope, scope_match.extract_hostname


def _bootstrap_crucible_import():
    """Import CRUCIBLE's ethics gate, adding engine/crucible to sys.path if needed; FALL BACK to the
    stdlib-only ``scope_match`` when framework is genuinely absent (the gateway container).

    The gateway is offense-side infrastructure; reusing ``framework`` is the single source of truth when it
    is importable (the host-run path). But the egress gateway also ships as a STDLIB-ONLY container with no
    framework and no engine/crucible on the path — there the per-connection matching predicate must STILL
    work (else the proxy denies every host and the injected scope is inert). So on a genuine ImportError we
    return the verbatim-ported local matching functions instead of raising (B2 red-pen BLOCK)."""
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
        try:
            from framework.v2.common.ethics import (  # type: ignore
                extract_hostname,
                host_matches_scope,
                parse_scope,
            )
            return parse_scope, host_matches_scope, extract_hostname
        except ImportError:
            # Fall back to the ported local matcher ONLY when the framework package is GENUINELY absent (the
            # stdlib-only container). If `framework` IS importable but ethics failed for a real reason (a
            # broken sibling on the host path), re-raise the true error rather than masking it behind the
            # container fallback (red-pen LOW: keep host-side faults diagnosable).
            import importlib.util
            if importlib.util.find_spec("framework") is None:
                return _local_gate()
            raise


_GATE: tuple | None = None


def _gate():
    """Lazily import CRUCIBLE's ethics gate on first use, so importing this module (and the
    pure denylist path that pulls the package ``__init__``) does not require the CRUCIBLE
    package to be present — only actually evaluating scope does."""
    global _GATE
    if _GATE is None:
        _GATE = _bootstrap_crucible_import()
    return _GATE


def _require_charter_signed(slug: str) -> None:
    """A3: refuse to trust a charter's scope unless the charter is SIGNED. Previously ``CharterScopeSource``
    read scope via ``parse_scope`` WITHOUT ever calling ``require_charter_signed``, so the gateway would
    authorize destinations from an UNSIGNED charter despite advertising signed-charter authorization. This
    enforces it (fail-closed: an unsigned/missing charter raises, exactly like the missing-charter path).
    Lazily imports CRUCIBLE's ethics gate with the same bootstrap as ``_gate``."""
    try:
        from framework.v2.common.ethics import require_charter_signed  # type: ignore
    except ImportError:
        _gate()   # ensures engine/crucible is on sys.path, then retry
        from framework.v2.common.ethics import require_charter_signed  # type: ignore
    require_charter_signed(slug)


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
        _require_charter_signed(self.slug)   # A3: an UNSIGNED/missing charter is refused (fail-closed)
        parse_scope, _, _ = _gate()
        return parse_scope(self.slug)
