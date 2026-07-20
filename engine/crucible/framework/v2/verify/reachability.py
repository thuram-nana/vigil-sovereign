"""
verify.reachability — reproduce a real transport handshake and confirm a service is reachable.

The service-reachability half of prove-don't-guess. A scanner (Nmap, W2.2) *observes* "open 443";
this turns that observation into a FACT by reproducing the handshake INDEPENDENTLY — a bounded TCP
connect to host:port that CRUCIBLE performs itself — and judging the retained connect evidence with
the pure ``service_reachability_oracle``. Because the evidence is JSON-safe and the oracle is
deterministic, a confirmed reachability RE-VERIFIES OFFLINE from its certificate (``verify.reverify``)
with no network and no trust in the scanner — exactly like every other oracle.

The active connect is GATED and BOUNDED, fail-closed by construction:

    kill-switch  ->  single-host target  ->  ACTIVE_RECON entitlement  ->  charter scope

A refusal (or a connect failure) returns a ``connected: False`` handshake with a reason — it never
raises and never fabricates a connection. One attempt, a hard timeout, a small bounded banner read.
``connect`` is injectable so the capture + oracle path is fully testable offline with no socket.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Callable

from .adapter import FindingContext
from .models import VerificationResult
from .verifier import OracleVerifier

_DEFAULT_TIMEOUT = 3.0
_BANNER_BYTES = 256


def _is_single_host(host: str) -> bool:
    """A handshake is to exactly ONE host: a single IPv4 literal or a single DNS hostname. Reject
    CIDR / range / list / wildcard / option-like input so the connect target is unambiguous and the
    scope gate validates the SAME host we probe (the W2.2 lesson, applied here too). IPv6 is rejected
    for now — the URL-shaped charter-scope gate truncates a bare IPv6 literal (``fe80::1`` -> ``fe80``),
    so it would validate a different string than the address dialled; support returns with bracketed
    IPv6 in the scope layer."""
    h = (host or "").strip()
    if not h or h.startswith("-") or any(c in h for c in "/,*") or any(c.isspace() for c in h):
        return False
    try:
        return ipaddress.ip_address(h).version == 4   # a single IPv4 literal (IPv6 deferred)
    except ValueError:
        return any(c.isalpha() for c in h)   # a hostname has a letter; a numeric non-IP is a range/typo


def _authorize(host: str, port: Any, slug: str) -> str | None:
    """Fail-closed pre-flight for the active connect. Returns a refusal reason, or None to proceed.
    Mirrors the tool invoker's gate order (kill-switch -> entitlement -> scope) for a raw socket.

    An active probe is ALWAYS bound to an engagement: an empty ``slug`` (no charter context) is
    refused, and the host must be in that charter's scope — there is no un-scoped active connect."""
    if not slug:
        return "an active probe requires an engagement slug (no charter context = no authorization)"
    try:
        from ..authority import KillSwitch
        if KillSwitch(slug).is_tripped():
            return "kill-switch tripped"
    except Exception as e:                       # a failing check REFUSES (fail-closed)
        return f"kill-switch check failed (fail-closed): {e}"
    if not _is_single_host(host):
        return "target must be a single host/IP (no CIDR/range/list/flag)"
    if not isinstance(port, int) or not (0 < port < 65536):
        return "port must be an integer in 1..65535"
    try:
        from ..entitlement import require_capability
        from ..entitlement.models import Capability
        require_capability(Capability.ACTIVE_RECON)
    except Exception as e:
        return f"active_recon not entitled: {e}"
    try:
        from ..common import ethics
        ethics.require_in_scope(slug, host)
    except Exception as e:
        return f"out of charter scope: {e}"
    return None


def _socket_connect(host: str, port: int, timeout: float, read_banner: bool) -> tuple[str, str]:
    """The default connector: ONE bounded TCP connect. Returns (peer, banner); raises OSError on a
    refused/timed-out connect (the caller turns that into a ``connected: False`` handshake)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        peer = ""
        try:
            pn = sock.getpeername()
            peer = f"{pn[0]}:{pn[1]}"
        except OSError:
            peer = ""
        banner = ""
        if read_banner:
            try:
                data = sock.recv(_BANNER_BYTES)
                banner = data.decode("utf-8", "replace") if data else ""
            except OSError:
                banner = ""
        return peer, banner


def capture_handshake(
    host: str,
    port: int,
    *,
    slug: str = "",
    protocol: str = "tcp",
    timeout: float = _DEFAULT_TIMEOUT,
    read_banner: bool = True,
    connect: Callable[[str, int, float, bool], tuple[str, str]] | None = None,
) -> dict:
    """Reproduce a bounded, gated handshake to ``host:port`` and return JSON-safe evidence the oracle
    judges. Fail-closed: a gate refusal or a connect failure returns ``connected: False`` with a
    reason — never an exception, never a fabricated connection. ``connect`` is injectable for tests."""
    base = {"connected": False, "host": str(host), "port": port, "protocol": protocol}
    refusal = _authorize(str(host), port, slug)
    if refusal is not None:
        return {**base, "error": refusal}
    conn = connect or _socket_connect
    try:
        peer, banner = conn(str(host), int(port), timeout, read_banner)
    except Exception as e:
        return {**base, "error": f"{type(e).__name__}: {e}"[:200]}
    return {"connected": True, "host": str(host), "port": int(port), "protocol": protocol,
            "peer": str(peer or ""), "banner": str(banner or "")}


def reachable_context(handshake: dict) -> dict:
    """The verifier context for a captured handshake — routes to the service-reachability oracle."""
    return FindingContext.from_handshake(handshake).to_verifier_context()


def confirm_reachable(handshake: dict, *, verifier: OracleVerifier | None = None) -> VerificationResult:
    """Judge a captured handshake with the deterministic oracle: ``confirmed`` iff a real connect to
    the concrete host:port reproduced. The retained ``handshake`` is JSON-safe, so the same verdict
    re-verifies offline from the finding's certificate via ``verify.reverify``."""
    return (verifier or OracleVerifier()).confirm(reachable_context(handshake))
