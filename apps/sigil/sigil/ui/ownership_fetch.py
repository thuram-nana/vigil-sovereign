"""SSRF-hardened sovereign fetcher for the ``/.well-known`` asset-ownership proof (Slice G0).

The ONE outbound fetch the ownership flow needs: ``GET https://<host>/.well-known/vigil-site-verification.txt``
to READ the token a customer published in their own web root. It is OFF by default
(``config.ownership_verify_enabled``) — the sovereign plane makes no outbound request to a customer-named
host unless the operator explicitly opts in (the same posture as the off-by-default email sender).

SSRF is the whole risk: the host is CUSTOMER-NAMED, so a malicious customer could name an internal
hostname (or one whose DNS resolves to internal space) to turn this process into a confused deputy fetching
an internal URL. Defence, fail-closed:
  * resolve the host to ALL of its addresses; if ANY resolves to NON-GLOBAL space (loopback, link-local incl.
    the 169.254.169.254 cloud-metadata address, RFC1918, CGNAT 100.64/10, IPv6-ULA, multicast, reserved,
    unspecified) the fetch is REFUSED and NO connection is made — so a split-horizon name that returns both a
    public and an internal address is refused, not fetched;
  * the socket connects to the VALIDATED resolved IP (pinned), while TLS SNI + certificate validation use the
    HOSTNAME — so a DNS rebind between the resolve-check and the connect cannot redirect the fetch to a fresh
    internal address;
  * https only, NO redirect following (a 30x toward an internal URL is never chased), a hard connect/read
    timeout, and a BOUNDED read (a huge or slow-drip body cannot exhaust memory).

The ``dns-txt`` method's VERDICT is built + tested (``governor.asset_ownership``), but its FETCH needs a DNS
TXT resolver the stdlib does not provide; this fetcher therefore serves the ``well-known`` method and refuses
``dns-txt`` (honest — a dns-txt fetch adapter is a follow-on). FATAL-2: sovereign-side, stdlib only
(socket/ssl/http.client/ipaddress), ``assert_no_offense`` at import; no framework/strix.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from typing import Any, Callable

from ..reuse import assert_no_offense

assert_no_offense()

from .target_authorization import _validate_host  # noqa: E402  (the ONE host floor; reused, no drift)
from ..governor.asset_ownership import METHOD_WELL_KNOWN, well_known_path  # noqa: E402

_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_MAX_BYTES = 4096        # a verification marker is tiny; a larger body is refused (anti-DoS)


class OwnershipFetchError(Exception):
    """A well-known fetch was refused or failed. The provisioner maps it to a clean customer-facing error
    without leaking internals."""


def _addr_is_internal(ip_str: Any) -> bool:
    """True iff ``ip_str`` is anything but a globally-routable public address — FAIL-CLOSED: an unparseable
    value, or any non-global / loopback / link-local / private / CGNAT / ULA / multicast / reserved /
    unspecified address, is treated as internal (refused). ``is_global`` is the primary allowlist; the
    explicit flags are belt-and-suspenders against any runtime quirk in the global classification."""
    try:
        ip = ipaddress.ip_address(str(ip_str))
    except ValueError:
        return True
    cgnat = ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")
    return bool((not ip.is_global) or ip.is_loopback or ip.is_link_local or ip.is_private
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified or cgnat)


def _resolve_public_ip(host: str, *, resolver: Callable[..., Any]) -> str:
    """Resolve ``host`` and return ONE validated-public IP to PIN the connect to. Raises
    ``OwnershipFetchError`` (fail-closed) if resolution fails, yields no address, or ANY resolved address is
    internal — refusing when ANY resolved address is internal defeats a split-horizon name that returns a
    public AND an internal address."""
    try:
        infos = resolver(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        raise OwnershipFetchError(f"could not resolve {host!r}") from None
    ips = []
    for info in infos:
        try:
            ip = info[4][0]
        except (IndexError, TypeError):
            raise OwnershipFetchError("malformed address resolution") from None
        if _addr_is_internal(ip):
            raise OwnershipFetchError(f"{host!r} resolves to a non-global address — refused (SSRF guard)")
        ips.append(str(ip))
    if not ips:
        raise OwnershipFetchError(f"no addresses for {host!r}")
    return ips[0]


class WellKnownFetcher:
    """Fetch the well-known marker over https, SSRF-hardened. ``resolver`` and ``ssl_context`` are injectable
    (tests inject a resolver to exercise the SSRF gate without real network)."""

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT_S, max_bytes: int = _DEFAULT_MAX_BYTES,
                 resolver: Callable[..., Any] = socket.getaddrinfo, ssl_context: "ssl.SSLContext | None" = None):
        self._timeout = float(timeout)
        self._max_bytes = int(max_bytes)
        self._resolver = resolver
        self._ctx = ssl_context if ssl_context is not None else ssl.create_default_context()

    def fetch(self, method: str, host: str, *, now: Any = None) -> str:
        """Return the well-known body as text, or raise ``OwnershipFetchError`` (fail-closed)."""
        if str(method) != METHOD_WELL_KNOWN:
            raise OwnershipFetchError(f"this fetcher serves only {METHOD_WELL_KNOWN!r} "
                                      f"(a dns-txt fetch adapter is not available)")
        # Re-apply the ONE host floor (bare DNS hostname, not an IP literal via the live tier, categorical
        # floor) before any network: the fetcher must never be driven to a URL/path/port or protected host.
        ok, host_or_err = _validate_host(str(host or ""), environment="live")
        if not ok:
            raise OwnershipFetchError(f"refused host: {host_or_err}")
        h = host_or_err
        ip = _resolve_public_ip(h, resolver=self._resolver)        # SSRF gate (raises if any addr internal)
        raw = socket.create_connection((ip, 443), timeout=self._timeout)
        try:
            tls = self._ctx.wrap_socket(raw, server_hostname=h)    # SNI + cert validation against the HOSTNAME
        except Exception as e:  # noqa: BLE001 — a TLS failure is a fail-closed refusal, not a crash
            raw.close()
            raise OwnershipFetchError(f"TLS to {h!r} failed: {e}") from None
        conn = http.client.HTTPSConnection(h, timeout=self._timeout)
        conn.sock = tls                                            # pinned to the validated IP; no re-resolve
        try:
            conn.request("GET", well_known_path(),
                         headers={"Host": h, "User-Agent": "VIGIL-ownership-verify", "Accept": "text/plain",
                                  "Connection": "close"})
            resp = conn.getresponse()                              # http.client does NOT auto-follow redirects
            if resp.status != 200:
                raise OwnershipFetchError(f"well-known returned HTTP {resp.status}")
            body = resp.read(self._max_bytes + 1)
            if len(body) > self._max_bytes:
                raise OwnershipFetchError("well-known body too large")
            return body.decode("utf-8", "replace")
        except OwnershipFetchError:
            raise
        except Exception as e:  # noqa: BLE001 — any transport error is a fail-closed refusal
            raise OwnershipFetchError(f"well-known fetch failed: {e}") from None
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
