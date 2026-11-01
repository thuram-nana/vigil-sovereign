"""SSRF-hardened sovereign fetcher for asset-ownership proofs (Slice G0): ``.well-known`` HTTP file AND
DNS-TXT (over DNS-over-HTTPS). OFF by default (``config.ownership_verify_enabled``) — the sovereign plane
makes no outbound request unless the operator explicitly opts in (same posture as the email sender).

Two methods, one hardened fetcher:
  * ``well-known`` — ``GET https://<host>/.well-known/vigil-site-verification.txt`` reads the token the
    customer published in their own web root. Returns the body string.
  * ``dns-txt`` — queries the TXT record at ``_vigil-challenge.<host>`` via DNS-over-HTTPS (JSON) to a
    PINNED, operator-configured PUBLIC resolver, and returns the list of TXT values. The customer host is
    NEVER connected for this method (we ask the resolver for the record), so it cannot be an SSRF vector;
    and because the published value must equal the owner-signed 256-bit challenge token (HMAC-compared in
    ``asset_ownership.observation_proves``), even a hostile/MITM resolver cannot forge a passing proof.

SSRF/rebinding defence (both methods, fail-closed), applied to whichever host we actually CONNECT to (the
customer host for well-known; the DoH resolver for dns-txt):
  * resolve the host to ALL addresses; if ANY is non-global (loopback, link-local incl. 169.254.169.254,
    RFC1918, CGNAT 100.64/10, IPv6-ULA, multicast, reserved, unspecified) the fetch is REFUSED — a
    split-horizon name is refused, not fetched;
  * the socket connects to the VALIDATED resolved IP (pinned) while TLS SNI + cert validation use the
    HOSTNAME — a DNS rebind between resolve-check and connect cannot redirect to a fresh internal address;
  * https only, NO redirect following (a 30x toward an internal URL is never chased), a hard per-op timeout
    under an absolute wall-clock budget, and a BOUNDED read (a huge/slow-drip body cannot exhaust memory).

The ``dns-txt`` VERDICT lives in ``governor.asset_ownership``; this module is the FETCH half. An HTML
meta-tag method is a follow-on (SS-2). Extensible: a new method adds a branch here + a verdict branch,
without touching the authorization system. FATAL-2: sovereign-side, stdlib only
(socket/ssl/http.client/ipaddress/json/urllib.parse), ``assert_no_offense`` at import; no framework/strix.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from typing import Any, Callable
from urllib.parse import quote

from ..reuse import assert_no_offense

assert_no_offense()

from .target_authorization import _validate_host  # noqa: E402  (the ONE host floor; reused, no drift)
from ..governor.asset_ownership import (  # noqa: E402
    METHOD_DNS_TXT,
    METHOD_WELL_KNOWN,
    dns_txt_name,
    well_known_path,
)

_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_TOTAL_TIMEOUT_S = 10.0  # absolute wall-clock budget for the whole fetch (anti slow-drip thread-hold)
_DEFAULT_MAX_BYTES = 4096        # a verification marker is tiny; a larger body is refused (anti-DoS)
_DEFAULT_DOH_RESOLVER = "cloudflare-dns.com"  # a PINNED public DoH resolver; operator-overridable, must be public
_DNS_TYPE_TXT = 16
_MAX_TXT_ANSWERS = 32            # a sane cap on parsed TXT answers (anti-DoS on a hostile resolver reply)


class OwnershipFetchError(Exception):
    """A fetch was refused or failed. The provisioner maps it to a clean customer-facing error without
    leaking internals."""


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
    """SSRF-hardened fetcher for both the ``well-known`` and ``dns-txt`` ownership methods. ``resolver`` and
    ``ssl_context`` are injectable (tests inject a resolver to exercise the SSRF gate without real network).
    ``doh_resolver`` is the PINNED public DNS-over-HTTPS resolver for the dns-txt method."""

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT_S, total_timeout: float = _DEFAULT_TOTAL_TIMEOUT_S,
                 max_bytes: int = _DEFAULT_MAX_BYTES, resolver: Callable[..., Any] = socket.getaddrinfo,
                 ssl_context: "ssl.SSLContext | None" = None, monotonic: Callable[[], float] = time.monotonic,
                 doh_resolver: str = _DEFAULT_DOH_RESOLVER):
        self._timeout = float(timeout)
        self._total = float(total_timeout)
        self._max_bytes = int(max_bytes)
        self._resolver = resolver
        self._ctx = ssl_context if ssl_context is not None else ssl.create_default_context()
        self._monotonic = monotonic
        self._doh_resolver = str(doh_resolver or _DEFAULT_DOH_RESOLVER)

    def _op_timeout(self, start: float) -> float:
        """Per-operation socket timeout, capped by the REMAINING total budget — an ABSOLUTE wall-clock
        deadline across connect→handshake→read, so a cooperating host cannot drip-feed just under the per-op
        timeout to hold a thread far beyond the budget. Raises (fail-closed) once the budget is spent."""
        remaining = self._total - (self._monotonic() - start)
        if remaining <= 0:
            raise OwnershipFetchError("ownership fetch exceeded its total time budget")
        return min(self._timeout, remaining)

    def _open_pinned_https(self, host: str, start: float) -> http.client.HTTPSConnection:
        """Open an https connection PINNED to a validated-public resolved IP for ``host`` (the SSRF gate +
        rebinding defence): resolve→refuse-if-any-internal→connect-to-validated-IP→TLS with SNI/cert against
        the HOSTNAME. Shared by both the well-known fetch (host = customer host) and the dns-txt fetch (host =
        the DoH resolver). Raises ``OwnershipFetchError`` fail-closed."""
        ip = _resolve_public_ip(host, resolver=self._resolver)     # SSRF gate (raises if any addr internal)
        raw = socket.create_connection((ip, 443), timeout=self._op_timeout(start))
        try:
            raw.settimeout(self._op_timeout(start))                # bound the TLS handshake by remaining budget
            tls = self._ctx.wrap_socket(raw, server_hostname=host)  # SNI + cert validation against the HOSTNAME
        except OwnershipFetchError:
            raw.close()
            raise                                                  # budget exhausted setting up the handshake
        except Exception as e:  # noqa: BLE001 — a TLS failure is a fail-closed refusal, not a crash
            raw.close()
            raise OwnershipFetchError(f"TLS to {host!r} failed: {e}") from None
        conn = http.client.HTTPSConnection(host, timeout=self._timeout)
        conn.sock = tls                                            # pinned to the validated IP; no re-resolve
        return conn

    def fetch(self, method: str, host: str, *, now: Any = None) -> "str | list[str]":
        """Return the ownership observation the verdict re-checks: the well-known body (str) for
        ``well-known``, or the list of TXT values (list[str]) for ``dns-txt``. Raises ``OwnershipFetchError``
        fail-closed. The host floor (bare DNS hostname, not IP/URL/port/protected) is re-applied before any
        network for BOTH methods."""
        m = str(method)
        # Re-apply the ONE host floor before any network: the fetcher must never be driven to a URL/path/port
        # or protected host (the customer-named host is the subject of BOTH methods).
        ok, host_or_err = _validate_host(str(host or ""), environment="live")
        if not ok:
            raise OwnershipFetchError(f"refused host: {host_or_err}")
        h = host_or_err
        start = self._monotonic()                                  # anchor the absolute wall-clock deadline
        if m == METHOD_WELL_KNOWN:
            return self._fetch_well_known(h, start)
        if m == METHOD_DNS_TXT:
            return self._fetch_dns_txt(h, start)
        raise OwnershipFetchError(f"unsupported ownership method {m!r}")

    def _fetch_well_known(self, h: str, start: float) -> str:
        conn = self._open_pinned_https(h, start)
        try:
            conn.sock.settimeout(self._op_timeout(start))          # bound request+response by remaining budget
            conn.request("GET", well_known_path(),
                         headers={"Host": h, "User-Agent": "VIGIL-ownership-verify", "Accept": "text/plain",
                                  "Connection": "close"})
            resp = conn.getresponse()                              # http.client does NOT auto-follow redirects
            if resp.status != 200:
                raise OwnershipFetchError(f"well-known returned HTTP {resp.status}")
            conn.sock.settimeout(self._op_timeout(start))          # bound the body read by remaining budget
            body = resp.read(self._max_bytes + 1)
            if len(body) > self._max_bytes:
                raise OwnershipFetchError("well-known body too large")
            return body.decode("utf-8", "replace")
        except OwnershipFetchError:
            raise
        except Exception as e:  # noqa: BLE001 — any transport error is a fail-closed refusal
            raise OwnershipFetchError(f"well-known fetch failed: {e}") from None
        finally:
            _quiet_close(conn)

    def _fetch_dns_txt(self, h: str, start: float) -> "list[str]":
        """Query ``_vigil-challenge.<h>`` TXT via DNS-over-HTTPS (JSON) at the pinned public resolver, and
        return the list of TXT string values (surrounding quotes stripped). We connect to the RESOLVER (not
        the customer host), so this is not an SSRF path to the customer's infra; the resolver host still goes
        through the full pinned/validated connect. Fail-closed on any transport/parse error."""
        qname = dns_txt_name(h)                                    # _vigil-challenge.<host> — exact host only
        conn = self._open_pinned_https(self._doh_resolver, start)
        try:
            conn.sock.settimeout(self._op_timeout(start))
            path = f"/dns-query?name={quote(qname, safe='')}&type=TXT"
            conn.request("GET", path,
                         headers={"Host": self._doh_resolver, "User-Agent": "VIGIL-ownership-verify",
                                  "Accept": "application/dns-json", "Connection": "close"})
            resp = conn.getresponse()                              # no auto-redirect; a 30x -> non-200 -> refused
            if resp.status != 200:
                raise OwnershipFetchError(f"DoH resolver returned HTTP {resp.status}")
            conn.sock.settimeout(self._op_timeout(start))
            raw = resp.read(self._max_bytes + 1)
            if len(raw) > self._max_bytes:
                raise OwnershipFetchError("DoH response too large")
            return _parse_doh_txt(raw)
        except OwnershipFetchError:
            raise
        except Exception as e:  # noqa: BLE001 — any transport error is a fail-closed refusal
            raise OwnershipFetchError(f"dns-txt fetch failed: {e}") from None
        finally:
            _quiet_close(conn)


def _parse_doh_txt(raw: bytes) -> "list[str]":
    """Extract TXT string values from a DNS-over-HTTPS JSON reply (fail-closed: malformed → []). Each TXT
    ``data`` is a DNS character-string, typically wrapped in double quotes by the resolver; strip ONE
    surrounding pair. Bounded to ``_MAX_TXT_ANSWERS``."""
    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return []
    if not isinstance(doc, dict):
        return []
    answers = doc.get("Answer")
    if not isinstance(answers, list):
        return []
    out: list[str] = []
    for ans in answers[:_MAX_TXT_ANSWERS]:
        if not isinstance(ans, dict) or ans.get("type") != _DNS_TYPE_TXT:
            continue
        data = ans.get("data")
        if not isinstance(data, str):
            continue
        s = data.strip()
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        out.append(s)
    return out


def _quiet_close(conn: Any) -> None:
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass
