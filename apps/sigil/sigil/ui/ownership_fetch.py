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
  * before any byte is sent, the connected socket's own peer address (``getpeername``) must equal the
    vetted IP — an undeterminable or different peer is refused;
  * https only, NO redirect following (a 30x toward an internal URL is never chased), a hard per-op timeout
    under an absolute wall-clock budget that covers the WHOLE fetch: the name resolution (run in a worker
    and abandoned at the deadline, so a customer's nameserver that drops queries cannot hold the fetch for
    the system resolver's own retry schedule), the connect, the handshake, and every send and every recv
    (re-armed to the REMAINING budget each time, so a server that drip-feeds its status line, headers or
    body cannot hold the fetch past the deadline) — and a BOUNDED read (a huge body cannot exhaust memory).

Every failure — resolve, connect, TLS, transport — is an ``OwnershipFetchError``. Its ``str()`` is the
fetcher's own fixed wording (it reaches the customer); the underlying library error text (resolver errors,
TLS alerts, socket errors) is carried separately in ``OwnershipFetchError.detail`` for the operator audit
only.

The ``dns-txt`` VERDICT lives in ``governor.asset_ownership``; this module is the FETCH half. An HTML
meta-tag method is a follow-on (SS-2). Extensible: a new method adds a branch here + a verdict branch,
without touching the authorization system. FATAL-2: sovereign-side, stdlib only
(socket/ssl/http.client/ipaddress/json/threading/urllib.parse), ``assert_no_offense`` at import; no
framework/strix.
"""
from __future__ import annotations

import http.client
import io
import ipaddress
import json
import socket
import ssl
import threading
import time
from typing import Any, Callable
from urllib.parse import quote

from ..reuse import assert_no_offense

assert_no_offense()

from .target_authorization import _validate_host  # noqa: E402  (the ONE host floor; reused, no drift)
from ..governor.asset_ownership import (  # noqa: E402
    METHOD_DNS_TXT,
    METHOD_META_TAG,
    METHOD_WELL_KNOWN,
    dns_txt_name,
    well_known_path,
)

_DEFAULT_TIMEOUT_S = 5.0
_DEFAULT_TOTAL_TIMEOUT_S = 10.0  # absolute wall-clock budget for the whole fetch (anti slow-drip thread-hold)
_DEFAULT_MAX_BYTES = 4096        # a verification marker is tiny; a larger body is refused (anti-DoS)
_META_MAX_BYTES = 262144         # a homepage is bigger than a marker; bounded read of the first 256 KiB (anti-DoS)
_DEFAULT_DOH_RESOLVER = "cloudflare-dns.com"  # a PINNED public DoH resolver; operator-overridable, must be public
_DNS_TYPE_TXT = 16
_MAX_TXT_ANSWERS = 32            # a sane cap on parsed TXT answers (anti-DoS on a hostile resolver reply)
_HTTPS_PORT = 443                # the only port ever connected (https); a module constant, never configuration
_connect = socket.create_connection  # the TCP connect (module-level so tests can drive it to loopback)


class OwnershipFetchError(Exception):
    """A fetch was refused or failed. ``str(e)`` is the fetcher's OWN fixed reason (HTTP status, too large,
    SSRF refusal, budget spent, TLS failed) and is what the provisioner shows the customer. ``detail`` is the
    underlying library error text (a TLS alert, a socket error) for the OPERATOR audit only — never echoed
    to the customer."""

    def __init__(self, message: str, *, detail: str = "") -> None:
        super().__init__(message)
        self.detail = str(detail)


def _detail(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"


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


def _call_within(fn: Callable[[], Any], timeout: float) -> Any:
    """Run ``fn`` in a daemon worker and wait at most ``timeout`` seconds for it: return its result or
    re-raise its exception here; raise ``TimeoutError`` if it has not finished. A late worker is abandoned
    (it ends on its own when the system resolver gives up), so the CALLER is never held past ``timeout``."""
    out: "list[Any]" = []
    err: "list[BaseException]" = []

    def run() -> None:
        try:
            out.append(fn())
        except BaseException as e:  # noqa: BLE001 — handed back to the waiting caller, never swallowed
            err.append(e)

    worker = threading.Thread(target=run, name="ownership-resolve", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise TimeoutError(f"name resolution did not finish within {timeout:.2f} s")
    if err:
        raise err[0]
    return out[0]


def _resolve_public_ip(host: str, *, resolver: Callable[..., Any], timeout: "float | None" = None) -> str:
    """Resolve ``host`` and return ONE validated-public IP to PIN the connect to. Raises
    ``OwnershipFetchError`` (fail-closed) if resolution fails, yields no address, or ANY resolved address is
    internal — refusing when ANY resolved address is internal defeats a split-horizon name that returns a
    public AND an internal address. With ``timeout``, a resolution still running after that many seconds is
    a failure too (the fetcher passes the remaining budget)."""
    def query() -> Any:
        return resolver(host, _HTTPS_PORT, type=socket.SOCK_STREAM)
    try:
        infos = query() if timeout is None else _call_within(query, timeout)
    except (socket.gaierror, OSError) as e:
        raise OwnershipFetchError(f"could not resolve {host!r}", detail=_detail(e)) from None
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


def _require_peer(sock: Any, ip: str) -> None:
    """Fail-closed check that ``sock`` is connected to exactly the vetted ``ip`` (taken from the socket
    itself via ``getpeername`` BEFORE any byte is sent). Raises ``OwnershipFetchError`` when the peer differs
    from the vetted address or cannot be determined."""
    try:
        peer = sock.getpeername()[0]
        same = ipaddress.ip_address(str(peer)) == ipaddress.ip_address(str(ip))
    except Exception:  # noqa: BLE001 — an undeterminable peer is a refusal, never a pass
        raise OwnershipFetchError("could not determine the connected peer — refused (SSRF guard)") from None
    if not same:
        raise OwnershipFetchError("connected peer is not the vetted address — refused (SSRF guard)")


class _BudgetedSocket:
    """The pinned TLS socket as ``http.client`` sees it (``conn.sock``). ``arm`` re-sets the socket timeout
    to the REMAINING total budget (raising once it is spent) and runs before EVERY send and EVERY recv: a
    single settimeout bounds each recv separately, so without this a server dripping one byte per recv just
    inside the per-op timeout holds the fetch for as long as it likes. ``close`` is a no-op: http.client
    calls it when a ``Connection: close`` / HTTP/1.0 response takes the socket over (and then sets
    ``conn.sock`` to None); the fetcher closes the real socket itself once the exchange is over."""

    def __init__(self, tls: Any, arm: Callable[[], None]) -> None:
        self._tls = tls
        self._arm = arm

    def sendall(self, data: bytes) -> None:
        self._arm()
        self._tls.sendall(data)

    def makefile(self, mode: str = "rb", *args: Any, **kwargs: Any) -> io.BufferedReader:
        return io.BufferedReader(_BudgetedReader(self._tls, self._arm))

    def close(self) -> None:
        pass


class _BudgetedReader(io.RawIOBase):
    """The raw byte stream under the response: every underlying recv is preceded by ``arm``."""

    def __init__(self, tls: Any, arm: Callable[[], None]) -> None:
        super().__init__()
        self._tls = tls
        self._arm = arm

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        self._arm()
        return int(self._tls.recv_into(b))


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
        if ssl_context is not None:
            self._ctx = ssl_context
        else:
            self._ctx = ssl.create_default_context()
            # Pin the TLS floor EXPLICITLY (do not rely on the interpreter's create_default_context default,
            # which varies by version) — reject TLSv1 / TLSv1.1 for this outbound ownership-verification fetch.
            self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._monotonic = monotonic
        self._doh_resolver = str(doh_resolver or _DEFAULT_DOH_RESOLVER)

    def _op_timeout(self, start: float) -> float:
        """Per-operation timeout, capped by the REMAINING total budget — an ABSOLUTE wall-clock deadline
        across resolve→connect→handshake→read, so a cooperating host (or its nameserver) cannot answer just
        under the per-op timeout to hold a thread far beyond the budget. Raises (fail-closed) once the budget
        is spent."""
        remaining = self._total - (self._monotonic() - start)
        if remaining <= 0:
            raise OwnershipFetchError("ownership fetch exceeded its total time budget")
        return min(self._timeout, remaining)

    def _open_pinned_https(self, host: str, start: float) -> "tuple[http.client.HTTPSConnection, ssl.SSLSocket]":
        """Open an https connection PINNED to a validated-public resolved IP for ``host`` (the SSRF gate +
        rebinding defence): resolve (within the budget)→refuse-if-any-internal→connect-to-validated-IP→verify
        the connected PEER is that IP→TLS with SNI/cert against the HOSTNAME. Shared by both the well-known
        fetch (host = customer host) and the dns-txt fetch (host = the DoH resolver). Returns ``(conn, tls)``:
        every send/recv of ``conn`` goes through ``_BudgetedSocket`` over ``tls`` (the socket the peer check
        vetted), and the caller closes ``tls`` itself — ``conn.sock`` cannot be used for that, http.client sets
        it to None once a ``Connection: close`` (or HTTP/1.0) response hands the socket to the response object.
        Raises ``OwnershipFetchError`` fail-closed (a resolve or connect failure included)."""
        ip = _resolve_public_ip(host, resolver=self._resolver,     # SSRF gate (raises if any addr internal);
                                timeout=self._op_timeout(start))   # bounded by the remaining budget
        try:
            raw = _connect((ip, _HTTPS_PORT), timeout=self._op_timeout(start))
        except OSError as e:                                       # refused / unreachable / connect timeout
            raise OwnershipFetchError(f"could not connect to {host!r}", detail=_detail(e)) from None
        try:
            _require_peer(raw, ip)                                 # the socket really landed on the vetted IP
            raw.settimeout(self._op_timeout(start))                # bound the TLS handshake by remaining budget
            tls = self._ctx.wrap_socket(raw, server_hostname=host)  # SNI + cert validation against the HOSTNAME
        except OwnershipFetchError:
            raw.close()
            raise                                                  # peer mismatch / budget exhausted
        except Exception as e:  # noqa: BLE001 — a TLS failure is a fail-closed refusal, not a crash
            raw.close()
            raise OwnershipFetchError(f"TLS to {host!r} failed", detail=_detail(e)) from None
        conn = http.client.HTTPSConnection(host, timeout=self._timeout)
        conn.auto_open = 0                     # never let http.client dial on its own (an UNPINNED re-resolve)
        conn.sock = _BudgetedSocket(tls, lambda: tls.settimeout(self._op_timeout(start)))  # pinned; budgeted
        return conn, tls

    def _pinned_get(self, host: str, path: str, accept: str, start: float, limit: int,
                    what: str) -> "tuple[int, bytes]":
        """One bounded GET over the pinned connection: ``(status, body[:limit + 1])``. Every send and recv
        is bounded by the remaining budget on the captured ``tls`` socket (``_BudgetedSocket``), whether the
        server keeps the connection alive or answers ``Connection: close``. No redirect following
        (http.client never chases a 30x). Fail-closed: any transport error raises ``OwnershipFetchError``."""
        conn, tls = self._open_pinned_https(host, start)
        try:
            conn.request("GET", path,
                         headers={"Host": host, "User-Agent": "VIGIL-ownership-verify", "Accept": accept,
                                  "Connection": "close"})
            resp = conn.getresponse()                              # http.client does NOT auto-follow redirects
            if resp.status != 200:
                return int(resp.status), b""
            return 200, resp.read(limit + 1)
        except OwnershipFetchError:
            raise
        except Exception as e:  # noqa: BLE001 — any transport error is a fail-closed refusal
            raise OwnershipFetchError(f"{what} fetch failed", detail=_detail(e)) from None
        finally:
            # ``tls`` is the ONLY OS resource of the exchange: ``conn`` never dials (auto_open=0) and its socket
            # wrapper's close() is a no-op, the response reads through a buffer over that same wrapper. Close it
            # here, deterministically — never left to the garbage collector (an exception's traceback keeps
            # this frame, and so the socket, alive for as long as the caller holds it).
            _quiet_close(tls)

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
        if m == METHOD_META_TAG:
            return self._fetch_meta_tag(h, start)
        raise OwnershipFetchError(f"unsupported ownership method {m!r}")

    def _fetch_well_known(self, h: str, start: float) -> str:
        status, body = self._pinned_get(h, well_known_path(), "text/plain", start, self._max_bytes, "well-known")
        if status != 200:
            raise OwnershipFetchError(f"well-known returned HTTP {status}")
        if len(body) > self._max_bytes:
            raise OwnershipFetchError("well-known body too large")
        return body.decode("utf-8", "replace")

    def _fetch_meta_tag(self, h: str, start: float) -> str:
        """GET the homepage ``https://<h>/`` (SSRF-hardened, pinned IP, NO redirect following) and return its
        HTML (bounded to 256 KiB) for the verdict to scan for the ``<meta name="vigil-site-verification">``
        tag. A root that 30x-redirects yields a non-200 and is refused (the customer uses DNS-TXT/well-known
        or places the tag on the exact served root) — never chasing a redirect to an internal URL."""
        status, body = self._pinned_get(h, "/", "text/html", start, _META_MAX_BYTES, "meta-tag")
        if status != 200:
            raise OwnershipFetchError(f"homepage returned HTTP {status}")
        if len(body) > _META_MAX_BYTES:
            body = body[:_META_MAX_BYTES]                         # bounded: scan the first 256 KiB (the <head>)
        return body.decode("utf-8", "replace")

    def _fetch_dns_txt(self, h: str, start: float) -> "list[str]":
        """Query ``_vigil-challenge.<h>`` TXT via DNS-over-HTTPS (JSON) at the pinned public resolver, and
        return the list of TXT string values (surrounding quotes stripped). We connect to the RESOLVER (not
        the customer host), so this is not an SSRF path to the customer's infra; the resolver host still goes
        through the full pinned/validated connect. Fail-closed on any transport/parse error."""
        qname = dns_txt_name(h)                                    # _vigil-challenge.<host> — exact host only
        path = f"/dns-query?name={quote(qname, safe='')}&type=TXT"
        status, raw = self._pinned_get(self._doh_resolver, path, "application/dns-json", start,
                                       self._max_bytes, "dns-txt")
        if status != 200:                                          # no auto-redirect; a 30x -> non-200 -> refused
            raise OwnershipFetchError(f"DoH resolver returned HTTP {status}")
        if len(raw) > self._max_bytes:
            raise OwnershipFetchError("DoH response too large")
        return _parse_doh_txt(raw)


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
