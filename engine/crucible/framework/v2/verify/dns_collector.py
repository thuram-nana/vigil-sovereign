"""
verify.dns_collector — an authoritative DNS out-of-band collector.

The HTTP collaborator (``verify.oob.OOBReceiver`` / ``verify.collaborator.RelayServer``) confirms a blind
class ONLY when the target actually completes an HTTP fetch of the callback URL. A HARDENED target commonly
blocks outbound HTTP at the egress firewall — yet its *internal resolver* still forwards DNS queries to the
public internet. So a blind SSRF / XXE / OS-command / deserialization callback to ``<token>.<base-domain>``
still triggers a DNS lookup that reaches the AUTHORITATIVE nameserver for ``<base-domain>``. If we own that
nameserver, the lookup itself is the out-of-band proof.

This module is that nameserver: a minimal, STDLIB-ONLY (``socket`` + ``struct``, no dnspython) authoritative
UDP DNS server. It:

  * parses the DNS query header + question section (decodes the QNAME labels; a query carries no name
    compression, so a plain length-prefixed label walk is complete and correct),
  * extracts the correlation TOKEN as the leftmost label(s) BENEATH the configured base domain,
  * REFUSES to record a name that is not under the configured base domain,
  * records the interaction as an :class:`~framework.v2.verify.oob.OOBHit` with ``method="DNS"``,
    ``path=<full qname>``, ``client_ip=<the resolver's source IP>``, ``received_at=now`` — and SIGNS it in
    ``_record`` with :func:`~framework.v2.verify.oob.sign_oob_receipt` EXACTLY as
    ``oob._OOBHTTPServer._record`` does (VF-2b), so the SAME
    :func:`~framework.v2.verify.oracles.oob_callback_oracle` + :func:`verify_oob_receipt` confirm a DNS
    observation with NO oracle change on the token/receipt path,
  * answers the query (a benign A record to a configurable advertise IP, or NXDOMAIN) so the resolver
    completes.

Boundaries, by construction:

  * The recorded ``client_ip`` is the RESOLVER's source IP, NOT the target's — a DNS lookup reaches us via
    the target's recursive resolver, so the resolver (not the target) is the DNS client we see. The unique,
    per-probe SECRET token is the correlator that ties the observation to the specific VIGIL probe, so the
    FACT holds regardless of which resolver forwarded it. This is documented in the honest-caveats inventory.
  * A DNS lookup proves resolution REACHED us — NOT that a full HTTP (or other) connection then completed.
    That is a strictly weaker (but still sound) claim than the HTTP collaborator's completed-fetch proof.
  * Deployment assumption: the base domain must be an operator-OWNED domain whose NS records delegate to this
    collector's public IP. Loopback-bindable on a configurable port for tests; real deployment binds UDP :53
    (needs root / CAP_NET_BIND_SERVICE).
"""

from __future__ import annotations

import secrets
import socket
import socketserver
import struct
import threading
import time
from types import TracebackType
from typing import Any

from .oob import OOBHit, sign_oob_receipt

# DNS constants (RFC 1035).
_QR_RESPONSE = 0x8000
_AA = 0x0400          # authoritative answer
_RD = 0x0100          # recursion desired (echoed from the query)
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3
_TYPE_A = 1
_CLASS_IN = 1
_MAX_UDP = 512        # classic DNS UDP payload cap; we never exceed it


class _DecodeError(ValueError):
    """A malformed / truncated DNS query we decline to answer."""


def _decode_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Decode the length-prefixed labels of a QNAME starting at ``offset``.

    Queries carry NO name compression (compression pointers appear only in responses), so a plain label
    walk is complete. Returns ``(dotted_lowercase_name, offset_after_the_terminating_null)``. Raises
    :class:`_DecodeError` on truncation, an over-length label, or a compression pointer (which a well-formed
    query must not contain)."""
    labels: list[str] = []
    i = offset
    total = 0
    while True:
        if i >= len(data):
            raise _DecodeError("qname truncated")
        length = data[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0:
            # A compression pointer (top two bits set) must not appear in a question — refuse it rather
            # than follow it, so a crafted packet cannot make us read arbitrary offsets.
            raise _DecodeError("compression pointer in question section")
        i += 1
        if i + length > len(data):
            raise _DecodeError("label truncated")
        total += length + 1
        if total > 255:
            raise _DecodeError("qname exceeds 255 octets")
        labels.append(data[i:i + length].decode("ascii", "replace").lower())
        i += length
    return ".".join(labels), i


def _parse_query(data: bytes) -> tuple[int, int, str, int, int, int]:
    """Parse a DNS query. Returns ``(txn_id, flags, qname, qname_end, qtype, qclass)`` where ``qname_end``
    is the offset of the QNAME's terminating null + 1 (the start of QTYPE). Raises :class:`_DecodeError`
    if it is not a well-formed single-question query we should answer."""
    if len(data) < 12:
        raise _DecodeError("short header")
    txn_id, flags, qdcount, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if flags & _QR_RESPONSE:
        raise _DecodeError("not a query (QR set)")
    if qdcount < 1:
        raise _DecodeError("no question")
    qname, after = _decode_qname(data, 12)
    if after + 4 > len(data):
        raise _DecodeError("question truncated")
    qtype, qclass = struct.unpack("!HH", data[after:after + 4])
    return txn_id, flags, qname, after, qtype, qclass


def _build_response(query: bytes, txn_id: int, flags: int, qname_end: int, *,
                    answer_ip: "str | None") -> bytes:
    """Build a response echoing the question. With ``answer_ip`` → one A record (RCODE NOERROR, AA set);
    with ``answer_ip=None`` → NXDOMAIN (RCODE 3, no answer). The resolver completes either way, so the
    triggering lookup does not hang."""
    rd = flags & _RD
    question = query[12:qname_end + 4]   # QNAME (+ null) + QTYPE + QCLASS, verbatim
    if answer_ip is not None:
        resp_flags = _QR_RESPONSE | _AA | rd | _RCODE_NOERROR
        header = struct.pack("!HHHHHH", txn_id, resp_flags, 1, 1, 0, 0)
        # Name pointer to the question's QNAME at offset 12 (0xC00C), TYPE A / CLASS IN, a short TTL,
        # RDLENGTH 4, and the 4-octet A record.
        answer = struct.pack("!HHHIH", 0xC00C, _TYPE_A, _CLASS_IN, 60, 4) + socket.inet_aton(answer_ip)
        return header + question + answer
    resp_flags = _QR_RESPONSE | _AA | rd | _RCODE_NXDOMAIN
    header = struct.pack("!HHHHHH", txn_id, resp_flags, 1, 0, 0, 0)
    return header + question


def _extract_token(qname: str, base_labels: list[str]) -> "str | None":
    """The token is the leftmost label(s) of ``qname`` beneath ``base_labels`` (the configured base
    domain). Returns None when ``qname`` is NOT strictly under the base domain (a name we refuse to
    record) or is exactly the base domain (no token)."""
    q = qname.rstrip(".").lower()
    labels = q.split(".") if q else []
    n = len(base_labels)
    if len(labels) <= n:
        return None                       # equal to, or shorter than, the base domain → not under it
    if labels[-n:] != base_labels:
        return None                       # different suffix → not under the base domain
    return ".".join(labels[:-n])


class _DNSHandler(socketserver.BaseRequestHandler):
    """One UDP datagram. Records a token-bearing lookup under the base domain and answers it."""

    def handle(self) -> None:
        data, sock = self.request
        server: "_DNSUDPServer" = self.server  # type: ignore[assignment]
        client_ip = self.client_address[0] if self.client_address else ""
        try:
            txn_id, flags, qname, qname_end, _qtype, _qclass = _parse_query(data)
        except _DecodeError:
            return                         # unparseable → drop silently (a stray/garbage packet)
        token = _extract_token(qname, server._base_labels)
        if token:
            # A name UNDER the base domain carrying a token → record it (VF-2b signed in _record). A name
            # NOT under the base domain yields token=None and is never recorded.
            server._record(OOBHit(
                token=token,
                method="DNS",
                path=qname,
                query="",
                client_ip=client_ip,
                received_at=time.time(),
            ))
        # Always answer so the resolver completes: an A record when an advertise IP is set, else NXDOMAIN.
        try:
            resp = _build_response(data, txn_id, flags, qname_end, answer_ip=server._answer_ip)
            if len(resp) <= _MAX_UDP:
                sock.sendto(resp, self.client_address)
        except (OSError, struct.error):
            return


class _DNSUDPServer(socketserver.ThreadingUDPServer):
    """ThreadingUDPServer carrying the base-domain config, the lock-guarded hit registry, and the
    collector signing key (VF-2b)."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], base_domain: str, *, answer_ip: "str | None",
                 signing_key: "str | None") -> None:
        super().__init__(addr, _DNSHandler)
        self._base_labels = base_domain.rstrip(".").lower().split(".")
        self._answer_ip = answer_ip
        self._signing_key = signing_key
        self._lock = threading.Lock()
        self._registered: set[str] = set()
        self._hits: dict[str, list[OOBHit]] = {}

    def _register(self, token: str) -> None:
        with self._lock:
            self._registered.add(token)
            self._hits.setdefault(token, [])

    def _record(self, hit: OOBHit) -> None:
        # VF-2b: sign the receipt AS OBSERVED, over target-observed facts only, EXACTLY as
        # oob._OOBHTTPServer._record — so the identical verify_oob_receipt + oob_callback_oracle confirm a
        # DNS observation with no oracle change.
        if self._signing_key:
            hit.collector_sig = sign_oob_receipt(self._signing_key, hit)
        with self._lock:
            self._hits.setdefault(hit.token, []).append(hit)

    def _poll(self, token: str) -> list[OOBHit]:
        with self._lock:
            return list(self._hits.get(token, []))


class DNSCollector:
    """Context-managed authoritative DNS OOB collector.

    Start it, mint per-probe tokens whose callback HOST is ``<token>.<base-domain>``, hand the host to a
    blind payload (SSRF / XXE / OS-command / deserialization), and poll for the DNS lookup the target's
    resolver forwards. Exposes the same ``poll(token)`` surface as ``OOBReceiver`` plus a DNS-specific
    ``register_dns_token()``; ``register_token()`` is an alias so it drops into the OOB check path.

    ``base_domain`` is the operator-owned, delegated domain (e.g. ``oob.op.example``). ``host``/``port`` are
    where the UDP server binds — loopback + a configurable/ephemeral port for tests; UDP :53 in production
    (needs root). ``answer_ip`` is the A record handed back (default the advertise IP); pass None for
    NXDOMAIN. ``collector_keypair`` is the INDEPENDENT collector's Ed25519 keypair (VF-2b); when set, every
    recorded lookup is signed into a receipt a verifier checks against the PINNED collector pubkey."""

    def __init__(self, base_domain: str, *, host: str = "127.0.0.1", port: int = 0,
                 answer_ip: "str | None" = "127.0.0.1", collector_keypair: Any = None) -> None:
        if not base_domain or not base_domain.strip("."):
            raise ValueError("DNSCollector requires a non-empty base domain")
        self._base_domain = base_domain.rstrip(".").lower()
        self._host = host
        self._port = port
        self._answer_ip = answer_ip
        self._collector_priv = getattr(collector_keypair, "private_key_b64", None) if collector_keypair else None
        self._collector_pub = getattr(collector_keypair, "public_key_b64", None) if collector_keypair else None
        self._server: _DNSUDPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "DNSCollector":
        if self._server is not None:
            return self
        self._server = _DNSUDPServer((self._host, self._port), self._base_domain,
                                     answer_ip=self._answer_ip, signing_key=self._collector_priv)
        self._thread = threading.Thread(target=self._server.serve_forever, name="oob-dns-collector",
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "DNSCollector":
        return self.start()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.stop()

    # -- properties --------------------------------------------------------

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("DNSCollector is not started")
        return self._server.server_address[1]

    @property
    def base_domain(self) -> str:
        return self._base_domain

    @property
    def collector_pubkey(self) -> "str | None":
        """The independent collector's public key (b64) when a signing keypair was given, else None. The
        operator distributes this OUT-OF-BAND; a verifier PINS it to check each DNS receipt (VF-2b)."""
        return self._collector_pub

    # -- client-less API ---------------------------------------------------

    def register_dns_token(self) -> tuple[str, str]:
        """Mint a fresh per-probe correlation token and return ``(token, "<token>.<base-domain>")``. The
        host is what a blind payload embeds; any DNS lookup whose leftmost label(s) equal the token, under
        the base domain, is recorded under it."""
        if self._server is None:
            raise RuntimeError("DNSCollector is not started")
        token = secrets.token_hex(16)
        self._server._register(token)
        return token, f"{token}.{self._base_domain}"

    # OOBReceiver-shaped alias so the DNS collector drops into the OOB check path unchanged.
    register_token = register_dns_token

    def poll(self, token: str) -> list[OOBHit]:
        """Return all DNS lookups recorded against ``token`` so far (possibly empty)."""
        if self._server is None:
            raise RuntimeError("DNSCollector is not started")
        return self._server._poll(token)
