"""dns_pin — bind an authorization decision to the IP the connection actually reaches.

The gate authorizes a HOSTNAME. urllib then resolves that hostname again at connect time, so nothing ties
the authorization to the destination: between the check and the connection the answer can change (DNS
rebinding, a short-TTL record, a poisoned resolver, a multi-A record where one address is in scope and
another is not). Closing the proxy hole fixed one way traffic could leave the authorized destination; this
closes the other.

Two properties, both required — either alone is insufficient:

* **Validate**: every address the name resolves to is checked against the scope decision BEFORE connecting.
  A name that resolves to any unauthorized address is refused rather than connected-to-and-hoped-about.
* **Pin**: the socket connects to the exact validated address, and the TLS/Host handshake still uses the
  original hostname. Re-resolving after validation would reopen the window the validation just closed.

The pinned address travels with the capture, so a certificate records *which* endpoint was observed rather
than only which name was requested.

WHAT LIVES HERE NOW. Only the PIN half — :func:`pinned_handlers` and the two pinned connection classes,
which ``live/web_redrive.py`` still uses. The VALIDATE half (:func:`resolve_and_validate`) is REMOVED and
raises: it was charter-relative, so it never consulted the never-liftable L3/L4 egress floor and a charter
listing a metadata address satisfied it. ``live/egress_floor.pin_egress`` is the one validator now.

Pure stdlib; no framework imports (FATAL-2 safe).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from dataclasses import dataclass, field


@dataclass
class PinnedResolution:
    """The outcome of resolving a host under a scope decision."""

    host: str
    addresses: "list[str]" = field(default_factory=list)   # every address the name resolved to
    pinned: str = ""                                       # the address the connection will use
    refused_reason: str = ""

    @property
    def allowed(self) -> bool:
        return bool(self.pinned) and not self.refused_reason


def resolve_and_validate(host: str, port: int, is_authorized) -> PinnedResolution:
    """REMOVED — always raises. Use ``live.egress_floor.pin_egress`` instead.

    This was a CHARTER-RELATIVE pin: it required every resolved address to satisfy the caller's own
    ``is_authorized`` predicate and nothing else. That predicate bottoms out in
    ``ethics.host_matches_scope``, pure string matching, so a charter that LISTS ``169.254.169.254``
    satisfied it and the "pin" happily pinned the connection to cloud instance metadata. The
    never-liftable L3/L4 floor (``vigil_gateway.denylist.is_egress_denied``) was never consulted.

    Every call site now uses :func:`egress_floor.pin_egress`, which runs the charter-INDEPENDENT floor
    FIRST and keeps the scope predicate on top of it. This stub stays — rather than the function being
    quietly deleted — because the name reads like the safe thing and sits one import away from the next
    author who adds a resolve-then-connect site; a silent revival is exactly how this class-bug reached
    four sites. ``pinned_handlers`` below is NOT deprecated: ``web_redrive`` uses it to dial the address
    ``pin_egress`` validated.

    :raises RuntimeError: always.
    """
    raise RuntimeError(
        "dns_pin.resolve_and_validate is removed: it was a charter-RELATIVE pin with no L3/L4 egress "
        "floor, so a charter listing 169.254.169.254 pinned the connection straight at cloud instance "
        "metadata. Use vigil_integration.live.egress_floor.pin_egress(host, port, slug=..., "
        "address_authorized=charter_address_authorizer(slug)) — it runs the never-liftable gateway "
        "denylist over EVERY resolved address before the scope predicate, and returns the literal to "
        "pin the connect to (pair it with dns_pin.pinned_handlers / egress_floor.pinned_*_connector).")


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a pinned IP while presenting the original hostname."""

    pinned_ip: str = ""

    def connect(self) -> None:                                  # pragma: no cover - exercised via the opener
        self.sock = socket.create_connection((self.pinned_ip or self.host, self.port), self.timeout,
                                             self.source_address)
        if getattr(self, "_tunnel_host", None):
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """As above, with TLS still verified against the requested hostname — pinning the transport must not
    weaken certificate validation, or closing a rebinding hole would open an impersonation one."""

    pinned_ip: str = ""

    def connect(self) -> None:                                  # pragma: no cover - exercised via the opener
        sock = socket.create_connection((self.pinned_ip or self.host, self.port), self.timeout,
                                        self.source_address)
        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def pinned_handlers(pinned_ip: str) -> "list[urllib.request.BaseHandler]":
    """urllib handlers that route every connection to ``pinned_ip``."""

    http_conn = type("_PinnedHTTP", (PinnedHTTPConnection,), {"pinned_ip": pinned_ip})
    https_conn = type("_PinnedHTTPS", (PinnedHTTPSConnection,), {"pinned_ip": pinned_ip})

    class _HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):                               # noqa: ANN001, ANN201
            return self.do_open(http_conn, req)

    class _HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):                              # noqa: ANN001, ANN201
            return self.do_open(https_conn, req)

    return [_HTTPHandler(), _HTTPSHandler()]


def is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False
