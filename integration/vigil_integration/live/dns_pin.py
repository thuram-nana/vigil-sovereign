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
    """Resolve ``host`` and require EVERY address to satisfy ``is_authorized(ip)``.

    All-or-nothing on purpose: with a multi-address name, connecting to the one address that happens to be
    in scope would let the others be reachable on a retry, so a mixed answer is refused. A name that does not
    resolve is refused too — an unresolvable target is not an authorized one."""
    out = PinnedResolution(host=host)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        out.refused_reason = f"cannot resolve {host!r}: {exc}"
        return out
    for info in infos:
        address = info[4][0]
        if address not in out.addresses:
            out.addresses.append(address)
    if not out.addresses:
        out.refused_reason = f"{host!r} resolved to no addresses"
        return out
    for address in out.addresses:
        if not is_authorized(address):
            out.refused_reason = (
                f"{host!r} resolves to {address} which the scope decision does not authorize "
                f"(all {len(out.addresses)} address(es) must be in scope)")
            return out
    out.pinned = out.addresses[0]
    return out


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
