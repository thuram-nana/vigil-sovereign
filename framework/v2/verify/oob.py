"""
verify.oob — a local out-of-band interaction receiver.

Blind bug classes (SSRF, out-of-band SQLi, blind XXE, deserialization
gadgets) produce no signal in the response the attacker can see. The proof
is an *inbound* interaction the payload triggers against infrastructure the
attacker controls. This module is that infrastructure, scoped to a single
host: a stdlib http.server bound to 127.0.0.1 on an ephemeral port that mints
unique correlation tokens and records every inbound hit that carries one.

Hard constraints, by construction:

  * Binds to 127.0.0.1 only. Never 0.0.0.0. No external egress, ever.
  * Ephemeral port (bind :0) — the OS assigns; nothing well-known is claimed.
  * The receiver only *listens*. It sends no traffic of its own; the sole
    response is a 1-byte 200 so the triggering request completes cleanly.

Usage:

    with OOBReceiver() as oob:
        token, url = oob.register_token()
        # ... hand `url` to a probe; something blind fetches it ...
        hits = oob.poll(token)          # list[OOBHit]
        if hits:
            ...   # feed to oob_callback_oracle

A token is the first path segment: http://127.0.0.1:<port>/<token>[/...].
That also models a DNS-style callback where the token is the interacting
label — here it rides the path instead of a subdomain, keeping everything
on loopback.
"""

from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


class OOBHit(BaseModel):
    """One recorded inbound interaction against a correlation token."""

    model_config = ConfigDict(extra="forbid")

    token: str
    method: str
    path: str
    query: str = ""
    client_ip: str = ""
    user_agent: str = ""
    host_header: str = ""
    received_at: float = Field(description="epoch seconds when the hit landed")


def _token_of(path: str) -> str:
    """First non-empty path segment, e.g. /<token>/anything -> <token>."""
    parts = urlsplit(path).path.strip("/").split("/")
    return parts[0] if parts and parts[0] else ""


class _OOBHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying the shared, lock-guarded hit registry."""

    daemon_threads = True

    def __init__(self, addr: tuple[str, int]) -> None:
        super().__init__(addr, _OOBRequestHandler)
        self._lock = threading.Lock()
        self._registered: set[str] = set()
        self._hits: dict[str, list[OOBHit]] = {}

    def _register(self, token: str) -> None:
        with self._lock:
            self._registered.add(token)
            self._hits.setdefault(token, [])

    def _record(self, hit: OOBHit) -> None:
        with self._lock:
            self._hits.setdefault(hit.token, []).append(hit)

    def _poll(self, token: str) -> list[OOBHit]:
        with self._lock:
            return list(self._hits.get(token, []))


class _OOBRequestHandler(BaseHTTPRequestHandler):
    # Keep the receiver quiet; it must not spam stderr during an engagement.
    def log_message(self, *args: object) -> None:  # noqa: D401
        return

    def _handle(self) -> None:
        server: _OOBHTTPServer = self.server  # type: ignore[assignment]
        split = urlsplit(self.path)
        token = _token_of(self.path)
        client_ip = self.client_address[0] if self.client_address else ""
        server._record(
            OOBHit(
                token=token,
                method=self.command,
                path=split.path,
                query=split.query,
                client_ip=client_ip,
                user_agent=self.headers.get("User-Agent", ""),
                host_header=self.headers.get("Host", ""),
                received_at=time.time(),
            )
        )
        # Drain any request body so keep-alive clients don't stall.
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        body = b"."
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle


class OOBReceiver:
    """Context-managed, localhost-only out-of-band interaction receiver.

    Start it, register per-finding tokens, hand out the resulting URLs, and
    poll for hits. All state is in-process; nothing is persisted and nothing
    leaves the machine."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(
                f"OOBReceiver refuses to bind to {host!r}; loopback only."
            )
        self._host = "127.0.0.1" if host == "localhost" else host
        self._server: _OOBHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "OOBReceiver":
        if self._server is not None:
            return self
        self._server = _OOBHTTPServer((self._host, 0))
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="oob-receiver", daemon=True
        )
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

    def __enter__(self) -> "OOBReceiver":
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    # -- properties --------------------------------------------------------

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("OOBReceiver is not started")
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self.port}"

    # -- client-less API ---------------------------------------------------

    def register_token(self) -> tuple[str, str]:
        """Mint a fresh correlation token and return (token, callback_url).

        The URL is what a probe embeds; any inbound request whose first path
        segment equals the token is recorded under it."""
        if self._server is None:
            raise RuntimeError("OOBReceiver is not started")
        token = secrets.token_hex(16)
        self._server._register(token)
        return token, f"{self.base_url}/{token}"

    def poll(self, token: str) -> list[OOBHit]:
        """Return all hits recorded against `token` so far (possibly empty)."""
        if self._server is None:
            raise RuntimeError("OOBReceiver is not started")
        return self._server._poll(token)
