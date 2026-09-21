"""
verify.collaborator — a self-hostable out-of-band interaction relay.

`verify.oob.OOBReceiver` binds loopback only, so it confirms blind classes (SSRF,
XXE, OOB SQLi, deserialization/JNDI) ONLY when the target is co-resident on the
same host. A real remote target's blind fetch cannot reach loopback. This module
is the sovereign answer to that gap — a Collaborator you HOST, not one you rent:

  * :class:`RelayServer` — a small HTTP server the OPERATOR runs on a host they
    own and have put on the engagement's charter allowlist (e.g.
    ``relay.op.example``). It records every inbound interaction keyed by the
    token in the first path segment, and exposes an authenticated poll endpoint.
    Because the operator runs it on an allowlisted host, the scanner's only
    egress is to that allowlisted relay — the sovereignty/egress doctrine holds
    (the ``engage`` runner already refuses a relay host not in charter scope).

  * :class:`RelayClient` — the scanner-side half. It mints unique correlation
    tokens whose callback URL points at the relay, and polls the relay's
    authenticated ``/_poll`` endpoint for interactions. It exposes exactly the
    ``register_token()`` / ``poll()`` surface of ``OOBReceiver`` and is a no-op
    context manager, so it drops into the OOB check path unchanged: a blind
    payload embeds ``{callback}`` = the relay URL, the remote target fetches it,
    the relay records it, the client polls it, and the oob oracle confirms.

Boundaries, by construction:
  * The relay is AUTHENTICATED: polling requires a shared secret (constant-time
    compared), so a third party cannot read the operator's interactions.
  * The relay only records and serves interactions on its own tokens; it sends
    no traffic of its own beyond a 1-byte 200 so the triggering fetch completes.
  * Scope: HTTP (and any protocol that resolves to an HTTP fetch of the callback
    URL — most SSRF, JNDI-over-LDAP-referral-to-HTTP, webhook gadgets). A
    DNS-only interaction (``nslookup``/``dig`` with no HTTP fetch, or an HTTP-egress-
    blocked callback whose hostname still resolves) is covered by the SIBLING
    authoritative DNS collector, :mod:`verify.dns_collector` — it records the
    token-bearing DNS query the target's resolver forwards and VF-2b-signs it with
    the SAME receipt machinery, so the identical ``oob_callback`` oracle confirms it.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Any
from urllib.parse import parse_qs, urlsplit

import urllib.error
import urllib.request

from .oob import OOBHit, sign_oob_receipt

_POLL_PREFIX = "/_poll/"
# X6 — the poll secret travels in this request HEADER, not the query string, so it never lands
# in the relay's HTTP access logs (a `?key=<secret>` does). The legacy query form is still
# accepted server-side for back-compat.
_RELAY_KEY_HEADER = "X-Relay-Key"


def _is_loopback(host: str) -> bool:
    """True for a genuine loopback host: the name ``localhost`` or ANY loopback IP — the whole
    127.0.0.0/8 range and every IPv6 loopback form — so a legitimate non-canonical loopback relay
    (e.g. 127.0.0.2 or an expanded ::1) is not wrongly forced onto https."""
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        import ipaddress
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# RelayServer — the operator-hosted half
# ---------------------------------------------------------------------------


class _RelayHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying the lock-guarded hit registry + poll secret."""

    daemon_threads = True

    def __init__(self, addr: tuple[str, int], secret: str,
                 signing_key: "str | None" = None) -> None:
        super().__init__(addr, _RelayHandler)
        self._lock = threading.Lock()
        self._hits: dict[str, list[OOBHit]] = {}
        self._secret = secret
        # VF-2b: the INDEPENDENT collector's private key (b64), or None. Mirrors oob._OOBHTTPServer.
        self._signing_key = signing_key

    def _record(self, hit: OOBHit) -> None:
        # VF-2b: sign the receipt AS OBSERVED (over the target-observed receipt core only), exactly as the
        # loopback receiver does (oob._OOBHTTPServer._record). A verifier checks it against a caller-PINNED
        # collector pubkey, so a fully-dishonest producer that does not hold the collector key cannot forge a
        # receipt that verifies — the remote relay now reaches the same VF-2b tier as the loopback receiver.
        if self._signing_key:
            hit.collector_sig = sign_oob_receipt(self._signing_key, hit)
        with self._lock:
            self._hits.setdefault(hit.token, []).append(hit)

    def _poll(self, token: str) -> list[OOBHit]:
        with self._lock:
            return list(self._hits.get(token, []))

    def _secret_ok(self, presented: str) -> bool:
        return hmac.compare_digest(presented or "", self._secret)


class _RelayHandler(BaseHTTPRequestHandler):
    # Keep the relay quiet; it must not spam stderr during an engagement.
    def log_message(self, *args: object) -> None:  # noqa: D401
        return

    def _serve(self) -> None:
        server: _RelayHTTPServer = self.server  # type: ignore[assignment]
        split = urlsplit(self.path)

        # Authenticated poll endpoint: /_poll/<token>. X6: the secret is read from the
        # X-Relay-Key header (not logged); the legacy ?key= query is still accepted for
        # back-compat with an older client.
        if split.path.startswith(_POLL_PREFIX):
            token = split.path[len(_POLL_PREFIX):].strip("/").split("/")[0]
            key = self.headers.get(_RELAY_KEY_HEADER, "") or parse_qs(split.query).get("key", [""])[0]
            if not server._secret_ok(key):
                self._reply(403, b'{"error":"forbidden"}', "application/json")
                return
            payload = json.dumps([h.model_dump() for h in server._poll(token)]).encode("utf-8")
            self._reply(200, payload, "application/json")
            return

        # Otherwise: an inbound interaction. Record it under its token.
        token = split.path.strip("/").split("/")[0] if split.path.strip("/") else ""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)  # drain body so keep-alive clients don't stall
        server._record(OOBHit(
            token=token,
            method=self.command,
            path=split.path,
            query=split.query,
            client_ip=self.client_address[0] if self.client_address else "",
            user_agent=self.headers.get("User-Agent", ""),
            host_header=self.headers.get("Host", ""),
            received_at=time.time(),
        ))
        self._reply(200, b".", "text/plain")

    def _reply(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve
    do_POST = _serve
    do_PUT = _serve
    do_HEAD = _serve
    do_OPTIONS = _serve


class RelayServer:
    """A context-managed OOB relay the operator hosts on an allowlisted host.

    ``host``/``port`` are where it binds (the operator may bind a public
    interface — that is their infrastructure decision, distinct from the
    scanner's egress). ``secret`` gates the poll endpoint. A random secret is
    minted if none is given (read it from :attr:`secret`)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, *, secret: str | None = None,
                 collector_keypair: "Any" = None) -> None:
        self._host = host
        self._port = port
        self.secret = secret or secrets.token_hex(16)
        # VF-2b: an optional INDEPENDENT collector signing key (a vigil_core KeyPair). When set, every
        # recorded interaction is signed into a receipt a verifier checks against the PINNED collector pubkey
        # — the mechanism that survives a fully-dishonest producer. Mirrors OOBReceiver.__init__. Held by the
        # collector (a party distinct from the producer); this class does not enforce that independence — it is
        # a deployment assumption, like witness independence.
        self._collector_priv = getattr(collector_keypair, "private_key_b64", None) if collector_keypair else None
        self._collector_pub = getattr(collector_keypair, "public_key_b64", None) if collector_keypair else None
        self._server: _RelayHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "RelayServer":
        if self._server is not None:
            return self
        self._server = _RelayHTTPServer((self._host, self._port), self.secret,
                                        signing_key=self._collector_priv)
        self._thread = threading.Thread(target=self._server.serve_forever, name="oob-relay", daemon=True)
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

    def __enter__(self) -> "RelayServer":
        return self.start()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.stop()

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("RelayServer is not started")
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://{self._host}:{self.port}"

    @property
    def collector_pubkey(self) -> "str | None":
        """The independent collector's public key (b64) when a signing keypair was given, else None. The
        operator distributes this OUT-OF-BAND to the scanner (RelayClient pin), and a verifier PINS it to
        check each hit's receipt (VF-2b)."""
        return self._collector_pub

    def serve_forever(self) -> None:
        """Run the relay in the foreground until interrupted (the CLI path)."""
        self.start()
        try:
            while self._thread is not None:
                self._thread.join(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


# ---------------------------------------------------------------------------
# RelayClient — the scanner-side half (OOBReceiver-shaped)
# ---------------------------------------------------------------------------


class RelayClient:
    """Scanner-side client for a :class:`RelayServer`. Mints tokens whose callback
    URL points at the relay and polls the relay's authenticated endpoint.

    Exposes the same ``register_token()`` / ``poll()`` surface as
    ``verify.oob.OOBReceiver`` and is a no-op context manager, so it substitutes
    for a loopback receiver in the OOB check path with no other change. A poll
    error yields an empty list (a transient relay/network fault must never crash
    a scan or fabricate a hit)."""

    def __init__(self, base_url: str, secret: str, *, timeout: float = 5.0,
                 collector_pubkey: "str | None" = None) -> None:
        self._base = base_url.rstrip("/")
        # X6: a REMOTE relay's secret + polled interaction data must travel over TLS. Refuse a
        # non-loopback http:// relay — the poll secret and recorded hits would otherwise cross
        # the network in the clear. A loopback relay (the local test/tunnel model) may use http.
        parts = urlsplit(self._base)
        remote = not _is_loopback(parts.hostname or "")
        if remote and parts.scheme != "https":
            raise ValueError(
                f"remote OOB relay {self._base!r} must use https:// — refusing to send the poll "
                f"secret and interaction data in plaintext to a non-loopback host")
        # VF-2b FAIL-CLOSED: the collector public key the verifier PINS out-of-band (supplied by the
        # charter/CLI — NEVER fetched from the relay at poll time, which would let a compromised relay hand
        # over its own key and defeat the pin). A REMOTE relay MUST carry a non-blank pin: remote OOB is the
        # VF-2b tier by construction, never a silent drop to VF-2a token-only (which a fully-dishonest producer
        # can forge). A loopback relay (the local test/tunnel model) may omit it — the token-only tier is
        # honest there, and the loopback receiver's own minted key covers loopback VF-2b.
        self._collector_pubkey = str(collector_pubkey).strip() if collector_pubkey else None
        if remote and not self._collector_pubkey:
            raise ValueError(
                f"remote OOB relay {self._base!r} requires an out-of-band collector public key (VF-2b): a "
                f"remote callback cannot rely on token-equality alone, which a dishonest producer can forge "
                f"— supply the relay's collector pubkey via the charter/CLI, do not fetch it from the relay")
        self._secret = secret
        self._timeout = timeout

    # -- lifecycle (no-op; the relay is a separate, already-running process) --

    def start(self) -> "RelayClient":
        return self

    def stop(self) -> None:
        return None

    def __enter__(self) -> "RelayClient":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        return None

    @property
    def base_url(self) -> str:
        return self._base

    @property
    def collector_pubkey(self) -> "str | None":
        """The OUT-OF-BAND-pinned collector public key (b64) for this relay, or None on a loopback relay
        with no pin. The verifier reads THIS (an authority the caller supplied), never a key from the
        producer-controlled context, to demand a VF-2b collector receipt."""
        return self._collector_pubkey

    # -- OOBReceiver-shaped API ----------------------------------------------

    def register_token(self) -> tuple[str, str]:
        """Mint a fresh correlation token and its callback URL on the relay."""
        token = secrets.token_hex(16)
        return token, f"{self._base}/{token}"

    def poll(self, token: str) -> list[OOBHit]:
        """Fetch the interactions the relay recorded for ``token`` (possibly
        empty). Authenticated with the shared secret; fail-safe to ``[]``."""
        url = f"{self._base}{_POLL_PREFIX}{token}"   # X6: secret in a header, not the query string
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "CRUCIBLE-collaborator/1.0",
                _RELAY_KEY_HEADER: self._secret,
            })
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        hits: list[OOBHit] = []
        for row in data:
            try:
                hits.append(OOBHit.model_validate(row))
            except Exception:
                continue
        return hits
