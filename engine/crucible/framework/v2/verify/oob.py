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
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

# VF-2b: an INDEPENDENT, receipt-signing collector. The receiver (a party distinct from the producer) signs
# each observed hit's {token, client_ip, received_at, method, path} with ITS OWN key; a verifier checks the
# receipt against a caller-PINNED collector pubkey (out-of-band, like the PCF trust-root pin). A producer who
# does not hold the collector private key cannot forge a receipt that verifies under the pinned key — so an OOB
# proof survives even a FULLY-dishonest producer (VF-2a token-equality alone does not). vigil_core is the shared
# offense-free integrity substrate (Ed25519 + canonical JSON); the offense venv installs it.
from vigil_core import canonical_json, sign, verify_one
from vigil_core.crypto import IntegrityError, load_public_key

_OOB_RECEIPT_DOMAIN = b"vigil-oob-receipt-v1\x00"


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
    # VF-2b: the INDEPENDENT collector's Ed25519 signature over the receipt core (empty when the receiver was
    # not given a collector key). A verifier checks it against a caller-PINNED collector pubkey.
    collector_sig: str = ""


def _receipt_core(hit: Any) -> dict:
    """The exact fields the collector signature covers, from an OOBHit or a plain dict (the retained,
    serialized form). Only TARGET-observed facts — never the collector_sig itself."""
    def g(k: str) -> Any:
        return hit.get(k) if isinstance(hit, dict) else getattr(hit, k, None)
    return {
        "token": str(g("token") or ""),
        "client_ip": str(g("client_ip") or ""),
        "received_at": float(g("received_at") or 0.0),
        "method": str(g("method") or ""),
        "path": str(g("path") or ""),
    }


def _receipt_signing_bytes(core: dict) -> bytes:
    m = canonical_json(core)
    return _OOB_RECEIPT_DOMAIN + (m if isinstance(m, bytes) else m.encode("utf-8"))


def sign_oob_receipt(collector_private_key_b64: str, hit: Any) -> str:
    """The collector signs a hit's receipt core with its OWN key."""
    return sign(collector_private_key_b64, _receipt_signing_bytes(_receipt_core(hit)))


def verify_oob_receipt(hit: Any, *, collector_pubkey: str) -> bool:
    """True iff the hit carries a collector signature that verifies against the PINNED collector pubkey over the
    hit's own receipt core. Fail-closed: a missing/empty signature, an empty pinned key, or malformed key/sig
    material → False. ``collector_pubkey`` MUST be pinned OUT-OF-BAND by the verifier — never trusted from the
    producer-controlled context — or the guarantee is void (a producer would supply its own key)."""
    sig = (hit.get("collector_sig") if isinstance(hit, dict) else getattr(hit, "collector_sig", "")) or ""
    if not sig or not str(collector_pubkey or "").strip():
        return False
    try:
        load_public_key(collector_pubkey)   # reject non-canonical / low-order keys before verifying
        return bool(verify_one(collector_pubkey, _receipt_signing_bytes(_receipt_core(hit)), str(sig)))
    except (IntegrityError, TypeError, ValueError):
        return False


def _token_of(path: str) -> str:
    """First non-empty path segment, e.g. /<token>/anything -> <token>."""
    parts = urlsplit(path).path.strip("/").split("/")
    return parts[0] if parts and parts[0] else ""


class _OOBHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying the shared, lock-guarded hit registry."""

    daemon_threads = True

    def __init__(self, addr: tuple[str, int], signing_key: "str | None" = None) -> None:
        super().__init__(addr, _OOBRequestHandler)
        self._lock = threading.Lock()
        self._registered: set[str] = set()
        self._hits: dict[str, list[OOBHit]] = {}
        self._signing_key = signing_key   # VF-2b: the collector's private key (b64), or None

    def _register(self, token: str) -> None:
        with self._lock:
            self._registered.add(token)
            self._hits.setdefault(token, [])

    def _record(self, hit: OOBHit) -> None:
        # VF-2b: the collector signs the receipt AS IT OBSERVES the hit, so the signature is bound to what the
        # independent collector actually saw (not to anything the producer supplies later).
        if self._signing_key:
            hit.collector_sig = sign_oob_receipt(self._signing_key, hit)
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

    def __init__(self, host: str = "127.0.0.1", *, advertise_base_url: str | None = None,
                 collector_keypair: Any = None) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(
                f"OOBReceiver refuses to bind to {host!r}; loopback only."
            )
        self._host = "127.0.0.1" if host == "localhost" else host
        # VF-2b: an optional INDEPENDENT collector signing key (a vigil_core KeyPair). When set, every recorded
        # hit is signed into a receipt a verifier checks against the PINNED collector pubkey — the mechanism
        # that survives a fully-dishonest producer. Held by the collector (a party distinct from the producer);
        # this class does not enforce that independence — it is a deployment assumption, like witness independence.
        self._collector_priv = getattr(collector_keypair, "private_key_b64", None) if collector_keypair else None
        self._collector_pub = getattr(collector_keypair, "public_key_b64", None) if collector_keypair else None
        # Opt-in operator-hosted relay (default off). The receiver STILL binds
        # loopback only — this URL is merely what probes embed as the callback.
        # The operator runs an allowlisted tunnel from that host back to this
        # loopback receiver (e.g. an SSH reverse forward), so a remote target's
        # blind fetch reaches loopback and is recorded here, WITHOUT the receiver
        # ever binding a public interface. The caller MUST verify the advertise
        # host is on the engagement's charter allowlist before enabling it — this
        # class validates the URL shape, not the authorization.
        self._advertise = self._validate_advertise(advertise_base_url)
        self._server: _OOBHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @staticmethod
    def _validate_advertise(url: str | None) -> str | None:
        if url is None:
            return None
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError(
                f"advertise_base_url must be an absolute http(s) URL, got {url!r}"
            )
        return url.rstrip("/")

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "OOBReceiver":
        if self._server is not None:
            return self
        self._server = _OOBHTTPServer((self._host, 0), signing_key=self._collector_priv)
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
    def collector_pubkey(self) -> "str | None":
        """The independent collector's public key (b64) when a signing key was given, else None. A verifier
        PINS this out-of-band and checks each hit's receipt against it (VF-2b)."""
        return self._collector_pub

    @property
    def base_url(self) -> str:
        """The callback base a probe embeds. The operator-hosted relay URL when
        one was configured (blind classes then confirm on remote targets), else
        the loopback receiver's own URL."""
        if self._advertise is not None:
            # Touch .port so an unstarted receiver still raises consistently.
            if self._server is None:
                raise RuntimeError("OOBReceiver is not started")
            return self._advertise
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
