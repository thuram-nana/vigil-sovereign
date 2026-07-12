"""
aegis.gateway — the AEGIS Gateway: an inline reverse-proxy "provable firewall".

The gateway sits IN FRONT of the operator's own web app (point DNS / the load-balancer at it). For
each request it inspects the input with the deterministic ``verify/`` oracles and — ONLY under
``enforce`` mode AND only on a CONFIRMED verdict (a fired oracle + a re-runnable certificate,
doctrine D1) — returns 403 without forwarding. Otherwise it forwards to the configured upstream and
relays the response (response-side inspection lands in G4).

Doctrine (non-negotiable, enforced here and tested):
  * DEFENSIVE ONLY. Protects the operator's OWN app; never attacks anyone; not anti-defender.
  * PROVE-DON'T-GUESS. A block rides ONLY on ``verdict.decision == "confirmed"`` + a ``CertRef`` the
    operator/auditor can re-run offline. Nothing below a fired oracle is ever blocked.
  * FAIL-OPEN. Any inspection error, an unproven verdict, or ``observe`` mode lets traffic pass. The
    firewall never takes the app down. (An upstream that is itself down yields an honest 502 — the
    gateway cannot fabricate a response, but it never *blocks* on its own error.)
  * NO FORWARD-SSRF. The upstream host is operator-configured and fixed; only the request's
    path+query is appended, never a caller-supplied scheme/host.

The enforce ENTITLEMENT gate (``aegis.respond``), the kill-switch pass-through, and audit events are
layered on in G2; this module is the serving + forwarding + request-side-inspect core, defaulting to
read-only ``observe``.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from ..common.logging import get_logger
from .inspect import inspect_request, inspect_response
from .models import AegisConfig, Verdict

_log = get_logger("aegis.gateway")

# Hop-by-hop headers (RFC 7230 6.1) — never forwarded end-to-end in either direction.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})

_MAX_REQUEST_BODY = 10 * 1024 * 1024   # 10 MiB — bounded request body (DoS-safe)
_MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # bounded upstream response we buffer
_FORWARD_TIMEOUT_S = 30.0


class GatewaySettings:
    """Per-gateway runtime state, stored on the server instance (like ``api.server``'s handler
    state). ``on_verdict`` is an optional sink the operator wires for logging/metrics — the gateway
    calls it for EVERY non-None verdict (confirmed or observed), never blocking on it.

    Enforcement is doubly gated (defence in depth, both fail-safe toward *not blocking*):
      * ENTITLEMENT (once, at construction): active blocking needs the ``AEGIS_RESPOND`` capability.
        A GOVERNED deployment that has not granted it is DOWNGRADED to observe (fail-closed to safe);
        an ungoverned deployment permits it (flagged), like every non-baseline capability.
      * KILL-SWITCH (per request): a tripped kill-switch for ``slug`` drops enforcement to
        pass-through, so a misbehaving firewall can be neutralised instantly WITHOUT taking the app
        down (availability-first)."""

    def __init__(self, upstream: str, config: AegisConfig, *, slug: str = "aegis-gateway",
                 on_verdict: Callable[[Verdict], None] | None = None) -> None:
        u = urlsplit(upstream)
        if u.scheme not in ("http", "https") or not u.netloc:
            raise ValueError(f"upstream must be an http(s) URL with a host, got {upstream!r}")
        self.upstream_scheme = u.scheme
        self.upstream_netloc = u.netloc
        self.upstream_base = f"{u.scheme}://{u.netloc}"
        self.config = config
        self.slug = slug or "aegis-gateway"
        self.on_verdict = on_verdict
        self._enforce_authorized = self._authorize_enforce()

    def _authorize_enforce(self) -> bool:
        """Entitlement check, once. Only meaningful when mode==enforce; a denied grant downgrades to
        observe. Total: any entitlement-subsystem error fails CLOSED (no enforcement)."""
        if self.config.mode != "enforce":
            return False
        try:
            from ..entitlement import Capability
            from ..entitlement.policy import is_capability_available
            ok = bool(is_capability_available(Capability.AEGIS_RESPOND))
        except Exception:
            ok = False
        if not ok:
            _log.warning("aegis.gateway.enforce_downgraded_to_observe",
                         slug=self.slug, reason="AEGIS_RESPOND entitlement not available")
        return ok

    def _killswitch_tripped(self) -> bool:
        try:
            from ..authority.killswitch import KillSwitch
            return bool(KillSwitch(self.slug).is_tripped())
        except Exception:
            return False   # a kill-switch read error must not itself start blocking traffic

    @property
    def enforce(self) -> bool:
        """Block ONLY when configured enforce AND entitled AND the kill-switch is not tripped. Every
        term fails toward NOT blocking (availability-first)."""
        return (self.config.mode == "enforce"
                and self._enforce_authorized
                and not self._killswitch_tripped())


class AegisGatewayHandler(BaseHTTPRequestHandler):
    """One request: inspect -> (block under enforce+confirmed) -> forward -> relay. Total and
    fail-open; a handler error yields a best-effort pass-through, never a spurious block."""

    server_version = "AegisGateway/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: Any) -> None:   # quiet by default; use on_verdict for telemetry
        return

    # every method funnels through _handle
    def do_GET(self) -> None: self._handle()
    def do_POST(self) -> None: self._handle()
    def do_PUT(self) -> None: self._handle()
    def do_DELETE(self) -> None: self._handle()
    def do_PATCH(self) -> None: self._handle()
    def do_HEAD(self) -> None: self._handle()
    def do_OPTIONS(self) -> None: self._handle()

    # -- helpers ----------------------------------------------------------

    @property
    def settings(self) -> GatewaySettings:
        return self.server.settings   # type: ignore[attr-defined]

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return b""
        if length <= 0:
            return b""
        if length > _MAX_REQUEST_BODY:
            # drain a bounded amount so the socket stays clean, then treat as empty for inspection
            self.rfile.read(min(length, _MAX_REQUEST_BODY))
            return b""
        return self.rfile.read(length)

    def _request_headers(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self.headers.items()]

    def _emit(self, verdict: Verdict | None) -> None:
        if verdict is not None and self.settings.on_verdict is not None:
            try:
                self.settings.on_verdict(verdict)
            except Exception:
                pass

    def _send_block(self, verdict: Verdict) -> None:
        """403 with the certificate id — the honest, auditable block. The cert is re-runnable offline
        (``CertRef.reverify``), so the block is provable, not a guess."""
        cid = verdict.certificate.cert_id if verdict.certificate else ""
        # AUDIT — every aegis.respond block is recorded with its re-runnable certificate id, the
        # attack class, and the client, so the operator has a complete, provable enforcement trail.
        try:
            _log.info("aegis.gateway.blocked", slug=self.settings.slug,
                      attack_class=verdict.attack_class, certificate=cid,
                      client=(self.client_address[0] if self.client_address else ""),
                      method=self.command, provenance=verdict.provenance)
        except Exception:
            pass
        body = (
            b'{"blocked":true,"by":"aegis-gateway","attack_class":"' + verdict.attack_class.encode()
            + b'","certificate":"' + cid.encode() + b'","reason":"a deterministic oracle proved this '
            b'request is a structured attack; the certificate re-runs offline"}'
        )
        self.send_response(403)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aegis-Block", verdict.attack_class)
        self.send_header("X-Aegis-Certificate", cid)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _forward_url(self, raw_path: str) -> str:
        """Configured-upstream base + ONLY the request's path+query (scheme/host discarded) — closes
        forward-SSRF: a caller cannot redirect the forward to another host."""
        p = urlsplit(raw_path)
        pq = p.path or "/"
        if p.query:
            pq += "?" + p.query
        return self.settings.upstream_base + pq

    def _forward(self, method: str, body: bytes) -> tuple[int, list[tuple[str, str]], bytes] | None:
        """Forward to the operator's upstream via httpx and CAPTURE the response ``(status, headers,
        content)``. Returns None on an upstream/transport error (caller sends a 502). Does not write
        to the client — the caller inspects the response, then relays or blocks."""
        try:
            import httpx
        except Exception:
            return None
        url = self._forward_url(self.path)
        fwd_headers = [(k, v) for k, v in self._request_headers() if k.lower() not in _HOP_BY_HOP]
        fwd_headers.append(("Host", self.settings.upstream_netloc))
        fwd_headers.append(("X-Forwarded-For", self.client_address[0] if self.client_address else ""))
        try:
            with httpx.Client(follow_redirects=False, timeout=_FORWARD_TIMEOUT_S) as client:
                resp = client.request(method, url, headers=fwd_headers, content=body or None)
                content = resp.content[:_MAX_RESPONSE_BYTES]
        except Exception:
            return None
        return resp.status_code, list(resp.headers.items()), content

    def _relay(self, status: int, headers: list[tuple[str, str]], content: bytes) -> None:
        """Send a captured upstream response to the client, stripping hop-by-hop headers."""
        self.send_response(status)
        for k, v in headers:
            if k.lower() not in _HOP_BY_HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def _send_bad_gateway(self) -> None:
        body = b'{"error":"bad_gateway","by":"aegis-gateway"}'
        self.send_response(502)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- the request lifecycle --------------------------------------------

    def _handle(self) -> None:
        settings = self.settings
        method = self.command
        body = self._read_body()

        # (1) REQUEST-SIDE inspection — pure, fail-open. Any error => verdict None => forward.
        verdict: Verdict | None = None
        try:
            verdict = inspect_request(
                method, self.path, self._request_headers(),
                body.decode("utf-8", "replace") if body else None,
                honeypot_paths=settings.config.honeypot_paths,
                enforce=settings.enforce,
            )
        except Exception:
            verdict = None
        self._emit(verdict)

        # (2) ENFORCE (request-side) — block ONLY on a confirmed verdict whose action is "block" (D1).
        #     Anything else forwards (fail-open). observe mode never sets action="block".
        if self._is_block(verdict):
            self._send_block(verdict)  # type: ignore[arg-type]
            return

        # (3) FORWARD to the operator's upstream and CAPTURE the response.
        captured = self._forward(method, body)
        if captured is None:
            self._send_bad_gateway()
            return
        status, resp_headers, content = captured

        # (4) RESPONSE-SIDE inspection — the app's own answer can PROVE exploitation (reflected XSS /
        #     error-based SQLi). Pure, fail-open: any error => rverdict None => relay untouched.
        rverdict: Verdict | None = None
        try:
            rverdict = inspect_response(
                self.path, self._request_headers(),
                body.decode("utf-8", "replace") if body else None,
                content.decode("utf-8", "replace") if content else None,
                enforce=settings.enforce,
            )
        except Exception:
            rverdict = None
        self._emit(rverdict)

        # (5) ENFORCE (response-side) — withhold a response that PROVES exploitation; else relay.
        if self._is_block(rverdict):
            self._send_block(rverdict)  # type: ignore[arg-type]
            return
        self._relay(status, resp_headers, content)

    @staticmethod
    def _is_block(verdict: Verdict | None) -> bool:
        return verdict is not None and verdict.decision == "confirmed" and verdict.action == "block"


def serve_gateway(upstream: str, *, config: AegisConfig, host: str = "127.0.0.1", port: int = 8080,
                  slug: str = "aegis-gateway",
                  on_verdict: Callable[[Verdict], None] | None = None) -> ThreadingHTTPServer:
    """Build (but do not start) the gateway server. The caller runs ``.serve_forever()``. Unlike the
    loopback-only ``api``/``console`` servers, a data-plane proxy must be reachable by real clients,
    so ``host`` is NOT forced to loopback — the compensating controls are the ``boundary``/inspect
    hardening, the ``AEGIS_RESPOND`` entitlement, and the per-request kill-switch. Default ``observe``
    is read-only: it inspects and forwards, never blocking. ``slug`` names the gateway for the
    kill-switch and the audit trail."""
    httpd = ThreadingHTTPServer((host, port), AegisGatewayHandler)
    httpd.settings = GatewaySettings(upstream, config, slug=slug, on_verdict=on_verdict)  # type: ignore[attr-defined]
    return httpd
