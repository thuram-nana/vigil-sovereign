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

import itertools
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from ..common.logging import get_logger
from .actor_graph import ActorGraph
from .inspect import inspect_request, inspect_response
from .models import AegisConfig, BeliefRef, Verdict
from .response_policy import feed_and_score, feed_oob_correlation, graduated_action

_log = get_logger("aegis.gateway")

# Hop-by-hop headers (RFC 7230 6.1) — never forwarded end-to-end in either direction.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
})

_MAX_REQUEST_BODY = 10 * 1024 * 1024   # hard cap: a larger body is REFUSED (413), never truncated
_MAX_INSPECT_BYTES = 2 * 1024 * 1024    # only the first N bytes of the body are inspected (the whole body is forwarded)
_MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # bounded upstream response we buffer
_FORWARD_TIMEOUT_S = 30.0
_CLIENT_TIMEOUT_S = 60.0                 # per-connection socket read deadline (slowloris bound)


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
        # G5 — the inline per-actor Beta belief graph + a monotonic sequence for its observations, and
        # a lock (the server is threaded, so belief updates must be serialised). ``actor_last_class``
        # remembers each tracked actor's most recent affirming class to label a graduated response.
        self.actor_graph = ActorGraph()
        self._belief_seq = itertools.count(1)
        self._belief_lock = threading.Lock()
        self.actor_last_class: dict[str, str] = {}
        # OPT-IN passive OOB belief elevation (default OFF). Started ONLY when the operator configured a
        # canary URL AND the AEGIS_RESPOND entitlement is available (like the rest of the response
        # layer). The receiver binds LOOPBACK ONLY (verify.oob refuses any non-loopback bind). Any
        # error → the feature stays dormant (fail-open); the gateway proxies exactly as before.
        self.oob_correlator = None   # type: ignore[var-annotated]
        self.oob_receiver = None     # type: ignore[var-annotated]
        if config.oob_canary and self._authorize_oob():
            try:
                from ..verify.oob import OOBReceiver
                from .oob_correlator import OOBCorrelator
                self.oob_correlator = OOBCorrelator(config.oob_canary)
                self.oob_receiver = OOBReceiver().start()   # loopback-only, ephemeral port
                _log.info("aegis.gateway.oob_enabled", slug=self.slug,
                          canary_host=self.oob_correlator.canary_host)
            except Exception:
                self.oob_correlator = None
                self.oob_receiver = None
                _log.warning("aegis.gateway.oob_disabled", slug=self.slug, reason="start failed")

    def _authorize_oob(self) -> bool:
        """Entitlement check for the OOB belief-elevation feature — the SAME AEGIS_RESPOND gate the
        response layer uses (a governed deployment without the grant leaves it dormant). Total: any
        entitlement-subsystem error fails CLOSED (feature off)."""
        try:
            from ..entitlement import Capability
            from ..entitlement.policy import is_capability_available
            return bool(is_capability_available(Capability.AEGIS_RESPOND))
        except Exception:
            return False

    def stop_oob(self) -> None:
        """Clean shutdown of the loopback OOB receiver (idempotent, total). The gateway's CLI/callers
        invoke this in their teardown; the receiver thread is a daemon regardless, so a missed stop
        never hangs the process."""
        r = self.oob_receiver
        self.oob_receiver = None
        if r is not None:
            try:
                r.stop()
            except Exception:
                pass

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
    timeout = _CLIENT_TIMEOUT_S   # bound a slow/stalled client so it cannot hold a thread forever

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

    def _framing_unsupported(self) -> bool:
        """This stdlib handler cannot safely buffer+forward a body it does not delimit by a valid
        Content-Length: a chunked (Transfer-Encoding) body, or a malformed Content-Length. Such a
        request is REFUSED (411 + close) rather than read-as-empty (which would drop the body and
        desync the keep-alive stream). Returns True when the framing is unsupported."""
        if self.headers.get("Transfer-Encoding"):
            return True
        cl = self.headers.get("Content-Length")
        if cl is not None:
            try:
                int(cl)
            except ValueError:
                return True
        return False

    def _read_body(self) -> tuple[bytes, bool]:
        """Read the FULL request body (for forwarding intact). Returns ``(body, too_large)``. Callers
        must first check ``_framing_unsupported``; here Content-Length is known valid. A body over the
        hard cap is NOT read (``too_large=True``) so the caller sends 413 + closes — never a silent
        truncation (which would corrupt the upload and desync the keep-alive stream)."""
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return b"", False
        if length > _MAX_REQUEST_BODY:
            return b"", True
        try:
            return self.rfile.read(length), False
        except Exception:
            return b"", False

    def _request_headers(self) -> list[tuple[str, str]]:
        return [(k, v) for k, v in self.headers.items()]

    def _emit(self, verdict: Verdict | None) -> None:
        if verdict is not None and self.settings.on_verdict is not None:
            try:
                self.settings.on_verdict(verdict)
            except Exception:
                pass

    # -- G5: graduated challenge/throttle on the per-actor Beta belief -----

    def _actor_key(self) -> str:
        """The actor this request is attributed to — the client IP (stable + correlatable, per the
        doctrine). Total: an unknown peer folds to a shared ``anon`` bucket."""
        return (self.client_address[0] if self.client_address else "") or "anon"

    def _note_belief(self, verdict: Verdict | None) -> BeliefRef | None:
        """Fold this request's verdict into the actor's Beta belief and return it. Called EXACTLY ONCE
        per request (with its strongest verdict). Serialised (the server is threaded); total (a belief
        error must never break the request path)."""
        try:
            key = self._actor_key()
            with self.settings._belief_lock:
                belief = feed_and_score(self.settings.actor_graph, key, verdict,
                                        seq=next(self.settings._belief_seq))
                if verdict is not None and verdict.decision in ("confirmed", "lead"):
                    self.settings.actor_last_class[f"session:{key}"] = verdict.attack_class
            return belief
        except Exception:
            return None

    def _current_belief(self) -> BeliefRef | None:
        """The actor's belief accumulated from PRIOR requests (read-only; does NOT record this
        request). The graduated decision rides on this, so a request is never judged on its own
        contribution — 'sustained' means an established history."""
        try:
            with self.settings._belief_lock:
                return self.settings.actor_graph.belief(f"session:{self._actor_key()}")
        except Exception:
            return None

    # -- passive OOB belief elevation (opt-in; TRANSLATOR not generator) ---

    def _note_oob_lead(self, verdict: Verdict | None, inspect_body: str | None) -> None:
        """If this request tripped an SSRF/XXE LEAD, record a pending OOB observation IFF the
        attacker's OWN payload referenced the operator's canary host. Reads only the client's request
        (self.path + the inspected body); NEVER mutates or plants anything. Total (fail-open)."""
        corr = self.settings.oob_correlator
        if corr is None or verdict is None or verdict.decision != "lead":
            return
        if verdict.attack_class not in ("ssrf", "xxe"):
            return
        try:
            corr.note_lead(self._actor_key(), path=self.path, body=inspect_body,
                           attack_class=verdict.attack_class)
        except Exception:
            pass

    def _note_oob_elevation(self, actor_key: str, attack_class: str) -> None:
        """Fold ONE OOB-correlated elevation into the actor's Beta belief via the EXISTING belief path
        (``feed_oob_correlation``) — a strong AFFIRMING signal, NEVER a certificate, NEVER a block.
        Serialised under the belief lock (the server is threaded); total."""
        try:
            with self.settings._belief_lock:
                feed_oob_correlation(self.settings.actor_graph, actor_key, attack_class,
                                     seq=next(self.settings._belief_seq))
                self.settings.actor_last_class[f"session:{actor_key}"] = attack_class
        except Exception:
            pass

    def _oob_elevation_verdict(self, attack_class: str, referenced_host: str) -> Verdict:
        """A LEAD verdict for the on_verdict telemetry sink describing an OOB correlation — decision
        LEAD, action observe, NO certificate. It is belief-only; it drives no response by itself (the
        elevated belief surfaces on the actor's NEXT request as a graduated challenge/throttle)."""
        return Verdict(decision="lead", attack_class=attack_class, confidence=0.0, certificate=None,
                       provenance="intel:aegis:oob_correlation", action="observe",
                       contributing=[f"oob-canary:{referenced_host}"])

    def _drain_oob_elevations(self) -> None:
        """Poll the loopback OOB receiver for unsolicited canary hits, correlate them to pending
        SSRF/XXE observations, and elevate the tied actors' beliefs. Belief-only; total (any error
        forwards). Called pre-request so a PRIOR inbound hit raises belief the CURRENT/next request's
        graduated decision can act on."""
        s = self.settings
        corr, recv = s.oob_correlator, s.oob_receiver
        if corr is None or recv is None:
            return
        try:
            elevations = corr.poll_elevations(recv)
        except Exception:
            return
        for el in elevations:
            self._note_oob_elevation(el.actor_key, el.attack_class)
            try:
                self._emit(self._oob_elevation_verdict(el.attack_class, el.referenced_host))
            except Exception:
                pass

    def _graduated_verdict(self, action: str, current: Verdict | None) -> Verdict:
        """A lead Verdict carrying the graduated ``action`` (challenge/throttle) — for the on_verdict
        telemetry sink. It is a LEAD (no certificate): belief NEVER mints a certificate. Its
        attack_class names the actor's dominant suspicious class (honest attribution)."""
        cls = current.attack_class if (current is not None and current.decision == "lead") else None
        cls = cls or self.settings.actor_last_class.get(f"session:{self._actor_key()}") or "automated_access"
        return Verdict(decision="lead", attack_class=cls, confidence=0.0, certificate=None,
                       provenance=f"intel:aegis:belief:{action}", action=action, contributing=[])

    def _send_graduated(self, action: str, current: Verdict | None) -> None:
        """Send an availability-first 429 for a belief-driven ``challenge``/``throttle`` — NOT a block
        (no certificate, retryable). Emits the graduated verdict for telemetry and audits it."""
        retry_after = 30 if action == "throttle" else 5
        try:
            _log.info("aegis.gateway.graduated", slug=self.settings.slug, action=action,
                      client=self._actor_key(), method=self.command)
        except Exception:
            pass
        self._emit(self._graduated_verdict(action, current))
        body = (
            b'{"aegis":"' + action.encode() + b'","by":"aegis-gateway","reason":"sustained per-actor '
            b'suspicion crossed a belief threshold; this is an availability-first challenge/throttle, '
            b'NOT a proven block (no certificate) - retry after the interval"}'
        )
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aegis-Action", action)
        self.send_header("Retry-After", str(retry_after))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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
        forward-SSRF: a caller cannot redirect the forward to another host. The path is FORCED to
        begin with a single '/', so an origin-form target that does not start with '/' (e.g.
        `@evil.com/x`, which would otherwise splice as userinfo@host and re-home the forward) cannot
        escape the fixed upstream host. urlsplit failures (a malformed IPv6 target) fall back to '/'."""
        try:
            p = urlsplit(raw_path)
            pq = p.path or "/"
            if p.query:
                pq += "?" + p.query
        except Exception:
            pq = "/"
        # collapse any leading '/' or '\' runs to exactly one '/' so neither '@host', '//host', nor
        # '\\host' can be re-parsed as an authority against the upstream base.
        pq = "/" + pq.lstrip("/\\")
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

    def _send_too_large(self) -> None:
        """413 for a body over the hard cap, and CLOSE the connection — we did not read the body, so
        the residual bytes must not be mis-parsed as the next request (keep-alive desync)."""
        self._refuse_body(413, "payload_too_large")

    def _send_length_required(self) -> None:
        """411 for a body this handler cannot delimit (chunked / bad Content-Length) — CLOSE the
        connection so the un-read body cannot desync the keep-alive stream. A real deployment fronts
        the gateway with a proxy that de-chunks; unbuffered streaming is roadmap."""
        self._refuse_body(411, "length_required")

    def _refuse_body(self, status: int, err: str) -> None:
        self.close_connection = True
        body = ('{"error":"%s","by":"aegis-gateway"}' % err).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # -- the request lifecycle --------------------------------------------

    def _handle(self) -> None:
        try:
            self._handle_inner()
        except Exception:
            # Total fail-safe: a handler error must not drop the connection with no response (that
            # would be a fail-CLOSED reset). Send an honest 502 instead. Best-effort.
            try:
                self._send_bad_gateway()
            except Exception:
                pass

    def _handle_inner(self) -> None:
        settings = self.settings
        method = self.command
        # (0) OPT-IN passive OOB belief elevation — drain any unsolicited canary hits and fold the
        #     correlated elevations into the tied actors' beliefs BEFORE the graduated decision, so a
        #     prior inbound hit is reflected in this/next request's belief. Belief-only; total; a no-op
        #     when the feature is off. Reads nothing from THIS request — never mutates it.
        self._drain_oob_elevations()
        if self._framing_unsupported():
            self._send_length_required()   # chunked/bad-CL: refuse+close, never drop-body+desync
            return
        body, too_large = self._read_body()
        if too_large:
            self._send_too_large()   # honest 413 + close; never a truncated/desynced forward
            return
        # Inspect only a bounded prefix (the whole body is still forwarded intact).
        inspect_body = body[:_MAX_INSPECT_BYTES].decode("utf-8", "replace") if body else None

        # (1) REQUEST-SIDE inspection — pure, fail-open. Any error => verdict None => forward.
        verdict: Verdict | None = None
        try:
            verdict = inspect_request(
                method, self.path, self._request_headers(), inspect_body,
                honeypot_paths=settings.config.honeypot_paths,
                enforce=settings.enforce,
            )
        except Exception:
            verdict = None
        self._emit(verdict)

        # (1b) OOB — if this is an SSRF/XXE LEAD whose payload referenced the operator's canary host,
        #      record a pending observation (reads the client's own request; NO injection). A later
        #      inbound hit on that canary will elevate this actor's belief via _drain_oob_elevations.
        self._note_oob_lead(verdict, inspect_body)

        # (2) ENFORCE (request-side) — block ONLY on a confirmed verdict whose action is "block" (D1).
        #     A PROVABLE block always wins over a belief-driven challenge (prove-don't-guess).
        #     Anything else forwards (fail-open). observe mode never sets action="block".
        if self._is_block(verdict):
            self._note_belief(verdict)   # a confirmed attack strongly raises the actor's belief (single feed)
            self._send_block(verdict)  # type: ignore[arg-type]
            return

        # (2b) G5 — a graduated challenge/throttle on SUSTAINED per-actor suspicion, riding on the
        #      belief accumulated from PRIOR requests (this request never counts toward its own
        #      escalation). NEVER a hard block on belief alone (prove-don't-guess) — only under enforce
        #      + entitlement, availability-first (a soft, retryable 429). observe mode never acts. This
        #      request's own verdict is recorded once, below, so challenge can graduate to throttle.
        if settings.enforce:
            action = graduated_action(self._current_belief())
            if action is not None:
                self._note_belief(verdict)   # record this request (single feed) so belief keeps accruing
                self._send_graduated(action, verdict)
                return

        # (3) FORWARD the FULL body to the operator's upstream and CAPTURE the response.
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
                self.path, self._request_headers(), inspect_body,
                content.decode("utf-8", "replace") if content else None,
                enforce=settings.enforce,
            )
        except Exception:
            rverdict = None
        self._emit(rverdict)

        # (5) Record this request's belief ONCE, with its strongest verdict (a response-proven attack
        #     dominates a request-side lead/benign), then either withhold a response that PROVES
        #     exploitation (response-side block) or relay.
        self._note_belief(rverdict if self._is_block(rverdict) else verdict)
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
