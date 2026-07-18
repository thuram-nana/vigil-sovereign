"""The SIGIL bridge server (Phase 9 W1-B) — the WireGuard-bound HTTP transport that lets an
AUTHORIZED phone reach the desktop `BridgeDaemon`. It forks the WS-C glass-cockpit server
(`sigil.ui.server`) verbatim in shape (ThreadingHTTPServer + BaseHTTPRequestHandler, the strict
CSP/nosniff/no-referrer header set, the body cap + 30s timeout, the never-log-auth `log_message`,
the SSE structure, the anti-DNS-rebinding Host/Origin/Referer gate) and changes ONLY three things:

  • THE BIND. It binds a `bind_ok` address (loopback or a PRIVATE/WireGuard address) — NEVER
    0.0.0.0 / a public address. The constructor asserts this; the CLI asserts it too. This is the
    non-negotiable exposure guard: the tunnel, not the transport, is the network boundary.

  • THE AUTH. There is NO wire bearer secret (the ui's printed token is gone). Authentication IS a
    per-request Ed25519 signature the phone makes with ITS OWN owner-authorized device key — the
    Wave-1 device envelope (`bridge.envelope`). The server verifies the signature against the
    owner-minted authorized-device set (recomputed PER REQUEST so a revocation takes effect at once),
    binds the authenticated envelope `action` to the endpoint it hit (a `read:pending` envelope can
    never reach the more-sensitive `read:recall`), applies a wallclock timestamp-freshness window
    (injectable clock), and for EFFECTFUL actions (panic/relay) additionally runs the envelope's
    strict monotonic-nonce replay gate (`consume(effectful=True)`). The owner trust-root is NEVER used
    to sign anything here — the phone signs, the server only verifies.

  • THE ALLOWLIST. The anti-rebind Host/Origin allowlist is derived from the REAL bound address (plus
    the loopback pair when bound to loopback, for dev), not a hardcoded 127.0.0.1.

Everything sensitive stays off the minimal frames: `/api/pending` and the SSE stream carry only
`{seq, tier, kind}` — never a subject, never a payload, never a secret. TLS wrapping is a LATER
slice; this is plain HTTP inside the tunnel. Offense-free."""
from __future__ import annotations

import base64
import ipaddress
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..config import SPINE_PATH
from ..governor.identity import owner_pubkey
from ..mesh import authorized_devices
from ..spine.store import SpineStore
from ..spine.verify import verify_record
from .daemon import BridgeDaemon, bind_ok
from .envelope import consume, verify_envelope
from .notifier import PushNotifier

_WEBAPP = Path(__file__).parent / "webapp"       # the PWA is a later slice — served if present, else 404
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
_DEFAULT_PORT = 8722
_TS_WINDOW = 120.0                               # ± seconds a request timestamp may differ from the server clock

# Each network endpoint declares the ONE envelope action that authorizes it. Binding the
# authenticated action to the endpoint stops a captured lesser-scoped envelope (e.g. `read:pending`,
# which leaks only {seq,tier,kind}) from being replayed against a more-sensitive endpoint (e.g.
# `read:recall`, which surfaces the owner's on-screen OCR history). `/api/graph` piggybacks on the
# `read:snapshot` scope: graph returns only aggregate health, strictly LESS sensitive than the
# snapshot, so a snapshot-scoped envelope reaching it is not an escalation (and a lesser envelope
# still cannot reach it).
_READ_ACTION = {
    "/api/pending": "read:pending",
    "/api/snapshot": "read:snapshot",
    "/api/graph": "read:snapshot",
    "/api/stream": "read:stream",
    "/api/recall": "read:recall",
}


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, spine_path, trusted_pubkey=None, clock=None,
                 ts_window: float = _TS_WINDOW):
        host = addr[0]
        if not bind_ok(host):
            raise ValueError(
                f"refusing to bind {host!r}: the bridge binds loopback or a PRIVATE (WireGuard) "
                f"address only — never 0.0.0.0 / an unspecified / a public address")
        super().__init__(addr, handler)
        self.spine_path = Path(spine_path)
        # the owner PUBLIC key is the trust anchor (injectable for tests); NO private key ever lives here
        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
        self.clock = clock or time.time          # injectable wallclock so the freshness gate is deterministic
        self.ts_window = ts_window
        port = self.server_address[1]            # the ACTUAL bound port (correct even for port 0)
        hosts = {f"{host}:{port}"}
        origins = {f"http://{host}:{port}"}
        if ipaddress.ip_address(host).is_loopback:   # dev convenience only — not added for a WG bind
            hosts |= {f"127.0.0.1:{port}", f"localhost:{port}"}
            origins |= {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        self.allowed_hosts = frozenset(hosts)
        self.allowed_origins = frozenset(origins)

    def store(self) -> SpineStore:
        return SpineStore(self.spine_path)       # fresh read each request (cheap, current)

    def daemon(self) -> BridgeDaemon:
        return BridgeDaemon(self.store(), trusted_pubkey=self.trusted_pubkey)


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "sigil-bridge/1.0"
    timeout = 30                                  # per-connection socket timeout (no hung reader)
    _MAX_BODY = 65536                             # bodies are tiny; cap to avoid a Content-Length hang/alloc

    # never log auth (an envelope can ride in ?env= for SSE; never write it to a log)
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    # --- request helpers --------------------------------------------------------------------------
    def _query(self) -> dict:
        return parse_qs(urlparse(self.path).query)

    def _authorized_now(self):
        """The owner-minted authorized-device set, recomputed PER REQUEST — a revoke takes effect now."""
        return authorized_devices(self.server.store(), self.server.trusted_pubkey)

    def _envelope_payload(self):
        """The device envelope: base64url of canonical JSON, in `X-SIGIL-Envelope` (GET/POST) or the
        `?env=` query (SSE, which cannot set a header). Returns the payload dict, or None if absent/
        malformed (fail-closed — the caller denies)."""
        raw = self.headers.get("X-SIGIL-Envelope") or (self._query().get("env", [""])[0])
        if not raw:
            return None
        try:
            data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
            payload = json.loads(data)
        except Exception:  # noqa: BLE001 — any decode/parse failure is an unauthenticated request
            return None
        return payload if isinstance(payload, dict) else None

    def _fresh(self, core) -> bool:
        """The server-layer wallclock freshness window (the envelope module is pure — it never reads a
        clock — so freshness lives HERE). A non-numeric / far-off timestamp fails closed."""
        try:
            ts = float(core.get("ts"))
        except (TypeError, ValueError):
            return False
        return abs(self.server.clock() - ts) <= self.server.ts_window

    def _authed(self, action: str):
        """Authenticate a READ: verify the device signature, apply freshness, bind the action to this
        endpoint. Reads are side-effect-free, so they are NOT receipted (no spine write per GET) — the
        freshness window is their replay bound. Returns the core, or None after sending a deny."""
        payload = self._envelope_payload()
        if payload is None:
            self._deny(401, "missing/invalid device envelope")
            return None
        ok, core = verify_envelope(payload, self._authorized_now())
        if not ok:
            self._deny(401, f"unauthenticated: {core}")
            return None
        if not self._fresh(core):
            self._deny(401, "stale request (timestamp outside freshness window)")
            return None
        if core.get("action") != action:
            self._deny(403, "envelope action does not authorize this endpoint")
            return None
        return core

    def _authed_effectful(self, action: str):
        """Authenticate an EFFECTFUL request (panic/relay): verify + freshness + endpoint-bind, then run
        the envelope's strict monotonic-nonce replay gate and receipt it on the spine
        (`consume(effectful=True)`). A replayed/stale-nonce envelope is refused. Returns core or None."""
        payload = self._envelope_payload()
        if payload is None:
            self._deny(401, "missing/invalid device envelope")
            return None
        authorized = self._authorized_now()
        ok, core = verify_envelope(payload, authorized)
        if not ok:
            self._deny(401, f"unauthenticated: {core}")
            return None
        if not self._fresh(core):
            self._deny(401, "stale request (timestamp outside freshness window)")
            return None
        if core.get("action") != action:
            self._deny(403, "envelope action does not authorize this endpoint")
            return None
        try:
            return consume(self.server.store(), payload, authorized, effectful=True)
        except ValueError as e:                   # replay: nonce not fresh (fail-closed)
            self._deny(409, f"refused: {str(e)[:120]}")
            return None

    def _rebind_ok(self) -> bool:
        """The anti-DNS-rebinding gate (ui `_action_ok` logic, minus the token — the envelope is the
        credential): the `Host` must be in the WG-derived allowlist, an `Origin`, if present, must
        EXACT-match an allowed origin (a prefix like `http://IP:PORT.evil.com` must NOT pass), and a
        `Referer`, if present, must sit under an allowed origin. Applied to the whole POST action
        plane as defense-in-depth."""
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return False
        o = self.headers.get("Origin") or ""
        ref = self.headers.get("Referer") or ""
        if o and o not in self.server.allowed_origins:
            return False
        if ref and not any(ref.startswith(a + "/") or ref == a for a in self.server.allowed_origins):
            return False
        return True

    # --- response helpers -------------------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj, code=200):
        self._send(code, _json_bytes(obj))

    def _deny(self, code=403, msg="forbidden"):
        self._json({"error": msg}, code)

    # --- GET (read plane) -------------------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path.startswith("/static/"):
            return self._serve_static(path[len("/static/"):])
        if not path.startswith("/api/"):
            return self._deny(404, "not found")
        if path == "/api/stream":
            return self._sse()                    # SSE authenticates via ?env= inside _authed
        if path == "/api/pending":
            if self._authed(_READ_ACTION[path]) is None:
                return
            return self._json({"pending": self.server.daemon().pending()})   # {seq,tier,kind} only
        if path == "/api/snapshot":
            if self._authed(_READ_ACTION[path]) is None:
                return
            from ..dashboard import snapshot
            return self._json(snapshot(self.server.store()))
        if path == "/api/graph":
            if self._authed(_READ_ACTION[path]) is None:
                return
            return self._graph()
        if path.startswith("/api/record/"):
            if self._authed("read:record") is None:
                return
            return self._record(path.rsplit("/", 1)[-1])
        if path == "/api/recall":
            if self._authed(_READ_ACTION[path]) is None:
                return
            subject = self._query().get("subject", [""])[0]
            return self._json({"subject": subject, "recall": self.server.daemon().recall(subject)})
        return self._deny(404, "unknown endpoint")

    def _serve_index(self):
        idx = _WEBAPP / "index.html"
        if not idx.is_file():
            return self._deny(404, "bridge PWA not built yet")   # graceful — the webapp is a later slice
        try:
            self._send(200, idx.read_bytes(), ctype="text/html; charset=utf-8")
        except OSError:
            self._deny(404, "not found")

    def _serve_static(self, sub: str):
        base = _WEBAPP.resolve()
        target = (base / sub).resolve()
        if base != target and base not in target.parents:        # traversal guard (allowlist by containment)
            return self._deny(404, "not found")
        if not target.is_file():
            return self._deny(404, "not found")                  # includes: webapp dir absent (later slice)
        name = target.name
        ctype = ("application/javascript" if name.endswith(".js")
                 else "text/css" if name.endswith(".css")
                 else "text/html" if name.endswith(".html")
                 else "application/octet-stream")
        try:
            self._send(200, target.read_bytes(), ctype=f"{ctype}; charset=utf-8")
        except OSError:
            self._deny(404, "not found")

    def _record(self, raw):
        try:
            seq = int(raw)
        except ValueError:
            return self._deny(400, "bad seq")
        rec = self.server.store().get(seq)
        if rec is None:
            return self._json({"error": "no such record", "seq": seq,
                               "note": "no grounded record — not fabricated"}, 404)
        ok, reason = verify_record(rec)                          # re-verify the atom LIVE (prove-don't-guess)
        self._json({"seq": rec.seq, "kind": rec.kind, "source": rec.source, "actor": rec.actor,
                    "ts": rec.ts, "entry_hash": rec.entry_hash, "prev_hash": rec.prev_hash,
                    "payload": rec.payload, "integrity_ok": ok, "integrity_reason": reason})

    def _graph(self):
        try:
            from ..graph import health
            self._json({"health": health()})
        except Exception as e:  # noqa: BLE001 — graph may not be built yet (ImportError included)
            self._json({"error": "graph unavailable", "note": str(e)[:200]})

    def _sse(self):
        if self._authed("read:stream") is None:                  # deny already sent (401/403)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            since = int(self._query().get("since", ["-1"])[0])
        except (ValueError, TypeError):
            since = -1                                            # any malformed cursor → from genesis
        notifier = PushNotifier(self.server.store(), since_seq=since)
        try:
            while True:
                sent = False
                for ev in notifier.poll():
                    frame = {"seq": ev["seq"], "tier": ev["tier"], "kind": ev["kind"]}   # minimal — no subject
                    self.wfile.write(f"data: {json.dumps(frame, ensure_ascii=False)}\n\n".encode("utf-8"))
                    sent = True
                self.wfile.write(b": hb\n\n")                     # heartbeat / flush
                self.wfile.flush()
                if not sent:
                    time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return                                                # client closed — end the stream

    # --- POST (action plane) ----------------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/action", "/api/panic", "/api/relay"):
            return self._deny(404, "not found")
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > self._MAX_BODY:                              # cap the body (no CL hang / alloc)
            return self._deny(413, "body too large")
        body_bytes = self.rfile.read(length) if length else b""
        if not self._rebind_ok():                               # anti-rebind gate on the whole action plane
            return self._deny(403, "action denied (origin / host — possible DNS rebinding)")
        if path == "/api/action":
            return self._device_action(body_bytes)
        # panic / relay — effectful, envelope-authenticated with the strict nonce replay gate
        action = "panic" if path == "/api/panic" else "relay"
        core = self._authed_effectful(action)
        if core is None:
            return
        if action == "panic":
            return self._json({"ok": True, "seq": self.server.daemon().panic_engage(by="phone")})
        text = str((core.get("args") or {}).get("text", ""))     # the relayed command is INSIDE the signed core
        return self._json({"ok": True, "reply": self.server.daemon().relay(text)})

    def _device_action(self, body_bytes):
        """The phone posts its OWN device-signed `governor.approval` payload. The SERVER only VERIFIES
        (it never signs) — `submit_device_approval` accepts it iff the signing device is currently
        authorized AND the signature verifies; the signed `target_seq` binds, so no nonce is needed."""
        try:
            body = json.loads(body_bytes or b"{}")
        except (ValueError, TypeError) as e:
            return self._deny(400, f"bad request: {e}")
        if not isinstance(body, dict):
            return self._deny(400, "bad request: body must be a JSON object")
        try:
            seq = self.server.daemon().submit_device_approval(body)
        except ValueError as e:                                  # unauthorized / forged / not-an-approval
            return self._deny(403, f"approval refused: {str(e)[:200]}")
        except Exception as e:  # noqa: BLE001 — never leak internals as a 500
            return self._deny(400, f"action failed: {str(e)[:200]}")
        self._json({"ok": True, "seq": seq})


def build_server(*, addr: str, port: int = _DEFAULT_PORT, spine_path=None, trusted_pubkey=None,
                 clock=None) -> BridgeServer:
    """Build (but do not run) the bridge server bound to `addr` (asserted `bind_ok`). `trusted_pubkey`
    and `clock` are injectable for deterministic tests; both default to the real owner identity / wallclock."""
    return BridgeServer((addr, port), Handler,
                        spine_path=Path(spine_path) if spine_path else SPINE_PATH,
                        trusted_pubkey=trusted_pubkey, clock=clock)


def serve(*, addr: str, port: int = _DEFAULT_PORT, spine_path=None) -> None:
    srv = build_server(addr=addr, port=port, spine_path=spine_path)
    bound = srv.server_address[1]
    print(f"  SIGIL bridge → http://{addr}:{bound}/   (WireGuard-bound; loopback/private only — NO wire secret)")
    print("  pair a phone (owner, at the desktop):  sigil mesh authorize <device-id> <device-pubkey>")
    print("  every request must carry an authorized-device signature (X-SIGIL-Envelope) — there is no token")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
