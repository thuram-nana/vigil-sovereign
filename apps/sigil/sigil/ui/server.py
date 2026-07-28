"""The SIGIL glass-cockpit server (Phase 7, WS-C) — a NON-PUBLIC, two-plane HTTP server (stdlib
only, minimal auditable surface). Mirrors the MCP server's posture: read-only over the spine +
provenance on every atom, plus a CSRF-proof owner-signed action plane.

Security model (the red-pen keystone):
  • binds a `bind_ok` address ONLY — loopback (default) or a PRIVATE (WireGuard/Tailscale) address.
    NEVER 0.0.0.0 / an unspecified / a public address (the constructor raises otherwise). To reach the
    cockpit by a real domain, put a reverse proxy in front that terminates TLS and forwards to this
    private bind — the tunnel/proxy is the network boundary, not a public listener (see
    apps/sigil/deploy/REMOTE-HOSTING.md).
  • a session TOKEN is minted at startup and PRINTED TO THE TERMINAL (so only someone at the machine
    can drive it, and no web page can read it). The served page embeds it; a cross-origin page cannot.
  • READ plane (GET /api/*): requires the token (header `X-SIGIL-Token`, or `?token=` for SSE which
    can't set headers). Read/query only — EXCEPT `/api/ask`, which DISPATCHES a WARDEN-gated KERNEL
    query (a subprocess), so it carries the FULL action gate (token + Origin + Host), not just token.
  • ACTION plane (POST /api/action): requires the token AND an EXACT-MATCH `Origin`/`Referer` in the
    allowlist AND a `Host` in the allowlist (defeats DNS-rebinding). The allowlist is derived from the
    REAL bound address (plus the loopback pair when bound to loopback) UNIONED with the operator's
    explicitly-configured domain Host/Origin (`allowed_hosts`/`allowed_origins`) — so a reverse proxy
    forwarding `Host: cockpit.example.com` + `Origin: https://cockpit.example.com` is accepted while
    every other cross-origin request is still refused. Routes ONLY the closed owner-signed action set.
    The private key never touches the browser — the server signs (see `ui.actions`).
  • Static assets + the index bootstrap are token-free (they carry no secret; the token is injected
    into the page as a data attribute, unreadable cross-origin). A strict CSP + external `self` JS/CSS
    keeps the page functional AND locked down."""
from __future__ import annotations

import hmac
import ipaddress
import json
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..bridge.daemon import bind_ok
from ..config import SPINE_PATH
from ..spine.store import SpineStore
from ..spine.tail import SpineTailer
from ..spine.verify import verify_record
from . import actions as _actions

_STATIC = Path(__file__).parent / "static"
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class UIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, token: str, spine_path: Path,
                 extra_hosts=(), extra_origins=()):
        host = addr[0]
        if not bind_ok(host):
            raise ValueError(
                f"refusing to bind {host!r}: the cockpit binds loopback or a PRIVATE (WireGuard/"
                f"Tailscale) address only — never 0.0.0.0 / an unspecified / a public address. To serve "
                f"a real domain, run a reverse proxy in front (see deploy/REMOTE-HOSTING.md).")
        ip = ipaddress.ip_address(host)             # bind_ok already proved this parses
        if ip.version == 6:                         # bind an IPv6 tunnel (WireGuard/Tailscale) address
            self.address_family = socket.AF_INET6   # (instance attr read by TCPServer.__init__ below)
        super().__init__(addr, handler)
        self.token = token
        self.spine_path = spine_path
        port = self.server_address[1]              # the ACTUAL bound port (correct even for port 0)
        # Anti-DNS-rebinding allowlist: the REAL bound address, plus the loopback pair only when bound to
        # loopback (dev convenience — never added for a private/WG bind), UNIONED with the operator's
        # explicitly-configured reverse-proxy domain Host/Origin. Empty/blank extras are dropped. IPv6
        # literals are bracketed to match the Host-header/Origin form a browser sends (`[::1]:port`).
        def _hp(h: str) -> str:
            return f"[{h}]:{port}" if ":" in h else f"{h}:{port}"

        hosts = {_hp(host)}
        origins = {f"http://{_hp(host)}"}
        if ip.is_loopback:
            lit = "::1" if ip.version == 6 else "127.0.0.1"
            hosts |= {_hp(lit), f"localhost:{port}"}
            origins |= {f"http://{_hp(lit)}", f"http://localhost:{port}"}
        hosts |= {h.strip() for h in extra_hosts if h and h.strip()}
        origins |= {o.strip().rstrip("/") for o in extra_origins if o and o.strip()}
        self.allowed_hosts = frozenset(hosts)
        self.allowed_origins = frozenset(origins)

    def store(self) -> SpineStore:
        return SpineStore(self.spine_path)         # fresh read each request (cheap, current)


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server: UIServer                    # set by the socketserver machinery to our concrete server
    server_version = "sigil-ui/1.0"
    timeout = 30                        # per-connection socket timeout (BLOCK-4: no hung reader)
    _MAX_BODY = 65536                   # action bodies are tiny; cap to avoid a Content-Length hang
    _STATIC_OK = frozenset({"app.js", "style.css"})

    # never log the token (it can ride in ?token= for SSE)
    def log_message(self, fmt, *args):  # noqa: A003
        pass

    # --- auth -------------------------------------------------------------------------------------
    def _query(self) -> dict:
        return parse_qs(urlparse(self.path).query)

    def _token_ok(self) -> bool:
        q = self._query()
        tok = self.headers.get("X-SIGIL-Token") or (q.get("token", [""])[0])
        return bool(tok) and hmac.compare_digest(tok, self.server.token)

    def _action_ok(self) -> bool:
        if self.headers.get("Host", "") not in self.server.allowed_hosts:
            return False                                       # anti DNS-rebinding
        o = self.headers.get("Origin") or ""
        ref = self.headers.get("Referer") or ""
        # EXACT-match the Origin (a `startswith` lets `http://127.0.0.1:80.evil.com` slip); a Referer,
        # if present, must sit under an allowed origin. A cross-origin Origin → refuse.
        if o and o not in self.server.allowed_origins:
            return False
        if ref and not any(ref.startswith(a + "/") or ref == a for a in self.server.allowed_origins):
            return False
        return self._token_ok()

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
            return self._serve_static(path.rsplit("/", 1)[-1])   # token-free bootstrap assets (no secret)
        if not path.startswith("/api/"):
            return self._deny(404, "not found")
        if not self._token_ok():
            return self._deny(401, "missing/invalid token")
        if path == "/api/ask":
            # /api/ask DISPATCHES a KERNEL subprocess → it gets the FULL action gate, not just token.
            return self._ask(self._query().get("q", [""])[0]) if self._action_ok() else self._deny(403, "denied")
        if path == "/api/snapshot":
            from ..dashboard import snapshot
            return self._json(snapshot(self.server.store()))
        if path == "/api/settings":
            from . import settings as _settings
            return self._json(_settings.settings_status())     # REDACTED — never a secret value
        if path.startswith("/api/record/"):
            return self._record(path.rsplit("/", 1)[-1])
        if path == "/api/stream":
            return self._sse()
        if path == "/api/sigil/hud":
            return self._hud()
        if path == "/api/graph":
            return self._graph()
        if path == "/api/graph/entity":
            return self._graph_entity(self._query().get("name", [""])[0])
        if path == "/api/classify":
            return self._classify(self._query().get("tool", [""])[0])
        return self._deny(404, "unknown endpoint")

    def _serve_static(self, name):
        if name not in self._STATIC_OK:
            return self._deny(404, "not found")
        try:
            data = (_STATIC / name).read_bytes()
        except OSError:
            return self._deny(404, "not found")
        ctype = "application/javascript" if name.endswith(".js") else "text/css"
        self._send(200, data, ctype=f"{ctype}; charset=utf-8")

    def _serve_index(self):
        try:
            html = (_STATIC / "index.html").read_text(encoding="utf-8")
        except OSError:
            return self._deny(500, "ui missing")
        html = html.replace("__SIGIL_TOKEN__", self.server.token)   # embed token for the same-origin page
        self._send(200, html.encode("utf-8"), ctype="text/html; charset=utf-8")

    def _record(self, raw):
        try:
            seq = int(raw)
        except ValueError:
            return self._deny(400, "bad seq")
        rec = self.server.store().get(seq)
        if rec is None:
            return self._json({"error": "no such record", "seq": seq, "note": "no grounded record — not fabricated"}, 404)
        ok, reason = verify_record(rec)                          # re-verify the atom LIVE (prove-don't-guess)
        self._json({"seq": rec.seq, "kind": rec.kind, "source": rec.source, "actor": rec.actor,
                    "ts": rec.ts, "entry_hash": rec.entry_hash, "prev_hash": rec.prev_hash,
                    "payload": rec.payload, "integrity_ok": ok, "integrity_reason": reason})

    def _graph(self):
        try:
            from ..graph import health
            self._json({"health": health()})
        except Exception as e:  # noqa: BLE001 — graph may not be built yet
            self._json({"error": "graph unavailable", "note": str(e)[:200]})

    def _graph_entity(self, name):
        try:
            from ..graph import entity
            self._json(entity(name))
        except Exception as e:  # noqa: BLE001
            self._json({"error": "graph unavailable", "note": str(e)[:200]})

    def _classify(self, tool):
        from ..agents.kernel_classify import KernelClassifier
        self._json({"tool": tool, "tier": KernelClassifier().classify(tool).label()})

    def _ask(self, q):
        from ..voice.dispatch import KernelDispatch
        self._json({"q": q, "answer": KernelDispatch().send(q)})

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        try:
            since = int(self._query().get("since", ["-1"])[0])
        except (ValueError, TypeError):
            since = -1                                          # any malformed cursor → from genesis
        tailer = SpineTailer(self.server.store(), since_seq=since)
        try:
            while True:
                sent = False
                for ev in tailer.poll():
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                    sent = True
                self.wfile.write(b": hb\n\n")                    # heartbeat / flush
                self.wfile.flush()
                if not sent:
                    time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return                                               # client closed — end the stream

    def _hud(self):
        """S2/S4 — the SIGIL on-screen HUD channel (SSE, token-gated in do_GET). Tails the owner-signed
        spine for ``sigil.nav`` SIGNALS and emits ``{"t":"nav","screen_id":…}`` so the browser switches to
        the commanded screen (voice/gesture). It DISPATCHES nothing (read-only signal fan-out; the token
        gate suffices — no action gate needed). A nav payload is fully plaintext (no CONTENT_FIELDS), so no
        vault is touched. S4 will add ``state``/``feedback`` events from the ephemeral status file."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        try:
            since = int(self._query().get("since", ["-1"])[0])
        except (ValueError, TypeError):
            since = -1
        store = self.server.store()
        cursor = since
        if since < 0:
            # default to the CURRENT tip: the HUD drives live navigation, so it must NOT replay historical
            # sigil.nav records on connect (that would bounce a freshly-loaded page to the last-voiced
            # screen). One scan at connect to find the tip; then only navs appended AFTER connect stream.
            for r in store.iter_records(since_seq=-1):
                cursor = r.seq
        from ..voice.hud_status import read_status
        last_state = None
        try:
            while True:
                sent = False
                # S4: fan out the voice FSM state (idle/listening/thinking/speaking) from the EPHEMERAL 0600
                # status file — deduped (emit only on change). It is read-only telemetry, never the spine.
                st = read_status()
                if isinstance(st, dict) and st != last_state:
                    last_state = st
                    ev = {"t": "state", "state": str(st.get("state", "idle")),
                          "transcript": str(st.get("transcript", "")), "feedback": str(st.get("feedback", ""))}
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                    sent = True
                for r in store.iter_records(since_seq=cursor):
                    cursor = r.seq
                    pay = getattr(store.decrypted_or_raw(r), "payload", None) or {}
                    if isinstance(pay, dict) and pay.get("signal") == "sigil.nav":
                        sid = str(pay.get("screen_id") or "")
                        direction = str(pay.get("nav") or "")
                        if sid:                                   # voice / pinch: an absolute screen id
                            ev = {"t": "nav", "screen_id": sid, "seq": r.seq}
                        elif direction in ("next", "prev"):        # gesture swipe: a relative step
                            ev = {"t": "nav", "direction": direction, "seq": r.seq}
                        else:
                            continue
                        self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
                        sent = True
                self.wfile.write(b": hb\n\n")
                self.wfile.flush()
                if not sent:
                    time.sleep(0.25)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # --- POST (action plane) ----------------------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/api/action":
            return self._deny(404, "not found")
        if not self._action_ok():
            return self._deny(403, "action denied (token / origin / host)")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > self._MAX_BODY:                         # BLOCK-4: cap the body (no CL hang / alloc)
                return self._deny(413, "body too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            action = str(body.get("action", ""))
            result = _actions.do_action(action, body, store=self.server.store())
            self._json(result)
        except (ValueError, KeyError) as e:
            self._deny(400, f"bad request: {e}")
        except Exception as e:  # noqa: BLE001 — ApprovalError etc. → 400, never 500-leak internals
            self._deny(400, f"action failed: {str(e)[:200]}")


def build_server(*, token: str, host: str = "127.0.0.1", port: int = 8733, spine_path=None,
                 allowed_hosts=(), allowed_origins=()) -> UIServer:
    """Build (do not run) the cockpit bound to ``host:port`` (asserted ``bind_ok`` — never public).
    ``allowed_hosts``/``allowed_origins`` are the operator's reverse-proxy domain forms (e.g.
    ``cockpit.example.com`` / ``https://cockpit.example.com``) unioned into the anti-rebind allowlist."""
    return UIServer((host, port), Handler, token=token,
                    spine_path=Path(spine_path) if spine_path else SPINE_PATH,
                    extra_hosts=allowed_hosts, extra_origins=allowed_origins)


def serve(*, token: str, host: str = "127.0.0.1", port: int = 8733, spine_path=None,
          allowed_hosts=(), allowed_origins=()) -> None:
    srv = build_server(token=token, host=host, port=port, spine_path=spine_path,
                       allowed_hosts=allowed_hosts, allowed_origins=allowed_origins)
    bound = srv.server_address
    bip = ipaddress.ip_address(bound[0])
    disp = f"[{bound[0]}]" if bip.version == 6 else bound[0]     # bracket IPv6 in the URL
    print(f"  SIGIL cockpit → http://{disp}:{bound[1]}/?token={token}")
    if bip.is_loopback:
        print("  (loopback only; the token gates every request — keep it to yourself)")
    else:
        print(f"  (private bind {bound[0]} — reach it via a reverse proxy / tunnel, never a public listener)")
    # the operator-configured reverse-proxy domains (printed from the inputs, not reverse-engineered)
    extras = ", ".join(sorted({h.strip() for h in allowed_hosts if h and h.strip()}))
    if extras:
        print(f"  (reverse-proxy Host allowlist: {extras})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
