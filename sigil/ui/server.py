"""The SIGIL glass-cockpit server (Phase 7, WS-C) — a loopback-only, two-plane HTTP server (stdlib
only, minimal auditable surface). Mirrors the MCP server's posture: read-only over the spine +
provenance on every atom, plus a CSRF-proof owner-signed action plane.

Security model (the red-pen keystone):
  • binds 127.0.0.1 ONLY (never 0.0.0.0/public).
  • a session TOKEN is minted at startup and PRINTED TO THE TERMINAL (so only someone at the machine
    can drive it, and no web page can read it). The served page embeds it; a cross-origin page cannot.
  • READ plane (GET /api/*): requires the token (header `X-SIGIL-Token`, or `?token=` for SSE which
    can't set headers). Read/query only — EXCEPT `/api/ask`, which DISPATCHES a WARDEN-gated KERNEL
    query (a subprocess), so it carries the FULL action gate (token + Origin + Host), not just token.
  • ACTION plane (POST /api/action): requires the token AND an EXACT-MATCH loopback `Origin`/`Referer`
    AND a `Host` in the allowlist (defeats DNS-rebinding). Routes ONLY the closed owner-signed action
    set. The private key never touches the browser — the server signs (see `ui.actions`).
  • Static assets + the index bootstrap are token-free (they carry no secret; the token is injected
    into the page as a data attribute, unreadable cross-origin). A strict CSP + external `self` JS/CSS
    keeps the page functional AND locked down."""
from __future__ import annotations

import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..config import SPINE_PATH
from ..spine.store import SpineStore
from ..spine.tail import SpineTailer
from ..spine.verify import verify_record
from . import actions as _actions

_STATIC = Path(__file__).parent / "static"
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class UIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, *, token: str, spine_path: Path):
        super().__init__(addr, handler)
        self.token = token
        self.spine_path = spine_path
        port = self.server_address[1]              # the ACTUAL bound port (correct even for port 0)
        self.allowed_hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
        self.allowed_origins = frozenset({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})

    def store(self) -> SpineStore:
        return SpineStore(self.spine_path)         # fresh read each request (cheap, current)


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
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
        if path.startswith("/api/record/"):
            return self._record(path.rsplit("/", 1)[-1])
        if path == "/api/stream":
            return self._sse()
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


def build_server(*, token: str, port: int = 8733, spine_path=None) -> UIServer:
    return UIServer(("127.0.0.1", port), Handler, token=token,
                    spine_path=Path(spine_path) if spine_path else SPINE_PATH)


def serve(*, token: str, port: int = 8733, spine_path=None) -> None:
    srv = build_server(token=token, port=port, spine_path=spine_path)
    print(f"  SIGIL cockpit → http://127.0.0.1:{port}/?token={token}")
    print("  (loopback only; the token gates every request — keep it to yourself)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
