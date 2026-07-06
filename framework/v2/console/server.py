"""
console.server — a loopback-only, read-only HTTP server for the Ops Console.

Stdlib `ThreadingHTTPServer` bound to 127.0.0.1 ONLY (never a routable interface).
Serves the self-contained SPA from `static/`, a set of read-only `/api/*` JSON
endpoints (each delegating to `console.api`), and a Server-Sent-Events stream that
tails the structured log. It issues zero outbound calls and performs no destructive
action — a read-only console is inherently in-scope. Safe operator actions (launch /
re-verify / kill-switch trip) are added in a later phase behind explicit POST routes.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import actions, api
from .sse import EventTailer, stream_path

STATIC_DIR = Path(__file__).resolve().parent / "static"

_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json; charset=utf-8",
    ".ico": "image/x-icon",
    ".map": "application/json; charset=utf-8",
}

# Read-only GET routes: exact path -> zero-arg api provider.
_EXACT_ROUTES = {
    "/api/status": api.status_data,
    "/api/engagements": api.list_engagements,
    "/api/runs": api.list_runs,
}


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "CrucibleConsole/0.1"

    # keep the console quiet — no request logging noise on the operator's terminal
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # ---- response helpers -------------------------------------------------

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel: str) -> None:
        # map the URL onto STATIC_DIR: "/" -> index.html, "/static/x" -> x
        rel = rel.lstrip("/")
        if rel.startswith("static/"):
            rel = rel[len("static/"):]
        if rel in ("", "index.html"):
            rel = "index.html"
        target = (STATIC_DIR / rel).resolve()
        # path-traversal guard: the resolved file must stay under STATIC_DIR
        if STATIC_DIR not in target.parents and target != STATIC_DIR:
            self._json({"error": "not found"}, status=404)
            return
        if not target.is_file():
            self._json({"error": "not found"}, status=404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", _CTYPES.get(target.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, path) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        tailer = EventTailer(path)
        last_beat = time.monotonic()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                for ev in tailer.read_new():
                    payload = json.dumps(ev, ensure_ascii=False, default=str)
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                now = time.monotonic()
                if now - last_beat > 15:
                    self.wfile.write(b": ping\n\n")  # heartbeat keeps the socket open
                    self.wfile.flush()
                    last_beat = now
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return  # client navigated away — end the stream quietly

    # ---- routing ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parts = urlsplit(self.path)
        path = parts.path
        try:
            if path.startswith("/api/events"):
                q = parse_qs(parts.query)
                self._sse(stream_path(run=(q.get("run") or [None])[0],
                                      slug=(q.get("slug") or [None])[0]))
                return
            if path in _EXACT_ROUTES:
                self._json(_EXACT_ROUTES[path]())
                return
            if path.startswith("/api/engagement/"):
                self._json(api.engagement_detail(path[len("/api/engagement/"):].strip("/")))
                return
            if path.startswith("/api/report/"):
                self._json(api.run_report(path[len("/api/report/"):].strip("/")))
                return
            if path.startswith("/api/"):
                self._json({"error": "unknown endpoint"}, status=404)
                return
            self._static(path)
        except BrokenPipeError:
            return
        except Exception as e:  # never 500 the whole console on one bad read
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)

    def _read_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def do_POST(self) -> None:  # noqa: N802
        """The three SAFE actions — the only mutations the console makes. Each is
        non-destructive and cannot relax scope or bypass a gate."""
        path = urlsplit(self.path).path
        body = self._read_body()
        try:
            if path == "/api/launch/scan":
                self._json(actions.launch_scan(
                    str(body.get("target", "")),
                    max_pages=int(body.get("max_pages", 60)),
                ))
                return
            if path.startswith("/api/reverify/"):
                self._json(actions.reverify_run(path[len("/api/reverify/"):].strip("/")))
                return
            if path.startswith("/api/killswitch/") and path.endswith("/trip"):
                slug = path[len("/api/killswitch/"):-len("/trip")].strip("/")
                self._json(actions.trip_killswitch(slug, str(body.get("reason", ""))))
                return
            self._json({"error": "unknown action"}, status=404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)


def serve(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    """Create (but do not block on) the loopback console server. The caller runs
    ``serve_forever()``. Refuses any non-loopback host — the console is a
    single-operator, on-host surface by design (sovereignty)."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"console binds loopback only, refusing host {host!r}")
    return ThreadingHTTPServer((host, port), ConsoleHandler)
