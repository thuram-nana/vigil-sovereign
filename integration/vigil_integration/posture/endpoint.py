"""posture.endpoint — a READ-ONLY, loopback/tunnel-bound HTTP endpoint that serves the latest signed
posture bundle so a counterparty (customer, auditor, insurer, regulator) can POLL it and re-verify it
OFFLINE with the bundle's own VIGIL-free verifier — the "HTTPS for security posture" surface.

It reaches no target, runs nothing, mutates nothing: GET-only, and `bind_ok` (reused from witness_service,
byte-for-byte with uiproxy) REFUSES a public/unspecified bind. It exposes only the already-signed bundle
artifacts + the out-of-band fingerprint pin. Sovereign-safe: stdlib + witness_service.bind_ok only.

Routes:
  GET /posture            -> the bundle.json a verifier consumes ({"posture": {certificate, signature}})
  GET /posture/trust-root -> the out-of-band fingerprint pin (text)
  GET /posture/how-to     -> HOW-TO-VERIFY.md (text)
  GET /healthz            -> {"ok": true}
Any other path -> 404; any non-GET -> 405. Nothing is writable.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ..witness_service import bind_ok


class PostureEndpointError(Exception):
    """Refused to serve (e.g. a public bind) — fail-closed."""


def _make_handler(bundle_dir: Path):
    class _Handler(BaseHTTPRequestHandler):
        timeout = 10

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):  # pragma: no cover
                pass

        def _file(self, name: str, ctype: str, missing: bytes) -> None:
            f = bundle_dir / name
            if not f.is_file():
                self._send(404, missing, ctype)
            else:
                self._send(200, f.read_bytes(), ctype)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0].rstrip("/") or "/"
            if path in ("/", "/posture", "/posture.json", "/bundle.json"):
                self._file("bundle.json", "application/json", b'{"error":"no posture attested yet"}')
            elif path == "/posture/trust-root":
                self._file("TRUST-ROOT-FINGERPRINT.txt", "text/plain", b"")
            elif path == "/posture/how-to":
                self._file("HOW-TO-VERIFY.md", "text/markdown; charset=utf-8", b"")
            elif path == "/healthz":
                self._send(200, b'{"ok":true}')
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self) -> None:  # noqa: N802
            self._send(405, b'{"error":"read-only posture endpoint"}')

        do_PUT = do_DELETE = do_PATCH = do_POST  # noqa: N815

        def log_message(self, *_a: Any) -> None:  # quiet
            return

    return _Handler


def serve_posture(host: str, port: int, bundle_dir: str | Path, *, allow_public: bool = False):
    """Build (do not start) a read-only posture server. `bind_ok` refuses a public/unspecified bind
    unless `allow_public` is explicitly set (never in production)."""
    if not allow_public and not bind_ok(host):
        raise PostureEndpointError(
            f"refusing to bind a public/unspecified address {host!r} — the posture endpoint is read-only "
            f"and loopback/tunnel-bound only")
    return ThreadingHTTPServer((host, int(port)), _make_handler(Path(bundle_dir).expanduser()))


def run_posture_endpoint_forever(host: str, port: int, bundle_dir: str | Path) -> None:
    srv = serve_posture(host, port, bundle_dir)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
