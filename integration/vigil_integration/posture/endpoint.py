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
  GET /healthz            -> {"ok": true}                 (liveness — the process is up)
  GET /readyz             -> {"ok": bool, "checks": [...]} (readiness — the SPINE INTEGRITY property holds)
Any other path -> 404; any non-GET -> 405. Nothing is writable.

/readyz (W6-7) is the readiness input: it runs the boundary-safe integrity verifier over the sovereign
spine home (chain integrity, signed-head freshness, anti-rollback floor, clock skew) AND the dead-man check
that the scheduled verifier is running, and returns HTTP 503 when the integrity property is VIOLATED — so a
load balancer / orchestrator drains a node whose spine has broken, rather than serving from it.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Optional

from ..witness_service import bind_ok


def _resolve_sigil_home() -> Path:
    """SIGIL_HOME — the sovereign spine home (env override, else ~/.sigil). Read WITHOUT importing sigil."""
    return Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil")))


def default_readyz() -> tuple[bool, dict]:
    """Run the integrity verifier over the sovereign spine home + the dead-man heartbeat check. Returns
    ``(ready, body)`` — ``ready`` False on any integrity FAILURE. Never raises (a verifier crash → not
    ready, with the error surfaced, fail-CLOSED)."""
    try:
        from .. import integrity_verifier as iv
        home = _resolve_sigil_home()
        report = iv.verify_integrity(home)
        stale, hb_detail = iv.heartbeat_is_stale(iv._default_heartbeat_path(home))
        body = {"ok": report.ok, "home": report.home, "heartbeat_stale": stale,
                "heartbeat_detail": hb_detail,
                "checks": [{"check": c.check, "status": c.status, "detail": c.detail}
                           for c in report.checks]}
        return report.ok, body
    except Exception as exc:  # noqa: BLE001 — a readiness probe that cannot run is NOT ready (fail-closed)
        return False, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

# The default port the read-only posture endpoint binds. DELIBERATELY off 8787: that is the offense
# console's fixed port (``uiproxy.CONSOLE_PORT``), and the two must be able to run AT THE SAME TIME — you
# serve the signed posture bundle to a counterparty WHILE the console is up. Binding 8787 by default put
# the posture endpoint straight on top of the console (issue #546). 8788 sits just above it, clear of the
# fixed UI ports (proxy 8770 · cockpit 8733 · console 8787 · api 8799).
DEFAULT_ENDPOINT_PORT = 8788


class PostureEndpointError(Exception):
    """Refused to serve (e.g. a public bind) — fail-closed."""


def _make_handler(bundle_dir: Path, readyz_provider: Optional[Callable[[], tuple[bool, dict]]] = None):
    provider = readyz_provider or default_readyz

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
            elif path == "/readyz":
                try:
                    ready, body = provider()
                except Exception as exc:  # noqa: BLE001 — a failing readiness probe is NOT ready (fail-closed)
                    ready, body = False, {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                payload = json.dumps(body, sort_keys=True).encode("utf-8")
                self._send(200 if ready else 503, payload)
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self) -> None:  # noqa: N802
            self._send(405, b'{"error":"read-only posture endpoint"}')

        do_PUT = do_DELETE = do_PATCH = do_POST  # noqa: N815

        def log_message(self, *_a: Any) -> None:  # quiet
            return

    return _Handler


def serve_posture(host: str, port: int, bundle_dir: str | Path, *, allow_public: bool = False,
                  readyz_provider: Optional[Callable[[], tuple[bool, dict]]] = None):
    """Build (do not start) a read-only posture server. `bind_ok` refuses a public/unspecified bind
    unless `allow_public` is explicitly set (never in production). `readyz_provider` overrides the default
    integrity-verifier readiness probe (injectable for tests)."""
    if not allow_public and not bind_ok(host):
        raise PostureEndpointError(
            f"refusing to bind a public/unspecified address {host!r} — the posture endpoint is read-only "
            f"and loopback/tunnel-bound only")
    return ThreadingHTTPServer((host, int(port)),
                               _make_handler(Path(bundle_dir).expanduser(), readyz_provider))


def run_posture_endpoint_forever(host: str, port: int, bundle_dir: str | Path) -> None:
    srv = serve_posture(host, port, bundle_dir)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
