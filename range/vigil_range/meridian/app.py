"""The MERIDIAN HTTP servers.

`target up` runs two loopback listeners in one process:
  * the TARGET portal on :19010 — the deliberately-vulnerable surface VIGIL scans. Only this plane writes
    access.log / auth.log (the telemetry `vigil detect` reads).
  * the Range Control cockpit on :19011 — the operator console that drives VIGIL against MERIDIAN.

Mode (vuln|hardened) is read fresh from the state file on every request, so `target harden on|off` flips
every sink live.
"""

from __future__ import annotations

import http.server
import threading
import urllib.parse
from typing import Optional

from . import config as cfg
from . import logs
from .handlers import base, build_router
from .router import Ctx, Response, Router


class RangeHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], config: cfg.Config, router: Router, plane: str) -> None:
        super().__init__(addr, _Handler)
        self.config = config
        self.router = router
        self.plane = plane  # 'gov' (writes telemetry) | 'control'


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MERIDIAN/1.0"
    protocol_version = "HTTP/1.1"

    # silence the default stderr logger; the gov plane writes its own CLF access.log
    def log_message(self, *args: object) -> None:
        return

    @property
    def _srv(self) -> RangeHTTPServer:
        return self.server  # type: ignore[return-value]

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _ctx(self, method: str) -> Ctx:
        parsed = urllib.parse.urlsplit(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}
        return Ctx(
            method=method,
            path=parsed.path,
            query=urllib.parse.parse_qs(parsed.query),
            headers=headers,
            body=self._read_body() if method in ("POST", "PUT", "PATCH") else b"",
            client_ip=self.client_address[0],
            base_dir=self._srv.config.base_dir,
            mode=cfg.read_mode(self._srv.config.base_dir),
        )

    def _write(self, resp: Response) -> None:
        self.send_response(resp.status)
        self.send_header("Content-Type", resp.content_type)
        self.send_header("Content-Length", str(len(resp.body)))
        for key, val in resp.headers.items():
            self.send_header(key, val)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(resp.body)
        if self._srv.plane == "gov":
            logs.write_access(
                self._srv.config.access_log, self.client_address[0], self.requestline,
                resp.status, len(resp.body),
                self.headers.get("Referer", "-"), self.headers.get("User-Agent", "-"),
            )

    def _handle(self, method: str) -> None:
        ctx = self._ctx(method)
        try:
            resp = self._srv.router.dispatch(ctx)
            if resp is None:
                resp = base.not_found(ctx)
        except Exception as exc:  # a target must never 500-crash the whole listener
            resp = Response.text(f"internal error: {type(exc).__name__}", status=500)
        self._write(resp)

    def do_GET(self) -> None:
        self._handle("GET")

    def do_HEAD(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")


def _control_router() -> Router:
    """The Range Control router. Full cockpit lands in S4; S0 ships a themed placeholder + health."""
    from . import theme
    r = Router()

    def _placeholder(ctx: Ctx) -> Response:
        body = (
            '<main class="wrap"><div class="screen-head">'
            '<span class="label">Operator cockpit</span>'
            '<h1>Range Control</h1>'
            '<p class="sub">Drives the real VIGIL verbs against MERIDIAN and streams the results — '
            'recon, oracle-confirmed findings, access-control, verify, evidence, detect, and '
            'harden → re-prove CLOSED.</p></div>'
            '<div class="card owner"><div class="card-h"><span class="label">Status</span>'
            '<h3>Cockpit coming online</h3></div>'
            '<p style="color:var(--text-1)">The live command-center is wired in a later build slice. '
            '<span class="mono">The target portal is live at '
            '<a href="http://127.0.0.1:19010/">http://127.0.0.1:19010/</a>.</span></p></div></main>'
        )
        return Response.html(theme.page("Range Control", body, plane="control", mode=ctx.mode))

    r.add("GET", "/", _placeholder)
    r.add("GET", "/healthz", lambda _c: Response.json({"status": "ok", "plane": "control"}))
    return r


def serve(config: cfg.Config, *, hardened: bool = False, block: bool = True,
          control: bool = True) -> tuple[RangeHTTPServer, Optional[RangeHTTPServer]]:
    """Bind the loopback server(s) and (optionally) block serving until interrupted.

    Returns (target, control|None). `control=False` runs the TARGET plane only — used when the range is
    driven by the generic `tools/livefire` harness, which treats MERIDIAN as just another loopback target.
    When block=False the caller owns shutdown (used by tests). Each listener runs its own daemon thread.
    """
    config.ensure_dirs()
    cfg.write_mode(config.base_dir, cfg.MODE_HARDENED if hardened else cfg.MODE_VULN)

    target = RangeHTTPServer((config.host, config.target_port), config, build_router(), plane="gov")
    control_srv: Optional[RangeHTTPServer] = None
    threading.Thread(target=target.serve_forever, name="meridian-target", daemon=True).start()
    if control:
        control_srv = RangeHTTPServer((config.host, config.control_port), config, _control_router(),
                                      plane="control")
        threading.Thread(target=control_srv.serve_forever, name="meridian-control", daemon=True).start()

    if not block:
        return target, control_srv

    stop = threading.Event()
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        target.shutdown()
        if control_srv is not None:
            control_srv.shutdown()
    return target, control_srv


def stop_servers(*servers: Optional[RangeHTTPServer]) -> None:
    for s in servers:
        if s is not None:
            s.shutdown()
            s.server_close()
