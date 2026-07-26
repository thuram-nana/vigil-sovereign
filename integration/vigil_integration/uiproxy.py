"""`vigil up` — the one-command unified-UI launcher + a self-contained stdlib reverse proxy.

`vigil up` brings the WHOLE VIGIL COMMAND UI up locally (and, hosted, behind the operator's domain)
at ONE origin, then federates the two isolated trust planes behind it:

    browser ─▶ vigil up proxy (the ONLY listener a human points a browser at)
                 ├─ /sovereign/*        ▶ 127.0.0.1:8733   (sigil serve — the sovereign cockpit)
                 ├─ /offense/api/v1/*   ▶ 127.0.0.1:8799   (crucible api — the gated action plane)
                 └─ /offense/*          ▶ 127.0.0.1:8787   (crucible console — read + SSE plane)
    /  and the bundle files (style.css, ui.js, manual.js, app.js, index.html) are served by the
    proxy itself from a runtime serve dir assembled by `vigil up`.

CRITICAL boundary property (mirrors ``dispatch``): this module is PURE STDLIB. It imports NEITHER
``framework``/``strix`` (the offense engine) NOR ``sigil`` (the sovereign core) — the three backends
run as SEPARATE OS processes in their own venvs (spawned via ``dispatch.resolve``), so a single
interpreter never co-loads the two trust domains (the FATAL-2 boundary). The proxy never itself
reaches a target; it only forwards to the three loopback backends.

Never-public: the proxy binds loopback (default 127.0.0.1:8770) or a PRIVATE/tunnel address only —
it refuses 0.0.0.0 / an unspecified / a globally-routable bind (``bind_ok``, reimplemented inline
here so this offense-side path imports no sigil). A ``--domain`` is an allowlist STRING (fronted by
the operator's TLS proxy), never a bind.

ROUTING NOTE (a deliberate, documented deviation): the offense side has TWO backends that BOTH use an
``/api/`` prefix — the console (8787: ``/api/status``, ``/api/tools``, ``/api/events`` (SSE), the read
plane the P1 UI actually calls) and the gated api (8799: ``/api/v1/*``). The single ``data-offense``
mount is ``/offense`` (``app.js`` does ``OFF(p) = "/offense" + p`` and fetches ``/offense/api/status``
etc.). So the ONLY routing that keeps the shipped P1 UI's read/SSE data reachable AND still exposes the
gated api is to disambiguate by the api's own ``/api/v1`` sub-prefix: ``/offense/api/v1/*`` → the api,
everything else under ``/offense`` → the console. Routing every ``/offense/api/*`` to the api (8799)
would strand the console's ``/api/status``/``/api/events`` (they live on 8787), which is exactly what
``app.js`` calls — so under the real-data-only tie-breaker the mount-prefix + ``/api/v1`` split wins.
"""
from __future__ import annotations

import http.client
import http.server
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Optional
from urllib.parse import urlsplit

from . import dispatch

# ---- ports (fixed; the proxy is the only human-facing listener) -----------------------------------
DEFAULT_PROXY_PORT = 8770
_MAX_BODY = 16 * 1024 * 1024   # cap a forwarded request body (UI actions are tiny); refuse oversized
SOVEREIGN_PORT = 8733     # sigil serve      (the sovereign cockpit)
CONSOLE_PORT = 8787       # crucible console (offense read + SSE plane)
API_PORT = 8799           # crucible api     (offense gated /api/v1 action plane)

# federated mount bases written into index.html (what app.js prepends to every fetch)
SOVEREIGN_BASE = "/sovereign"
OFFENSE_BASE = "/offense"

# the bundle files the proxy serves from the runtime serve dir
BUNDLE_JS = ("ui.js", "manual.js", "app.js")
_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8",
}
# strict same-origin CSP on the bundle the proxy serves (mirrors the console/cockpit posture). The app
# is CSP-native (no inline script/handlers): all script + style + XHR/EventSource are same-origin.
_BUNDLE_CSP = ("default-src 'self'; base-uri 'self'; form-action 'self'; "
               "frame-ancestors 'none'; object-src 'none'; img-src 'self' data:")

# hop-by-hop headers (RFC 7230 §6.1) — never forwarded across the proxy in either direction.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
})

# the cockpit prints e.g. `  SIGIL cockpit → http://127.0.0.1:8733/?token=XXXX`
_TOKEN_RE = re.compile(r"[?&]token=([A-Za-z0-9_\-]+)")

_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")   # Tailscale CGNAT
_ULA6 = ipaddress.ip_network("fc00::/7")           # IPv6 unique-local (WireGuard/Tailscale)
_LINKLOCAL6 = ipaddress.ip_network("fe80::/10")    # IPv6 link-local


# ==================================================================================================
# never-public bind predicate — a pure-stdlib reimplementation of sigil's daemon.bind_ok (so this
# offense-side up-path imports NO sigil). Kept byte-for-byte equivalent in behaviour.
# ==================================================================================================
def bind_ok(addr: str) -> bool:
    """True iff `addr` is safe to bind: loopback, an IPv4 PRIVATE (RFC1918) / Tailscale-CGNAT address,
    or an IPv6 unique-local (fc00::/7) / link-local (fe80::/10) address — i.e. a WireGuard/Tailscale
    tunnel or LAN address. NEVER 0.0.0.0/:: (unspecified) and NEVER a globally-routable address.

    IPv6 uses a POSITIVE allowlist rather than ``is_private`` because Python mis-labels the routable
    transition ranges Teredo (2001::/32) and 6to4 (2002::/16) as private."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_unspecified:                              # 0.0.0.0 / :: → refuse
        return False
    if ip.version == 6:
        return ip.is_loopback or ip in _ULA6 or ip in _LINKLOCAL6
    return ip.is_loopback or ip.is_private or ip in _CGNAT4


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost",)


def compute_authority(host: str, port: int, domain: str = "") -> tuple[str, str, bool]:
    """Compute the (authority, scheme, open_browser) the browser will use.

    * ``--domain NAME`` (hosted, TLS terminated by the operator's edge proxy) → authority ``NAME``,
      scheme ``https``, never auto-open a browser.
    * local / ``--host <tunnel-ip>`` → authority ``<host>:<port>`` (IPv6 literals bracketed), scheme
      ``http``; auto-open a browser ONLY for a loopback bind.
    """
    if domain:
        return domain, "https", False
    try:
        ip = ipaddress.ip_address(host)
        disp = f"[{host}]" if ip.version == 6 else host
    except ValueError:
        disp = host
    return f"{disp}:{port}", "http", _is_loopback(host)


def parse_cockpit_token(line: str) -> Optional[str]:
    """Extract the session token from a line of the cockpit's stdout (the ``?token=`` in its URL)."""
    m = _TOKEN_RE.search(line)
    return m.group(1) if m else None


# ==================================================================================================
# runtime serve dir — assembled by `vigil up` under .vigil-live/ui/ (gitignored)
# ==================================================================================================
def assemble_serve_dir(src_dir: Path, serve_dir: Path, *, token: str,
                       sovereign_base: str = SOVEREIGN_BASE, offense_base: str = OFFENSE_BASE) -> Path:
    """Build the runtime serve dir from the ``packages/vigil-ui`` bundle:

    * ``style.css`` = ``tokens.css`` + ``components.css`` concatenated,
    * ``ui.js`` / ``manual.js`` / ``app.js`` copied verbatim (+ ``manifest.json`` if present),
    * ``index.html`` written with the three placeholders substituted (token + federated mount bases).
    """
    # 0700 dir: index.html embeds the sovereign session TOKEN (a live bearer credential), so the runtime
    # serve dir and its files must never be world-readable on a multi-user host.
    serve_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(serve_dir, 0o700)
    tokens_css = (src_dir / "tokens.css").read_text(encoding="utf-8")
    components_css = (src_dir / "components.css").read_text(encoding="utf-8")
    (serve_dir / "style.css").write_text(tokens_css.rstrip() + "\n" + components_css, encoding="utf-8")
    for name in BUNDLE_JS:
        (serve_dir / name).write_text((src_dir / name).read_text(encoding="utf-8"), encoding="utf-8")
    manifest = src_dir / "manifest.json"
    if manifest.exists():
        (serve_dir / "manifest.json").write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    html = (src_dir / "index.html").read_text(encoding="utf-8")
    html = (html.replace("__VIGIL_TOKEN__", token)
                .replace("__VIGIL_SOVEREIGN__", sovereign_base)
                .replace("__VIGIL_OFFENSE__", offense_base))
    index = serve_dir / "index.html"
    index.write_text(html, encoding="utf-8")
    os.chmod(index, 0o600)   # token-bearing → owner-only
    return serve_dir


# ==================================================================================================
# the reverse proxy
# ==================================================================================================
def route(path: str) -> Optional[tuple[str, int, str]]:
    """Map a request path to ``(backend_host, backend_port, upstream_path)`` or ``None`` (serve
    static). Strips the mount prefix so the upstream sees its own path; the query is preserved by the
    caller. The offense api is disambiguated by its ``/api/v1`` sub-prefix (see the module docstring)."""
    if path == SOVEREIGN_BASE or path.startswith(SOVEREIGN_BASE + "/"):
        rest = path[len(SOVEREIGN_BASE):] or "/"
        return ("127.0.0.1", SOVEREIGN_PORT, rest)
    api_v1 = OFFENSE_BASE + "/api/v1"
    if path == api_v1 or path.startswith(api_v1 + "/"):
        rest = path[len(OFFENSE_BASE):] or "/"       # → /api/v1 or /api/v1/...
        return ("127.0.0.1", API_PORT, rest)
    if path == OFFENSE_BASE or path.startswith(OFFENSE_BASE + "/"):
        rest = path[len(OFFENSE_BASE):] or "/"       # → / or /api/status, /api/events, ...
        return ("127.0.0.1", CONSOLE_PORT, rest)
    return None


class _ProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded so SSE long-lived streams and normal requests can run concurrently."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, serve_dir: Path):
        self.serve_dir = serve_dir
        family = socket.AF_INET
        try:
            if ipaddress.ip_address(addr[0]).version == 6:
                family = socket.AF_INET6
        except ValueError:
            pass
        self.address_family = family
        super().__init__(addr, handler)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "vigil-up/1.0"

    # -- logging: never leak the ?token= that rides SSE URLs ----------------------------------------
    def log_message(self, fmt, *args):  # noqa: A002 (stdlib signature)
        try:
            msg = fmt % args
        except Exception:
            msg = fmt
        msg = _TOKEN_RE.sub("token=REDACTED", str(msg))
        sys.stderr.write(f"[vigil up] {self.address_string()} {msg}\n")

    # -- every method routes through one handler ----------------------------------------------------
    def do_GET(self):     # noqa: N802
        self._handle()

    def do_POST(self):    # noqa: N802
        self._handle()

    def do_PUT(self):     # noqa: N802
        self._handle()

    def do_PATCH(self):   # noqa: N802
        self._handle()

    def do_DELETE(self):  # noqa: N802
        self._handle()

    def do_HEAD(self):    # noqa: N802
        self._handle()

    def do_OPTIONS(self):  # noqa: N802
        self._handle()

    def _handle(self):
        try:
            split = urlsplit(self.path)
            target = route(split.path)
            if target is None:
                self._serve_static(split.path)
                return
            host, port, upstream_path = target
            if split.query:
                upstream_path = f"{upstream_path}?{split.query}"
            self._proxy(host, port, upstream_path)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001 — never 500 the whole proxy on one bad request
            self._fail(502, f"proxy error: {type(exc).__name__}: {exc}")

    # -- static bundle from the runtime serve dir ---------------------------------------------------
    def _serve_static(self, path: str):
        name = "index.html" if path in ("/", "") else path.lstrip("/")
        # never traverse out of the serve dir — resolve and confirm containment.
        serve_dir: Path = self.server.serve_dir  # type: ignore[attr-defined]
        candidate = (serve_dir / name).resolve()
        try:
            candidate.relative_to(serve_dir.resolve())
        except ValueError:
            self._fail(404, "not found")
            return
        if not candidate.is_file():
            self._fail(404, "not found")
            return
        data = candidate.read_bytes()
        ctype = _STATIC_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        # Drain any request body and CLOSE the connection after a static response (mirrors the proxied
        # path). Without this, a body left un-consumed on a kept-alive connection would be re-parsed as a
        # pipelined request → request smuggling. Closing per static response is the definitive fix.
        self._read_request_body()
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.send_header("Content-Security-Policy", _BUNDLE_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- faithful forward to a loopback backend, STREAMING the response ------------------------------
    def _proxy(self, host: str, port: int, upstream_path: str):
        try:
            clen = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            clen = 0
        if clen > _MAX_BODY:  # bound memory: UI actions are tiny; refuse an oversized upload
            self.close_connection = True
            self._fail(413, "request body too large")
            return
        body = self._read_request_body()
        req_headers = self._forward_request_headers()
        conn = http.client.HTTPConnection(host, port, timeout=None)  # no read timeout → SSE stays open
        try:
            conn.request(self.command, upstream_path, body=body or None, headers=req_headers)
            resp = conn.getresponse()
            self._relay_response(resp)
        except (ConnectionRefusedError, OSError) as exc:
            self._fail(502, f"backend {host}:{port} unreachable: {exc}")
        finally:
            conn.close()

    def _read_request_body(self) -> bytes:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            n = 0
        n = min(n, _MAX_BODY)  # bounded read (the connection is closed after, so any excess is dropped)
        return self.rfile.read(n) if n > 0 else b""

    def _forward_request_headers(self) -> dict:
        # forward the client's headers verbatim (incl. Host + Origin — the upstreams' anti-rebind
        # allowlist is configured with the proxy authority), minus hop-by-hop + Content-Length
        # (http.client recomputes the latter from the body we pass).
        out: dict[str, str] = {}
        for key in self.headers.keys():
            lk = key.lower()
            if lk in _HOP_BY_HOP or lk == "content-length":
                continue
            out[key] = self.headers[key]
        return out

    def _relay_response(self, resp: http.client.HTTPResponse):
        ctype = resp.getheader("Content-Type", "") or ""
        is_sse = ctype.split(";", 1)[0].strip().lower() == "text/event-stream"
        self.send_response_only(resp.status, resp.reason or "")
        for key, value in resp.getheaders():
            lk = key.lower()
            if lk in _HOP_BY_HOP:
                continue
            self.send_header(key, value)
        # frame the response by closing the connection: this streams SSE and length-less/chunked
        # bodies without buffering, and sidesteps every keep-alive framing edge case on proxied bytes.
        self.send_header("Connection", "close")
        if is_sse:
            self.send_header("X-Accel-Buffering", "no")  # tell any nginx in front not to buffer either
        self.close_connection = True
        self.end_headers()
        if self.command == "HEAD":
            return
        while True:
            chunk = resp.read1(65536)   # ONE underlying read → forwards each SSE event as it arrives
            if not chunk:
                break
            self.wfile.write(chunk)
            self.wfile.flush()          # push it to the browser live (do NOT buffer the stream)

    def _fail(self, status: int, message: str):
        try:
            body = message.encode("utf-8", "replace")
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True


def make_proxy_server(host: str, port: int, serve_dir: Path) -> _ProxyServer:
    """Build (do not run) the reverse proxy bound to ``host:port``. Refuses a public/unspecified bind
    (``bind_ok``) — the proxy is the only listener a human points a browser at, so it must never be
    reachable from the open internet."""
    if not bind_ok(host):
        raise ValueError(
            f"refusing to bind {host!r}: the vigil up proxy binds loopback or a PRIVATE "
            f"(WireGuard/Tailscale) address only — never 0.0.0.0 / an unspecified / a public address. "
            f"Front a real domain with a TLS reverse proxy (--domain; see deploy/reverse-proxy/).")
    return _ProxyServer((host, port), ProxyHandler, serve_dir=serve_dir)


# ==================================================================================================
# `vigil up` / `vigil down` orchestration (subprocess-only; imports no framework/strix/sigil)
# ==================================================================================================
_LIVE_UI_SUBDIR = ("ui",)
_PIDS_NAME = "pids"


def _child_env() -> dict:
    """A clean env for cross-venv children — strip PYTHONPATH/PYTHONHOME so the parent's offense-side
    path can never inject a module into a child (mirrors dispatch's discipline)."""
    return {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}


def _secure_log(log_path: Path):
    """Open a backend log 0600 under a 0700 dir — child stdout may include the cockpit's token line."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(log_path.parent, 0o700)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return fd


def _spawn(argv: list[str], log_path: Path) -> subprocess.Popen:
    log = open(_secure_log(log_path), "ab", buffering=0)  # noqa: SIM115 — closed when the child is reaped
    return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=_child_env())


def _spawn_capture(argv: list[str], log_path: Path) -> tuple[subprocess.Popen, "Queue[str]"]:
    """Spawn a child whose stdout we both TEE to a log file and scan (for the cockpit token). Returns
    the process and a queue of its stdout lines."""
    _fd = _secure_log(log_path)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            env=_child_env(), text=True, bufsize=1)
    q: "Queue[str]" = Queue()

    def _pump():
        log = os.fdopen(_fd, "a", encoding="utf-8")
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                log.write(line)
                log.flush()
                q.put(line)
        finally:
            log.close()
            q.put("")  # sentinel — the stream ended

    threading.Thread(target=_pump, daemon=True).start()
    return proc, q


def _await_token(q: "Queue[str]", proc: subprocess.Popen, timeout: float = 20.0) -> Optional[str]:
    """Read the cockpit's stdout lines until its ``?token=`` appears (or it exits / times out)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            line = q.get(timeout=0.25)
        except Empty:
            if proc.poll() is not None:
                return None
            continue
        if line == "":            # stream ended without a token
            return None
        tok = parse_cockpit_token(line)
        if tok:
            return tok
    return None


def _pids_path(base_dir: Path) -> Path:
    return base_dir.joinpath(*_LIVE_UI_SUBDIR, _PIDS_NAME)


def _write_pids(base_dir: Path, entries: list[dict]) -> None:
    p = _pids_path(base_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def _terminate(pid: int, *, grace: float = 5.0) -> bool:
    """SIGTERM a pid, then SIGKILL after a grace period. Returns True if a live process was signalled."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    except PermissionError:
        return False
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def run_up(*, host: str, port: int, domain: str, base_dir: str, no_browser: bool,
           insecure_no_api_key: bool = False, src_dir: Optional[Path] = None) -> int:
    """Bring the whole unified UI up: refuse a public bind, spawn the three backends in their own
    venvs, capture the cockpit token, assemble the runtime serve dir, and serve the single origin
    behind the reverse proxy. Blocks until SIGINT/SIGTERM, then tears the children + proxy down."""
    if not bind_ok(host):
        print(f"vigil up: refusing to bind {host!r} — loopback or a PRIVATE (WireGuard/Tailscale) "
              f"address only, never 0.0.0.0 / a public address. A real domain goes behind a TLS "
              f"reverse proxy via --domain (see deploy/reverse-proxy/).", file=sys.stderr)
        return 2

    authority, scheme, want_browser = compute_authority(host, port, domain)
    origin = f"{scheme}://{authority}"

    # FAIL-CLOSED: a --domain deployment is internet-fronted; the gated offense api must not be exposed
    # without its shared-secret. Refuse unless CRUCIBLE_API_KEY is set (or the operator explicitly
    # overrides with --insecure-no-api-key, e.g. when their edge proxy adds auth).
    if domain and not os.environ.get("CRUCIBLE_API_KEY") and not insecure_no_api_key:
        print("vigil up: REFUSED — --domain is internet-fronted but CRUCIBLE_API_KEY is unset, which "
              "would expose the gated offense api unauthenticated. Set CRUCIBLE_API_KEY (see "
              "deploy/REMOTE-HOSTING.md), or pass --insecure-no-api-key if your edge proxy adds auth.",
              file=sys.stderr)
        return 2

    root = dispatch._repo_root()
    src = src_dir or (root / "packages" / "vigil-ui")
    base = Path(base_dir)
    ui_dir = base.joinpath(*_LIVE_UI_SUBDIR)
    logs = ui_dir / "logs"

    # resolve the subsystem console-scripts (in their own venvs) — never import the subsystems.
    try:
        sigil_bin = dispatch.resolve("sigil")
        crucible_bin = dispatch.resolve("crucible")
    except dispatch.DispatchError as exc:
        print(f"vigil up: {exc}", file=sys.stderr)
        return 2
    for label, binpath in (("sigil (sovereign cockpit)", sigil_bin), ("crucible (offense)", crucible_bin)):
        if not binpath.exists():
            print(f"vigil up: {label} console-script not found at {binpath} — that environment is not "
                  f"built. Run envs/build_envs.sh (or `make envs`).", file=sys.stderr)
            return 127

    procs: list[tuple[str, subprocess.Popen]] = []

    def _cleanup(*_a):
        for _name, p in procs:
            if p.poll() is None:
                try:
                    p.terminate()
                except ProcessLookupError:
                    pass
        for _name, p in procs:
            try:
                p.wait(timeout=5)
            except (subprocess.TimeoutExpired, Exception):  # noqa: BLE001
                try:
                    p.kill()
                except ProcessLookupError:
                    pass

    # 1) cockpit — capture its printed session token.
    cockpit_argv = [str(sigil_bin), "serve", "--host", "127.0.0.1", "--port", str(SOVEREIGN_PORT),
                    "--allow-host", authority, "--allow-origin", origin]
    cockpit, cockpit_q = _spawn_capture(cockpit_argv, logs / "sovereign-cockpit.log")
    procs.append(("sovereign-cockpit", cockpit))
    token = _await_token(cockpit_q, cockpit)
    if not token:
        print("vigil up: the sovereign cockpit did not start / print a token (see "
              f"{logs / 'sovereign-cockpit.log'}). Aborting.", file=sys.stderr)
        _cleanup()
        return 1

    # 2) offense console (read + SSE plane) and 3) offense gated api.
    console_argv = [str(crucible_bin), "console", "--port", str(CONSOLE_PORT),
                    "--allow-host", authority, "--allow-origin", origin]
    api_argv = [str(crucible_bin), "api", "--port", str(API_PORT),
                "--allow-host", authority, "--allow-origin", origin]
    procs.append(("offense-console", _spawn(console_argv, logs / "offense-console.log")))
    procs.append(("offense-api", _spawn(api_argv, logs / "offense-api.log")))

    # 4) assemble the runtime serve dir with the token + federated mount bases.
    try:
        assemble_serve_dir(src, ui_dir, token=token)
    except OSError as exc:
        print(f"vigil up: could not assemble the UI serve dir from {src}: {exc}", file=sys.stderr)
        _cleanup()
        return 1

    # 5) start the proxy (the only human-facing listener).
    try:
        httpd = make_proxy_server(host, port, ui_dir)
    except ValueError as exc:
        print(f"vigil up: {exc}", file=sys.stderr)
        _cleanup()
        return 2

    _write_pids(base, [{"name": "orchestrator", "pid": os.getpid()},
                       *[{"name": n, "pid": p.pid} for n, p in procs]])

    url = f"{origin}/?token={token}"
    print("\n  ┌──────────────────────────────────────────────────────────────┐")
    print("  │  VIGIL COMMAND is up — open ONE origin in your browser:       │")
    print("  └──────────────────────────────────────────────────────────────┘")
    print(f"      {url}")
    if _is_loopback(host) and not domain:
        print("      (loopback only; the token gates the sovereign plane — keep it to yourself)")
    elif domain:
        print(f"      (bound {host}:{port}; front {authority} with your TLS reverse proxy — "
              f"deploy/reverse-proxy/vigil.Caddyfile)")
    else:
        print(f"      (private bind {host}:{port} — reach it over your tunnel, never a public listener)")
    print(f"      logs: {logs}    stop: vigil down  (or Ctrl-C)\n", flush=True)

    stop = threading.Event()

    def _on_signal(*_a):
        stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    if want_browser and not no_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 — a missing browser must never stop the server
            pass

    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
        _cleanup()
        try:
            _pids_path(base).unlink()
        except FileNotFoundError:
            pass
    print("vigil up: stopped (backends + proxy down).")
    return 0


def run_down(*, base_dir: str) -> int:
    """Stop a running `vigil up`: terminate the backend children + the orchestrator recorded in
    ``.vigil-live/ui/pids``. Idempotent — a missing/empty pids file is a clean no-op."""
    p = _pids_path(Path(base_dir))
    if not p.exists():
        print(f"vigil down: nothing to stop (no {p}).")
        return 0
    try:
        entries = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"vigil down: could not read {p}: {exc}", file=sys.stderr)
        return 1
    stopped = 0
    # children first, orchestrator last (so its own cleanup does not race ours).
    entries = sorted(entries, key=lambda e: e.get("name") == "orchestrator")
    for e in entries:
        pid = int(e.get("pid", 0) or 0)
        name = e.get("name", "?")
        if pid and _terminate(pid):
            stopped += 1
            print(f"  stopped {name} (pid {pid})")
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    print(f"vigil down: stopped {stopped} process(es).")
    return 0
