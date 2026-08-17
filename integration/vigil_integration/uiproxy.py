"""`vigil up` — the one-command unified-UI launcher + a self-contained stdlib reverse proxy.

`vigil up` brings the WHOLE VIGIL COMMAND UI up locally (and, hosted, behind the operator's domain)
at ONE origin, then federates the two isolated trust planes behind it:

    browser ─▶ vigil up proxy (the ONLY listener a human points a browser at)
                 ├─ /sovereign/*        ▶ 127.0.0.1:8733   (sigil serve — the sovereign cockpit)
                 ├─ /offense/api/v1/*   ▶ 127.0.0.1:8799   (crucible api — the gated action plane)
                 ├─ /offense/*          ▶ 127.0.0.1:8787   (crucible console — read + SSE plane)
                 └─ /__vigil/plane/*    ▶ answered BY THE PROXY (plane status + start the offense plane)
    /  and the bundle files (style.css, ui.js, manual.js, app.js, index.html) are served by the
    proxy itself from a runtime serve dir assembled by `vigil up`.

PLANE CONTROL (why it lives here): because the proxy serves the interface itself, the page still loads
when the offense backends are dead — and the proxy is the process that already owns their lifecycle. So
it is the one process that can honestly answer "is each plane up?" and "start the offense plane". The
operator keeps the command (`vigil up` is unchanged, byte-for-byte) AND gets a button. The action is
FIXED and NAMED: the request body is discarded and the argv is rebuilt from the proxy's own boot
configuration (``offense_argv`` — the single definition the boot path itself uses), so no path, port,
argument or command can ever come from a request. It is token-gated and loopback/private-peer-only like
every other route, single-flight + idempotent, and it changes NOTHING about gating, approvals, the
kill-switch, scope, or what counts as a fact — it only restarts the same two backends `vigil up` spawns.

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

import base64
import binascii
import gzip
import hashlib
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
import zlib
from pathlib import Path
from queue import Empty, Queue
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlsplit

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

# ---- proxy-local plane control (answered BY THE PROXY, never forwarded) ---------------------------
# A backend that is DOWN cannot answer a request to start itself. The proxy is the process that already
# OWNS the three backends' lifecycle and serves the interface itself, so it is the one place that can
# honestly offer to start them — which is what turns "go to a terminal and run `vigil up`" into a
# button, WITHOUT changing what `vigil up` does.
#
# The prefix is `/__vigil/` precisely because it cannot collide with a backend mount: `route()` maps
# only `/sovereign*` and `/offense*` to a backend, `_handle` checks the plane prefix BEFORE it tries to
# route, and `route()` ALSO refuses the prefix explicitly (belt-and-braces, so a future mount-prefix
# change can never silently forward a plane-control request to a backend).
PLANE_BASE = "/__vigil/plane"
PLANE_STATUS_PATH = PLANE_BASE + "/status"
PLANE_VERSION_PATH = PLANE_BASE + "/version"
PLANE_START_OFFENSE_PATH = PLANE_BASE + "/offense/start"
PLANE_STOP_OFFENSE_PATH = PLANE_BASE + "/offense/stop"
# The plane-control routes take NO input: the START action is a FIXED, NAMED action whose argv the proxy
# rebuilds from its OWN boot configuration. Any request body is drained and DISCARDED (never parsed as
# configuration) — a caller-named command/path/port would be remote code execution wearing a button — so
# the cap is small: a body this large is a client bug, not a payload.
_PLANE_MAX_BODY = 64 * 1024
# How long after a spawn the proxy will still say "starting". A backend that has not bound by then is
# not starting, it is broken — and saying "starting" forever would hide that behind a spinner.
_PLANE_START_GRACE_S = 45.0

# The credential carriers the whole UI already uses (mirrors console/server.py + the cockpit): the
# `X-SIGIL-Token` header the SPA fetch sets, or `?token=` for carriers that cannot set a header. The
# custom header a cross-site HTML form physically cannot set is the CSRF conjunct on POST.
_TOKEN_HEADER = "X-SIGIL-Token"
_TOKEN_QUERY = "token"
_CSRF_HEADER = "X-Requested-With"

# ==================================================================================================
# PER-USER AUTHENTICATION at the proxy boundary (Claim 6). See docs/CLAIM-6-RBAC.md.
#
# The proxy is the ONE listener a browser points at, so it is where per-user identity must be established.
# It is OFFENSE-side (`vigil_integration`) and MUST NOT import the sovereign accounts registry (FATAL-2 —
# a single interpreter never co-loads the two trust domains). It therefore DELEGATES verification to the
# sovereign plane's token-optional `/api/whoami`: a loopback GET carrying the request's bearer returns the
# resolved Principal (owner token → owner; a per-user bearer → that principal; anything else →
# authenticated:false). The sovereign plane is the AUTHORITY on the owner-signed accounts spine, so trusting
# its resolution is trusting exactly the right root — and the proxy stays PURE STDLIB (http.client, no
# cross-domain import). Fail-closed everywhere: any transport/parse error, a non-200, or authenticated:false
# resolves to None → 401, the request is NEVER forwarded.
# ==================================================================================================
_WHOAMI_PATH = "/api/whoami"
# Bootstrap routes that reach the sovereign plane WITHOUT proxy auth: the login-state probe and the login
# endpoint (verifying the token you present is their whole purpose). Everything else past these is gated.
_UNAUTH_FORWARD = frozenset({SOVEREIGN_BASE + "/api/whoami", SOVEREIGN_BASE + "/api/login"})
# The permission a MUTATING offense request / an offense-plane lifecycle action requires — an operator+
# capability. Offense reads/SSE need only an authenticated principal (viewer+). This is a COARSE proxy-side
# floor (read vs. run) over the offense plane, which does not itself do per-action RBAC; the sovereign plane
# keeps its fine-grained action→permission map, and owner-authority offense actions are sovereign-gated.
_OFFENSE_RUN_PERM = "run_engagement"
_READ_METHODS = frozenset({"GET", "HEAD"})
# Trusted identity headers the proxy STAMPS on an authenticated offense forward (and STRIPS from every
# inbound request, so a client can never spoof them). The offense side uses them for attribution.
_PRINCIPAL_HDR = "X-VIGIL-Principal"
_ROLE_HDR = "X-VIGIL-Role"
# Anti-spoof: strip the WHOLE `X-VIGIL-*` class from inbound requests, normalising case AND hyphen↔
# underscore — so no variant (`X_VIGIL_ROLE`, which some upstreams / WSGI stacks fold to the header the
# offense gate would read) survives to be mistaken for a proxy-set identity header.
_VIGIL_HDR_PREFIX = "x-vigil-"


def _is_vigil_identity_header(name: str) -> bool:
    return name.lower().replace("_", "-").startswith(_VIGIL_HDR_PREFIX)
# Short-TTL cache of sha256(bearer) → resolved principal (or None). Bounds whoami round-trips under SSE /
# polling; a revocation is visible after at most _AUTH_TTL_S (documented residual). A rejected bearer is
# cached briefly too, to blunt a guessing flood without pinning a wrong answer for long.
_AUTH_TTL_S = 30.0
_AUTH_NEG_TTL_S = 5.0
_WHOAMI_MAX = 64 * 1024          # cap the whoami response read (a Principal JSON is tiny)
_MISS = object()                 # cache sentinel: "not present" — distinct from a cached negative (None)
# BLOCK-A defense-in-depth caps: the ONLY time the proxy buffers+decodes a relayed body is the abnormal
# case where a backend returned a compressed NON-SSE body despite the forced `Accept-Encoding: identity`
# hop. Bound both the encoded read and the decoded size so a rogue/compromised backend cannot make the
# proxy a decompression bomb — exceed either → fail closed (never relay an un-scannable body).
_REDACT_MAX_ENCODED = 16 * 1024 * 1024
_REDACT_MAX_DECODED = 64 * 1024 * 1024

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


def _peer_ok(addr: str) -> bool:
    """True iff a CONNECTING peer may use the proxy-local plane-control routes: the same never-public
    predicate the bind itself is held to (``bind_ok``) — loopback, or a private/tunnel address. This is
    the existing check reused, not a second weaker one; the only normalisation is unwrapping an
    IPv4-mapped IPv6 peer (``::ffff:127.0.0.1``, what an AF_INET6 listener reports for a v4 client),
    which can only ever REJECT the same public addresses ``bind_ok`` already rejects."""
    try:
        ip = ipaddress.ip_address((addr or "").strip().strip("[]"))
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return bind_ok(str(mapped) if mapped is not None else str(ip))


def _authority_matches(value: str, scheme_default: int, port: int) -> bool:
    """True iff a ``Host``/``Origin`` authority names the LOOPBACK proxy on its exact bound port —
    the DNS-rebinding defense the console/cockpit apply (``_host_is_console``), reimplemented inline so
    this offense-side path imports nothing. A missing port means the scheme default (a browser omits it
    on 80/443); a malformed authority or port fails CLOSED."""
    try:
        u = urlsplit(value if "//" in value else "//" + value)
        host = u.hostname or ""
        try:
            p = u.port
        except ValueError:
            return False
    except ValueError:
        return False
    return _is_loopback(host) and (p if p is not None else scheme_default) == port


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
# per-user auth: the delegated whoami verifier + its short-TTL cache
# ==================================================================================================
class _PrincipalCache:
    """A tiny thread-safe TTL cache of ``sha256(bearer) → principal|None``. Keyed by the digest so a
    plaintext bearer never lingers in the map; a cached ``None`` is a (short-lived) negative result."""

    def __init__(self, *, max_entries: int = 4096):
        self._d: dict[str, tuple[object, float]] = {}
        self._lock = threading.Lock()
        self._max = max_entries

    def get(self, key: str):
        """The cached value, or the ``_MISS`` sentinel if absent/expired. A cached ``None`` (a negative)
        is returned as ``None``, distinct from ``_MISS``."""
        with self._lock:
            v = self._d.get(key)
            if v is None:
                return _MISS
            value, exp = v
            if time.monotonic() >= exp:
                self._d.pop(key, None)
                return _MISS
            return value

    def put(self, key: str, value, ttl: float) -> None:
        with self._lock:
            if len(self._d) >= self._max:
                now = time.monotonic()
                self._d = {k: v for k, v in self._d.items() if v[1] > now}  # prune expired
                if len(self._d) >= self._max:
                    self._d.clear()                                          # hard cap: never grow unbounded
            self._d[key] = (value, time.monotonic() + ttl)


def _whoami(bearer: str, *, host: str = "127.0.0.1", port: Optional[int] = None,
            timeout: float = 4.0) -> Optional[dict]:
    """DELEGATE bearer verification to the sovereign plane's token-optional ``/api/whoami`` (loopback GET,
    the bearer in ``X-SIGIL-Token``). Returns the resolved principal dict ``{username, role, permissions}``
    on ``authenticated:true``, else ``None``. PURE STDLIB (imports no sigil). Fail-closed: a blank bearer,
    any transport/parse error, a non-200, or ``authenticated:false`` all yield ``None``."""
    if not bearer:
        return None
    p = SOVEREIGN_PORT if port is None else port
    try:
        conn = http.client.HTTPConnection(host, p, timeout=timeout)
        try:
            conn.request("GET", _WHOAMI_PATH,
                         headers={_TOKEN_HEADER: bearer, "Host": f"{host}:{p}",
                                  "Accept": "application/json"})
            resp = conn.getresponse()
            raw = resp.read(_WHOAMI_MAX)
            if resp.status != 200:
                return None
            data = json.loads(raw.decode("utf-8", "replace"))
        finally:
            conn.close()
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if not isinstance(data, dict) or not data.get("authenticated"):
        return None
    perms = data.get("permissions")
    return {"username": str(data.get("username") or ""),
            "role": str(data.get("role") or ""),
            "permissions": [str(x) for x in perms] if isinstance(perms, list) else []}


# ==================================================================================================
# runtime serve dir — assembled by `vigil up` under .vigil-live/ui/ (gitignored)
# ==================================================================================================
def assemble_serve_dir(src_dir: Path, serve_dir: Path, *, token: str,
                       sovereign_base: str = SOVEREIGN_BASE, offense_base: str = OFFENSE_BASE) -> Path:
    """Build the runtime serve dir from the ``packages/vigil-ui`` bundle:

    * ``style.css`` = ``tokens.css`` + ``components.css`` concatenated,
    * ``ui.js`` / ``manual.js`` / ``app.js`` copied verbatim (+ ``manifest.json`` if present),
    * ``index.html`` written with the mount-base + build placeholders substituted — and the
      ``__VIGIL_TOKEN__`` placeholder emptied (Claim 6): the served page carries NO credential.

    PER-USER AUTH (Claim 6): the owner shared token is deliberately NOT embedded. If it were, every browser
    that reached the proxy would carry the owner's token and the sovereign plane would resolve everyone to
    ``OWNER_PRINCIPAL`` — the whole multi-user gate would be inert. Instead the SPA's login gate is the entry
    (``app.js renderLoginGate`` → ``POST /sovereign/api/login``) and each user carries THEIR OWN bearer in
    ``sessionStorage``. The ``token`` argument is retained for signature stability (``run_up`` passes the
    offense CONSOLE credential the PROXY presents to the offense backend after per-user auth — see
    ``ProxyHandler._forward_request``); it is never written into any served asset.
    """
    # 0700 dir / 0600 index: the serve dir is runtime state assembled per `vigil up`. It no longer embeds a
    # credential (Claim 6), but keeping it owner-only is defense-in-depth — a build id / mount config is not
    # something to expose to every local user, and the perms cost nothing.
    serve_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(serve_dir, 0o700)
    tokens_css = (src_dir / "tokens.css").read_text(encoding="utf-8")
    components_css = (src_dir / "components.css").read_text(encoding="utf-8")
    style_css = tokens_css.rstrip() + "\n" + components_css
    (serve_dir / "style.css").write_text(style_css, encoding="utf-8")
    js_blobs = {name: (src_dir / name).read_text(encoding="utf-8") for name in BUNDLE_JS}
    for name, text in js_blobs.items():
        (serve_dir / name).write_text(text, encoding="utf-8")
    # A per-deploy BUILD ID = a short content hash of every served asset. It is stamped as `?v=<build>`
    # on the bundle URLs (so a warm browser cache can never serve a stale bundle after a redeploy) and
    # exposed at /__vigil/version so an already-open tab can notice a new build and offer to reload.
    _digest = hashlib.sha256()
    _digest.update(style_css.encode("utf-8"))
    for name in BUNDLE_JS:                       # deterministic order (BUNDLE_JS is a fixed tuple)
        _digest.update(b"\0" + name.encode("utf-8") + b"\0")
        _digest.update(js_blobs[name].encode("utf-8"))
    build_id = _digest.hexdigest()[:12]
    try:
        (serve_dir / ".build-id").write_text(build_id, encoding="utf-8")
    except OSError:
        pass
    manifest = src_dir / "manifest.json"
    if manifest.exists():
        (serve_dir / "manifest.json").write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    # S1: the committed system-map (SIGIL's screen/nav manifest) is served same-origin as /system-map.json
    # so the SPA + SIGIL's voice nav (S2) can fetch it. It is immutable committed DATA (no secret, no token),
    # copied verbatim; the CI drift-check keeps it in lock-step with the UI's NAV/route().
    system_map = src_dir.parents[1] / "knowledge" / "system-map" / "system-map.json"
    if system_map.exists():
        (serve_dir / "system-map.json").write_text(system_map.read_text(encoding="utf-8"), encoding="utf-8")
    html = (src_dir / "index.html").read_text(encoding="utf-8")
    # __VIGIL_TOKEN__ → "" : NO credential in the served page (Claim 6 per-user auth). `ui.js` treats an
    # empty/placeholder data-token as "no owner token", so `token()` returns only the per-user session
    # bearer and the SPA renders its login gate until a user signs in.
    html = (html.replace("__VIGIL_TOKEN__", "")
                .replace("__VIGIL_SOVEREIGN__", sovereign_base)
                .replace("__VIGIL_OFFENSE__", offense_base)
                .replace("__VIGIL_BUILD__", build_id))
    index = serve_dir / "index.html"
    index.write_text(html, encoding="utf-8")
    os.chmod(index, 0o600)   # runtime state → owner-only (defense-in-depth; no secret embedded)
    return serve_dir


# ==================================================================================================
# the reverse proxy
# ==================================================================================================
def is_plane_path(path: str) -> bool:
    """True for a proxy-local plane-control path. Matched as a PREFIX (not just the two exact routes)
    so anything under it — including a traversal-looking or unknown sub-path — is answered by the proxy
    (with a 404) and can never fall through to the static server or to a backend."""
    return path == PLANE_BASE or path.startswith(PLANE_BASE + "/")


def route(path: str) -> Optional[tuple[str, int, str]]:
    """Map a request path to ``(backend_host, backend_port, upstream_path)`` or ``None`` (serve
    static). Strips the mount prefix so the upstream sees its own path; the query is preserved by the
    caller. The offense api is disambiguated by its ``/api/v1`` sub-prefix (see the module docstring)."""
    # PROXY-LOCAL, never forwarded: a backend that is DOWN cannot answer a request to start itself, so
    # `/__vigil/plane/*` must never resolve to a backend. `_handle` already intercepts it BEFORE routing;
    # this is the belt-and-braces half — if a mount prefix ever changed such that it could match, the
    # request would still be refused here rather than proxied to (or smuggled through) a backend.
    if is_plane_path(path):
        return None
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


class PlaneControl:
    """The offense plane's lifecycle, as the proxy is allowed to touch it: probe it, and start it.

    THE CALLER NAMES NOTHING. This object is constructed by ``run_up`` from the argv IT already built to
    spawn the backends at boot — the same list, captured, not rebuilt from a request. The HTTP surface
    passes no arguments at all: ``start_offense()`` takes none, so no path, port, flag or command can
    travel in a request. That is the whole security design of the feature; a button that accepted an
    argv would be remote code execution wearing a button.

    SINGLE-FLIGHT + IDEMPOTENT. ``_LOCK`` serialises the decision, so two clicks (or two browser tabs)
    cannot race into two copies of a backend. A backend already LISTENING is left alone and reported as
    such, and a child this object already started and that is still alive is never started again — so
    the operator cannot orphan a process by clicking twice.

    NOT A NEW AUTHORITY. Starting the console and the api is exactly what `vigil up` does; it changes
    nothing about scope, the charter, WARDEN's approve-then-run gate, the kill-switch, signing, or what
    counts as a fact. It is process lifecycle, and nothing else."""

    def __init__(self, specs, *, on_started=None, on_stopped=None):
        # specs: [(name, argv, log_path, extra_env, host, port), ...] — captured from the boot path.
        self._specs = list(specs)
        self._on_started = on_started      # run_up hands us a callback so `vigil down` learns the pids
        self._on_stopped = on_stopped      # …and one so a STOP terminates + un-tracks the boot children
        self._lock = threading.Lock()
        self._children: dict = {}          # name -> Popen, for the ones WE started
        self._started_at = 0.0             # when we last spawned — the basis for the "starting" signal

    # ---- reporting ------------------------------------------------------------------------------
    def ports(self) -> "list[tuple[str, str, int]]":
        return [(name, host, port) for name, _argv, _log, _env, host, port in self._specs]

    def is_starting(self) -> bool:
        """True only while a child we just spawned is alive and its port has NOT come up yet.

        Deliberately MEASURED, not a flag held over the spawn: the spawn itself takes milliseconds, so a
        boolean set-and-cleared around it would never be observed and the interface would flip straight
        from "down" to "down" while the backend was in fact booting. This says the honest thing —
        something is coming up — and stops saying it the moment the port answers, the child dies, or the
        grace window expires (a backend that never binds must NOT read as forever-starting)."""
        with self._lock:
            if not self._started_at or (time.monotonic() - self._started_at) > _PLANE_START_GRACE_S:
                return False
            for name, host, port in self.ports():
                if self._alive(name) and not _listening(host, port):
                    return True
            return False

    def _alive(self, name: str) -> bool:
        """True if a child WE started under this name is still running. A child that exited is reaped
        and forgotten, so a failed start never blocks a retry."""
        p = self._children.get(name)
        if p is None:
            return False
        if p.poll() is None:
            return True
        self._children.pop(name, None)
        return False

    # ---- the one named action -------------------------------------------------------------------
    def start_offense(self) -> dict:
        """Start whichever offense backends are not answering. Returns
        ``{"ok", "action": "start-offense", "result": "already_running"|"started"|"starting", ...}``.

        Never raises: a spawn failure is reported as a failure, with the reason, because the operator's
        alternative is a terminal and they need to know which."""
        with self._lock:
            # A plane is "down" only if nothing is LISTENING on its port and no child we started is
            # still alive on it. Both halves matter: the port check catches a backend someone else
            # started, and the liveness check covers the window between our spawn and its bind — which
            # is exactly the window a second click lands in.
            down = [(name, argv, log, env, host, port)
                    for name, argv, log, env, host, port in self._specs
                    if not (_listening(host, port) or self._alive(name))]
            if not down:
                return {"ok": True, "action": "start-offense", "result": "already_running",
                        "detail": "the offense console and API are already answering (or are coming up "
                                  "from a start already in flight).",
                        "status": self._status_locked()}
            started, failed = [], []
            for name, argv, log, env, _host, _port in down:
                try:
                    self._children[name] = _spawn(list(argv), Path(log), extra_env=dict(env or {}))
                    started.append(name)
                except (OSError, ValueError) as exc:
                    failed.append(f"{name} ({type(exc).__name__}: {exc})")
            if started:
                self._started_at = time.monotonic()
            if self._on_started and started:
                try:
                    self._on_started([(n, self._children[n]) for n in started if n in self._children])
                except Exception:  # noqa: BLE001 — bookkeeping must never fail the start
                    pass
            if failed and not started:
                return {"ok": False, "action": "start-offense", "result": "failed",
                        "error": "the offense plane could not be started: " + "; ".join(failed)
                                 + ". Start it in a terminal with `vigil up`.",
                        "status": self._status_locked()}
            detail = "starting the offense console and API — this takes a few seconds."
            if failed:
                detail += " (" + "; ".join(failed) + " did not start)"
            return {"ok": True, "action": "start-offense", "result": "started", "started": started,
                    "detail": detail, "status": self._status_locked()}

    def stop_offense(self) -> dict:
        """Stop the offense backends this proxy manages — the offense console and the gated api, and
        NOTHING else. The exact inverse of ``start_offense``: never the sovereign cockpit, never the
        proxy/orchestrator that serves this page, never the optional sidecars (feed / telemetry /
        learn) — only the two backends whose ports the offense indicator reflects. The set of names it
        may touch is fixed by ``self._specs`` (captured at boot), so a request can no more name what to
        stop than it can name what to start. Returns
        ``{"ok", "action": "stop-offense", "result": "already_stopped"|"stopped"|"failed", ...}``.

        SINGLE-FLIGHT under ``_lock`` — a second click cannot race a half-finished stop — and it never
        raises: a signal that cannot be delivered is reported, not thrown, because the operator's
        alternative is a terminal and they need to know which."""
        with self._lock:
            # "up" = a backend is LISTENING, or a child we started is still alive on its port. Both halves
            # matter for the same reason they do in start_offense: the port check catches a backend the
            # boot path (or a hand-run) started, the liveness check covers the spawn→bind window.
            up = [name for name, _argv, _log, _env, host, port in self._specs
                  if _listening(host, port) or self._alive(name)]
            if not up:
                self._started_at = 0.0
                return {"ok": True, "action": "stop-offense", "result": "already_stopped",
                        "detail": "the offense console and API are already stopped.",
                        "status": self._status_locked()}
            # 1) Terminate any child WE started (we hold its Popen): SIGTERM, then SIGKILL after a grace.
            failed = []
            for name in up:
                p = self._children.get(name)
                if p is None:
                    continue
                if p.poll() is not None:
                    # Already dead — reap the handle and move on. NEVER signal its pid: it may have been
                    # recycled, and looping _terminate over a zombie would just spin the full grace under
                    # the lock (a stall, not a wrong-kill). This mirrors _unadopt's poll() guard.
                    self._children.pop(name, None)
                    continue
                try:
                    _terminate(p.pid)
                except OSError as exc:
                    failed.append(f"{name} ({type(exc).__name__})")
                # Drop the handle ONLY if the child actually died; KEEP a survivor (a kill that did not
                # take — a D-state child) so a retry can still re-target it, symmetric with _unadopt.
                if p.poll() is not None:
                    self._children.pop(name, None)
            # 2) Ask the boot path to terminate + UN-TRACK any backend IT started under these names — a
            #    console spawned at `vigil up` time (not through this object) is stopped too, its port
            #    freed, and Ctrl-C / `vigil down` never chase a dead pid. Restricted to the offense names
            #    in `up`, so the cockpit and the orchestrator can never be reached through this path.
            if self._on_stopped:
                try:
                    self._on_stopped(list(up))
                except Exception:  # noqa: BLE001 — bookkeeping must never fail the stop
                    pass
            self._started_at = 0.0
            # 3) Report what is DOWN now, MEASURED (a live re-probe), not asserted. `_terminate` already
            #    waited for each process to exit, so the kernel closes its listener on the way out; a short
            #    settle covers the rare lag before the port reads free, so a clean stop never mis-reports.
            still_up: list[str] = []
            for _ in range(6):
                still_up = [name for name, _a, _l, _e, host, port in self._specs if _listening(host, port)]
                if not still_up:
                    break
                time.sleep(0.2)
            if still_up:
                return {"ok": False, "action": "stop-offense", "result": "failed",
                        "error": "the offense plane did not fully stop (" + ", ".join(still_up)
                                 + " still listening). Stop it in a terminal with `vigil down`.",
                        "status": self._status_locked()}
            detail = ("the offense console and API were stopped. Start them again here, or with "
                      "`vigil up` in a terminal.")
            if failed:
                detail += " (" + "; ".join(failed) + ")"
            return {"ok": True, "action": "stop-offense", "result": "stopped", "stopped": up,
                    "detail": detail, "status": self._status_locked()}

    def _status_locked(self) -> dict:
        # Called with ``_lock`` held, so it must not re-derive `starting` through `is_starting()`
        # (a plain Lock is NOT reentrant — that would deadlock the very request it is answering).
        return _plane_ports_status(self.ports(), starting=bool(
            self._started_at and (time.monotonic() - self._started_at) <= _PLANE_START_GRACE_S))


def _listening(host: str, port: int) -> bool:
    """True if something is LISTENING on (host, port) right now. A short-timeout connect, nothing sent:
    this REPORTS, it never probes a backend's behaviour."""
    try:
        with socket.create_connection((host, int(port)), timeout=0.35):
            return True
    except (OSError, ValueError, OverflowError):
        return False


def _plane_ports_status(ports, *, starting: bool = False) -> dict:
    out = {name: _listening(host, port) for name, host, port in ports}
    return {"ok": True, "planes": out, "running": bool(out) and all(out.values()), "starting": starting}


def plane_status(pc: "Optional[PlaneControl]") -> dict:
    """What each plane is doing right now, measured — never remembered.

    A LIVE port probe, so the answer is true even when the backend was started by a different `vigil up`,
    by hand, or died a second ago. ``can_start`` says whether THIS proxy can do anything about it: a
    proxy built without plane control (a test harness, an older boot path) reports the truth and offers
    no button, rather than showing one that cannot work.

    Works with ``pc is None``: probing needs no configuration, and a status route that fails closed
    would leave the interface unable to say why the offense side is dark."""
    ports = pc.ports() if pc is not None else [("offense-console", "127.0.0.1", CONSOLE_PORT),
                                               ("offense-api", "127.0.0.1", API_PORT)]
    st = _plane_ports_status(ports, starting=bool(pc is not None and pc.is_starting()))
    st["can_start"] = pc is not None
    st["sovereign"] = _listening("127.0.0.1", SOVEREIGN_PORT)
    return st


class _ProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded so SSE long-lived streams and normal requests can run concurrently."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, serve_dir: Path, token: str = "",
                 allowed_hosts: "tuple[str, ...]" = (), allowed_origins: "tuple[str, ...]" = (),
                 plane_control: "Optional[PlaneControl]" = None):
        self.serve_dir = serve_dir
        # The offense CONSOLE credential (= the owner boot token `vigil up` captured, which it also hands the
        # console as VIGIL_CONSOLE_TOKEN). Claim 6: it is NO LONGER embedded in index.html and NO LONGER the
        # gate every request is checked against — per-user auth is delegated to the sovereign whoami. It is
        # now presented by the proxy on the outbound hop to the offense console AFTER a request has been
        # authenticated per-user (`_forward_request_headers`), so the browser never holds it. Empty (a proxy
        # built without one) ⇒ the offense console receives "" and fails closed (401), never open.
        self.token = token or ""
        # The browser-visible authority/origin of THIS proxy (`--domain`, or a tunnel bind) — the same
        # values handed to the backends as --allow-host/--allow-origin. Loopback with the proxy's own
        # port is always accepted; everything else must be one of these.
        self.allowed_hosts = frozenset(h for h in allowed_hosts if h)
        self.allowed_origins = frozenset(o.rstrip("/") for o in allowed_origins if o)
        # None ⇒ the proxy can still REPORT plane status (a live port probe needs no configuration) but
        # cannot start anything (503). Only `vigil up`'s boot path supplies one.
        self.plane_control = plane_control
        # Claim 6: per-user auth is DELEGATED to the sovereign whoami; this caches the resolution briefly so
        # SSE / polling do not stampede it. Built here so every request handler shares one cache.
        self.auth_cache = _PrincipalCache()
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
            # PROXY-LOCAL FIRST: plane control is answered by this process, BEFORE any attempt to route
            # or to serve a file. That ordering is the whole point — a backend that is down cannot answer
            # a request to start itself, and the interface is still being served here while it is down.
            if is_plane_path(split.path):
                self._plane_control(split.path, split.query)
                return
            target = route(split.path)
            if target is None:
                self._serve_static(split.path)
                return
            self._forward_request(split, target)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as exc:  # noqa: BLE001 — never 500 the whole proxy on one bad request
            self._fail(502, f"proxy error: {type(exc).__name__}: {exc}")

    # -- per-user auth boundary (Claim 6): every forward past the login bootstrap is authenticated ----
    def _request_bearer(self, query: str) -> str:
        """The bearer on THIS request: the ``X-SIGIL-Token`` header, or ``?token=`` (SSE / downloads)."""
        return self.headers.get(_TOKEN_HEADER) or (parse_qs(query).get(_TOKEN_QUERY) or [""])[0]

    def _authenticate(self, bearer: str) -> Optional[dict]:
        """Resolve the request's bearer to a principal dict via the sovereign whoami (cached, short TTL),
        or None (fail-closed). A blank bearer is never resolved."""
        if not bearer:
            return None
        cache = getattr(self.server, "auth_cache", None)
        key = hashlib.sha256(bearer.encode("utf-8")).hexdigest()
        if cache is not None:
            hit = cache.get(key)
            if hit is not _MISS:
                return hit                                    # may be a cached negative (None)
        principal = _whoami(bearer)
        if cache is not None:
            cache.put(key, principal, _AUTH_TTL_S if principal is not None else _AUTH_NEG_TTL_S)
        return principal

    def _auth_fail(self, status: int, msg: str):
        """A fail-closed JSON refusal that DRAINS the request body and closes the connection — so a refused
        POST cannot leave an unread body to be re-parsed as a pipelined (smuggled) request, and nothing is
        forwarded to a backend."""
        self.close_connection = True
        self._plane_json({"ok": False, "error": msg}, status=status)   # not drained → reads+discards body

    def _forward_request(self, split, target):
        """Authenticate (per-user, fail-closed) then forward to a loopback backend.

        * The login BOOTSTRAP (`/sovereign/api/whoami`, `/sovereign/api/login`) is forwarded WITHOUT proxy
          auth — establishing a session is its whole purpose (the sovereign verifies the presented token).
        * Every other route requires a bearer the sovereign whoami resolves → else 401, NEVER forwarded.
        * Sovereign routes forward the user's OWN bearer (native `role_can`).
        * Offense routes enforce a coarse role floor (read vs. `run_engagement`), substitute the offense
          console credential (the browser never holds it), and stamp the resolved identity headers."""
        host, port, upstream_path = target
        path = split.path
        is_sovereign = path == SOVEREIGN_BASE or path.startswith(SOVEREIGN_BASE + "/")
        # 1) login bootstrap — forward verbatim, no proxy auth.
        if path in _UNAUTH_FORWARD:
            self._proxy(host, port, self._with_query(upstream_path, split.query))
            return
        # 2) authenticate, fail-closed.
        principal = self._authenticate(self._request_bearer(split.query))
        if principal is None:
            self._auth_fail(401, "missing/invalid token")
            return
        # 3a) sovereign plane — forward the user's own bearer; the sovereign self-enforces role_can.
        if is_sovereign:
            self._proxy(host, port, self._with_query(upstream_path, split.query))
            return
        # 3b) offense plane — coarse floor: a mutation needs run_engagement (operator+); reads need viewer+.
        if self.command not in _READ_METHODS and _OFFENSE_RUN_PERM not in principal["permissions"]:
            self._auth_fail(403, "offense action requires the run_engagement capability (operator+)")
            return
        # substitute the offense console credential in ?token= (SSE/downloads); the header is substituted in
        # _forward_request_headers. The browser's own bearer never reaches the offense backend.
        upstream = self._with_query(upstream_path, self._sub_token_query(split.query))
        self._proxy(host, port, upstream, offense_principal=principal)

    @staticmethod
    def _with_query(upstream_path: str, query: str) -> str:
        return f"{upstream_path}?{query}" if query else upstream_path

    def _sub_token_query(self, query: str) -> str:
        """Replace ``?token=`` (the SSE / download credential carrier) with the offense console credential,
        preserving every other query parameter. If there is no ``token`` param, the query is returned
        verbatim (nothing to substitute)."""
        if not query:
            return query
        parsed = parse_qs(query, keep_blank_values=True)
        if _TOKEN_QUERY not in parsed:
            return query
        parsed[_TOKEN_QUERY] = [getattr(self.server, "token", "") or ""]
        return urlencode(parsed, doseq=True)

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
        # Cache policy — two cases, both fixing the "I redeployed but still see the old UI" gap:
        #   * index.html embeds the live session TOKEN, so it is `no-store`: never written to any cache,
        #     so a token rotation (every `vigil up`) can never be shadowed by a stale, wrong-token page.
        #     Each load fetches it fresh → its `?v=<build>` refs and `data-build` are always current.
        #   * every other asset (the js/css bundle) is `no-cache` + an ETag over its exact bytes: the
        #     browser MUST revalidate, and a matching `If-None-Match` returns a bodyless 304, so a
        #     redeploy is picked up immediately at negligible cost. The `?v=<build>` on the URL is the
        #     belt-and-braces second layer (a changed build → a new URL a warm cache cannot satisfy).
        is_html = candidate.suffix.lower() == ".html" or candidate.name == "index.html"
        etag = '"' + hashlib.sha256(data).hexdigest()[:32] + '"'
        self._read_request_body()
        self.close_connection = True
        if not is_html:
            inm = self.headers.get("If-None-Match", "")
            if inm and etag in [t.strip() for t in inm.split(",")]:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        if is_html:
            self.send_header("Cache-Control", "no-store")
        else:
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Security-Policy", _BUNDLE_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # -- proxy-local plane control (status + start the offense plane) --------------------------------
    def _plane_control(self, path: str, query: str):
        """Answer a `/__vigil/plane/*` request in THIS process. Never forwarded, never served from the
        serve dir. The guards are the same conjunction every other endpoint is held to — private peer,
        Host/Origin (anti-rebinding), session token, and (POST) the SPA custom header a cross-site form
        cannot set — checked BEFORE anything is inspected or spawned."""
        # 1) Drain the request body EXACTLY ONCE, up front, and DISCARD it. The caller names no command:
        #    neither route takes input, so the body is never parsed. Draining keeps framing honest, and
        #    the connection is closed on every plane response anyway (no smuggling window).
        try:
            clen = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            clen = 0
        self.close_connection = True
        if clen > _PLANE_MAX_BODY:
            self._plane_json({"ok": False, "error": "request body too large"}, status=413, drained=True)
            return
        if clen > 0:
            self.rfile.read(clen)          # read + discard: NOT configuration, not logged

        # 2) never-public: only a loopback / private-tunnel peer may drive the planes.
        if not _peer_ok(self.client_address[0] if self.client_address else ""):
            self._plane_json({"ok": False, "error": "plane control refused (non-private peer)"},
                             status=403, drained=True)
            return
        # 3) anti-rebinding: the Host (and Origin, when present) must name THIS proxy.
        ok, why = self._plane_authority_ok()
        if not ok:
            self._plane_json({"ok": False, "error": f"plane control refused ({why})"},
                             status=403, drained=True)
            return
        # 4) per-user authentication (Claim 6) — the SAME sovereign-delegated identity the forwarded routes
        #    use. Fail-closed: an unresolved bearer is 401 before anything is inspected or spawned. Plane
        #    control talks to the SOVEREIGN plane (which is up even when the offense backends are down), so
        #    delegated auth is always available here. Reads (status/version) need viewer+; start/stop below
        #    additionally require run_engagement (operator+).
        principal = self._authenticate(self._request_bearer(query))
        if principal is None:
            self._plane_json({"ok": False, "error": "missing/invalid token"}, status=401, drained=True)
            return
        # 5) a mutating POST additionally needs the SPA's custom header (a cross-site HTML <form>
        #    physically cannot set one, forcing a preflight this proxy never answers) and a
        #    non-cross-site Sec-Fetch-Site — the console's own POST conjunction.
        if self.command == "POST":
            if not self.headers.get(_CSRF_HEADER):
                self._plane_json({"ok": False,
                                  "error": f"cross-site POST refused (missing {_CSRF_HEADER})"},
                                 status=403, drained=True)
                return
            sfs = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sfs and sfs not in ("same-origin", "none"):
                self._plane_json({"ok": False, "error": f"cross-site POST refused (Sec-Fetch-Site={sfs})"},
                                 status=403, drained=True)
                return

        pc: "Optional[PlaneControl]" = getattr(self.server, "plane_control", None)
        if path == PLANE_STATUS_PATH:
            if self.command not in ("GET", "HEAD"):
                self._plane_json({"ok": False, "error": "method not allowed"}, status=405, drained=True)
                return
            self._plane_json(plane_status(pc), drained=True)
            return
        if path == PLANE_VERSION_PATH:
            # The current bundle build id (a content hash), so a long-open tab can notice a redeploy and
            # offer to reload. Read-only, non-secret (just a hash); GET only. Guarded like every plane
            # route (private peer + Host/Origin + token), so it is never a cross-site read.
            if self.command not in ("GET", "HEAD"):
                self._plane_json({"ok": False, "error": "method not allowed"}, status=405, drained=True)
                return
            build = ""
            try:
                build = (self.server.serve_dir / ".build-id").read_text(encoding="utf-8").strip()
            except (OSError, AttributeError):
                build = ""
            self._plane_json({"ok": True, "build": build}, drained=True)
            return
        if path == PLANE_START_OFFENSE_PATH:
            # POST only: a GET/HEAD must never start anything (no side effect on a safe method).
            if self.command != "POST":
                self._plane_json({"ok": False, "error": "method not allowed (POST only)"},
                                 status=405, drained=True)
                return
            if _OFFENSE_RUN_PERM not in principal["permissions"]:   # operator+ lifecycle floor
                self._plane_json({"ok": False, "action": "start-offense",
                                  "error": "starting the offense plane requires the run_engagement "
                                           "capability (operator+)"}, status=403, drained=True)
                return
            if pc is None:
                self._plane_json({"ok": False, "action": "start-offense",
                                  "error": "this proxy has no plane control configured — start the "
                                           "planes with `vigil up`.",
                                  "status": plane_status(None)}, status=503, drained=True)
                return
            self._plane_json(pc.start_offense(), drained=True)
            return
        if path == PLANE_STOP_OFFENSE_PATH:
            # POST only, exactly like start: a GET/HEAD must never stop anything (no side effect on a
            # safe method). Same single-flight, same fixed set of backends — the request names nothing.
            if self.command != "POST":
                self._plane_json({"ok": False, "error": "method not allowed (POST only)"},
                                 status=405, drained=True)
                return
            if _OFFENSE_RUN_PERM not in principal["permissions"]:   # operator+ lifecycle floor
                self._plane_json({"ok": False, "action": "stop-offense",
                                  "error": "stopping the offense plane requires the run_engagement "
                                           "capability (operator+)"}, status=403, drained=True)
                return
            if pc is None:
                self._plane_json({"ok": False, "action": "stop-offense",
                                  "error": "this proxy has no plane control configured — stop the "
                                           "planes with `vigil down`.",
                                  "status": plane_status(None)}, status=503, drained=True)
                return
            self._plane_json(pc.stop_offense(), drained=True)
            return
        self._plane_json({"ok": False, "error": "not found"}, status=404, drained=True)

    def _plane_authority_ok(self) -> tuple[bool, str]:
        """Host/Origin must name THIS proxy: loopback on its bound port, or the exact authority/origin
        `vigil up` was launched with (the same strings handed to the backends as --allow-host /
        --allow-origin). A missing/rebinding/malformed Host fails closed."""
        port = self.server.server_address[1]
        allow_hosts = getattr(self.server, "allowed_hosts", frozenset())
        allow_origins = getattr(self.server, "allowed_origins", frozenset())
        host_hdr = (self.headers.get("Host") or "").strip()
        if not host_hdr:
            return False, "Host missing"
        if not (_authority_matches(host_hdr, 80, port) or host_hdr in allow_hosts):
            return False, f"Host={host_hdr!r}"
        origin = (self.headers.get("Origin") or "").strip()
        if origin:
            scheme_default = 443 if origin.lower().startswith("https:") else 80
            if not (_authority_matches(origin, scheme_default, port)
                    or origin.rstrip("/") in allow_origins):
                return False, f"Origin={origin!r}"
        return True, ""

    def _plane_json(self, payload: dict, status: int = 200, *, drained: bool = False):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if not drained:
            self._read_request_body()
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", _BUNDLE_CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True

    # -- faithful forward to a loopback backend, STREAMING the response ------------------------------
    def _proxy(self, host: str, port: int, upstream_path: str, *,
               offense_principal: "Optional[dict]" = None):
        try:
            clen = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            clen = 0
        if clen > _MAX_BODY:  # bound memory: UI actions are tiny; refuse an oversized upload
            self.close_connection = True
            self._fail(413, "request body too large")
            return
        body = self._read_request_body()
        req_headers = self._forward_request_headers(offense_principal=offense_principal)
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

    def _forward_request_headers(self, *, offense_principal: "Optional[dict]" = None) -> dict:
        # forward the client's headers verbatim (incl. Host + Origin — the upstreams' anti-rebind
        # allowlist is configured with the proxy authority), minus hop-by-hop + Content-Length
        # (http.client recomputes the latter from the body we pass). ALWAYS strip any client-supplied
        # X-VIGIL-* identity header (anti-spoof): identity is set by the proxy, never accepted from a client.
        # ALSO strip the client's Accept-Encoding (see below).
        out: dict[str, str] = {}
        for key in self.headers.keys():
            lk = key.lower()
            if (lk in _HOP_BY_HOP or lk == "content-length" or lk == "accept-encoding"
                    or _is_vigil_identity_header(key)):
                continue
            out[key] = self.headers[key]
        # BLOCK-A: force IDENTITY encoding on the proxy→backend hop so the response is CLEARTEXT the hop
        # credential redactor can scan. A compressed body has no literal token bytes to find, so a forwarded
        # `Accept-Encoding: gzip` would let a token-embedding backend index slip past redaction and reach the
        # browser, which decompresses and recovers the owner token. The backends we control never compress;
        # an nginx sitting IN FRONT of the proxy that gzips the proxy's ALREADY-redacted output is safe (it
        # compresses redacted bytes). Set for BOTH planes and the login bootstrap alike.
        out["Accept-Encoding"] = "identity"
        if offense_principal is not None:
            # Present the offense CONSOLE's OWN credential (never the user's bearer): the console gates on
            # VIGIL_CONSOLE_TOKEN, the browser must never hold it, and only an already-authenticated request
            # reaches here. Stamp the resolved identity so the offense side can attribute the action (and a
            # future per-action offense gate can read the role). A proxy with no token presents "" → the
            # console fails closed (401), never open.
            out[_TOKEN_HEADER] = getattr(self.server, "token", "") or ""
            out[_PRINCIPAL_HDR] = str(offense_principal.get("username") or "")
            out[_ROLE_HDR] = str(offense_principal.get("role") or "")
        return out

    def _relay_response(self, resp: http.client.HTTPResponse):
        ctype = resp.getheader("Content-Type", "") or ""
        is_sse = ctype.split(";", 1)[0].strip().lower() == "text/event-stream"
        # HOP-ONLY CREDENTIAL — the owner backend credential the proxy presents on the hop
        # (`self.server.token`, = the offense console's VIGIL_CONSOLE_TOKEN AND the cockpit's own token)
        # must NEVER reach the browser. A backend's OWN static index.html embeds it (the console's
        # __CONSOLE_TOKEN__ / the cockpit's __SIGIL_TOKEN__), and static `/` is NOT token-gated on the
        # backend — so a plain relay would stream `data-token="<owner token>"` to a mere VIEWER, who could
        # replay it and be resolved as OWNER. So every relayed NON-SSE body is scanned and any exact
        # occurrence of the credential is blanked with an EQUAL-LENGTH marker (Content-Length stays valid).
        needle = (getattr(self.server, "token", "") or "").encode("utf-8")
        enc = (resp.getheader("Content-Encoding", "") or "").strip().lower()
        # BLOCK-A defense-in-depth: the hop forces `Accept-Encoding: identity`, so a backend we control
        # returns cleartext and `enc` is empty. If a backend/middleware IGNORED that and compressed a NON-SSE
        # body anyway, the literal-byte redactor would scan ciphertext and MISS the token — so we DECODE it
        # here (gzip/deflate) before scanning, or FAIL CLOSED (never relay an un-scannable, possibly
        # token-bearing body). Handled BEFORE headers are sent, so we can drop the stale Content-Encoding /
        # Content-Length and send the correct ones for the decoded, redacted cleartext.
        if (not is_sse) and needle and enc not in ("", "identity"):
            prepared = self._decode_and_redact(resp, enc, needle)
            if prepared is None:
                self._fail(502, f"proxy refused to relay a {enc}-encoded body it could not scan for the "
                                f"hop credential")
                return
            self.send_response_only(resp.status, resp.reason or "")
            for key, value in resp.getheaders():
                lk = key.lower()
                if lk in _HOP_BY_HOP or lk in ("content-encoding", "content-length"):
                    continue            # drop the stale encoding/length — we send decoded cleartext
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(prepared)))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(prepared)
            return
        # normal path — identity (or SSE). Stream (SSE / no-token) or stream-redact (non-SSE cleartext).
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
        # SSE is exempt from redaction: its event data provably never carries the session token (pinned by
        # the SSE negative-control test), and a carry-window would break incremental delivery — the property
        # the SSE relay exists to preserve. A token-free response (no needle) streams straight through.
        if is_sse or not needle:
            while True:
                chunk = resp.read1(65536)   # ONE underlying read → forwards each SSE event as it arrives
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()          # push it to the browser live (do NOT buffer the stream)
            return
        self._relay_redacting(resp, needle)

    def _decode_and_redact(self, resp: http.client.HTTPResponse, enc: str,
                           needle: bytes) -> "Optional[bytes]":
        """Read a compressed NON-SSE body, DECODE it (gzip / deflate) so the hop credential can be scanned
        in cleartext, then redact it (equal-length marker). Returns the redacted CLEARTEXT bytes, or None
        (FAIL CLOSED) if the encoding is one we cannot decode, or the body is malformed / oversized — the
        proxy then refuses to relay it, never forwarding an un-scannable body that might carry the token."""
        raw = b""
        while len(raw) <= _REDACT_MAX_ENCODED:
            chunk = resp.read1(65536)
            if not chunk:
                break
            raw += chunk
        else:
            return None                                   # encoded body exceeded the cap → fail closed
        try:
            if enc == "gzip":
                data = gzip.decompress(raw)
            elif enc == "deflate":
                try:
                    data = zlib.decompress(raw)
                except zlib.error:
                    data = zlib.decompress(raw, -zlib.MAX_WBITS)   # raw DEFLATE (no zlib header)
            else:
                return None                               # br / zstd / unknown → cannot scan → fail closed
        except (OSError, zlib.error, EOFError, ValueError):
            return None                                   # malformed → fail closed
        if len(data) > _REDACT_MAX_DECODED:
            return None                                   # decompression bomb → fail closed
        return data.replace(needle, b"X" * len(needle))

    def _relay_redacting(self, resp: http.client.HTTPResponse, needle: bytes):
        """Stream a NON-SSE body, replacing every exact occurrence of ``needle`` (the hop-only owner
        credential) with an equal-length marker so it can NEVER reach the browser. Bounded memory: only a
        ``len(needle)-1`` carry is held back, so a needle split across two read boundaries is still caught.
        Equal-length replacement keeps the backend's Content-Length valid; only the exact secret is touched,
        so any other byte (HTML, JSON, a download) passes through unchanged."""
        mark = b"X" * len(needle)
        keep = len(needle) - 1
        carry = b""
        while True:
            chunk = resp.read1(65536)
            if not chunk:
                break
            buf = (carry + chunk).replace(needle, mark)
            if keep and len(buf) >= keep:
                emit, carry = buf[:-keep], buf[-keep:]
            elif keep:
                emit, carry = b"", buf          # not enough yet — hold it all as carry
            else:
                emit, carry = buf, b""
            if emit:
                self.wfile.write(emit)
                self.wfile.flush()
        if carry:
            self.wfile.write(carry.replace(needle, mark))   # flush the residual (a full needle cannot fit it)
            self.wfile.flush()

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


def make_proxy_server(host: str, port: int, serve_dir: Path, *, token: str = "",
                      allowed_hosts: "tuple[str, ...]" = (), allowed_origins: "tuple[str, ...]" = (),
                      plane_control: "Optional[PlaneControl]" = None) -> _ProxyServer:
    """Build (do not run) the reverse proxy bound to ``host:port``. Refuses a public/unspecified bind
    (``bind_ok``) — the proxy is the only listener a human points a browser at, so it must never be
    reachable from the open internet.

    The plane-control credentials are OPTIONAL and default to nothing, which fails CLOSED: a proxy
    built without a token (a test harness, an embedding caller) answers 401 on every plane-control
    route, and one built without a ``plane_control`` can report plane status but starts nothing (503).
    Only ``run_up`` — the boot path that owns the backends' lifecycle — supplies either."""
    if not bind_ok(host):
        raise ValueError(
            f"refusing to bind {host!r}: the vigil up proxy binds loopback or a PRIVATE "
            f"(WireGuard/Tailscale) address only — never 0.0.0.0 / an unspecified / a public address. "
            f"Front a real domain with a TLS reverse proxy (--domain; see deploy/reverse-proxy/).")
    return _ProxyServer((host, port), ProxyHandler, serve_dir=serve_dir, token=token,
                        allowed_hosts=tuple(allowed_hosts), allowed_origins=tuple(allowed_origins),
                        plane_control=plane_control)


# ==================================================================================================
# `vigil up` / `vigil down` orchestration (subprocess-only; imports no framework/strix/sigil)
# ==================================================================================================
_LIVE_UI_SUBDIR = ("ui",)
_PIDS_NAME = "pids"


# The auto-patch owner SIGNING key must NEVER be inherited by a spawned child from the ambient parent env
# (A4). The sovereign settings-plane allowlist (`_OFFENSE_ENV_ALLOWLIST`) only governs settings INJECTED
# afterward — it does not govern the ambient env `_child_env` starts from — so a value already exported in the
# parent `vigil up` shell would otherwise reach offense console/API/Strix children and let one self-authorize a
# destructive PR. Strip it here at the source. The owner key is only ever used by the operator's OWN shell
# for `vigil authorize-destruction`, never by a spawned child.
_CHILD_ENV_HARD_EXCLUDE = frozenset({"VIGIL_DESTRUCTION_OWNER_KEY"})


def _child_env() -> dict:
    """A clean env for cross-venv children — strip PYTHONPATH/PYTHONHOME so the parent's offense-side
    path can never inject a module into a child (mirrors dispatch's discipline), strip the BASE64
    file-content credential vars so a value that happens to be in the PARENT `vigil up` env can never leak
    into a child's environment (the child only ever gets the materialised file PATH, never the content), and
    HARD-EXCLUDE the owner signing key (A4) so it can never be inherited from the ambient parent env."""
    _content_vars = {cv for cv, _p, _f in _FILE_SECRET_MATERIALISE}
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONHOME")
           and k not in _content_vars
           and k not in _CHILD_ENV_HARD_EXCLUDE}
    # Unbuffer child stdout (B2): the cockpit prints its ?token= line then immediately blocks in
    # serve_forever; with a PIPE (a fresh box), CPython block-buffers that ~200-byte line and _await_token
    # would hang the full cockpit-timeout before aborting. PYTHONUNBUFFERED forces the flush.
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _secure_log(log_path: Path):
    """Open a backend log 0600 under a 0700 dir — child stdout may include the cockpit's token line."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(log_path.parent, 0o700)
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    return fd


def _port_free(host: str, port: int) -> bool:
    """True if (host, port) is bindable right now (no ACTIVE listener). The bring-up preflight uses this so
    a port collision REFUSES before any backend is spawned — never orphaning children (B1). We set
    SO_REUSEADDR to MIRROR the real proxy's ``allow_reuse_address`` (B1-1): otherwise the preflight would be
    stricter than the actual bind and falsely refuse a quick restart whose port still holds TIME_WAIT
    sockets — a bind the proxy itself would accept. (SO_REUSEADDR relaxes TIME_WAIT, NOT an active listener,
    so a genuinely-in-use port is still correctly detected.)"""
    import socket as _socket
    fam = _socket.AF_INET6 if ":" in host else _socket.AF_INET
    s = _socket.socket(fam, _socket.SOCK_STREAM)
    s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _wait_listening(host: str, port: int, deadline: float) -> bool:
    """True once something is LISTENING on (host, port) before the deadline — a lightweight backend
    readiness probe (B4) so a silently-dead offense plane is surfaced, not hidden behind a later 502."""
    import socket as _socket
    while time.monotonic() < deadline:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect((host, port))
                return True
            except OSError:
                time.sleep(0.15)
    return False


def _spawn(argv: list[str], log_path: Path, *, extra_env: Optional[dict] = None) -> subprocess.Popen:
    log = open(_secure_log(log_path), "ab", buffering=0)  # noqa: SIM115 — closed when the child is reaped
    env = _child_env()
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env)


def _spawn_tracked(procs: list, name: str, argv: list[str], log_path: Path, cleanup,
                   *, extra_env: Optional[dict] = None) -> bool:
    """Spawn + append a backend to ``procs``; on a spawn failure (OSError: EMFILE/ENOMEM/fork pressure, a
    full or read-only .vigil-live, a bin TOCTOU) run ``cleanup()`` on everything already started and return
    True (the caller then returns cleanly). A failed spawn must NEVER orphan the running backends (B?-2).
    Module-scoped so this cleanup-on-failure path is unit-testable, not buried in a run_up closure."""
    try:
        procs.append((name, _spawn(argv, log_path, extra_env=extra_env)))
        return False
    except (OSError, ValueError) as exc:   # ValueError too, for uniformity with assemble/proxy guards
        print(f"vigil up: backend {name!r} failed to start ({exc}) — cleaned up, nothing orphaned.",
              file=sys.stderr)
        cleanup()
        return True


# The runtime vars the offense engine may receive from the sovereign settings plane. The ONE hard exclusion
# is VIGIL_DESTRUCTION_OWNER_KEY — a keyless offense process must never receive the auto-patch SIGNING key
# (it must not be able to self-authorize a destructive PR; A2a red-pen). The GitHub token + LLM/cloud/
# integration keys ARE legitimately needed by the offense engine (PR push, model calls, OAST relay, gated API).
_OFFENSE_ENV_ALLOWLIST = frozenset({
    # routing + model/config (bring-your-own-model providers)
    "CRUCIBLE_LLM_BACKEND", "SIGIL_LLM_MODEL", "VIGIL_MODEL_CHOICE",
    "CRUCIBLE_ANTHROPIC_MODEL", "CRUCIBLE_BEDROCK_MODEL", "CRUCIBLE_VERTEX_MODEL",
    "CRUCIBLE_MISTRAL_MODEL", "CRUCIBLE_AZURE_OPENAI_DEPLOYMENT", "CRUCIBLE_SELFHOSTED_MODEL",
    "CRUCIBLE_OLLAMA_MODEL",
    "CRUCIBLE_BEDROCK_REGION", "CRUCIBLE_VERTEX_PROJECT", "CRUCIBLE_VERTEX_REGION",
    "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_OPENAI_ENDPOINT", "CRUCIBLE_AZURE_OPENAI_API_VERSION",
    "CRUCIBLE_SELFHOSTED_ENDPOINT", "CRUCIBLE_OLLAMA_HOST",
    "STRIX_LLM", "LLM_API_BASE",
    "CRUCIBLE_EFFORT",                          # reasoning-effort level (output_config.effort on current models)
    "STRIX_REASONING_EFFORT",                   # the same choice mapped onto the Strix codebase agent
    # general offense-engine tuning knobs the Settings "System configuration" plane exposes — these MUST
    # mirror settings.CONFIG_OFFENSE_VARS (plane=="offense"), or a UI knob becomes a placebo (emitted by the
    # sovereign side then silently dropped here). test_config_plane_allowlists_agree guards the two sets.
    "CRUCIBLE_LLM_MAX_WORKERS", "CRUCIBLE_LLM_MIN_INTERVAL_S", "CRUCIBLE_RECON_MAX_WORKERS",
    "VIGIL_APPROVAL_WAIT_SECONDS",              # how long a queued offense action waits for an owner signature
    # The protected-domain safety-floor toggle (VIGIL_ALLOW_PROTECTED_DOMAINS). Must be mirrored here or the
    # owner's OFF setting is silently dropped and the guard stays ON forever (fails safe, but the operator
    # thinks it is off). Delivered only when set to a truthy "1"; unset ⇒ absent ⇒ guard reads ON (protected).
    "VIGIL_ALLOW_PROTECTED_DOMAINS",
    # The sovereignty ladder itself. Without these on the allowlist an operator's tier choice would be
    # silently DROPPED on the way to the offense children — i.e. an AIR_GAPPED deployment would run
    # PERMISSIVE. Passing them can only ever narrow what the child may call, never widen it.
    "CRUCIBLE_SOVEREIGNTY_TIER", "CRUCIBLE_SOVEREIGN_MODE", "CRUCIBLE_SOVEREIGNTY_SEALED",
    "CRUCIBLE_ANTHROPIC_ZDR", "CRUCIBLE_EMBEDDER", "CRUCIBLE_BURP_URL", "CRUCIBLE_CLOUD_INVENTORY_URL",
    "CRUCIBLE_BEDROCK_REGION_ALLOWLIST", "CRUCIBLE_VERTEX_REGION_ALLOWLIST",
    # cloud-provider CONFIG (non-secret) the Phase-C live collectors read via the SDK ambient chains
    "AWS_REGION", "AWS_ROLE_ARN", "CRUCIBLE_AWS_ENDPOINT_URL",
    "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_SUBSCRIPTION_ID",
    # provider + integration KEYS the offense engine needs — NEVER VIGIL_DESTRUCTION_OWNER_KEY
    "ANTHROPIC_API_KEY", "MISTRAL_API_KEY", "OPENAI_API_KEY", "PERPLEXITY_API_KEY",
    "AZURE_OPENAI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT_SECRET",                      # cloud posture service-principal secret (read-only Azure)
    "GOOGLE_CLOUD_PROJECT", "KUBE_CONTEXT",     # GCP/K8s non-secret config
    # knowledge-graph connection: non-secret URI + username (shown) + the sealed password. The offense
    # engine opens its OWN Neo4j driver (graph_driver) to project the per-session graph; never the owner key.
    "NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD",
    # BASE64 file-content creds — bridged only to be MATERIALISED to a 0600 file here (then dropped from the
    # child env; the child sees only the path via GOOGLE_APPLICATION_CREDENTIALS / KUBECONFIG).
    "GOOGLE_APPLICATION_CREDENTIALS_JSON", "KUBECONFIG_CONTENT",
    "GITHUB_TOKEN", "CRUCIBLE_API_KEY", "CRUCIBLE_OOB_RELAY_SECRET",   # never ELEVENLABS (voice = sovereign)
})

# BASE64 file-content secret → (path env var the SDK reads, FIXED on-disk filename). The bridge decodes the
# content to a 0600 file with this exact name (never an operator-controlled name → no path traversal) and
# hands the child only the PATH, never the raw content.
_FILE_SECRET_MATERIALISE = (
    ("GOOGLE_APPLICATION_CREDENTIALS_JSON", "GOOGLE_APPLICATION_CREDENTIALS", "gcp-sa.json"),
    ("KUBECONFIG_CONTENT", "KUBECONFIG", "kubeconfig"),
)


def _materialise_file_secrets(env: dict, runtime_dir: "Optional[Path]") -> dict:
    """Turn any BASE64 file-content cred in ``env`` into a 0600 file the offense SDKs read by PATH. The raw
    content var is ALWAYS removed from the child env (materialised or not) — an offense child never receives
    the credential body as an env var, only a path. Fixed filenames under ``runtime_dir/creds`` (0700), so a
    crafted value can never traverse. Fail-soft: a bad base64 / no runtime dir simply drops the cred (the
    collector then fails closed with no cloud identity), never a crash, never a raw-content leak."""
    creds_dir = (runtime_dir / "creds") if runtime_dir else None
    for content_var, path_var, filename in _FILE_SECRET_MATERIALISE:
        b64 = env.pop(content_var, None)                 # ALWAYS drop the raw content from the child env
        if not b64 or creds_dir is None:
            continue
        try:
            blob = base64.b64decode(b64, validate=True)
        except (ValueError, binascii.Error):
            continue                                     # not decodable → skip (collector fails closed)
        try:
            # NEVER follow a pre-planted symlink (a plaintext credential must not be written through one to a
            # victim path). Refuse a symlinked creds dir; refuse a symlinked target; and O_NOFOLLOW on the
            # open closes the TOCTOU (open fails rather than following a symlink swapped in at the last moment).
            if creds_dir.is_symlink():
                continue
            creds_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(creds_dir, 0o700)
            path = creds_dir / filename                  # FIXED name; no operator input in the path
            # Remove any pre-existing name (a symlink / hardlink / stale file), then create a FRESH inode with
            # O_EXCL: if anything is (re-)planted at the name in a TOCTOU race, O_EXCL fails rather than writing
            # the plaintext credential THROUGH it. This defeats symlink- AND hardlink-write-through; O_NOFOLLOW
            # is belt-and-braces, and the st_nlink==1 check confirms the created inode has no other hard link.
            try:
                os.unlink(str(path))
            except FileNotFoundError:
                pass
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                if os.fstat(fd).st_nlink != 1:
                    os.close(fd)
                    continue
                with os.fdopen(fd, "wb") as fh:
                    fh.write(blob)
            except OSError:
                try:
                    os.close(fd)
                except OSError:
                    pass
                continue
            os.chmod(str(path), 0o600)
            env[path_var] = str(path)
        except OSError:
            continue                                     # symlink refused / could not write → skip (fail closed)
    return env


def _resolve_offense_llm_env(sigil_bin: Path, runtime_dir: "Optional[Path]" = None) -> dict:
    """Ask the SOVEREIGN venv for the runtime LLM env (model vars + resolved API key) and hand it to the
    keyless offense children, so the key/model set in the UI reaches the offense engine WITHOUT the
    offense plane ever importing sigil. The key may live in a keyring / TPM-sealed store only the sovereign
    side can decrypt — hence the subprocess. Captured on a PRIVATE pipe (never the teed backend logs) and
    never printed/logged here. Fail-soft: any error → {} (the offense engine simply runs keyless)."""
    try:
        proc = subprocess.run(
            [str(sigil_bin), "settings", "export-runtime-env", "--include-secrets"],
            capture_output=True, text=True, env=_child_env(), timeout=20)
    except (OSError, subprocess.SubprocessError):
        return {}
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    try:
        data = json.loads(proc.stdout)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    # Defense-in-depth: even though the sovereign emitter is closed to these keys, the CONSUMER also
    # allowlists them by name (str→str, non-empty) — so this can never become an arbitrary env-injection
    # channel even if the emitter changed.
    env = {k: str(v) for k, v in data.items()
           if k in _OFFENSE_ENV_ALLOWLIST and isinstance(v, str) and v}
    # BASE64 file-content creds (GCP JSON / kubeconfig) are materialised to a 0600 file here and replaced by
    # their PATH env var; the raw content never reaches an offense child as an env var.
    return _materialise_file_secrets(env, runtime_dir)


def _resolve_owner_pubkey(sigil_bin: Path) -> "Optional[str]":
    """Ask the SOVEREIGN venv for the base64 owner PUBLIC key (the pin the offense ``learn-drain`` verifies
    each learn-grant against). Read-only, subprocess, never logged; the private key never leaves the
    sovereign store. Returns None if no owner identity exists / any error (the offense drain sidecar is then
    skipped — fail-safe, never started with a missing pin)."""
    try:
        proc = subprocess.run([str(sigil_bin), "owner-pubkey"], capture_output=True, text=True,
                              env=_child_env(), timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    pk = (proc.stdout or "").strip()
    return pk or None


def _console_vigil_bin(crucible_bin: Path) -> "Optional[str]":
    """The `vigil` entrypoint to hand the offense console child as ``VIGIL_BIN``. The console launcher's
    graph-backed engage (``console/actions.py _vigil_bin``) resolves ``VIGIL_BIN`` else ``shutil.which(
    "vigil")`` — so if the operator started ``vigil up`` by an absolute path (venv not activated), the child
    can't find ``vigil`` on PATH and a graph-backed run SILENTLY falls back to the non-graph engine. ``vigil``
    is the sibling of the already-resolved offense ``crucible`` console-script (both live in
    ``.venv-offense/bin/``), so hand the child that exact absolute path. Returns None if it does not exist
    (then the child keeps its PATH fallback — never point it at a bad path)."""
    cand = crucible_bin.parent / "vigil"
    return str(cand) if cand.exists() else None


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

    # If the pump thread can't start (thread/RLIMIT_NPROC exhaustion) AFTER the child already forked, the
    # child would be left running but never returned — an orphan. Tear it down + close the log fd and
    # re-raise, so the caller's spawn-failure path applies (nothing is left running).
    try:
        threading.Thread(target=_pump, daemon=True).start()
    except (RuntimeError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        try:
            os.close(_fd)
        except OSError:
            pass
        raise
    return proc, q


def _cockpit_timeout() -> float:
    """The cockpit cold-start budget in seconds (embedding model + spine/graph rebuild can exceed 20s).
    Parsed HERE, not as a default arg (B6): a bad VIGIL_UP_COCKPIT_TIMEOUT must not raise at import. And
    clamp degenerate-but-float-valid values (B6-4): inf/1e999 would make _await_token hang FOREVER (worse
    than the bug this fixed), nan aborts instantly, ≤0 aborts instantly — all fall back to 120."""
    try:
        t = float(os.environ.get("VIGIL_UP_COCKPIT_TIMEOUT", "120"))
    except (TypeError, ValueError):
        return 120.0
    # Reject the whole degenerate class → 120: nan, +inf/1e300 (~forever hang, worse than the bug this
    # fixed), and <=1s / non-positive (instant spurious abort of a healthy cockpit). A real cold-start
    # budget lives in [1s, 3600s]; anything outside is a misconfiguration, not an intent.
    if t != t or t <= 1 or t > 3600:
        return 120.0
    return t


def _await_token(q: "Queue[str]", proc: subprocess.Popen,
                 timeout: Optional[float] = None) -> Optional[str]:
    """Read the cockpit's stdout lines until its ``?token=`` appears (or it exits / times out).
    Override the budget with ``VIGIL_UP_COCKPIT_TIMEOUT`` (seconds)."""
    if timeout is None:
        timeout = _cockpit_timeout()
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
           insecure_no_api_key: bool = False, src_dir: Optional[Path] = None,
           with_feed: bool = False, feed_slug: str = "", feed_interval: int = 3600,
           with_voice: bool = False, with_gesture: bool = False,
           with_telemetry: bool = False, telemetry_interval: int = 15) -> int:
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

    # Preflight (B1): every listener port must be FREE before we spawn anything, so a collision (a prior
    # `vigil up` still running, or a port otherwise in use) refuses cleanly here instead of aborting
    # mid-spawn and orphaning backends. The proxy binds host:port; the three backends bind loopback.
    _wanted = [(host, port, "the UI proxy"),
               ("127.0.0.1", SOVEREIGN_PORT, "the sovereign cockpit"),
               ("127.0.0.1", CONSOLE_PORT, "the offense console"),
               ("127.0.0.1", API_PORT, "the offense api")]
    _busy = [(h, p, what) for h, p, what in _wanted if not _port_free(h, p)]
    if _busy:
        for h, p, what in _busy:
            print(f"vigil up: {what} port {h}:{p} is already in use — is `vigil up` already running? "
                  "Stop it with `vigil down` (or free the port), then retry.", file=sys.stderr)
        return 2

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

    def _track(name: str, argv: list[str], log_path: Path, *, extra_env: Optional[dict] = None) -> bool:
        return _spawn_tracked(procs, name, argv, log_path, _cleanup, extra_env=extra_env)

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
    # Bridge the LLM key/model the operator set in the UI (sealed on the sovereign side) into the keyless
    # offense children's env — so an engagement actually reasons with the chosen model. Resolved via the
    # sovereign venv (subprocess), never logged. Empty when nothing is set → the offense engine runs keyless.
    offense_llm_env = _resolve_offense_llm_env(sigil_bin, base.resolve())
    console_argv = [str(crucible_bin), "console", "--port", str(CONSOLE_PORT),
                    "--allow-host", authority, "--allow-origin", origin]
    api_argv = [str(crucible_bin), "api", "--port", str(API_PORT),
                "--allow-host", authority, "--allow-origin", origin]
    # point the console's chat transcripts at the SAME .vigil-live base the rest of the live plane uses
    # (the console otherwise defaults to a different root); resolved absolute so cwd can't move it.
    #
    # VIGIL_CONSOLE_TOKEN hands the offense console the SAME session token that is embedded in the
    # unified UI's index.html, so ONE credential covers both federated planes: the browser sends
    # `X-SIGIL-Token` (and `?token=` for SSE / downloads) to /sovereign/* and /offense/* alike. Without
    # it the console would mint its own token and every /offense/* call from the UI would 401. The
    # token rides the child's ENV — never argv (argv is world-readable in /proc) and never a log line.
    console_env = {**offense_llm_env, "VIGIL_LIVE_DIR": str(base.resolve()),
                   "VIGIL_CONSOLE_TOKEN": token}
    # Hand the console child the absolute `vigil` path so its graph-backed engage never SILENTLY falls back
    # to the non-graph engine when `vigil` isn't on the child's inherited PATH (venv not activated).
    vigil_bin = _console_vigil_bin(crucible_bin)
    if vigil_bin:
        console_env["VIGIL_BIN"] = vigil_bin
    if _track("offense-console", console_argv, logs / "offense-console.log", extra_env=console_env):
        return 1
    if _track("offense-api", api_argv, logs / "offense-api.log", extra_env=offense_llm_env):
        return 1

    # PLANE CONTROL captures THESE spawns — the argv, env and log path just used, byte for byte — so the
    # button restarts exactly what the boot path started. It is built from what we already have; nothing
    # about `vigil up` above changed to accommodate it, and no request will ever contribute a value to it.
    def _adopt(started: "list[tuple[str, subprocess.Popen]]") -> None:
        """A backend restarted through the proxy joins the SAME bookkeeping the boot path uses, so
        Ctrl-C still reaps it and `vigil down` still finds it. Without this a restarted console would
        outlive its parent as an orphan holding port 8787 — and the next `vigil up` would refuse to
        start because the port it needs is 'already in use'."""
        for name, proc in started:
            procs[:] = [(n, p) for n, p in procs if n != name] + [(name, proc)]
        try:
            _write_pids(base, [{"name": "orchestrator", "pid": os.getpid()},
                               *[{"name": n, "pid": p.pid} for n, p in procs]])
        except OSError:
            pass                      # the children are still tracked in-process for Ctrl-C

    def _unadopt(names: "list[str]") -> None:
        """A backend STOPPED through the proxy leaves the SAME bookkeeping the boot path uses: terminate
        any child we track under these names (SIGTERM→SIGKILL) and drop the dead ones, so Ctrl-C /
        `vigil down` never chase a dead pid and the next start (or the next `vigil up`) can rebind the
        freed port. Only the NAMED offense backends are touched — the cockpit and this orchestrator are
        never in `names`, and a still-alive child (a kill that did not take) is KEPT so cleanup retries."""
        want = set(names)
        for name, proc in list(procs):
            if name in want and proc.poll() is None:
                _terminate(proc.pid)
        procs[:] = [(n, p) for n, p in procs if not (n in want and p.poll() is not None)]
        try:
            _write_pids(base, [{"name": "orchestrator", "pid": os.getpid()},
                               *[{"name": n, "pid": p.pid} for n, p in procs]])
        except OSError:
            pass

    plane_control = PlaneControl(
        [("offense-console", list(console_argv), logs / "offense-console.log", dict(console_env),
          "127.0.0.1", CONSOLE_PORT),
         ("offense-api", list(api_argv), logs / "offense-api.log", dict(offense_llm_env),
          "127.0.0.1", API_PORT)],
        on_started=_adopt, on_stopped=_unadopt)

    # Readiness (B4): the cockpit's startup is verified via its token, but the offense console/api are
    # spawned fire-and-forget — if one fails to bind (an import error, a port race), the proxy would still
    # come up and /offense/* would 502 with NO signal to the operator. Probe their ports briefly and WARN
    # (never abort) which plane is unhealthy, so a half-up UI is visible instead of silent.
    for _pname, _pport in (("offense console", CONSOLE_PORT), ("offense api", API_PORT)):
        if not _wait_listening("127.0.0.1", _pport, time.monotonic() + 6.0):
            print(f"vigil up: WARNING — {_pname} (127.0.0.1:{_pport}) is not up yet; the offense plane may "
                  f"be starting slowly or failed to bind (see {logs}). The UI will still come up, but "
                  "/offense/* may return 502 until it is ready.", file=sys.stderr)

    # 3b) OPTIONAL recurring vuln-intel feed sidecar. OFF by default — a recurring LIVE egress pull is a
    # conscious act, so it needs --with-feed AND an explicit --feed-slug (the persisted store the Knowledge
    # screen reads). Every tick honours that slug's kill-switch, so STOP halts it. Shares VIGIL_LIVE_DIR with
    # the console so the feed writes where the UI reads. Absent slug → skip with a note (never a silent no-op).
    if with_feed:
        if not feed_slug.strip():
            print("vigil up: --with-feed needs --feed-slug (the engagement store the feed persists into and "
                  "the Knowledge screen reads); skipping the feed.", file=sys.stderr)
        else:
            feed_argv = [str(crucible_bin), "intel", "feed-daemon", "--live",
                         "--slug", feed_slug.strip(), "--interval", str(max(1, feed_interval))]
            if _track("offense-feed", feed_argv, logs / "offense-feed.log",
                      extra_env={"VIGIL_LIVE_DIR": str(base.resolve())}):
                return 1

    # 3b') OPTIONAL live assurance/metrics collector (G2). OFF by default. A READ-ONLY, one-way projection of
    # the signed spine (no egress, mints nothing) — it tails the blackboard and writes a continuous
    # fact/lead/refusal/tool snapshot the console's Assurance view reads. Runs the `vigil telemetry` verb (the
    # blackboard is lazy-imported inside it). Skipped with a note if the `vigil` bin is unresolved.
    if with_telemetry:
        if vigil_bin:
            tel_out = base.resolve() / "live-ui" / "telemetry.json"
            tel_argv = [vigil_bin, "telemetry", "--out", str(tel_out), "--interval", str(max(1, telemetry_interval))]
            if _track("offense-telemetry", tel_argv, logs / "offense-telemetry.log",
                      extra_env={"VIGIL_LIVE_DIR": str(base.resolve())}):
                return 1
        else:
            print("vigil up: --with-telemetry skipped (`vigil` bin unresolved) — the console still computes "
                  "assurance metrics on demand.", file=sys.stderr)

    # 3c) the K2b→K3 learn bridge (A2 keystone): the sovereign producer signs a learn_grant for each
    # owner-approved learn-proposal into a shared spool; the offense consumer verifies it and runs deep-learn.
    # Both are INERT until the owner approves AND autolearn is latched on (defaults disabled), so they are safe
    # to run by default. Fail-safe: the offense drain needs the owner PUBLIC key as a verify pin — if no owner
    # identity exists, the producer still runs but the consumer is skipped (never started without its pin).
    learn_spool = base.resolve() / "learn-spool"
    grant_argv = [str(sigil_bin), "knowledge", "export-learn-grants", "--spool", str(learn_spool), "--watch"]
    if _track("sovereign-learn-grants", grant_argv, logs / "sovereign-learn-grants.log"):
        return 1
    owner_pub = _resolve_owner_pubkey(sigil_bin)
    if owner_pub and vigil_bin:
        drain_argv = [vigil_bin, "learn-drain", "--spool", str(learn_spool),
                      "--owner-pubkey", owner_pub, "--watch"]
        if _track("offense-learn-drain", drain_argv, logs / "offense-learn-drain.log",
                  extra_env={"VIGIL_LIVE_DIR": str(base.resolve())}):
            return 1
    else:
        print("vigil up: learn-drain skipped (no owner pubkey resolvable or `vigil` bin unresolved) — the "
              "sovereign producer runs, but grants won't be consumed until both are available.", file=sys.stderr)

    # 3d) OPTIONAL SIGIL embodiment producers (S2/S3). OFF by default (hardware/phone-dependent). The cockpit
    # already serves /api/sigil/hud and the UI subscribes; these produce the `sigil.nav` the HUD channel
    # carries. Both are A1 SIGNALS that inject NOTHING into the OS — the UI navigates only to a KNOWN in-app
    # screen. `--with-voice` spawns the real long-running voice-nav producer (needs a mic). `--with-gesture`
    # flips the nav-mode latch ON (one-shot) so an owner-armed PHONE gesture session navigates (local camera
    # gesture is not functional — gesture input is the phone companion).
    if with_voice:
        if _track("sovereign-voice", [str(sigil_bin), "voice", "--mic"], logs / "sovereign-voice.log"):
            return 1
    if with_gesture:
        try:
            subprocess.run([str(sigil_bin), "gesture-nav", "on"], env=_child_env(),
                           timeout=20, capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError):
            print("vigil up: could not enable gesture nav-mode (`sigil gesture-nav on` failed) — enable it "
                  "later from the sovereign CLI.", file=sys.stderr)

    # 4) assemble the runtime serve dir with the token + federated mount bases. Catch ValueError too
    # (B?-3): read_text on a non-UTF-8 bundle asset raises UnicodeDecodeError (a ValueError, NOT an
    # OSError), which would otherwise escape past _cleanup() and orphan every backend.
    try:
        assemble_serve_dir(src, ui_dir, token=token)
    except (OSError, ValueError) as exc:
        print(f"vigil up: could not assemble the UI serve dir from {src}: {exc}", file=sys.stderr)
        _cleanup()
        return 1

    # 5) start the proxy (the only human-facing listener). Catch OSError too (B1): allow_reuse_address
    # does NOT prevent an EADDRINUSE collision with an ACTIVE listener, and an uncaught bind error here
    # would escape past _cleanup() and orphan every backend already spawned above.
    try:
        # The plane-control routes take the SAME session token the two federated planes take (the one
        # the cockpit printed and that is embedded in index.html), and the SAME Host/Origin allowlist
        # handed to the backends. One credential, one anti-rebinding rule — not a second, weaker path.
        httpd = make_proxy_server(host, port, ui_dir, token=token,
                                  allowed_hosts=(authority,), allowed_origins=(origin,),
                                  plane_control=plane_control)
    except (ValueError, OSError) as exc:
        print(f"vigil up: could not bind the UI proxy on {host}:{port}: {exc}", file=sys.stderr)
        _cleanup()
        return 2

    # Write the pids file so `vigil down` can find these (B3): guard it — a write failure must clean up
    # and abort, never leave orphaned backends with no pids file. (Ctrl-C still cleans up the foreground
    # process, but `vigil down` relies on this file.)
    try:
        _write_pids(base, [{"name": "orchestrator", "pid": os.getpid()},
                           *[{"name": n, "pid": p.pid} for n, p in procs]])
    except OSError as exc:
        print(f"vigil up: could not write the pids file ({exc}) — aborting so no backends are orphaned. "
              "Check that .vigil-live/ is writable.", file=sys.stderr)
        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass
        _cleanup()
        return 1

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
