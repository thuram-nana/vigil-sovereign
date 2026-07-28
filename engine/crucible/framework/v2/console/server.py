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

import ipaddress
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


# X6 — a custom request header the same-origin SPA fetch sets and a cross-site HTML form cannot.
_CSRF_HEADER = "X-Requested-With"

# Strict Content-Security-Policy (mirrors the sovereign cockpit). Self-contained assets only; no inline
# script/style trust, no external origins, un-framable. Sent on EVERY response (reads + SSE + actions).
_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def _is_loopback_host(host: str) -> bool:
    """True for a genuine loopback host: the name ``localhost`` or ANY loopback IP —
    127.0.0.0/8 (not just 127.0.0.1) and every IPv6 loopback form (``::1``, expanded,
    bracketed). Rejects a routable host / a DNS-rebinding domain."""
    h = (host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False

from . import actions, api, chat, sessions
from .blackboard_sse import BlackboardTailer
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
    "/api/sessions": api.sessions_list,
    "/api/benchmark": api.benchmark_data,
    "/api/memory": api.memory_data,
    "/api/kernel": api.kernel_data,
    "/api/tools": api.tools_data,
    "/api/toolprofiles": api.tool_profiles_data,
    "/api/capabilities": api.capabilities_data,
    "/api/aegis/status": api.aegis_status,
}

# Prefixed GET routes: "/api/<name>/<arg>" -> api provider taking one string arg.
# NB (A6 cleanup): the unified UI calls `/api/engagements` (plural, list) and `/api/report/<run>` (singular),
# never `/api/engagement/` (singular) or `/api/reports/` (plural) — those had zero unified-UI callers (only
# the retired per-plane SPA), so their HTTP surface is dropped (the api.engagement_detail / api.reports_data
# providers REMAIN + keep their unit tests). `/api/authority/` was re-exposed for the Charter & Attestation
# screen.
_PREFIX_ROUTES = {
    "/api/session/": api.session_detail,
    "/api/report/": api.run_report,
    "/api/worldmodel/": api.worldmodel,
    "/api/coverage/": api.coverage_data,
    "/api/authority/": api.authority_full,      # re-exposed for the Charter & Attestation screen
    "/api/charter/": api.charter_status,        # the remote-charter picture (scope, loopback-only?, ceremony)
    "/api/planner/": api.planner_data,
    "/api/intel/": api.intel_data,
    "/api/vulnintel/": api.vulnintel_data,
    "/api/evolve/": api.evolve_data,
    "/api/compliance/": api.compliance_data,
    "/api/drift/": api.drift_data,
    "/api/evidence/": api.evidence,
    "/api/proof/": api.proof_list,
    "/api/remediate/": api.remediate_plan,
    "/api/toolresearch/": api.tool_research_data,
}


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "CrucibleConsole/0.1"

    # keep the console quiet — no request logging noise on the operator's terminal
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # ---- response helpers -------------------------------------------------

    def _sec_headers(self) -> None:
        """Strict security headers on every response (parity with the sovereign cockpit)."""
        self.send_header("Content-Security-Policy", _CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._sec_headers()
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
        # The strict `'self'` CSP is deliberately NOT sent on these STATIC (HTML/SPA) responses: this dir
        # still serves the LEGACY console SPA (inline handlers/styles/data: icons) that strict CSP would
        # break. The strict CSP belongs to the CSP-clean unified bundle (packages/vigil-ui) — served by the
        # `vigil up` reverse proxy (which sets the canonical CSP) or once that bundle retires this SPA. Data
        # responses (_json/_sse) DO carry the CSP as harmless defense-in-depth (JSON/events render nothing).
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, path) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._sec_headers()
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

    def _sse_blackboard(self, slug: str, since: int) -> None:
        """SSE over one engagement's append-only blackboard spine (the Live view's 14-kind
        timeline). Each event is emitted with an ``id:`` line so an EventSource reconnect resumes
        from ``Last-Event-ID`` — a durable cursor. Read-only; the blackboard stays append-only."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._sec_headers()
        self.end_headers()
        tailer = BlackboardTailer(slug, since_id=since)
        last_beat = time.monotonic()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                for event_id, ev in tailer.read_new():
                    payload = json.dumps(ev, ensure_ascii=False, default=str)
                    self.wfile.write(f"id: {event_id}\ndata: {payload}\n\n".encode("utf-8"))
                self.wfile.flush()
                now = time.monotonic()
                if now - last_beat > 15:
                    self.wfile.write(b": ping\n\n")  # heartbeat keeps the socket open
                    self.wfile.flush()
                    last_beat = now
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return
        finally:
            tailer.close()

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
            if path == "/api/blackboard":
                q = parse_qs(parts.query)
                slug = (q.get("slug") or [""])[0]
                # durable cursor: the Last-Event-ID reconnect header wins over the ?since= seed.
                since = 0
                for src in ((q.get("since") or ["0"])[0], self.headers.get("Last-Event-ID")):
                    try:
                        if src is not None:
                            since = int(src)
                    except (TypeError, ValueError):
                        pass
                self._sse_blackboard(slug, since)
                return
            if path == "/api/chat/sessions":
                self._json(chat.list_sessions())
                return
            if path.startswith("/api/chat/session/"):
                self._json(chat.get_session(path[len("/api/chat/session/"):].strip("/")))
                return
            if path == "/api/aegis/verdicts":
                # the live Defense verdict feed — tail the managed gateway's browser-safe verdicts JSONL
                # (oracle-context already stripped at the sink). EventTailer is robust to a missing file.
                vpath = actions.aegis_verdicts_path()
                if not vpath:
                    self._json({"error": "no AEGIS gateway is running"}, status=404)
                    return
                self._sse(vpath)
                return
            if path in _EXACT_ROUTES:
                self._json(_EXACT_ROUTES[path]())
                return
            for prefix, fn in _PREFIX_ROUTES.items():
                if path.startswith(prefix):
                    self._json(fn(path[len(prefix):].strip("/")))
                    return
            if path.startswith("/api/"):
                self._json({"error": "unknown endpoint"}, status=404)
                return
            self._static(path)
        except BrokenPipeError:
            return
        except ValueError as e:  # an unsafe run id (run_dir guard) → honest 404, not a 500 or a traversal
            self._json({"error": str(e)}, status=404)
        except Exception as e:  # never 500 the whole console on one bad read
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)

    def _read_body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    def _same_origin_as_console(self) -> tuple[bool, str]:
        """X6: refuse a cross-site POST. The console binds to loopback, but a malicious web page
        the operator visits (or a DNS-rebinding domain that resolves to 127.0.0.1) could POST to
        127.0.0.1:<port> and drive the console's actions from the operator's browser. Accept a POST
        only when it is same-origin to the loopback console:
          * the Host header MUST be present and name the loopback console with the exact port (an
            HTTP/1.1 request always carries Host; a missing/rebinding/wrong-port Host is refused);
          * an Origin, when present, MUST likewise be the loopback console with the exact port (a
            modern browser sends Origin on EVERY cross-origin POST, so this catches the CSRF page);
          * a cross-site Sec-Fetch-Site is refused.
        Read-only GET/SSE are unaffected. Port comparison is exact — a portless or wrong-port
        loopback Origin (e.g. another local service on :80) is NOT treated as same-origin."""
        port = self.server.server_address[1]
        # POSITIVE proof of same-origin, not merely absence-of-signal: require a CUSTOM header the
        # SPA's fetch sets and a cross-site HTML <form> physically CANNOT (a custom header forces a
        # CORS preflight the console never answers). This is the load-bearing check — it closes the
        # gap where a cross-site form POST omits BOTH Origin and Sec-Fetch-Site (Safari <16.4,
        # in-app WebViews), which a deny-by-signal guard would let through.
        if not self.headers.get(_CSRF_HEADER):
            return False, f"missing {_CSRF_HEADER} (cross-site form / non-SPA client)"
        sfs = self.headers.get("Sec-Fetch-Site", "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):        # cross-site / same-site → refuse
            return False, f"Sec-Fetch-Site={sfs}"

        def _port_ok(parsed, scheme_default: int) -> bool:
            # a missing port means the scheme default (so a legit SPA on a default port — where the
            # browser omits the port in Host/Origin — is accepted); a malformed port fails closed.
            try:
                p = parsed.port
            except ValueError:
                return False
            return (p if p is not None else scheme_default) == port

        def _authority_ok(value: str, scheme_default: int) -> bool:
            # Parse a host[:port] authority and check loopback + matching port. urlsplit itself
            # raises ValueError on a malformed IPv6 authority (e.g. "127.0.0.1]"), so the parse is
            # guarded — a malformed Host/Origin fails CLOSED (a clean 403), never a 500/traceback.
            try:
                u = urlsplit("//" + value if "//" not in value else value)
                return _is_loopback_host(u.hostname or "") and _port_ok(u, scheme_default)
            except ValueError:
                return False

        # Federation allowlist (default EMPTY → loopback-only, byte-identical to before). When VIGIL runs
        # behind the unified reverse proxy, the operator adds the proxy's exact domain Host/Origin here so
        # a same-origin request forwarded by the proxy is accepted; every other Host/Origin is still refused
        # (the custom-header + Sec-Fetch-Site checks above still apply). The console still BINDS loopback —
        # the proxy is the only public listener.
        allow_hosts = getattr(self.server, "allowed_hosts", frozenset())
        allow_origins = getattr(self.server, "allowed_origins", frozenset())

        # Host is mandatory (an HTTP/1.1 request always carries it) + strict (loopback + matching port, OR
        # an exact operator-allowlisted domain) — this refuses a DNS-rebinding domain even if it forged the
        # custom header.
        host_hdr = self.headers.get("Host", "").strip()
        if not host_hdr:
            return False, "Host missing"
        if not (_authority_ok(host_hdr, 80) or host_hdr in allow_hosts):
            return False, f"Host={host_hdr!r}"                # missing / rebinding / wrong-port / malformed
        origin = self.headers.get("Origin", "").strip()
        if origin:
            scheme_default = 443 if origin.lower().startswith("https:") else 80
            if not (_authority_ok(origin, scheme_default) or origin.rstrip("/") in allow_origins):
                return False, f"Origin={origin}"
        return True, ""

    def do_POST(self) -> None:  # noqa: N802
        """The SAFE actions — the only mutations the console makes. Each is non-destructive and
        cannot relax scope or bypass a gate: launch (scan / assessment) spawns only the already-gated
        CLIs, re-verify is a pure re-computation, and kill-switch trip is the emergency stop."""
        ok, why = self._same_origin_as_console()
        if not ok:
            self._json({"error": f"cross-site POST refused ({why})"}, status=403)
            return
        path = urlsplit(self.path).path
        body = self._read_body()
        try:
            if path == "/api/launch/scan":
                self._json(actions.launch_scan(
                    str(body.get("target", "")),
                    max_pages=int(body.get("max_pages", 60)),
                ))
                return
            if path == "/api/launch/assessment":
                # The New-Assessment wizard's one action. It spawns only the SAME gated CLIs; it
                # cannot relax scope (charter-signed, never an arg) or bypass a gate. A clean JSON
                # refusal (no charter / bad target / CIDR scope) is returned as a normal 200 body.
                self._json(actions.launch_assessment(body))
                return
            if path == "/api/launch/cloud":
                # Seedless cloud/Kubernetes/infra posture launch (slice C2b). Spawns the already-gated
                # `engage --fuse-only`; validation + the signed-charter gate live in actions.launch_cloud.
                self._json(actions.launch_cloud(
                    str(body.get("slug", "")),
                    str(body.get("mode", "")),
                    str(body.get("target", "")),
                    provider=str(body.get("provider", "")),
                ))
                return
            if path.startswith("/api/reverify/"):
                self._json(actions.reverify_run(path[len("/api/reverify/"):].strip("/")))
                return
            if path == "/api/proof/export":
                # Proof Studio (C1): assemble a client-verifiable proof bundle for a run (offline zero-trust
                # re-verify). CSRF/rebind-gated above; shells the exec-only `vigil proof-export`. A bad run id
                # raises ValueError in run_dir → caught below → clean 404.
                self._json(actions.proof_export(str(body.get("run", ""))))
                return
            if path == "/api/authority/provision":
                # Charter & Attestation screen: mint a LOOPBACK authority (scope hard-fixed to 127.0.0.1 in
                # the action — the UI cannot provision a remote charter). CSRF/rebind-gated above.
                self._json(actions.provision_loopback_authority(str(body.get("slug", ""))))
                return
            if path == "/api/authority/ledger":
                # replay the who/when/what usage-attestation ledger + verify its chain (read-only).
                self._json(actions.attestation_ledger())
                return
            if path == "/api/knowledge/gitsync":
                # A6c: run `vigil knowledge status|sync` (regenerate + secret-scan + local commit; NOT push).
                # CSRF/rebind-gated above; shells the exec-only vigil, surfacing the secret-scan refusal.
                self._json(actions.knowledge_gitsync(str(body.get("action", "status"))))
                return
            if path.startswith("/api/evolve/") and path.endswith("/tick"):
                # K5: RUN one self-evolve tick that PERSISTS (the GET evolve_data is read-only). CSRF/rebind-
                # gated above + kill-switch gated inside; it drafts proposals + records calibration
                # predictions, never merges/applies and mints no fact.
                slug = path[len("/api/evolve/"):-len("/tick")].strip("/")
                self._json(actions.run_evolve_tick(slug))
                return
            if path.startswith("/api/killswitch/") and path.endswith("/trip"):
                slug = path[len("/api/killswitch/"):-len("/trip")].strip("/")
                self._json(actions.trip_killswitch(slug, str(body.get("reason", ""))))
                return
            if path == "/api/tools/install":
                # on-demand tool provisioning (B2). CSRF/rebind-gated above. Fail-closed in provision_tool:
                # only a B1-admitted tool, only its declared apt/pip hint, only with explicit consent
                # (else it returns the exact command it WOULD run and installs nothing).
                self._json(actions.provision_tool(body))
                return
            if path == "/api/session/create":
                # F2: create a named session. CSRF/rebind-gated above; the registry mints no fact and
                # authorizes nothing — it only organises runs/chats under an operator-editable name.
                self._json(sessions.create_session(
                    name=str(body.get("name", "")), kind=str(body.get("kind", "engagement"))))
                return
            if path == "/api/session/rename":
                self._json(sessions.rename_session(str(body.get("id", "")), str(body.get("name", ""))))
                return
            if path == "/api/session/delete":
                # SOFT tombstone by default; HARD only on an explicit boolean true (removes the registry
                # entry + rebuildable graph partition, never the append-only spine or a FACT).
                self._json(sessions.delete_session(
                    str(body.get("id", "")), hard=(body.get("hard") is True)))
                return
            if path == "/api/session/connect":
                # F4: connect A → B (directional). The POST IS the consent; stores a read-time scope entry,
                # never a graph merge. CSRF/rebind-gated above; the registry authorizes nothing.
                self._json(sessions.connect_session(str(body.get("id", "")), str(body.get("other", ""))))
                return
            if path == "/api/session/disconnect":
                self._json(sessions.disconnect_session(str(body.get("id", "")), str(body.get("other", ""))))
                return
            if path == "/api/chat/send":
                # the operator chatbot turn — a natural-language front door to the SAME gated launcher.
                # CSRF/rebind-gated above; launches only via actions.launch_assessment (scope/charter/gate
                # enforced there), persists the transcript, and mints no facts.
                self._json(chat.chat_send(body))
                return
            if path == "/api/aegis/setup":
                # launch the managed AEGIS gateway (the SAME gated `aegis gateway` CLI). CSRF/rebind-gated
                # above; validated fail-closed in actions.aegis_setup before any spawn.
                self._json(actions.aegis_setup(body))
                return
            if path == "/api/aegis/stop":
                self._json(actions.aegis_stop(body))
                return
            self._json({"error": "unknown action"}, status=404)
        except ValueError as e:  # an unsafe run id (run_dir guard) → honest 404, consistent with do_GET
            self._json({"error": str(e)}, status=404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)


def serve(host: str = "127.0.0.1", port: int = 8787,
          allowed_hosts=(), allowed_origins=()) -> ThreadingHTTPServer:
    """Create (but do not block on) the loopback console server. The caller runs
    ``serve_forever()``. Refuses any non-loopback BIND — the console is a
    single-operator, on-host surface by design (sovereignty); the unified reverse
    proxy is the only public listener.

    ``allowed_hosts``/``allowed_origins`` are the operator's exact reverse-proxy
    domain Host/Origin forms (e.g. ``vigil.example.com`` / ``https://vigil.example.com``)
    unioned into the anti-CSRF/anti-rebind guard so a same-origin request forwarded
    by the proxy is accepted. Empty (the default) = loopback-only, unchanged."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"console binds loopback only, refusing host {host!r}")
    srv = ThreadingHTTPServer((host, port), ConsoleHandler)
    srv.allowed_hosts = frozenset(h.strip() for h in allowed_hosts if h and h.strip())
    srv.allowed_origins = frozenset(o.strip().rstrip("/") for o in allowed_origins if o and o.strip())
    return srv
