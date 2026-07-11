"""
api.server — a LOOPBACK-ONLY, DEFAULT-SAFE external API for CRUCIBLE.

A stdlib ``ThreadingHTTPServer`` bound to 127.0.0.1 ONLY (never a routable interface),
that lets an operator drive/observe CRUCIBLE programmatically. It mirrors the Ops
Console's security posture (``console.server``) and EXTENDS it with a GATED action
surface — it does not reinvent a riskier server:

  * DEFAULT-SAFE. Nothing runs unless the operator starts it (``framework.v2 api``).
  * LOOPBACK-ONLY. ``serve()`` refuses any non-loopback bind host.
  * READ-FIRST. The safe majority is GET ``/api/v1/*`` reads (delegated to the
    console's audited read layer); they issue no traffic and mutate nothing.
  * GATED ACTIONS. Every POST is a tool invocation through ``agents.tools.invoke_tool``
    — the SAME fail-closed gate chain as local. An unauthorized action is REFUSED;
    the tool never runs and nothing is sent.
  * UNTRUSTED INPUT. A POST body is bounded (``_MAX_BODY``), parsed as JSON only (no
    eval/shell), and type-checked. A cross-site POST is refused (loopback + custom
    header + Host/Origin proof, per ``api.guard``). There is NO static-file serving,
    so there is no path-traversal surface at all.

The server holds a SAFE tool registry (``api.actions.default_registry``): re-verify and
import only — no egress/exploit tool is exposed. A different registry can be injected
(``serve(registry=...)``) — tests inject a gated stub to prove a refusal is returned.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import actions, reads
from .authn import check_api_key, load_api_key
from .guard import LOOPBACK_BIND_HOSTS, check_same_origin

# a POST body is bounded so an untrusted client cannot exhaust memory. Generous enough
# for a real third-party report, far below a DoS.
_MAX_BODY = 8 * 1024 * 1024

_API = "/api/v1"

# GET routes with no argument -> a zero-arg reads provider.
_EXACT_GET = {
    f"{_API}/status": reads.status,
    f"{_API}/engagements": reads.engagements,
    f"{_API}/runs": reads.runs,
}

# GET routes of the form "<prefix>/<arg>" -> a reads provider taking one string arg.
_PREFIX_GET = {
    f"{_API}/engagement/": reads.engagement,
    f"{_API}/authority/": reads.authority,
    f"{_API}/report/": reads.report,
    f"{_API}/worldmodel/": reads.worldmodel,
    f"{_API}/evidence/": reads.evidence,
    f"{_API}/intel/": reads.intel,
}


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "CrucibleApi/1.0"

    # keep the API quiet — no request-logging noise on the operator's terminal.
    def log_message(self, *_args) -> None:  # noqa: D401
        return

    # ---- optional API-key hardening (stacked ON TOP of loopback + same-origin) --

    def _api_key_ok(self) -> bool:
        """Fail-closed API-key gate, checked FIRST on every GET/POST dispatch. It is
        STACKED ON TOP of the loopback bind + same-origin guards, never in place of them.
        When no key is configured (the default) this is a NO-OP and behaviour is unchanged;
        when a key IS configured, a missing key is 401 and a wrong key is 403, and the
        request never reaches a read or an action."""
        ok, why = check_api_key(self.headers, getattr(self.server, "api_key", None))
        if ok:
            return True
        status = 401 if why.startswith("missing") else 403
        self._json({"error": f"API key required ({why})"}, status=status)
        return False

    # ---- response helpers -------------------------------------------------

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # a loopback JSON API is not a browser resource; deny embedding/sniffing.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- GET (read-first) -------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if not self._api_key_ok():   # fail-closed key gate on top of the loopback bind
            return
        path = urlsplit(self.path).path
        try:
            if path == f"{_API}/tools":
                self._json(reads.tools(self.server.registry))
                return
            if path.startswith(f"{_API}/imports/"):
                slug = path[len(f"{_API}/imports/"):].strip("/")
                self._json(reads.imports(slug, store_factory=self.server.import_store_factory))
                return
            if path in _EXACT_GET:
                self._json(_EXACT_GET[path]())
                return
            for prefix, fn in _PREFIX_GET.items():
                if path.startswith(prefix):
                    self._json(fn(path[len(prefix):].strip("/")))
                    return
            self._json({"error": "unknown endpoint"}, status=404)
        except BrokenPipeError:
            return
        except Exception as e:  # never 500 the whole API on one bad read
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)

    # ---- POST (gated actions) --------------------------------------------

    def _read_json_body(self) -> tuple[dict | None, str]:
        """Read + parse a bounded JSON object body. Returns ``(obj, error)`` — a dict on
        success, else (None, reason). Untrusted: a bad length, an oversize body, non-JSON,
        or a non-object all fail with a clean message (never a traceback)."""
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except (TypeError, ValueError):
            return None, "invalid Content-Length"
        if n < 0:
            return None, "invalid Content-Length"
        if n > _MAX_BODY:
            # DRAIN a bounded amount of the oversize body (discarding it, never buffering
            # it into memory) so the client receives a clean 4xx rather than a connection
            # reset / broken pipe. Bounded so a lying Content-Length cannot loop us.
            remaining = min(n, _MAX_BODY * 4)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            return None, f"body exceeds {_MAX_BODY} bytes"
        raw = self.rfile.read(n) if n else b""
        try:
            obj = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return None, f"malformed JSON body: {e}"
        if not isinstance(obj, dict):
            return None, "JSON body must be an object"
        return obj, ""

    def do_POST(self) -> None:  # noqa: N802
        if not self._api_key_ok():   # fail-closed key gate ON TOP of same-origin (below)
            return
        path = urlsplit(self.path).path
        # 1. same-origin / CSRF guard (loopback + custom header + Host/Origin proof).
        ok, why = check_same_origin(self.headers, self.server.server_address[1])
        if not ok:
            self._json({"error": f"cross-site POST refused ({why})"}, status=403)
            return
        # 2. bounded, safe JSON body.
        body, err = self._read_json_body()
        if body is None:
            self._json({"error": err}, status=400)
            return
        # 3. route -> a GATED tool invocation (never an ungated capability).
        try:
            registry = self.server.registry
            # a FRESH world-model per request — no shared mutable state across the
            # ThreadingHTTPServer's request threads (durability is the intel store).
            from ..worldmodel.graph import WorldModel
            world = WorldModel()
            if path == f"{_API}/tool/invoke":
                tool = body.get("tool")
                if not isinstance(tool, str) or not tool.strip():
                    self._json({"error": "'tool' (string) is required"}, status=400)
                    return
                slug = body.get("slug", "")
                args = body.get("args", {})
                self._json(actions.invoke(
                    registry, slug=str(slug or ""), tool=tool,
                    args=args if isinstance(args, dict) else {}, world=world))
                return
            if path == f"{_API}/import":
                fmt = body.get("format", "")
                rep = body.get("report", "")
                if not isinstance(rep, str):
                    try:
                        rep = json.dumps(rep)
                    except (TypeError, ValueError):
                        self._json({"error": "'report' must be a string or JSON-serializable"},
                                   status=400)
                        return
                self._json(actions.import_findings(
                    registry, slug=str(body.get("slug", "") or ""),
                    fmt=str(fmt or ""), report=rep,
                    source_tool=(str(body.get("source_tool", "")) or None), world=world))
                return
            self._json({"error": "unknown action"}, status=404)
        except BrokenPipeError:
            return
        except Exception as e:  # a gate/tool error must never 500 into a traceback
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)


def serve(host: str = "127.0.0.1", port: int = 8799, *, registry=None,
          import_store_factory=None, api_key: str | None = None) -> ThreadingHTTPServer:
    """Create (but do not block on) the loopback external API server. The caller runs
    ``serve_forever()``. Refuses any non-loopback host — the API is a single-operator,
    on-host surface by design (sovereignty), same as the console.

    ``registry`` overrides the SAFE default tool registry (tests inject a gated stub);
    ``import_store_factory`` overrides the importer's persistence target (tests).

    ``api_key`` opts IN to an additional shared-secret gate (see ``api.authn``): a request
    then has to present it (``Authorization: Bearer <key>`` or ``X-Relay-Key``) STACKED ON
    TOP of the loopback + same-origin guards, fail-closed. Left ``None`` (the default) it is
    loaded from ``CRUCIBLE_API_KEY``; unset/blank there too → NO enforcement (behaviour
    unchanged, still loopback + same-origin only). It is opt-in hardening for the one case
    the loopback bind doesn't cover — an operator fronting the API behind a proxy/tunnel."""
    if host not in LOOPBACK_BIND_HOSTS:
        raise ValueError(f"api binds loopback only, refusing host {host!r}")
    httpd = ThreadingHTTPServer((host, port), ApiHandler)
    httpd.registry = registry if registry is not None else actions.default_registry(
        import_store_factory=import_store_factory)
    httpd.import_store_factory = import_store_factory
    # None → load from CRUCIBLE_API_KEY; blank/unset → None → the default no-op.
    httpd.api_key = load_api_key(api_key)
    return httpd
