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
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import actions, reads
from .authn import check_api_key, load_api_key
from .guard import LOOPBACK_BIND_HOSTS, check_same_origin

# W16-12 — wire the gated api to the SAME multi-user model as the offense console instead of a second
# one. `vigil_core.rbac` is the ONE role→permission vocabulary (`role_can`) and offense route→permission
# map (`offense_perm_for`); `vigil_core.hopauth` is the ONE construction of the proxy→offense role
# assertion the console verifies. Both are namespace-pure `vigil_core` modules the console already
# reuses, so importing them here crosses no trust boundary (FATAL-2 holds).
from vigil_core.hopauth import verify_hop_assertion
from vigil_core.rbac import offense_perm_for, role_can

# Attribution/authorization audit log. INFO by default (quiet — Python's last-resort handler only emits
# WARNING+), so it stays silent on the operator's terminal unless they configure logging, while every
# authorized action and every attributed refusal IS recorded against a principal for an operator who wants
# the trail.
_LOG = logging.getLogger("crucible.api.authz")

# a POST body is bounded so an untrusted client cannot exhaust memory. Generous enough
# for a real third-party report, far below a DoS.
_MAX_BODY = 8 * 1024 * 1024

_API = "/api/v1"

# W16-12 — the proxy-stamped per-user identity headers (IDENTICAL names to the offense console). The
# `vigil up` proxy resolves the caller against the owner-signed sovereign accounts spine and stamps the
# resolved principal/role here, binding them under a per-run hop secret (`VIGIL_CONSOLE_HOP_KEY`, the SAME
# env the console child receives) so a client that merely holds the loopback credential cannot forge a
# role. A request with NO role assertion is a DIRECT credential-holder (owner-equivalent, no-regression).
_PRINCIPAL_HDR = "X-VIGIL-Principal"
_ROLE_HDR = "X-VIGIL-Role"
_ROLE_SIG_HDR = "X-VIGIL-Role-Sig"
_ROLE_TS_HDR = "X-VIGIL-Role-Ts"
_HOP_KEY_ENV = "VIGIL_CONSOLE_HOP_KEY"

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

    # ---- per-action RBAC + principal attribution (W16-12) -----------------

    def _authorize(self, path: str) -> tuple[bool, dict, str]:
        """Per-action RBAC + principal attribution on a same-origin POST. Mirrors the offense console's
        ``_rbac_ok`` (SAME shared ``vigil_core`` role model + hop-assertion) and additionally returns the
        resolved ACTOR, so a permitted action is attributed to an AUTHENTICATED principal — not the OS
        login + git config — and a refusal NAMES the principal it refused.

        Three mutually-exclusive cases:

          * NO role assertion (neither ``X-VIGIL-Role`` nor ``X-VIGIL-Role-Sig``) → a DIRECT credential-
            holder reaching the loopback api on-host. Holding the loopback/api credential is owner-
            equivalent, so this keeps today's FULL access (no regression for a local operator / the CLI /
            a legacy client). Attributed as the on-host operator (``authenticated: False`` — it is not a
            named human, the honest residual).
          * A role assertion that VERIFIES (fresh HMAC under the hop key) → the proxy-resolved per-user
            principal from the owner-signed accounts spine. Enforce ``role_can(role, offense_perm_for(path))``;
            an UNMAPPED route ⇒ ``offense_perm_for`` is None ⇒ ``role_can`` False ⇒ DEFAULT-DENY.
          * A role assertion PRESENT but INVALID (forged/expired/incomplete, or no hop key to verify it) →
            REFUSE. A forged ``X-VIGIL-Role: owner`` with no valid MAC never lifts the role; the refusal is
            still attributed to the CLAIMED (unverified) principal so it is logged against a name.

        Returns ``(allowed, actor, reason)``; the caller maps a False to a 403 that names the actor."""
        role = (self.headers.get(_ROLE_HDR) or "").strip()
        sig = (self.headers.get(_ROLE_SIG_HDR) or "").strip()
        principal = (self.headers.get(_PRINCIPAL_HDR) or "").strip()
        ts = (self.headers.get(_ROLE_TS_HDR) or "").strip()
        if not role and not sig:
            actor = {"principal": "on-host-operator", "role": "owner",
                     "authenticated": False, "via": "direct-credential"}
            return True, actor, ""
        hop_key = getattr(self.server, "hop_key", "") or ""
        if not verify_hop_assertion(hop_key, principal, role, self.command, path, ts, sig):
            actor = {"principal": principal or "(unnamed)", "role": role or "(none)",
                     "authenticated": False, "via": "hop-unverified"}
            return False, actor, "unverified role assertion (bad/expired hop signature)"
        actor = {"principal": principal or "(unnamed)", "role": role,
                 "authenticated": True, "via": "hop"}
        required = offense_perm_for(path)                     # None ⇒ unmapped route ⇒ default-deny
        if not role_can(role, required):
            need = required or "(unmapped route → default-deny)"
            return (False, actor,
                    f"principal {actor['principal']!r} (role {role!r}) lacks required permission {need}")
        return True, actor, ""

    def _log_attribution(self, path: str, actor: dict, allowed: bool, why: str) -> None:
        """Record the action against its principal — the audit trail the loopback bind alone cannot give.
        A permitted action logs at INFO (silent by default); a refusal logs the attributed denial. Never
        raises (a logging failure must not break the request)."""
        try:
            verb = "authorized" if allowed else "REFUSED"
            _LOG.info("api action %s: principal=%s role=%s via=%s %s %s%s",
                      verb, actor.get("principal"), actor.get("role"), actor.get("via"),
                      self.command, path, "" if allowed else f" ({why})")
        except Exception:  # noqa: BLE001 — attribution logging is best-effort, never load-bearing
            pass

    # ---- response helpers -------------------------------------------------

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # a loopback JSON API is not a browser resource; deny embedding/sniffing.
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- health / readiness probes (UNAUTHENTICATED, secret-free) ---------

    def _healthz(self) -> None:
        """Liveness — the process answers. UNAUTHENTICATED and gate-UNGATED (a k8s/LB probe presents
        neither an API key nor a same-origin proof), and carries NO secret."""
        self._json({"ok": True})

    def _readyz(self) -> None:
        """Readiness — checks the API's REAL dependency: the console working directory it reads from and
        the importer persists into. Returns 503 when that store cannot be created/written, so an
        orchestrator drains an API that cannot serve a read or record an import. UNAUTHENTICATED and
        gate-UNGATED; the body carries no path/token (only a boolean + the exception TYPE name on
        failure)."""
        ok, name = True, ""
        try:
            from ..console import actions as console_actions
            d = console_actions.console_dir()       # creates + returns the console's .console working dir
            if not os.access(d, os.W_OK):
                ok, name = False, "not_writable"
        except Exception as exc:  # noqa: BLE001 — a store that will not open is NOT ready (fail-closed)
            ok, name = False, type(exc).__name__
        body: dict = {"ok": ok, "checks": [{"name": "console_store", "ok": ok}]}
        if not ok:
            body["error"] = name                     # exception TYPE / short reason — never a path
        self._json(body, status=200 if ok else 503)

    # ---- GET (read-first) -------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path
        # Health/readiness probes are answered FIRST — before the API-key gate — so a k8s/LB probe
        # (which presents no key) can reach them. They expose no sensitive state.
        if path == "/healthz":
            return self._healthz()
        if path == "/readyz":
            return self._readyz()
        if not self._api_key_ok():   # fail-closed key gate on top of the loopback bind
            return
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
        ok, why = check_same_origin(self.headers, self.server.server_address[1],
                                    getattr(self.server, "allowed_hosts", ()),
                                    getattr(self.server, "allowed_origins", ()))
        if not ok:
            self._json({"error": f"cross-site POST refused ({why})"}, status=403)
            return
        # 2. per-action RBAC + attribution (W16-12). A proxy-forwarded per-user request carries a
        #    hop-signed role, enforced against this route's required permission; a direct credential-holder
        #    (no role assertion) keeps full access; a present-but-unverified role assertion is refused. The
        #    refusal NAMES the principal it refused — the negative control.
        allowed, actor, deny_why = self._authorize(path)
        self._log_attribution(path, actor, allowed, deny_why)
        if not allowed:
            self._json({"error": f"forbidden: {deny_why}",
                        "principal": actor["principal"], "role": actor["role"]}, status=403)
            return
        # 3. bounded, safe JSON body.
        body, err = self._read_json_body()
        if body is None:
            self._json({"error": err}, status=400)
            return
        # 4. route -> a GATED tool invocation (never an ungated capability). Each action result is stamped
        #    with the resolved actor so the response ATTRIBUTES the mutation to an authenticated principal.
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
                result = actions.invoke(
                    registry, slug=str(slug or ""), tool=tool,
                    args=args if isinstance(args, dict) else {}, world=world)
                result["actor"] = actor
                self._json(result)
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
                result = actions.import_findings(
                    registry, slug=str(body.get("slug", "") or ""),
                    fmt=str(fmt or ""), report=rep,
                    source_tool=(str(body.get("source_tool", "")) or None), world=world)
                result["actor"] = actor
                self._json(result)
                return
            self._json({"error": "unknown action"}, status=404)
        except BrokenPipeError:
            return
        except Exception as e:  # a gate/tool error must never 500 into a traceback
            self._json({"error": f"{type(e).__name__}: {e}"}, status=500)


def _resolve_hop_key(explicit: str | None = None) -> str:
    """The proxy→api hop secret: an explicit argument (tests) → ``$VIGIL_CONSOLE_HOP_KEY`` → ``""``.
    UNLIKE a session token this is NEVER minted — it must equal the value the `vigil up` proxy holds
    (shared out-of-band via the api child's env at spawn), so a minted-here value could never verify.
    Blank ⇒ the api trusts NO stamped role (fail-closed): a proxy-forwarded per-user request cannot be
    role-verified and is refused; only the direct credential-holder (no role assertion) path stays open.
    This is the SAME env the offense console child receives, so the proxy's one stamp verifies at both."""
    for candidate in (explicit, os.environ.get(_HOP_KEY_ENV)):
        v = (candidate or "").strip()
        if v:
            return v
    return ""


def serve(host: str = "127.0.0.1", port: int = 8799, *, registry=None,
          import_store_factory=None, api_key: str | None = None, hop_key: str | None = None,
          allowed_hosts=(), allowed_origins=()) -> ThreadingHTTPServer:
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
    the loopback bind doesn't cover — an operator fronting the API behind a proxy/tunnel.

    ``hop_key`` (W16-12) is the proxy→api role-assertion secret; None → ``$VIGIL_CONSOLE_HOP_KEY``
    (the SAME env the offense console child receives from ``vigil up``). It enables per-action RBAC +
    principal attribution for a proxy-forwarded per-user request; unset/blank ⇒ no stamped role is
    trusted (fail-closed) and only the direct credential-holder path is open — byte-identical to before."""
    if host not in LOOPBACK_BIND_HOSTS:
        raise ValueError(f"api binds loopback only, refusing host {host!r}")
    httpd = ThreadingHTTPServer((host, port), ApiHandler)
    httpd.registry = registry if registry is not None else actions.default_registry(
        import_store_factory=import_store_factory)
    httpd.import_store_factory = import_store_factory
    # None → load from CRUCIBLE_API_KEY; blank/unset → None → the default no-op.
    httpd.api_key = load_api_key(api_key)
    # None → load from VIGIL_CONSOLE_HOP_KEY; blank/unset → "" → no stamped role trusted (fail-closed).
    httpd.hop_key = _resolve_hop_key(hop_key)
    # operator reverse-proxy domain allowlist (empty default = loopback-only, unchanged).
    httpd.allowed_hosts = frozenset(h.strip() for h in allowed_hosts if h and h.strip())
    httpd.allowed_origins = frozenset(o.strip().rstrip("/") for o in allowed_origins if o and o.strip())
    return httpd
