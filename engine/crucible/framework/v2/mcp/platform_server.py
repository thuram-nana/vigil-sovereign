"""framework.v2.mcp.platform_server — the PLATFORM MCP server (stdio), a pure MCP↔HTTP adapter.

Exposes VIGIL's console/REST operations as role-gated MCP tools so an operator can drive their OWN
authorized VIGIL from an MCP client (Claude, Cursor, …). It is a THIN TRANSLATOR and holds **zero
authority of its own**:

  * the tool LIST is generated from the one authoritative operation registry (``platform_tools``);
  * a tool CALL is translated into an authenticated **loopback** HTTP request to ``vigil up`` (the uiproxy)
    carrying the operator's OWN bearer token — the proxy does whoami → role → hop-stamp → and the EXISTING
    console gate ``role_can(role, offense_perm_for(path))`` runs unchanged. The adapter never stamps a role,
    never holds the hop key, and never presents the shared console token (which would resolve to the
    owner-equivalent branch and silently escalate every caller).

Safety invariants (asserted in ``tests/test_platform_server.py``):
  * LOOPBACK-ONLY egress — the base URL host must be loopback (127.0.0.1 / ::1 / localhost); any other host
    is refused at construction, so the adapter can never be pointed off-host. (The proxy, not this adapter,
    is the per-user auth boundary; this adapter only ever talks to the local proxy.)
  * ROUTE FIXED BY TOOL NAME — the HTTP route is taken from the tool descriptor, never from arguments;
    path args are URL-encoded (``render_console_request``), so a value cannot inject a path segment or
    reach a different operation.
  * FAIL-CLOSED — an unknown / out-of-profile tool name is refused BEFORE any HTTP; a render error is a
    refusal, not a malformed request; redirects are never followed; the response read is bounded.
  * NO AUTHORITY MINTED — the adapter forwards the bearer and surfaces the gate's answer verbatim; a 4xx
    (e.g. a 403 gate refusal) is surfaced as ``isError`` with the console's reason.

Pure stdlib + ``platform_tools`` + the shared ``mcp.protocol``/``mcp.server`` JSON-RPC machinery. The HTTP
transport is injectable so the whole adapter is unit-testable with no network.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from .protocol import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    MAX_MESSAGE_BYTES,
    Request,
    dumps,
    err_response,
    ok_response,
    parse_request,
)
from .server import PROTOCOL_VERSION, serve_stdio
from .platform_tools import DEFAULT_PROFILE, PROFILES, build_platform_tools, render_console_request

# The forward transport: (method, url, headers, body_bytes|None, timeout) -> (status:int, body_bytes:bytes).
# Injected for tests; the default is a loopback-pinned stdlib urllib client.
HttpForward = Callable[[str, str, dict, Optional[bytes], float], "tuple[int, bytes]"]

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "ip6-localhost"})
_MAX_RESP_BYTES = 8 << 20   # 8 MiB response cap — a console read can be large; a stdio line is not the cap here

# The `vigil up` proxy authenticates the operator from the X-SIGIL-Token header (not Authorization) and
# requires a CSRF custom header (X-Requested-With) on a mutating POST — a cross-site HTML form can set
# neither. The offense plane is mounted under /offense (/offense/api/v1/* → gated api, /offense/* → console).
# These mirror integration/vigil_integration/uiproxy.py (_TOKEN_HEADER / _CSRF_HEADER / OFFENSE_BASE).
_TOKEN_HEADER = "X-SIGIL-Token"
_CSRF_HEADER = "X-Requested-With"
_OFFENSE_MOUNT = "/offense"


def _require_loopback(base_url: str) -> str:
    """Validate ``base_url`` is a loopback http(s) URL and return it normalised (no trailing slash). Refuses
    any non-loopback host — the adapter must never egress off-host; it only ever calls the local proxy."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"base URL must be http(s), got {parsed.scheme!r}")
    if parsed.username or parsed.password:
        # No legitimate loopback-proxy URL carries userinfo; rejecting it removes the `user@host` ambiguity
        # (e.g. `evil.com@127.0.0.1` parses to host 127.0.0.1) and any credential-in-URL surprise.
        raise ValueError("base URL must not contain userinfo (user:pass@)")
    host = (parsed.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        raise ValueError(f"base URL host must be loopback (one of {sorted(_LOOPBACK_HOSTS)}), got {host!r}")
    return base_url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect — a JSON-RPC-over-console request has no legitimate 30x, and following one
    could leave the pinned loopback host. A redirect is surfaced as its raw status to the caller."""
    def redirect_request(self, *_a: Any, **_k: Any) -> None:  # noqa: D401
        return None


def _default_forward(method: str, url: str, headers: dict, body: Optional[bytes], timeout: float) -> "tuple[int, bytes]":
    """Loopback stdlib HTTP transport. No redirects, bounded read, per-call timeout. Returns (status, body)
    even for a 4xx/5xx (surfaced to the operator as the gate's answer) — only a transport failure raises."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    # ProxyHandler({}) DISABLES urllib's default proxy handling (http_proxy / ALL_PROXY env, macOS/Windows
    # system proxy). Without it, a request to the loopback base URL would be sent to the configured PROXY
    # host instead — off-host, carrying the operator's bearer — defeating the loopback pin. The adapter
    # dials the loopback target DIRECTLY, always.
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read(_MAX_RESP_BYTES + 1)[:_MAX_RESP_BYTES]
    except urllib.error.HTTPError as e:   # 4xx/5xx carry a body (the gate's JSON refusal) — surface it
        return e.code, (e.read(_MAX_RESP_BYTES + 1)[:_MAX_RESP_BYTES] if hasattr(e, "read") else b"")


class PlatformMCPServer:
    """A stdio MCP server advertising the VIGIL console operations for ``profile`` and forwarding each call
    to the loopback ``vigil up`` proxy with the operator's bearer. Duck-types the interface ``serve_stdio``
    drives (``max_bytes`` + ``handle_raw``)."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer: Optional[str] = None,
        profile: str = DEFAULT_PROFILE,
        timeout: float = 60.0,
        forward: Optional[HttpForward] = None,
        server_name: str = "vigil-platform",
        server_version: str = "1",
        max_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        if profile not in PROFILES:
            raise ValueError(f"unknown profile {profile!r}; one of {PROFILES}")
        self.base_url = _require_loopback(base_url)   # refuses a non-loopback target up front
        self.bearer = bearer
        self.profile = profile
        self.timeout = float(timeout)
        self._forward: HttpForward = forward or _default_forward
        self.server_name = server_name
        self.server_version = server_version
        self.max_bytes = int(max_bytes)
        self._tools = build_platform_tools(profile)
        self._by_name = {t["name"]: t for t in self._tools}

    # ---- method handlers ---------------------------------------------------

    def _initialize(self, _params: Any) -> dict:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.server_name, "version": self.server_version},
            "instructions": (
                "VIGIL platform MCP server. Each tool is a VIGIL console operation; a call is forwarded to "
                "the local `vigil up` proxy under YOUR bearer and passes the SAME role gate as the web UI "
                f"(profile={self.profile!r}: owner-tier operations are hidden unless profile='full', and are "
                "gated at owner regardless). readOnly/destructive/idempotent hints are advisory disclosure; "
                "the gate, not the hint, enforces. A result is console data, never a confirmed FACT."),
        }

    def _tools_list(self, _params: Any) -> dict:
        return {"tools": list(self._tools)}

    def _tools_call(self, rid: Any, params: Any) -> dict:
        if not isinstance(params, dict):
            return err_response(rid, INVALID_PARAMS, "tools/call params must be an object")
        name = params.get("name")
        if not isinstance(name, str) or not name.strip():
            return err_response(rid, INVALID_PARAMS, "tools/call requires a string 'name'")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return err_response(rid, INVALID_PARAMS, "tools/call 'arguments' must be an object")
        return ok_response(rid, self._invoke(name.strip(), arguments))

    def _invoke(self, name: str, arguments: dict) -> dict:
        """Resolve → render → forward one platform tool. An unknown / out-of-profile name is refused BEFORE
        any HTTP (fail-closed, never a new door); a render error is a refusal, not a malformed gate request."""
        desc = self._by_name.get(name)
        if desc is None:
            return self._result(is_error=True, text=f"no such tool in profile {self.profile!r}: {name}",
                                 gate="expose-profile", status=None, route=None, method=None, structured={})
        try:
            rendered = render_console_request(desc, arguments)
        except ValueError as e:
            meta = desc["_meta"]["vigil"]
            return self._result(is_error=True, text=f"bad arguments: {e}", gate="render",
                                 status=None, route=meta["route"], method=meta["method"], structured={})
        return self._forward_call(desc, rendered)

    def _forward_call(self, desc: dict, rendered: dict) -> dict:
        meta = desc["_meta"]["vigil"]
        method = rendered["method"]
        path = rendered["path"]
        query = rendered.get("query") or {}
        body = rendered.get("body")
        # Prepend the /offense mount so the request can ONLY be served by the `vigil up` proxy (which strips
        # /offense and routes /offense/api/v1/* → gated api, /offense/* → console). A mispoint at a backend's
        # DIRECT port serves no /offense/* route → 404 (fail-closed), never the owner-equivalent direct-console
        # branch. The console route itself (OFFENSE_ACTION_PERM key) is fixed by the tool name, not arguments.
        url = self.base_url + _OFFENSE_MOUNT + path
        if query:
            url = url + "?" + urllib.parse.urlencode(query)
        headers = {"Accept": "application/json"}
        if self.bearer:
            headers[_TOKEN_HEADER] = self.bearer       # the proxy authenticates from X-SIGIL-Token
        headers[_CSRF_HEADER] = "vigil-mcp"            # CSRF conjunct the proxy requires on a mutating POST
        data: Optional[bytes] = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            data = json.dumps(body or {}).encode("utf-8")
        try:
            status, raw = self._forward(method, url, headers, data, self.timeout)
        except Exception as e:   # noqa: BLE001 — a transport failure is a clean refusal, never a crash
            return self._result(is_error=True, text=f"forward failed: {type(e).__name__}: {e}",
                                 gate="transport", status=None, route=meta["route"], method=method, structured={})
        structured: dict = {}
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
            if isinstance(parsed, dict):
                structured = parsed
            else:
                structured = {"result": parsed}
        except Exception:  # noqa: BLE001 — non-JSON body (unexpected) is surfaced as text only
            structured = {}
        is_error = status is None or status >= 400
        if is_error:
            reason = ""
            if isinstance(structured, dict):
                reason = structured.get("error") or structured.get("detail") or ""
            text = f"console returned {status}" + (f": {reason}" if reason else "")
        else:
            text = f"ok ({status})"
        return self._result(is_error=is_error, text=text, gate=None, status=status,
                            route=meta["route"], method=method, structured=structured)

    @staticmethod
    def _result(*, is_error: bool, text: str, gate: Optional[str], status: Optional[int],
                route: Optional[str], method: Optional[str], structured: dict) -> dict:
        """Map a forwarded console response onto an MCP ``tools/call`` result. A refusal reads the same over
        MCP as it does locally; the result is disclosed as console data, never a confirmed fact."""
        return {
            "content": [{"type": "text", "text": text}],
            "isError": bool(is_error),
            "structuredContent": structured if isinstance(structured, dict) else {},
            "_meta": {"vigil": {
                "gated": True,
                "transport": "console-hop",
                "method": method,
                "route": route,
                "httpStatus": status,
                "gate": gate,
                "provenance": "console-operation",
            }},
        }

    # ---- dispatch (mirrors mcp.server.MCPServer.handle/handle_raw) ----------

    def handle(self, request: Request) -> dict | None:
        if request.is_notification:
            return None
        method = request.method
        try:
            if method == "initialize":
                return ok_response(request.id, self._initialize(request.params))
            if method == "tools/list":
                return ok_response(request.id, self._tools_list(request.params))
            if method == "tools/call":
                return self._tools_call(request.id, request.params)
            if method == "ping":
                return ok_response(request.id, {})
            return err_response(request.id, METHOD_NOT_FOUND, f"unknown method: {method}")
        except Exception as e:   # noqa: BLE001 — never let one bad request crash the server
            return err_response(request.id, INTERNAL_ERROR, f"{type(e).__name__}: {e}")

    def handle_raw(self, raw: str | bytes) -> str | None:
        request, error = parse_request(raw, max_bytes=self.max_bytes)
        if error is not None:
            return dumps(error)
        assert request is not None
        response = self.handle(request)
        return None if response is None else dumps(response)


def from_env(env: Optional[dict] = None) -> PlatformMCPServer:
    """Build a PlatformMCPServer from the operator's environment:
      * VIGIL_MCP_BASE_URL  — the loopback `vigil up` proxy URL (default http://127.0.0.1:8770)
      * VIGIL_MCP_BEARER    — the operator's session bearer token (forwarded; the proxy decides the role)
      * VIGIL_MCP_PROFILE   — 'core' (default) or 'full'
      * VIGIL_MCP_TIMEOUT   — per-call seconds (default 60)
    The base URL is loopback-validated; a non-loopback value raises (fail-closed)."""
    e = env if env is not None else os.environ
    return PlatformMCPServer(
        base_url=e.get("VIGIL_MCP_BASE_URL", "http://127.0.0.1:8770"),
        bearer=e.get("VIGIL_MCP_BEARER") or None,
        profile=e.get("VIGIL_MCP_PROFILE", DEFAULT_PROFILE),
        timeout=float(e.get("VIGIL_MCP_TIMEOUT", "60") or "60"),
    )


def serve(env: Optional[dict] = None) -> None:
    """Entry point: build from env and drive over stdio until EOF (on-host, no network surface of its own)."""
    serve_stdio(from_env(env))  # type: ignore[arg-type]  # duck-typed: max_bytes + handle_raw
