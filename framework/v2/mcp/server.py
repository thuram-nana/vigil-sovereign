"""
mcp.server — EXPOSE CRUCIBLE's gated capabilities as MCP tools (W6b, EXPOSE direction).

An external AI agent / MCP client can enumerate and invoke a curated set of CRUCIBLE capabilities
over JSON-RPC 2.0 — but ONLY through the SAME fail-closed gate chain a local caller uses. There is
no second, ungated door: ``tools/call`` routes every invocation through ``agents.tools.invoke_tool``
(kill-switch → entitlement → charter-scope → destructive-confirm → egress), so an unentitled or
out-of-scope call is REFUSED over MCP exactly as it is locally, and the tool never runs.

Security posture (load-bearing — a bypass here is a bypass of the whole safety stack):
  * DEFAULT-SAFE / FAIL-CLOSED. The :class:`ExposePolicy` advertises and permits ONLY tools that are
    Tier-1, entitlement-free, non-destructive, and no-egress (read-only / already-safe). An offensive
    tool is not even listed, and a call to one is refused BEFORE ``invoke_tool`` (defense in depth on
    top of the gate chain, never instead of it). Nothing exposed is ungated.
  * SLUG IS SERVER-FIXED. The charter/scope/kill-switch binding (``slug``) is set when the server is
    constructed, NEVER read from a request — a remote caller cannot choose which charter it runs
    under, so it cannot widen scope.
  * OBSERVATION, NOT FACT. A tool's output is returned as a provenance-labelled observation
    (``_meta.crucible.provenance = "observation"``); MCP callers get leads, an oracle confirms facts.
  * UNTRUSTED WIRE. Every request is size-bounded and safely parsed (:mod:`mcp.protocol`); a malformed
    message is a clean JSON-RPC error, never a crash and never an invocation.
  * DETERMINISTIC. Dispatch + gate composition are a pure function of (config, request); no wallclock,
    no rng. (I/O framing in ``serve_stdio`` is the only side effect.)

Transport: stdio (newline-delimited JSON, the MCP default) — inherently on-host, no network surface.
The dispatcher (:meth:`MCPServer.handle`) is transport-agnostic and in-process testable.
"""

from __future__ import annotations

import sys
from typing import Any

from ..agents.tools import ToolContext, ToolRegistry, ToolResult, invoke_tool
from .protocol import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    INTERNAL_ERROR,
    MAX_MESSAGE_BYTES,
    Request,
    dumps,
    err_response,
    ok_response,
    parse_request,
)

# The MCP protocol revision this seam speaks. A client requesting another revision still gets a
# valid handshake — we advertise ours and stay maximally compatible for a minimal tool surface.
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "crucible-mcp"
SERVER_VERSION = "0.1.0"


# The default EXPOSE allowlist: the ONLY capabilities advertised/permitted over MCP unless the
# operator explicitly widens it. Every one is Tier-1, entitlement-free, no-egress, non-destructive,
# and read-only/passive — and each is named EXPLICITLY (the allowlist is fail-closed: a new tool is
# never exposed until listed here), with ``invoke_tool``'s full gate chain re-checking every call:
#   * reverify_finding — re-execute a finding's oracle certificate OFFLINE (read-only, no host, no path).
#   * declared_service — normalise operator-declared host services (host-scoped, no side effect, no path).
# DELIBERATELY EXCLUDED even though passive: any tool that reads a caller-influenced local file PATH
# (e.g. sbom_vuln / importers) is NOT exposed over MCP — the "no path" rule stays fail-closed, so the
# MCP surface can never become a local-filesystem path-existence / partial-content oracle, regardless of
# the on-host transport. ACTIVE / egress / exploit sensors (nmap, nuclei_*, zap_web, burp_web, cloud_pull,
# …) are likewise NOT listed — the property re-check below (Tier-1 / no-capability / non-destructive /
# no-egress) is defense-in-depth ON TOP of this allowlist.
DEFAULT_EXPOSE_ALLOW = frozenset({"reverify_finding", "declared_service"})


class ExposePolicy:
    """Decides which registered tools may be ENUMERATED and INVOKED over MCP — an ALLOWLIST, so it is
    FAIL-CLOSED by construction: a tool not on the list is never exposed, no matter its metadata.

    On TOP of the allowlist it re-checks the safe properties as DEFENSE IN DEPTH: an allowlisted tool
    must still be Tier-1, declare no entitlement ``capability``, be non-``destructive``, and reach no
    ``egress_hosts`` — so if an allowlisted tool later gains an offensive flag it is auto-hidden. And
    ``invoke_tool``'s gate chain remains the real guarantee on every call; this policy only narrows
    what is reachable, it never widens it. All metadata is read defensively (missing/wrong-typed/
    raising ⇒ NON-exposable)."""

    def __init__(self, allow: Any = None) -> None:
        self.allow = frozenset(allow) if allow is not None else DEFAULT_EXPOSE_ALLOW

    def exposable(self, tool: Any) -> bool:
        try:
            name = getattr(tool, "name", "")
            if not isinstance(name, str) or name not in self.allow:
                return False                                     # ALLOWLIST — fail-closed
            if str(getattr(tool, "tier", "T1")) != "T1":
                return False
            if getattr(tool, "capability", None) is not None:
                return False
            if bool(getattr(tool, "destructive", False)):
                return False
            if bool(getattr(tool, "egress_hosts", ()) or False):
                return False
            return callable(getattr(tool, "run", None))
        except Exception:
            return False


def default_exposed_registry() -> ToolRegistry:
    """A registry over CRUCIBLE's capability surface: the safe built-in tools (``reverify_finding``)
    plus the built-in sensors. Registration is NOT exposure — the active sensors (Nmap/Nuclei/…) are
    present but the default :class:`ExposePolicy` hides them and refuses a call to them; only the
    Tier-1, entitlement-free, no-egress, read-only, no-local-path producers on the allowlist
    (``reverify_finding``, ``declared_service``) are reachable over MCP. Even those
    are still gated by ``invoke_tool`` on every call."""
    from ..agents.tools.builtin import register_builtin_tools
    from ..sensors.builtin import register_builtin_sensors

    reg = ToolRegistry()
    register_builtin_tools(reg)
    register_builtin_sensors(reg)
    return reg


class MCPServer:
    """A gated MCP tool-server over a CRUCIBLE ``ToolRegistry``. Transport-agnostic: :meth:`handle`
    takes a parsed :class:`Request` and returns a response dict (or ``None`` for a notification);
    :meth:`handle_raw` adds untrusted-wire parsing; :func:`serve_stdio` drives it over stdio."""

    def __init__(
        self,
        *,
        slug: str,
        registry: ToolRegistry | None = None,
        expose: ExposePolicy | None = None,
        sink: Any = None,
        world: Any = None,
        prompt_callback: Any = None,
        dry_run: bool = False,
        max_bytes: int = MAX_MESSAGE_BYTES,
        server_name: str = SERVER_NAME,
        server_version: str = SERVER_VERSION,
    ) -> None:
        if not isinstance(slug, str) or not slug.strip():
            raise ValueError("MCPServer requires a non-empty engagement slug (charter/scope binding)")
        self.slug = slug.strip()
        self.registry = registry if registry is not None else default_exposed_registry()
        self.expose = expose if expose is not None else ExposePolicy()
        self.sink = sink
        self.world = world
        # destructive-confirm defaults to DENY over MCP (no prompt_callback) — and exposable tools are
        # non-destructive anyway, so a destructive tool is doubly unreachable here.
        self.prompt_callback = prompt_callback
        self.dry_run = bool(dry_run)
        self.max_bytes = max(1, int(max_bytes))
        self.server_name = str(server_name)
        self.server_version = str(server_version)

    # ---- context -----------------------------------------------------------

    def _ctx(self) -> ToolContext:
        # slug is server-fixed — NEVER taken from a request — so a remote caller cannot widen scope.
        return ToolContext(slug=self.slug, world=self.world,
                           prompt_callback=self.prompt_callback, dry_run=self.dry_run)

    # ---- enumeration -------------------------------------------------------

    def exposed(self) -> list[Any]:
        """The tools this server advertises/permits, sorted by name (deterministic)."""
        out = []
        for name in self.registry.names():
            tool = self.registry.get(name)
            if tool is not None and self.expose.exposable(tool):
                out.append(tool)
        return out

    def _descriptor(self, tool: Any) -> dict:
        """An MCP ``Tool`` object for one exposed capability, disclosing its gating metadata under
        ``_meta.crucible`` so a client knows the call is gated and its output is an observation."""
        desc = getattr(tool, "mcp_description", None)
        if not isinstance(desc, str) or not desc:
            doc = (getattr(tool, "__doc__", "") or "").strip()
            desc = doc.split("\n", 1)[0].strip() if doc else f"CRUCIBLE tool {tool.name!r}."
        schema = getattr(tool, "mcp_input_schema", None)
        if not isinstance(schema, dict):
            schema = {"type": "object", "additionalProperties": True}
        return {
            "name": tool.name,
            "description": desc,
            "inputSchema": schema,
            "annotations": {
                "title": tool.name,
                "readOnlyHint": not bool(getattr(tool, "destructive", False)),
                "destructiveHint": False,
                "openWorldHint": bool(getattr(tool, "egress_hosts", ()) or False),
            },
            "_meta": {"crucible": {
                "gated": True,
                "tier": str(getattr(tool, "tier", "T1")),
                "capability": getattr(getattr(tool, "capability", None), "value", "") or "",
                "provenance": "observation",
            }},
        }

    # ---- method handlers ---------------------------------------------------

    def _initialize(self, _params: Any) -> dict:
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.server_name, "version": self.server_version},
            "instructions": (
                "CRUCIBLE exposes only default-safe, already-gated capabilities. Every tools/call "
                "routes through the fail-closed gate chain (kill-switch / entitlement / charter-scope "
                "/ destructive-confirm / egress); an unentitled or out-of-scope call is REFUSED and "
                "does nothing. Tool output is a provenance-labelled observation, never a confirmed "
                "fact — a CRUCIBLE oracle confirms facts."),
        }

    def _tools_list(self, _params: Any) -> dict:
        return {"tools": [self._descriptor(t) for t in self.exposed()]}

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
        result = self._invoke(name.strip(), arguments)
        return ok_response(rid, self._call_result(result))

    def _invoke(self, name: str, arguments: dict) -> ToolResult:
        """Resolve + gate + run one exposed tool. A tool that is not registered, or registered but
        NOT exposable (an offensive/gated capability), is REFUSED here — before the invoker — and
        never runs. An exposable tool goes through ``invoke_tool``'s full fail-closed gate chain, so
        even it is refused without entitlement / in-scope / an untripped kill-switch."""
        tool = self.registry.get(name)
        if tool is None:
            return ToolResult(ok=False, note=f"no such tool: {name}")
        if not self.expose.exposable(tool):
            return ToolResult(ok=False, refused=True, gate="expose-policy",
                              note=f"tool {name!r} is not exposed over MCP (default-safe policy)")
        return invoke_tool(self.registry, name, arguments, self._ctx(), sink=self.sink)

    def _call_result(self, tr: ToolResult) -> dict:
        """Map a gated ``ToolResult`` onto an MCP ``tools/call`` result. A refusal is surfaced as
        ``isError`` with the gate + reason — the remote caller sees the refusal exactly as locally.
        ``structuredContent`` carries the tool's observation output; ``_meta.crucible`` states that
        it is an OBSERVATION (a lead), never a confirmed fact, and records the gate outcome."""
        if tr.refused:
            text = f"refused by gate {tr.gate!r}: {tr.note}"
        elif tr.ok:
            text = tr.summary or "ok"
        else:
            text = tr.note or "tool failed"
        return {
            "content": [{"type": "text", "text": text}],
            "isError": (not tr.ok),
            "structuredContent": tr.output if isinstance(tr.output, dict) else {},
            "_meta": {"crucible": {
                "ok": bool(tr.ok),
                "refused": bool(tr.refused),
                "gate": tr.gate,
                "note": tr.note,
                "provenance": "observation",
            }},
        }

    # ---- dispatch ----------------------------------------------------------

    def handle(self, request: Request) -> dict | None:
        """Dispatch one validated request. Returns a response dict, or ``None`` for a notification
        (no response is emitted). Never raises — any internal error becomes a JSON-RPC error."""
        if request.is_notification:
            return None   # notifications (e.g. notifications/initialized) get no response
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
        except Exception as e:   # never let one bad request crash the server
            return err_response(request.id, INTERNAL_ERROR, f"{type(e).__name__}: {e}")

    def handle_raw(self, raw: str | bytes) -> str | None:
        """Parse an untrusted wire message and dispatch it. Returns the serialized JSON response, or
        ``None`` for a notification (nothing to write). A malformed/oversized message yields a clean
        JSON-RPC error string — never a crash, never an invocation."""
        request, error = parse_request(raw, max_bytes=self.max_bytes)
        if error is not None:
            return dumps(error)
        assert request is not None
        response = self.handle(request)
        return None if response is None else dumps(response)


# ---- stdio transport -------------------------------------------------------


_OVERSIZE = object()


def _read_message(fp: Any, cap: int) -> Any:
    """Read one newline-delimited message from a binary stream, BOUNDED to ``cap`` bytes. Returns the
    raw bytes, ``None`` at EOF, or the ``_OVERSIZE`` sentinel for a line that exceeds the cap (whose
    remaining bytes are drained so the stream re-syncs at the next line). No unbounded buffering."""
    raw = fp.readline(cap + 1)
    if not raw:
        return None
    if len(raw) > cap and not raw.endswith(b"\n"):
        while True:                       # drain the rest of this over-long physical line
            chunk = fp.readline(cap + 1)
            if not chunk or chunk.endswith(b"\n"):
                break
        return _OVERSIZE
    return raw


def serve_stdio(server: MCPServer, *, stdin: Any = None, stdout: Any = None) -> None:
    """Drive ``server`` over newline-delimited JSON on stdio (the MCP default transport). Blocks
    until EOF. Each response is written on its own line and flushed. On-host only — stdio has no
    network surface; this is the safest transport for a default-safe, loopback-only seam."""
    inp = stdin if stdin is not None else sys.stdin.buffer
    out = stdout if stdout is not None else sys.stdout.buffer

    def _write(text: str) -> None:
        out.write(text.encode("utf-8") + b"\n")
        try:
            out.flush()
        except Exception:
            pass

    while True:
        msg = _read_message(inp, server.max_bytes)
        if msg is None:
            return
        if msg is _OVERSIZE:
            _write(dumps(err_response(None, INVALID_REQUEST, "message exceeds maximum size")))
            continue
        response = server.handle_raw(msg)
        if response is not None:
            _write(response)
