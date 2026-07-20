"""
mcp.client — a minimal, SAFE JSON-RPC 2.0 client for CONSUMING an external MCP server (W6b).

CRUCIBLE consumes an external MCP tool by driving it through this client and wrapping the tool as a
gated :class:`mcp.sensor.MCPSensor`. The client is deliberately thin and TRANSPORT-INJECTED: it takes
a ``transport`` callable ``(request_dict) -> response_dict`` so the sensor/tests can drive it fully in
process with a fake transport — no real subprocess, no network. A real :class:`StdioSubprocessTransport`
is provided for production (fixed argv, no shell, bounded, timed out), but it is strictly opt-in.

Untrusted-response doctrine — the external server is NOT trusted:
  * The response envelope is validated defensively (dict, matching ``jsonrpc``, ``result`` XOR
    ``error``); anything malformed becomes a structured error, never a crash.
  * A tool result is data to be treated as a LEAD by the sensor — the client never elevates it.
  * The real stdio transport bounds every read (no unbounded buffering) and uses ``json.loads`` only.
  * DETERMINISTIC ids: a plain incrementing counter (no wallclock, no rng).
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .protocol import JSONRPC_VERSION, MAX_MESSAGE_BYTES

# A transport sends one JSON-RPC request object and returns the raw response object.
Transport = Callable[[dict], dict]


class MCPClientError(Exception):
    """A transport/protocol failure talking to an external MCP server (never a trust decision)."""


class MCPClient:
    """Speak JSON-RPC 2.0 to one external MCP server through an injected ``transport``. Every method
    returns plain data; nothing here is trusted as a fact — the consuming :class:`MCPSensor` labels
    it as a lead."""

    def __init__(self, transport: Transport, *, name: str = "mcp-client") -> None:
        if not callable(transport):
            raise MCPClientError("transport must be callable: (request_dict) -> response_dict")
        self._transport = transport
        self.name = str(name)
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _call(self, method: str, params: dict) -> tuple[Any, dict | None]:
        """Send one request and return ``(result, error)`` — exactly one is non-None. The response is
        validated defensively; a transport exception or a malformed envelope is returned as an error
        dict (``{"code","message"}``), never raised out of a normal call path."""
        request = {"jsonrpc": JSONRPC_VERSION, "id": self._next_id(), "method": method, "params": params}
        try:
            response = self._transport(request)
        except Exception as e:
            return None, {"code": -32001, "message": f"transport error: {type(e).__name__}: {e}"}
        if not isinstance(response, dict):
            return None, {"code": -32002, "message": "malformed response: not a JSON object"}
        if "error" in response and response.get("error") is not None:
            err = response["error"]
            return None, err if isinstance(err, dict) else {"code": -32003, "message": str(err)}
        if "result" not in response:
            return None, {"code": -32004, "message": "malformed response: no result and no error"}
        return response.get("result"), None

    def initialize(self) -> dict:
        """Perform the MCP handshake. Returns the server's ``result`` (or a structured error under
        ``{"error": ...}``)."""
        result, error = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": self.name, "version": "0.1.0"},
        })
        return {"error": error} if error is not None else (result if isinstance(result, dict) else {})

    def list_tools(self) -> list[dict]:
        """Enumerate the external server's tools. Returns a list of tool descriptors (possibly empty);
        a malformed/absent list degrades to ``[]``."""
        result, error = self._call("tools/list", {})
        if error is not None or not isinstance(result, dict):
            return []
        tools = result.get("tools")
        return [t for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        """Invoke one external tool. Returns a NORMALISED, defensively-typed view — never trusted as a
        fact:

            {"ok": bool, "is_error": bool, "structured": dict, "content": list, "error": dict|None}

        ``structured`` is the tool's ``structuredContent`` (an object) — where a consuming sensor reads
        a tool's machine-readable output. A JSON-RPC/transport error sets ``ok=False`` + ``error``."""
        result, error = self._call("tools/call", {"name": str(name), "arguments": dict(arguments or {})})
        if error is not None:
            return {"ok": False, "is_error": True, "structured": {}, "content": [], "error": error}
        if not isinstance(result, dict):
            return {"ok": False, "is_error": True, "structured": {}, "content": [],
                    "error": {"code": -32005, "message": "tools/call result is not an object"}}
        is_error = bool(result.get("isError", False))
        structured = result.get("structuredContent")
        content = result.get("content")
        return {
            "ok": not is_error,
            "is_error": is_error,
            "structured": structured if isinstance(structured, dict) else {},
            "content": content if isinstance(content, list) else [],
            "error": None,
        }


class StdioSubprocessTransport:
    """Production transport: a child MCP server spoken to over its stdio pipes (newline-delimited
    JSON). OPT-IN and DEFENSIVE — a fixed ``argv`` list (never a shell string, ``shell=False``), the
    child spawned lazily on first send, every stdout read bounded, and a per-call timeout. Its stderr
    is discarded so a chatty server cannot wedge the pipe. Not used by tests (no live subprocess)."""

    def __init__(self, argv: list[str], *, cwd: str | None = None, env: dict | None = None,
                 timeout_s: float = 30.0, max_bytes: int = MAX_MESSAGE_BYTES) -> None:
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
            raise MCPClientError("StdioSubprocessTransport needs a non-empty argv list of strings")
        self._argv = list(argv)
        self._cwd = cwd
        self._env = env
        self._timeout_s = float(timeout_s)
        self._max_bytes = max(1, int(max_bytes))
        self._proc: Any = None

    def _ensure(self) -> Any:
        if self._proc is not None and self._proc.poll() is None:
            return self._proc
        import subprocess
        self._proc = subprocess.Popen(
            self._argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=self._cwd, env=self._env, shell=False, close_fds=True, bufsize=0)
        return self._proc

    def __call__(self, request: dict) -> dict:
        proc = self._ensure()
        line = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(line) > self._max_bytes:
            raise MCPClientError("outbound request exceeds maximum size")
        try:
            proc.stdin.write(line)
            proc.stdin.flush()
        except Exception as e:
            raise MCPClientError(f"failed writing to MCP subprocess: {e}") from e
        raw = proc.stdout.readline(self._max_bytes + 1)
        if not raw:
            raise MCPClientError("MCP subprocess closed its stdout (no response)")
        if len(raw) > self._max_bytes and not raw.endswith(b"\n"):
            raise MCPClientError("MCP subprocess response exceeds maximum size")
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except Exception as e:
            raise MCPClientError(f"MCP subprocess returned invalid JSON: {e}") from e
        if not isinstance(obj, dict):
            raise MCPClientError("MCP subprocess response is not a JSON object")
        return obj

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        for stream in (getattr(proc, "stdin", None), getattr(proc, "stdout", None)):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
        try:
            proc.terminate()
        except Exception:
            pass
