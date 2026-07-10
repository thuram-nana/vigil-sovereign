"""
mcp.protocol — a stdlib-only, SAFE JSON-RPC 2.0 envelope layer for the MCP seam (W6b).

MCP is JSON-RPC 2.0 over a byte stream (stdio / loopback). This module is the transport-agnostic
envelope: parse an UNTRUSTED wire message into a validated :class:`Request`, and build spec-shaped
success/error responses. Nothing here runs a capability, reaches a host, or makes a trust decision —
it is pure string/JSON plumbing, so the same code serves both the EXPOSE server and the CONSUME
client.

Untrusted-input doctrine (every byte off the wire is hostile until proven otherwise):
  * BOUNDED. A message over ``max_bytes`` is rejected before ``json.loads`` — no unbounded buffer.
  * SAFE PARSE. ``json.loads`` only (never ``eval``/``exec``/pickle); any parse failure is a clean
    ``-32700`` response, never a traceback.
  * STRICT ENVELOPE. ``jsonrpc == "2.0"`` and a string ``method`` are required; a bad envelope is a
    clean ``-32600``. ``params``, when present, must be an object or array.
  * DETERMINISTIC. Pure functions of their input — no wallclock, no rng. Response ``id`` is ECHOED
    from the request, never generated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# JSON-RPC 2.0 reserved error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

JSONRPC_VERSION = "2.0"

# Default hard cap on a single wire message (1 MiB). A local tool exchanges small JSON; anything
# larger is treated as hostile/oversized and refused before it is parsed.
MAX_MESSAGE_BYTES = 1 << 20


@dataclass(frozen=True)
class Request:
    """A validated JSON-RPC 2.0 request/notification. ``is_notification`` is True when the message
    carried no ``id`` (the client wants no response). ``id`` is echoed verbatim into the response."""

    method: str
    params: Any            # dict | list | None (validated to one of these)
    id: Any                # the echoed id (str | int | float | None); meaningless if is_notification
    is_notification: bool


def _as_text(raw: str | bytes) -> str | None:
    """Decode wire bytes to text WITHOUT raising. Invalid UTF-8 → None (a parse error upstream)."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            return bytes(raw).decode("utf-8")
        except Exception:
            return None
    return None


def parse_request(raw: str | bytes, *, max_bytes: int = MAX_MESSAGE_BYTES) -> tuple[Request | None, dict | None]:
    """Parse and VALIDATE one untrusted wire message.

    Returns ``(request, None)`` on success or ``(None, error_response)`` on any failure — the error
    response is a fully-formed JSON-RPC error object ready to serialize (``id`` recovered from the
    payload when possible, else null). Never raises."""
    text = _as_text(raw)
    if text is None:
        return None, err_response(None, PARSE_ERROR, "message is not valid UTF-8 text")

    # BOUND before parsing — measure the encoded byte length, not the character count.
    if len(text.encode("utf-8", "ignore")) > max(0, int(max_bytes)):
        return None, err_response(None, INVALID_REQUEST, "message exceeds maximum size")

    stripped = text.strip()
    if not stripped:
        return None, err_response(None, PARSE_ERROR, "empty message")

    try:
        payload = json.loads(stripped)
    except Exception:
        return None, err_response(None, PARSE_ERROR, "message is not well-formed JSON")

    # Batches (a JSON array of calls) are not supported by this minimal seam — refuse cleanly.
    if not isinstance(payload, dict):
        return None, err_response(None, INVALID_REQUEST,
                                  "request must be a single JSON-RPC object")

    # An id, when present, MUST be a string/number/null — an object/array/bool id is malformed.
    if "id" in payload and not _valid_id(payload.get("id")):
        return None, err_response(None, INVALID_REQUEST, "id must be a string, number, or null")
    rid = payload.get("id")
    has_id = "id" in payload

    if payload.get("jsonrpc") != JSONRPC_VERSION:
        return None, err_response(rid, INVALID_REQUEST, "jsonrpc must be exactly '2.0'")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        return None, err_response(rid, INVALID_REQUEST, "method must be a non-empty string")

    params = payload.get("params")
    if params is not None and not isinstance(params, (dict, list)):
        return None, err_response(rid, INVALID_PARAMS, "params must be an object or array")

    return Request(method=method, params=params, id=rid, is_notification=not has_id), None


def _valid_id(rid: Any) -> bool:
    """A JSON-RPC id may be a string, a number, or null. Objects/arrays/bools are not valid ids."""
    return rid is None or (isinstance(rid, (str, int, float)) and not isinstance(rid, bool))


def ok_response(rid: Any, result: Any) -> dict:
    """A JSON-RPC 2.0 success response echoing ``rid``."""
    return {"jsonrpc": JSONRPC_VERSION, "id": rid, "result": result}


def err_response(rid: Any, code: int, message: str, *, data: Any = None) -> dict:
    """A JSON-RPC 2.0 error response echoing ``rid`` (null when the id could not be recovered)."""
    err: dict[str, Any] = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": rid, "error": err}


def dumps(obj: Any) -> str:
    """Serialize a response to a single-line JSON string (newline-delimited framing safe). Uses
    ``default=str`` so an unexpected non-JSON value degrades to its string form rather than raising."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
