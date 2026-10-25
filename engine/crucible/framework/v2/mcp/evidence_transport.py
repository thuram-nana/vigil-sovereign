"""
mcp.evidence_transport — the PRODUCTION HTTP transport for CONSUMING an operator's external MCP
*evidence* server, pinned to the never-liftable egress FLOOR (the evidence-connector, "Module C").

Where :class:`mcp.client.StdioSubprocessTransport` speaks JSON-RPC 2.0 to a *local* child MCP server
over stdio pipes, this is its network-facing sibling: it speaks the SAME JSON-RPC request/response
contract to a *remote* MCP server the operator has explicitly provisioned, over HTTP, THROUGH the
sovereign egress guard. It is a plain :data:`mcp.client.Transport` — a callable ``(request) -> response``
— so an :class:`mcp.client.MCPClient` drives it exactly like the stdio transport, and a consuming
evidence sensor wraps the result.

Doctrine — this module is pure plumbing and makes NO trust decision:
  * THIRD-PARTY SAY-SO → LEAD, NEVER A FACT. Everything an external MCP server returns is one remote
    party's claim. This transport returns it verbatim as a dict; it never calls ``confirm()``, never
    writes a Finding, and never constructs a ``GroundingToken.oracle``. The consuming sensor ingests it
    as a provenance-labelled intel LEAD (``IntelSourceKind``, Admiralty C3) that a deterministic
    CRUCIBLE oracle must re-fire over a trusted-channel capture to promote. Promotion lives downstream,
    never here.
  * EVERY OUTBOUND BYTE PASSES THE FLOOR. The request is issued through the exact client
    ``agents.http_executor._client`` builds: an ``httpx.Client`` wrapping
    :class:`agents.egress_guard.SovereignHttpxTransport` with ``sovereign_only=False`` — so the
    operator's NAME allowlist is ALWAYS enforced (in every sovereignty mode, not only sovereign-strict)
    — under which the never-liftable Tier-1a L3/L4 ADDRESS floor (``vigil_gateway.denylist`` or its
    pure-stdlib backstop) resolves-once / validates-all / dials-only-validated. A metadata / link-local
    / RFC1918 / multicast / CGNAT / reserved address (directly or via a DNS-rebinding answer) and any
    off-allowlist host are REFUSED (``SovereigntyViolation``) before a byte leaves the host. A refusal
    is re-raised unchanged — fail-closed — never softened into a normal result.
  * UNTRUSTED RESPONSE. No redirects are ever followed (``follow_redirects=False``; a 3xx is an error,
    not a hop); the response body is read BOUNDED (never an unbounded buffer); a per-call timeout
    applies; only ``json.loads`` parses it; a non-2xx / malformed / oversized / non-object response is a
    structured :class:`MCPClientError`, never a crash and never a silent success. Mirrors the
    untrusted-response doctrine of :class:`mcp.client.StdioSubprocessTransport`.
  * SECRET HYGIENE. The operator's bearer token is sent only as an ``Authorization: Bearer`` request
    header — never in the URL, never in an exception message, never in ``repr``, never logged.

Stdlib + framework/vigil_core only (``httpx`` is the shared egress dependency the guard itself uses); no
sigil import, no integration-layer import.
"""

from __future__ import annotations

import json
from typing import Callable

import httpx

from ..agents.egress_guard import EgressAllowlist, SovereignHttpxTransport
from ..common.errors import SovereigntyViolation
from .client import MCPClientError
from .protocol import MAX_MESSAGE_BYTES


class FloorPinnedHttpTransport:
    """A :data:`mcp.client.Transport` (callable ``(request_dict) -> response_dict``) that speaks JSON-RPC
    2.0 to an operator's external MCP server over HTTP, through the sovereign egress guard + the
    never-liftable L3/L4 egress floor. The production, network-facing counterpart of
    :class:`mcp.client.StdioSubprocessTransport`.

    Fail-closed everywhere: an off-allowlist host, a metadata/link-local/RFC1918/multicast/CGNAT/
    reserved destination (directly or via DNS rebinding), a non-2xx HTTP status (a redirect included), an
    oversized request or response, and malformed/non-object JSON are all refused — the first two as a
    :class:`SovereigntyViolation` (re-raised unchanged), the rest as a :class:`MCPClientError`.
    """

    def __init__(
        self,
        url: str,
        allowlist: EgressAllowlist,
        *,
        slug: str = "",
        token: str | None = None,
        timeout_s: float = 30.0,
        max_bytes: int = MAX_MESSAGE_BYTES,
        inner: "httpx.BaseTransport | None" = None,
        resolver: Callable[..., object] | None = None,
    ) -> None:
        """
        ``url``        the external MCP server endpoint (absolute ``http``/``https`` URL with a host);
                       validated at construction (fail-closed) — every call POSTs JSON-RPC to it.
        ``allowlist``  the operator-only egress :class:`EgressAllowlist` (the NAME control); the server's
                       host must be permitted by it or the request is refused before any byte leaves.
        ``slug``       the engagement slug — supplies the charter IP literals that let the floor lift the
                       loopback/private tier for an exact literal (e.g. a loopback evidence server); the
                       metadata/link-local/reserved tier is never lifted.
        ``token``      an operator-provided bearer token → ``Authorization: Bearer <token>`` (never
                       logged / repr'd / put in the URL or an error); CR/LF is rejected (header-injection
                       guard). ``None``/empty => no Authorization header.
        ``timeout_s``  per-call timeout (connect/read/write/pool).
        ``max_bytes``  bounds BOTH the outbound request and the inbound response (default 1 MiB).
        ``inner``      TEST SEAM — inject an ``httpx.BaseTransport`` (e.g. ``httpx.MockTransport``). When
                       given, ``SovereignHttpxTransport`` applies the NAME control only (no floor backend,
                       no network); when ``None`` (production) the never-liftable floor backend is
                       installed under a real ``httpx.HTTPTransport``.
        ``resolver``   TEST SEAM — a ``getaddrinfo``-shaped callable injected into the floor backend so a
                       floor refusal can be exercised without real DNS.
        """
        if not isinstance(allowlist, EgressAllowlist):
            raise MCPClientError("allowlist must be an EgressAllowlist")
        self._url = self._validate_url(url)
        self._bearer = self._validate_token(token)
        self._timeout_s = float(timeout_s)
        self._max_bytes = max(1, int(max_bytes))
        # Build the egress guard EXACTLY as agents.http_executor._client does, with sovereign_only=False
        # so the operator's name allowlist is enforced in every mode (an external evidence server must
        # always be explicitly provisioned). Under it, the never-liftable L3/L4 floor pins every connect.
        self._sov = SovereignHttpxTransport(
            allowlist, inner=inner, sovereign_only=False, slug=str(slug), resolver=resolver)
        self._client = httpx.Client(
            transport=self._sov, timeout=self._timeout_s, follow_redirects=False)

    # ---------------------------------------------------------------- construction-time validation

    @staticmethod
    def _validate_url(url: str) -> str:
        try:
            parsed = httpx.URL(str(url))
        except Exception as e:  # malformed URL => refuse to construct (fail-closed)
            raise MCPClientError(
                f"invalid external MCP server URL: {type(e).__name__}") from e
        if parsed.scheme not in ("http", "https") or not parsed.host:
            raise MCPClientError(
                "external MCP server URL must be an absolute http(s) URL with a host")
        return str(parsed)

    @staticmethod
    def _validate_token(token: str | None) -> str | None:
        if token is None:
            return None
        t = str(token)
        if not t:
            return None
        if any(c in t for c in "\r\n"):
            # A newline in a header value is a request-splitting primitive; refuse rather than send it.
            raise MCPClientError("bearer token must not contain CR/LF (header-injection guard)")
        return t

    # ---------------------------------------------------------------- the Transport contract

    def __call__(self, request: dict) -> dict:
        """Send one JSON-RPC request object and return the raw response object. Raises
        :class:`SovereigntyViolation` on an egress refusal (fail-closed) or :class:`MCPClientError` on any
        HTTP/size/JSON failure. Never follows a redirect; never raises a raw/unexpected exception out of
        the normal path (the caller — :class:`MCPClient` — further degrades either to a structured error)."""
        try:
            body = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except Exception as e:
            raise MCPClientError(f"request is not JSON-serializable: {type(e).__name__}") from e
        if len(body) > self._max_bytes:
            raise MCPClientError("outbound request exceeds the maximum size")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"

        raw = bytearray()
        try:
            with self._client.stream("POST", self._url, content=body, headers=headers) as response:
                status = int(response.status_code)
                if status // 100 != 2:
                    # follow_redirects=False => a 3xx arrives here UNFOLLOWED; any non-2xx is a transport
                    # failure (a JSON-RPC *error* is a 200 with an "error" member, handled downstream).
                    raise MCPClientError(
                        f"external MCP server returned HTTP {status} (no redirect is ever followed)")
                for chunk in response.iter_bytes():
                    raw += chunk
                    if len(raw) > self._max_bytes:
                        raise MCPClientError("external MCP server response exceeds the maximum size")
        except SovereigntyViolation:
            raise                       # egress floor / name-allowlist refusal — fail closed, never soften
        except MCPClientError:
            raise
        except httpx.HTTPError as e:    # connect/timeout/protocol/read errors — never leak the token/body
            raise MCPClientError(
                f"HTTP transport error talking to the external MCP server: {type(e).__name__}") from e

        try:
            obj = json.loads(bytes(raw).decode("utf-8", "replace"))
        except Exception as e:
            raise MCPClientError(
                f"external MCP server returned invalid JSON: {type(e).__name__}") from e
        if not isinstance(obj, dict):
            raise MCPClientError("external MCP server response is not a JSON object")
        return obj

    def close(self) -> None:
        """Close the underlying ``httpx.Client`` (idempotent; never raises)."""
        try:
            self._client.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        # Secret-redacting: show ONLY the origin (scheme://host[:port]) — never the full URL (a path/query
        # could carry a token, e.g. ``?api_key=…``) and never the bearer. The config layer already refuses
        # a query/fragment on an evidence URL; this is the defence-in-depth backstop for any direct caller.
        try:
            u = httpx.URL(self._url)
            origin = f"{u.scheme}://{u.host}" + (f":{u.port}" if u.port else "")
        except Exception:
            origin = "<url>"
        return f"FloorPinnedHttpTransport(origin={origin!r}, token={'<set>' if self._bearer else None})"
