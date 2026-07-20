"""
aegis.middleware — the light WSGI shim + the raw ``/aegis/detect`` HTTP boundary (tier C).

Minimal for the MVP: a WSGI middleware that watches for honeypot-path fetches (the class-4
tripwire) passively, and a ``detect_http`` entry that ingests a raw ``TelemetryEnvelope`` JSON
body and returns a ``Verdict`` JSON. The untrusted-input hardening lives at the boundary
(``aegis.boundary``); this module only wires it to a request.

DOCTRINE: default read-only. The middleware NEVER blocks or challenges in ``observe`` mode —
it only records a passive verdict (available to the operator's own logging). Any response
action is opt-in ``enforce`` mode and would ride the existing ``invoke_tool`` gate (roadmap).
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .boundary import BoundaryError
from .models import ActorRef, Surface, Verdict


class AegisWSGIMiddleware:
    """A passive WSGI middleware: for every request it derives an ActorRef and, if the path is
    a seeded honeypot, records an AEGIS verdict via ``aegis.observe``. It NEVER alters the
    response in the default observe mode; ``on_verdict`` lets the operator sink the verdict
    (log/metric) without AEGIS acting."""

    def __init__(self, app: Callable, aegis: "Any", *,
                 on_verdict: Callable[[Verdict], None] | None = None) -> None:
        self._app = app
        self._aegis = aegis
        self._on_verdict = on_verdict

    def __call__(self, environ: dict, start_response: Callable):
        path = environ.get("PATH_INFO", "") or ""
        if self._aegis.guard.is_honeypot(path):
            actor = ActorRef(
                ip=environ.get("REMOTE_ADDR", "") or "",
                session=environ.get("HTTP_X_SESSION_ID", "") or "",
                principal=environ.get("REMOTE_USER", "") or "")
            ua = environ.get("HTTP_USER_AGENT", "") or ""
            verdict = self._aegis.observe(
                surface=Surface.REQUEST, actor=actor, requested_path=path,
                crawler_allowlisted=self._aegis.guard.is_allowlisted(ua))
            if self._on_verdict is not None:
                self._on_verdict(verdict)
        return self._app(environ, start_response)


def detect_http(body: bytes | str, aegis: "Any", *, crawler_allowlisted: bool = False) -> tuple[int, dict[str, Any]]:
    """The raw ``POST /aegis/detect`` entry: ingest a bounded TelemetryEnvelope JSON body and
    return ``(status, verdict_dict)``. A boundary rejection is a fail-closed HTTP 400 — never a
    silent pass, never an exception leaking to the caller."""
    from .pipeline import detect
    try:
        verdict = detect(body, config=aegis.config, guard=aegis.guard,
                         actor_graph=aegis.actor_graph, crawler_allowlisted=crawler_allowlisted)
    except BoundaryError as e:
        return 400, {"error": "boundary_rejected", "detail": str(e)}
    return 200, json.loads(verdict.model_dump_json())


def inspect_http(body: bytes | str, *, enforce: bool = False,
                 honeypot_paths: list[str] | None = None) -> tuple[int, dict[str, Any]]:
    """The SIDECAR API (the "add it in the form of an API" surface): ingest a JSON request
    description ``{method, path, headers, body}`` and return ``(status, verdict_dict)`` from the
    request-side oracles. The caller (the app, in any language) enforces the returned verdict itself
    — ``verdict["action"] == "block"`` means AEGIS PROVED an attack (with a re-runnable certificate).
    ``decision == "clear"`` is NOT "safe", only "nothing proved". Bounded, fail-closed on malformed
    input (HTTP 400), total (never raises)."""
    from .inspect import inspect_request
    try:
        data = json.loads(body) if isinstance(body, (str, bytes, bytearray)) else body
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object with method/path/headers/body")
        method = str(data.get("method", "GET"))
        path = str(data.get("path", "/"))
        raw_headers = data.get("headers") or []
        if isinstance(raw_headers, dict):
            headers = [(str(k), str(v)) for k, v in raw_headers.items()]
        else:
            headers = [(str(h[0]), str(h[1])) for h in raw_headers if isinstance(h, (list, tuple)) and len(h) >= 2]
        rbody = data.get("body")
        rbody = str(rbody) if rbody is not None else None
    except Exception as e:
        return 400, {"error": "bad_request", "detail": str(e)}
    verdict = inspect_request(method, path, headers, rbody,
                              honeypot_paths=list(honeypot_paths or ()), enforce=enforce)
    if verdict is None:
        return 200, {"decision": "clear", "action": "allow", "attack_class": ""}
    return 200, json.loads(verdict.model_dump_json())


def _wsgi_request(environ: dict) -> tuple[str, str, list[tuple[str, str]], str | None]:
    """Extract ``(method, path?query, headers, body)`` from a WSGI environ, BUFFERING the request
    body and replacing ``wsgi.input`` so the wrapped app still reads it unchanged."""
    import io
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "") or "/"
    if environ.get("QUERY_STRING"):
        path += "?" + environ["QUERY_STRING"]
    headers: list[tuple[str, str]] = []
    if environ.get("CONTENT_TYPE"):
        headers.append(("Content-Type", environ["CONTENT_TYPE"]))
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers.append((k[5:].replace("_", "-").title(), str(v)))
    body: str | None = None
    try:
        length = int(environ.get("CONTENT_LENGTH", "0") or "0")
    except ValueError:
        length = 0
    if length > 0 and length <= 10 * 1024 * 1024 and environ.get("wsgi.input") is not None:
        raw = environ["wsgi.input"].read(length)
        environ["wsgi.input"] = io.BytesIO(raw)   # put it back for the app
        body = raw.decode("utf-8", "replace")
    return method, path, headers, body


class AegisEnforceMiddleware:
    """An ENFORCING in-process WSGI middleware — the lowest-latency "add AEGIS" option for a Python/
    WSGI app. It inspects each request with the request-side oracles and, ONLY under ``enforce`` mode
    AND on a CONFIRMED verdict, returns 403 WITHOUT calling the app (doctrine D1). Everything else
    calls the app unchanged (FAIL-OPEN): observe mode, an unproven request, or any inspection error
    all pass through. The request body is buffered and restored, so the app reads it normally."""

    def __init__(self, app: Callable, config: "Any", *,
                 on_verdict: Callable[[Verdict], None] | None = None) -> None:
        self._app = app
        self._config = config
        self._on_verdict = on_verdict

    def __call__(self, environ: dict, start_response: Callable):
        from .inspect import inspect_request
        enforce = getattr(self._config, "mode", "observe") == "enforce"
        verdict: Verdict | None = None
        try:
            method, path, headers, body = _wsgi_request(environ)
            verdict = inspect_request(method, path, headers, body,
                                      honeypot_paths=list(getattr(self._config, "honeypot_paths", []) or []),
                                      enforce=enforce)
        except Exception:
            verdict = None
        if verdict is not None and self._on_verdict is not None:
            try:
                self._on_verdict(verdict)
            except Exception:
                pass
        if verdict is not None and verdict.decision == "confirmed" and verdict.action == "block":
            cid = verdict.certificate.cert_id if verdict.certificate else ""
            payload = json.dumps({"blocked": True, "by": "aegis", "attack_class": verdict.attack_class,
                                  "certificate": cid}).encode("utf-8")
            start_response("403 Forbidden", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("X-Aegis-Block", verdict.attack_class),
                ("X-Aegis-Certificate", cid)])
            return [payload]
        return self._app(environ, start_response)
