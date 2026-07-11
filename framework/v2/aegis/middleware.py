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
