"""
scanner.engine — the autonomous audit engine.

This is the zero-manual replacement for a human driving Burp's Scanner + Intruder
by hand. Given one request, it enumerates every insertion point (``insertion``),
fires every applicable check (``checks``) into each, and hands the observed
responses to the deterministic oracle layer (``verify``) for confirmation. A
finding is emitted only when a real oracle signal fires — no LLM say-so, no
heuristic — so the output is precision-anchored.

It sends nothing itself: a ``send`` callable is injected. In production that is
the scope/charter/kill-switch/egress/rate-gated executor, so authorization stays
enforced; in tests it is a loopback client against an operator-owned target. A
request budget bounds the sweep so an autonomous run cannot blow up.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from ..verify.confirmation import confirm_finding
from ..verify.verifier import OracleVerifier
from .checks import DEFAULT_CHECKS, Check, Send
from .insertion import HttpRequest, InsertionKind, RequestTemplate


class AuditFinding(BaseModel):
    """One oracle-confirmed finding: the check that produced it, the exact
    insertion point, and the deterministic proof (which oracle fired, its
    calibrated confidence, and the rationale)."""

    model_config = ConfigDict(extra="forbid")

    check_id: str
    bug_class: str
    insertion_point: str = Field(description="The point id (kind:locator) the payload hit.")
    param: str = Field(description="Human name of the point (param/header/cookie/pointer).")
    confidence: float = Field(ge=0.0, le=1.0)
    confirmed_by: str = Field(description="The oracle kind that fired.")
    rationale: str = ""


class BudgetExceeded(RuntimeError):
    """Raised internally when the request budget is hit; the audit returns what
    it has confirmed so far rather than sending more traffic."""


class AuditEngine:
    """Drives checks across a request's insertion points, confirming via oracles.

    ``send(HttpRequest) -> {status, body, latency_ms?}`` is the only I/O; it is
    injected so the engine stays testable and so production runs funnel through
    the gated executor. ``max_requests`` caps the sweep (0 = unbounded)."""

    def __init__(
        self,
        send: Send,
        *,
        verifier: OracleVerifier | None = None,
        max_requests: int = 0,
    ) -> None:
        self._send = send
        self.verifier = verifier or OracleVerifier()
        self.max_requests = max_requests
        self.requests_sent = 0

    def _counted_send(self, request: HttpRequest) -> dict:
        if self.max_requests and self.requests_sent >= self.max_requests:
            raise BudgetExceeded()
        self.requests_sent += 1
        return self._send(request)

    def audit(
        self,
        request: HttpRequest,
        checks: tuple[Check, ...] = DEFAULT_CHECKS,
        *,
        insertion_kinds: tuple[InsertionKind, ...] | None = None,
    ) -> list[AuditFinding]:
        """Sweep ``checks`` across ``request``'s insertion points and return the
        oracle-confirmed findings, de-duplicated per (bug_class, insertion point).

        Deterministic given ``send``: insertion points and checks are iterated in
        a stable order. Stops early (returning what is confirmed) if the request
        budget is exhausted."""
        template = RequestTemplate(request)
        points = template.insertion_points(kinds=insertion_kinds)
        seen: set[tuple[str, str]] = set()
        findings: list[AuditFinding] = []
        try:
            for point in points:
                for check in checks:
                    key = (check.bug_class, point.id)
                    if key in seen:
                        continue
                    ctx = check.probe(template, point, self._counted_send)
                    if ctx is None:
                        continue
                    confirmed = confirm_finding(
                        finding={
                            "bug_class": check.bug_class,
                            "title": f"{check.bug_class} via {point.name}",
                            "severity": "High",
                            "surface": point.id,
                            "summary": f"{check.id} probe fired an oracle at {point.name}",
                        },
                        context=ctx,
                        verifier=self.verifier,
                    )
                    if confirmed is None:
                        continue
                    seen.add(key)
                    kind = confirmed.confirmed_by
                    findings.append(AuditFinding(
                        check_id=check.id,
                        bug_class=check.bug_class,
                        insertion_point=point.id,
                        param=point.name,
                        confidence=confirmed.confidence,
                        confirmed_by=kind.value if hasattr(kind, "value") else str(kind),
                        rationale=confirmed.rationale,
                    ))
        except BudgetExceeded:
            pass
        return findings
