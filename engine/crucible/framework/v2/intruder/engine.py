"""
intruder.engine — run an attack and triage it.

``IntruderEngine.run`` drives an attack's rendered requests through the injected
``send`` (the scope/charter/kill-switch/egress/rate-gated executor in production),
records a results row per request (payloads, status, length, latency, grep flags),
and hands the population to the outlier detector. The output is the anomalous rows
— the needles a human would have hunted for in Burp's table, found automatically.

Bounded by ``max_requests`` so an autonomous fuzz cannot run away. Latency uses a
monotonic timer (an I/O measurement, not business logic), everything else is
deterministic given ``send``.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from ..scanner.insertion import HttpRequest, InsertionPoint, RequestTemplate
from .analysis import detect_outliers
from .attack import AttackType, render_attack


class AttackResultRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int
    payloads: tuple[str, ...]
    status: int
    length: int
    latency_ms: float
    body_excerpt: str = ""
    grep: dict[str, bool] = Field(default_factory=dict)
    error: str = ""


class AttackResult(BaseModel):
    """The full results table plus the indices flagged as anomalous."""

    model_config = ConfigDict(extra="forbid")

    rows: list[AttackResultRow] = Field(default_factory=list)
    outlier_indices: list[int] = Field(default_factory=list)
    requests_sent: int = 0
    truncated: bool = Field(default=False, description="True if the budget cut the attack short.")

    @property
    def outliers(self) -> list[AttackResultRow]:
        return [self.rows[i] for i in self.outlier_indices]


class IntruderEngine:
    """Runs an Intruder attack and triages the results. ``send(HttpRequest) ->
    {status, body, latency_ms?}`` is injected. ``grep`` expressions become
    per-row boolean columns (and any hit flags the row as an outlier)."""

    def __init__(
        self,
        send,
        *,
        max_requests: int = 10000,
        grep: tuple[str, ...] = (),
    ) -> None:
        self._send = send
        self.max_requests = max_requests
        self.grep = grep

    def run(
        self,
        template: RequestTemplate,
        positions: list[InsertionPoint],
        generators: list[Iterable[str]],
        attack_type: AttackType,
    ) -> AttackResult:
        rows: list[AttackResultRow] = []
        truncated = False
        for i, (payloads, req) in enumerate(
            render_attack(template, positions, generators, attack_type)
        ):
            if self.max_requests and i >= self.max_requests:
                truncated = True
                break
            rows.append(self._issue(i, payloads, req))

        outliers = detect_outliers(rows)
        return AttackResult(
            rows=rows, outlier_indices=outliers, requests_sent=len(rows), truncated=truncated
        )

    def _issue(self, index: int, payloads: tuple[str, ...], req: HttpRequest) -> AttackResultRow:
        t0 = time.monotonic()
        try:
            resp = self._send(req)
            latency = (time.monotonic() - t0) * 1000.0
            status = int(resp.get("status", 0)) if isinstance(resp, dict) else 0
            body = str(resp.get("body", "")) if isinstance(resp, dict) else str(resp)
            grep = {expr: (expr in body) for expr in self.grep}
            return AttackResultRow(
                index=index, payloads=payloads, status=status, length=len(body),
                latency_ms=latency, body_excerpt=body[:200], grep=grep,
            )
        except Exception as e:  # a single failed request must not sink the attack
            latency = (time.monotonic() - t0) * 1000.0
            return AttackResultRow(
                index=index, payloads=payloads, status=0, length=0,
                latency_ms=latency, error=f"{type(e).__name__}: {e}",
            )
