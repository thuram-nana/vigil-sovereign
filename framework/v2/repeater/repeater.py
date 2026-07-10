"""
repeater.repeater — the ``Repeater`` façade: capture -> edit -> gated replay -> transcript (W4.D).

The operator-facing (and engine-facing) surface. It ties the pieces together WITHOUT ever holding
a raw socket: every replay goes through ``agents.tools.invoke_tool`` -> ``HttpRepeaterTool`` ->
``HttpExecutor.gated_fetch``, so the full fail-closed chain (kill-switch / entitlement / scope /
destructive-confirm / budget / rate-limit / egress) runs on every request and the correlatable UA
is forced. A refused replay sends nothing and is still recorded (refusals are evidence).

Three audit trails, by construction:
  * the in-memory ``transcript`` — the ordered (request, response) pairs of the session;
  * the executor's on-disk evidence archive (``targets/<slug>/evidence/<action_id>/``);
  * the immutable event spine — ``invoke_tool`` records ``tool_call`` / ``tool_result`` (and a
    ``refusal`` when a gate fires) when a ``sink`` is provided.

Prove-don't-guess: a captured response is a provenance-labelled OBSERVATION. Use
``RepeaterExchange.oracle_context_with`` to hand a baseline/probe PAIR to the deterministic
differential oracle — the repeater never promotes a response to a finding on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..agents.tools import ToolContext, ToolRegistry, ToolResult, invoke_tool
from .models import RepeaterExchange, RepeaterRequest
from .tool import HttpRepeaterTool


def build_repeater_registry(
    *, request_budget: int = 100, timeout_seconds: float = 30.0, executor_factory: Any = None,
) -> tuple[ToolRegistry, HttpRepeaterTool]:
    """A fresh registry holding a single ``HttpRepeaterTool``, plus the tool instance (so the
    façade can ``close`` its executors). Kept OFF the built-in tool/sensor registries so the
    repeater is opt-in and never on the scanner-benchmark path."""
    tool = HttpRepeaterTool(
        request_budget=request_budget, timeout_seconds=timeout_seconds,
        executor_factory=executor_factory,
    )
    registry = ToolRegistry()
    registry.register(tool)
    return registry, tool


@dataclass
class Repeater:
    """Capture, edit, and REPLAY HTTP requests against an in-scope target — gated, correlatable,
    audit-logged.

    Construct one per engagement (``slug`` binds it to the charter / scope / kill-switch /
    evidence paths). ``prompt_callback`` (``(question, timeout_s) -> bool``, default-deny) backs
    the executor's per-request destructive-confirm. ``sink`` (a duck-typed ``agents.SpineSink``)
    mirrors every replay onto the event spine. ``dry_run`` exercises the whole gate chain but the
    executor never touches the network."""

    slug: str
    prompt_callback: Any = None
    dry_run: bool = False
    sink: Any = None
    request_budget: int = 100
    timeout_seconds: float = 30.0
    executor_factory: Any = None

    _registry: ToolRegistry = field(init=False)
    _tool: HttpRepeaterTool = field(init=False)
    _transcript: list[RepeaterExchange] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self._registry, self._tool = build_repeater_registry(
            request_budget=self.request_budget,
            timeout_seconds=self.timeout_seconds,
            executor_factory=self.executor_factory,
        )

    # ---- capture / edit (no I/O) -------------------------------------------------

    @staticmethod
    def capture(
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | Iterable[Any] | None = None,
        body: str | None = None,
    ) -> RepeaterRequest:
        """Capture a base request to later edit and replay. Performs no network I/O."""
        return RepeaterRequest.capture(url, method=method, headers=headers, body=body)

    # ---- replay (gated) ----------------------------------------------------------

    def replay(self, request: RepeaterRequest) -> RepeaterExchange:
        """Replay ``request`` through the full gate chain and record the exchange in the transcript.

        Fail-closed: an out-of-scope target, a missing ``EXPLOIT_EXECUTION`` entitlement, or a
        tripped kill-switch refuses at ``invoke_tool`` BEFORE the tool runs — nothing leaves the
        host — and the refusal is still recorded (as an exchange, and on the spine when a sink is
        set). The executor re-gates scope/destructive/budget/rate-limit/egress and forces the
        correlatable UA on anything that does go out."""
        ctx = ToolContext(
            slug=self.slug, prompt_callback=self.prompt_callback, dry_run=self.dry_run,
        )
        args = {
            "target": request.url,   # what the invoker scope-gates
            "url": request.url,      # what the executor issues (must equal target)
            "method": request.method,
            "headers": request.header_list(),
            "body": request.body,
        }
        result = invoke_tool(self._registry, self.name, args, ctx, sink=self.sink)
        exchange = _exchange_from_result(request, result)
        self._transcript.append(exchange)
        return exchange

    # ---- audit trail -------------------------------------------------------------

    @property
    def name(self) -> str:
        return self._tool.name

    def transcript(self) -> tuple[RepeaterExchange, ...]:
        """The ordered (request, response) pairs of this session — the in-memory audit trail."""
        return tuple(self._transcript)

    def last(self) -> RepeaterExchange | None:
        return self._transcript[-1] if self._transcript else None

    def stats(self) -> dict[str, int]:
        """Per-engagement executor counters (requests made, budget, scope violations, …), or an
        empty dict if no request has been issued yet (no executor built)."""
        ex = self._tool._executors.get(self.slug)  # noqa: SLF001 - façade owns the tool
        return ex.stats() if ex is not None else {}

    def close(self) -> None:
        self._tool.close()


def _exchange_from_result(request: RepeaterRequest, result: ToolResult) -> RepeaterExchange:
    """Map a gated ``ToolResult`` into a ``RepeaterExchange``. A gate refusal (at the invoker or
    the executor's inner chain) yields ``refused=True`` with the gate; a successful replay carries
    the captured response; anything else is a non-refusing failure (e.g. a malformed capture)."""
    output = result.output or {}
    if result.refused:
        return RepeaterExchange(
            request=request, response=None, refused=True,
            gate=result.gate, ok=False, note=result.note,
        )
    if result.ok:
        response = output.get("response") if isinstance(output, dict) else None
        return RepeaterExchange(
            request=request, response=response if isinstance(response, dict) else None,
            refused=False, gate="", ok=True, note=result.note,
            evidence={"request": output.get("request")} if isinstance(output, dict) else {},
        )
    return RepeaterExchange(
        request=request, response=None, refused=False, gate="", ok=False, note=result.note,
    )
