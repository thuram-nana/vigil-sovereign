"""
warden_gate — the WARDEN raise-only tool-NAME floor for offense tools (VIGIL P7 Slice 2).

Every offense tool call is gated by its CLASS/NAME here, not by its target — target authorization
is the P6 egress gateway's job (this gate asserts only "is a tool of THIS class permitted, and does
it need owner approval"). The SIGIL WARDEN kernel classifies a tool name to a tier A0..A3
(danger-first, whole-token, fail-closed to A3). Two facts from the seam map drive this module:

  * Read-shaped offense names auto-classify LOW: ``http.get`` / ``dns.query`` / ``port.list`` all
    contain an A0 verb token and classify to A0, which would AUTO-RUN. So a raise-only FLOOR
    (default A2) is imposed the same ``max()`` way the kernel's own registry raises a pin — the
    floor can only ever RAISE a tool's tier, never lower it.
  * The Governor auto-approves only tiers at/below the auto-bar (A1) AND at/below the agent's
    ceiling. Setting the offense ceiling to A1 with an A2 floor means every offense tool is QUEUED
    for owner approval — offense never auto-runs. (Posture knob: on a TWIN/STAGING target the
    operator may lower the floor to A1 so recon auto-runs while destructive/exec stays A3→queue.)

Classification is delegated to an INJECTABLE classifier (default: the ``sigil-kernel`` binary via
subprocess, which is env-agnostic and fail-closed), so this module imports neither the SIGIL
package nor any offense engine — it is import-clean and lives on the shared integration seam.

The SDK wiring lands in TWO parts. (a) ATTACHING ``WardenGateHooks`` to the Strix ``Runner`` is done by
:func:`attach_from_env` — an ``install_from_env``-style OPT-IN soft-wire (see the proof_sink bootstrap in
``vendor/strix``): gated on the ``VIGIL_WARDEN_STRIX_GATE`` env var so standalone / non-governed Strix stays
byte-identical, it composes this gate onto the run hooks so Strix's arbitrary ``exec_command`` shell tool is
classified + gated (a non-AUTO classification RAISES ``WardenDenied`` → the tool call is BLOCKED). (b) The
tool-invoke wrapper that routes a QUEUE decision to the owner-signed approval queue — upgrading QUEUE from
hard-block to approve-then-run — is still DEFERRED; until it lands the hook fails safe (only an AUTO decision
runs, everything else hard-blocks). The DECISION CORE is complete and fully tested.

FATAL-2: this module is import-clean (stdlib only at module scope) so it loads in BOTH environments, but it
is OFFENSE-side — only the offense-env Strix process ever calls :func:`attach_from_env`; the sovereign never
loads it. The SDK (``agents.lifecycle``) and the classifier (``live.wiring.default_classify``) are imported
LAZILY inside the wiring functions, so importing this module never drags the offense engine or the SDK into
the sovereign environment.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Iterable

# Tier is represented as the kernel's own string labels ("A0".."A3") + an ordinal, rather than a
# third copy of the Tier enum (the seam map warned the Rust and Python enums must stay in sync;
# a third would be worse). The kernel emits these exact strings.
TIERS: tuple[str, ...] = ("A0", "A1", "A2", "A3")
_ORD = {t: i for i, t in enumerate(TIERS)}

DEFAULT_FLOOR = "A2"    # offense tools floor here — never auto-A0/A1 on a LIVE target
DEFAULT_CEILING = "A1"  # offense agent ceiling — anything above A1 must QUEUE (never auto-approve)
AUTO_BAR = "A1"         # mirrors governor AUTO_BAR: only <=A1 can auto

Classifier = Callable[[str], str]


class WardenDenied(RuntimeError):
    """A tool call the WARDEN gate refuses outright (a class that must never run, or — in the
    fail-safe hook — anything not auto-approved). Raised; must not be silently caught."""


@dataclass(frozen=True)
class ToolDecision:
    tool: str
    tier: str        # the floored, effective tier ("A0".."A3")
    outcome: str     # "auto" | "queue" | "deny"
    reason: str

    @property
    def auto(self) -> bool:
        return self.outcome == "auto"


def _tier_max(a: str, b: str) -> str:
    return a if _ORD.get(a, 3) >= _ORD.get(b, 3) else b


def decide_tool(
    tool_name: str,
    *,
    classify: Classifier,
    floor: str = DEFAULT_FLOOR,
    ceiling: str = DEFAULT_CEILING,
    denylist: Iterable[str] = (),
) -> ToolDecision:
    """Decide a tool call by name. Pure — the classifier is injected. Fail-closed throughout.

    - empty / unknown name or unknown classifier output → DENY (fail-closed A3).
    - a name on ``denylist`` → DENY.
    - else tier = max(classify(name), floor) (raise-only) → AUTO iff tier<=A1 AND tier<=ceiling,
      else QUEUE.
    """
    name = (tool_name or "").strip()
    if not name:
        return ToolDecision("", "A3", "deny", "empty tool name (fail-closed)")
    if name in set(denylist):
        return ToolDecision(name, "A3", "deny", f"tool {name!r} is on the hard denylist")

    base = classify(name)
    if base not in _ORD:
        base = "A3"  # a classifier that returned garbage is treated as maximally dangerous
    fl = floor if floor in _ORD else "A3"
    tier = _tier_max(base, fl)

    if _ORD[tier] <= _ORD[AUTO_BAR] and _ORD[tier] <= _ORD.get(ceiling, 0):
        return ToolDecision(name, tier, "auto", f"{tier} is at/below the auto-bar and the ceiling")
    return ToolDecision(
        name, tier, "queue",
        f"{tier} requires owner approval (>= A2 or above the offense ceiling {ceiling})",
    )


def kernel_classifier(kernel_bin: str | None = None, *, timeout: float = 15.0) -> Classifier:
    """A classifier backed by the ``sigil-kernel classify`` CLI (env-agnostic subprocess).

    NOTE: this is the OPTIONAL real-kernel classifier. The LIVE offense gate wires the pure in-process
    ``live.wiring.default_classify`` (no subprocess), so this factory is exercised only when a caller
    explicitly opts into the Rust kernel. It stays import-clean (no sigil / offense import) by design.

    Returns a function name->tier-string. Fail-closed: ANY failure (missing binary, timeout,
    non-zero exit, unparseable output, unknown tier) yields "A3". Results are cached by name
    (classify is pure/deterministic) so a hook gating many tools does not re-shell per call.

    An UNRESOLVED binary (no explicit ``kernel_bin`` and none on PATH) fail-closes to A3 WITHOUT executing
    a bare ``sigil-kernel`` name — a bare-name exec would resolve via PATH at call time, letting an attacker
    who plants a ``sigil-kernel`` on PATH control tier decisions (the same verify≠exec footgun the sigil
    side's kernel pin closes). Verifying the binary's owner-signed pin here is out of scope until this
    path is wired live (it would need the owner pubkey + manifest plumbed cross-env)."""
    resolved = kernel_bin or shutil.which("sigil-kernel")   # None if unresolved — NO bare-name fallback
    cache: dict[str, str] = {}

    def classify(name: str) -> str:
        if name in cache:
            return cache[name]
        if not resolved:
            return "A3"   # unresolved → fail-closed; never bare-name-exec an attacker-planted PATH binary
        tier = "A3"
        try:
            proc = subprocess.run(
                [resolved, "classify", name, "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                last = proc.stdout.strip().splitlines()[-1]
                obj = json.loads(last)
                t = obj.get("tier") if isinstance(obj, dict) else None
                if t in _ORD:
                    tier = t
        except Exception:
            tier = "A3"  # fail-closed
        cache[name] = tier
        return tier

    return classify


class WardenGateHooks:
    """Duck-typed openai-agents ``RunHooks`` adapter for the tool-name gate.

    Not a subclass of the SDK ``RunHooks`` (the SDK isn't vendored on disk) — it exposes the same
    ``async on_tool_start(context, agent, tool)`` shape so it can be composed/attached once the SDK
    is available. Per the seam map, ``on_tool_start``'s return value is ignored and the ONLY way to
    block a call is to RAISE, so this adapter is deliberately fail-safe: it raises ``WardenDenied``
    for anything that is not an AUTO decision. A QUEUE decision therefore blocks (does not run)
    until the graceful approval-queue wrapper is wired — a future slice upgrades QUEUE from
    hard-block to approve-then-run. Every decision is recorded for audit/testing.
    """

    def __init__(
        self,
        *,
        classify: Classifier,
        floor: str = DEFAULT_FLOOR,
        ceiling: str = DEFAULT_CEILING,
        denylist: Iterable[str] = (),
    ):
        self._classify = classify
        self._floor = floor
        self._ceiling = ceiling
        self._denylist = tuple(denylist)
        self.decisions: list[ToolDecision] = []

    def evaluate(self, tool_name: str) -> ToolDecision:
        d = decide_tool(
            tool_name, classify=self._classify, floor=self._floor,
            ceiling=self._ceiling, denylist=self._denylist,
        )
        self.decisions.append(d)
        return d

    async def on_tool_start(self, context, agent, tool) -> None:
        name = getattr(tool, "name", None) or str(tool)
        decision = self.evaluate(name)
        if not decision.auto:
            raise WardenDenied(
                f"WARDEN gate blocked tool {name!r}: {decision.outcome} ({decision.reason}). "
                f"Offense tools at/above A2 require owner approval; not yet wired to the queue."
            )


# ---------------------------------------------------------------------------------------------------
# T3 — the Strix runner soft-wire: compose this offense-side gate onto Strix's run hooks, opt-in.
# ---------------------------------------------------------------------------------------------------

# The explicit opt-in for the Strix WARDEN wire. Absent (or empty) ⇒ :func:`attach_from_env` is a NO-OP and
# vendored / non-governed Strix behaves byte-identically. A VIGIL-governed run sets this to route Strix's
# arbitrary shell through the gate. It is a posture switch only — it can never LOWER a tier or auto-allow.
_STRIX_GATE_ENV = "VIGIL_WARDEN_STRIX_GATE"


def compose_run_hooks(*members: Any) -> Any:
    """Compose N openai-agents ``RunHooks``-shaped objects into ONE ``RunHooks`` that fans each lifecycle
    callback out to every member in order. Used to run Strix's existing ``ReportUsageHooks`` (SDK usage /
    budget accounting) AND this module's :class:`WardenGateHooks` (the ``on_tool_start`` tool-name gate) off
    a single hooks object, because the SDK ``Runner`` accepts only one. A member that does not implement a
    given callback is skipped; a ``WardenDenied`` raised by a member's ``on_tool_start`` PROPAGATES (that is
    exactly how a denied classification BLOCKS the tool call). Forwarding is signature-agnostic
    (``*args, **kwargs``) so it is robust to SDK callback-arity changes.

    The SDK base class (``agents.lifecycle.RunHooks``) is imported LAZILY here — offense-env only — so this
    module stays import-clean in the sovereign environment (FATAL-2)."""
    from agents.lifecycle import RunHooks   # lazy — offense/SDK env only; never at module scope (FATAL-2)

    active = [m for m in members if m is not None]

    class _CompositeRunHooks(RunHooks):   # type: ignore[misc,valid-type]
        async def _fan(self, method: str, *args: Any, **kwargs: Any) -> None:
            for m in active:
                fn = getattr(m, method, None)
                if fn is None:
                    continue
                await fn(*args, **kwargs)   # a WardenDenied propagates here → blocks the tool call

        async def on_agent_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_agent_start", *a, **k)

        async def on_agent_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_agent_end", *a, **k)

        async def on_handoff(self, *a: Any, **k: Any) -> None:
            await self._fan("on_handoff", *a, **k)

        async def on_tool_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_tool_start", *a, **k)

        async def on_tool_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_tool_end", *a, **k)

        async def on_llm_start(self, *a: Any, **k: Any) -> None:
            await self._fan("on_llm_start", *a, **k)

        async def on_llm_end(self, *a: Any, **k: Any) -> None:
            await self._fan("on_llm_end", *a, **k)

    return _CompositeRunHooks()


def attach_from_env(base_hooks: Any) -> Any:
    """Best-effort compose this offense-side WARDEN tool-name gate onto Strix's run ``base_hooks``, GATED on
    the explicit opt-in env var ``VIGIL_WARDEN_STRIX_GATE``. Returns ``base_hooks`` UNCHANGED when the gate
    is not opted in, when the integration/SDK cannot be wired, or on ANY failure — so vendored / non-governed
    Strix is byte-identical and a wiring error can never stop a scan. When opted in, returns a composite
    ``RunHooks`` that runs the existing accounting AND the WARDEN ``on_tool_start`` gate, where a non-AUTO
    classification RAISES ``WardenDenied`` and BLOCKS the tool call (Strix's arbitrary ``exec_command`` shell
    classifies A3 → blocked).

    The gate uses the SAME classifier the live offense gate uses (``live.wiring.default_classify``) and the
    module-default floor/ceiling (A2 / A1) — fully fail-closed: an offense tool never auto-runs; it
    hard-blocks until the signed approval queue is wired (a future slice). Classifier + SDK are imported
    LAZILY (offense-env only), keeping this module import-clean in the sovereign env (FATAL-2)."""
    if not os.environ.get(_STRIX_GATE_ENV):
        return base_hooks
    try:
        from .live.wiring import default_classify   # lazy — offense-env only (pulls the live engine)
        warden = WardenGateHooks(classify=default_classify)
        return compose_run_hooks(base_hooks, warden)
    except Exception:  # noqa: BLE001 — never let WARDEN wiring stop a scan; fall back to the base hooks
        return base_hooks
