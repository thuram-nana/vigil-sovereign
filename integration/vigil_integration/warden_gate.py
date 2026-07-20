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

The SDK wiring (attaching ``WardenGateHooks`` to the Strix ``Runner`` and the tool-invoke wrapper
that routes a QUEUE decision to the owner-signed approval queue) is a DEFERRED integration gate —
the openai-agents SDK is not vendored on disk, so it can't be exercised here. The DECISION CORE
below is complete and fully tested; the hook adapter fails safe (only an AUTO decision runs) until
that wiring lands.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable

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

    Returns a function name->tier-string. Fail-closed: ANY failure (missing binary, timeout,
    non-zero exit, unparseable output, unknown tier) yields "A3". Results are cached by name
    (classify is pure/deterministic) so a hook gating many tools does not re-shell per call.
    """
    resolved = kernel_bin or shutil.which("sigil-kernel") or "sigil-kernel"
    cache: dict[str, str] = {}

    def classify(name: str) -> str:
        if name in cache:
            return cache[name]
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
