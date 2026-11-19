"""jobs.apex_retest_scheduler — APEX PR-3 Deliverable 3: the CONTINUOUS autonomous retest scheduler.

Once a finding is fixed, the fix must STAY fixed. This is the cadence driver that re-fires each watched,
confirmed finding's proof on an interval — proving fixes stay fixed and FLAGGING / RE-OPENING a regression the
moment an old vulnerability comes back. It REUSES the merged live retest re-proof (#1175): the per-finding
re-fire is the SAME deterministic, model-free primitive the customer retest uses (``redpen_fix.refire_reproduction``
against the current tree / verified host, or an offline ``reverify_context`` re-fire over the retained
``oracle_context``). The ``refire`` is INJECTED, so this module is the cadence + regression-detection layer on
top of the existing re-proof — it adds no new oracle and sends no traffic itself.

Soundness:
  * A finding is reported CLEARED only on POSITIVE evidence (``fired is False`` — every required run completed and
    none fired). ``fired is None`` (silence / timeout / unrunnable) is INCONCLUSIVE and NEVER clears — silence is
    not a fix. ``fired is True`` is STILL_PRESENT.
  * A REGRESSION is the transition "was confirmed CLEARED at least once → now STILL_PRESENT". It latches
    ``reopened`` so the finding is surfaced as re-opened until it clears again; the ``regression`` flag marks the
    TRANSITION tick (so an operator is alerted once, not every cadence). INCONCLUSIVE never clears and never
    re-opens.
  * Default OFF (``VIGIL_APEX_IMPACT``) ⇒ :func:`run_cadence_tick` is inert (no re-fire, no state change).
  * Deterministic: the cadence/regression logic reads only the INJECTED clock and the injected ``refire`` result
    — no wallclock, no RNG. Persistence is atomic (temp + ``os.replace``) and total (a torn file loads empty).

FATAL-2: module scope is stdlib + the pure ``vigil_core`` wire constants; the live re-fire is injected (the
caller wires ``redpen_fix.refire_reproduction``, framework-free), so this module is import-clean in either venv.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from vigil_core.retest_reproof import CLEARED, INCONCLUSIVE, STILL_PRESENT

from ..apex_flags import apex_impact_enabled

#: the injected per-finding re-fire: ``refire(watched) -> {"fired": True|False|None, "reason": str, ...}`` —
#: the SAME return shape as ``redpen_fix.refire_reproduction``. ``True`` = still present, ``False`` = POSITIVE
#: clearance (every run clean), ``None`` = inconclusive (silence is never a fix).
Refire = Callable[["WatchedFinding"], dict]


@dataclass
class WatchedFinding:
    """One confirmed finding under continuous retest. ``interval_s`` is its cadence; ``last_run`` the injected
    clock value of its last re-fire (None = never run = due now). ``ever_cleared`` latches once a re-fire has
    POSITIVELY cleared it, so a later STILL_PRESENT is a provable regression; ``reopened`` latches True on a
    regression and clears only when the finding clears again."""

    slug: str
    finding_ref: str
    bug_class: str = ""
    interval_s: float = 86400.0
    last_run: Optional[float] = None
    last_verdict: str = ""
    runs: int = 0
    consecutive_clear: int = 0
    ever_cleared: bool = False
    reopened: bool = False


@dataclass
class RetestTickOutcome:
    """The result of one finding's re-fire on a cadence tick. ``regression`` marks the TRANSITION into re-opened
    (a once-cleared finding firing again); ``reopened`` is the latched current state."""

    slug: str
    finding_ref: str
    verdict: str
    ran_at: float
    regression: bool = False
    reopened: bool = False
    reason: str = ""


class RetestRegistry:
    """The durable set of findings under continuous retest + their per-finding state. In-memory core (pure,
    deterministic) with an optional atomic JSON backing file. Total: a missing/torn file loads empty."""

    def __init__(self, path: "str | os.PathLike | None" = None) -> None:
        self.path = Path(path) if path is not None else None
        self.findings: dict[str, WatchedFinding] = {}
        self.history: list[dict] = []
        if self.path is not None:
            self.load()

    def watch(self, wf: WatchedFinding) -> None:
        """Register (or replace) a finding to retest. Keyed by ``finding_ref`` (re-watching updates its spec but
        PRESERVES the existing re-test state when the ref already exists, so a re-registration never silently
        forgets that the finding was cleared/re-opened)."""
        cur = self.findings.get(wf.finding_ref)
        if cur is not None:
            wf.last_run = cur.last_run if wf.last_run is None else wf.last_run
            wf.last_verdict = cur.last_verdict or wf.last_verdict
            wf.runs = max(wf.runs, cur.runs)
            wf.consecutive_clear = cur.consecutive_clear
            wf.ever_cleared = wf.ever_cleared or cur.ever_cleared
            wf.reopened = wf.reopened or cur.reopened
        self.findings[wf.finding_ref] = wf

    def due(self, now: float) -> "list[WatchedFinding]":
        """Findings whose cadence is due at ``now`` (never run, or ``last_run + interval_s <= now``), in a
        deterministic (finding_ref) order."""
        t = float(now)
        return [wf for wf in sorted(self.findings.values(), key=lambda w: w.finding_ref)
                if wf.last_run is None or (float(wf.last_run) + float(wf.interval_s)) <= t]

    def reopened_findings(self) -> "list[WatchedFinding]":
        """The findings currently flagged as regressions (re-opened), deterministic order."""
        return [wf for wf in sorted(self.findings.values(), key=lambda w: w.finding_ref) if wf.reopened]

    def load(self) -> None:
        if self.path is None:
            return
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        fields = {f for f in WatchedFinding.__dataclass_fields__}  # type: ignore[attr-defined]
        for ref, raw in (doc.get("findings") or {}).items():
            if isinstance(raw, dict):
                try:
                    self.findings[str(ref)] = WatchedFinding(**{k: v for k, v in raw.items() if k in fields})
                except Exception:  # noqa: BLE001 — a torn record is skipped, never crashes load
                    continue
        hist = doc.get("history")
        if isinstance(hist, list):
            self.history = [h for h in hist if isinstance(h, dict)]

    def save(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            doc = {"findings": {ref: asdict(wf) for ref, wf in self.findings.items()},
                   "history": self.history[-500:]}
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            return


def _verdict_for(fired: Any) -> str:
    if fired is False:
        return CLEARED
    if fired is True:
        return STILL_PRESENT
    return INCONCLUSIVE


def run_cadence_tick(
    registry: RetestRegistry,
    *,
    now: float,
    refire: Refire,
    record_history: bool = True,
) -> "list[RetestTickOutcome]":
    """Re-fire every DUE watched finding once and return the per-finding outcomes, detecting regressions.

    Default OFF (``VIGIL_APEX_IMPACT``) ⇒ inert: returns ``[]`` and touches no state (byte-identical). ON, for
    each finding due at ``now``: call the injected ``refire`` (the live re-proof / offline re-fire), map its
    ``fired`` to CLEARED / STILL_PRESENT / INCONCLUSIVE (silence NEVER clears), update the finding's state, and
    flag a REGRESSION on the transition "once-cleared → STILL_PRESENT" (latching ``reopened``). Deterministic
    (the injected clock + refire result are the only inputs); persists the updated registry when it is backed by
    a file. Total: a raising ``refire`` degrades that finding to INCONCLUSIVE, never a crash."""
    if not apex_impact_enabled():
        return []
    t = float(now)
    outcomes: list[RetestTickOutcome] = []
    for wf in registry.due(t):
        try:
            res = refire(wf)
            fired = res.get("fired") if isinstance(res, dict) else None
            reason = str((res.get("reason") if isinstance(res, dict) else "") or "")
        except Exception as exc:  # noqa: BLE001 — a re-fire failure is INCONCLUSIVE (never a false clear/regression)
            fired, reason = None, f"re-fire errored: {type(exc).__name__}"
        verdict = _verdict_for(fired)

        regression = False
        if verdict == CLEARED:
            wf.ever_cleared = True
            wf.consecutive_clear += 1
            wf.reopened = False
        elif verdict == STILL_PRESENT:
            wf.consecutive_clear = 0
            if wf.ever_cleared and not wf.reopened:
                regression = True           # the TRANSITION tick: a once-cleared finding is back
            wf.reopened = wf.reopened or wf.ever_cleared
        # INCONCLUSIVE: no clear, no re-open — leave ever_cleared / reopened / consecutive_clear unchanged.

        wf.last_run = t
        wf.last_verdict = verdict
        wf.runs += 1
        outcome = RetestTickOutcome(slug=wf.slug, finding_ref=wf.finding_ref, verdict=verdict, ran_at=t,
                                    regression=regression, reopened=wf.reopened,
                                    reason=reason or ("fix holds" if verdict == CLEARED else ""))
        outcomes.append(outcome)
        if record_history:
            registry.history.append({"finding_ref": wf.finding_ref, "slug": wf.slug, "verdict": verdict,
                                     "ran_at": t, "regression": regression, "reopened": wf.reopened})
    if outcomes:
        registry.save()
    return outcomes


__all__ = ["WatchedFinding", "RetestTickOutcome", "RetestRegistry", "run_cadence_tick", "Refire"]
