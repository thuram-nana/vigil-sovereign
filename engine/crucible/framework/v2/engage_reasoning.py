"""
engage_reasoning — the LLM-in-the-loop reasoning HOOK (Workstream F, first slice).

The reasoning kernel (``framework/v2/kernel/``) already turns the v1 cognitive
prose into typed, LLM-backed bindings (``hypothesize`` / ``pivot`` / ``critique``
/ ``decide`` …). Today those bindings run only as ADVISORY telemetry under
``engage --spine``; nothing lets the *autonomous* loop consult them to decide
what to look at next.

This module is that missing hook — a single, standalone, additive entry point:

    reason_step(world, findings, ctx) -> ReasoningAdvice

Given the run's world-model and the findings confirmed so far, it runs ONE
bounded reasoning step (reusing the existing kernel bindings + their self-
consistency wrappers) and returns structured **advice** for the next autonomous
action: which surface / bug-class / hypothesis to prioritise, and — when a thread
looks stalled — lateral moves to reset it.

It is the hook Workstream A's ``_run_autonomous`` calls (with a graceful
fallback if this module is absent). It is deliberately OFF the default path:
only ``--autonomous`` invokes it, so ``make gate`` and every replayed run stay
byte-identical.

Doctrine (prove-don't-guess) — the load-bearing invariants of this module:

* **Advice, never a verdict.** ``reason_step`` returns candidate hypotheses and
  a recommended focus. It NEVER confirms a finding, sets a severity, or touches
  an oracle. The only authority that promotes a claim to a fact is a fired
  deterministic oracle; nothing here can override that (CLAUDE.md / crucible
  invariant 1). The returned object carries no "confirmed" field by construction.
* **Read-only over state.** It never mutates ``findings``, the world-model, or
  any verdict. It composes a *summary* of them and reasons over that summary.
* **Abstain honestly.** It reuses the kernel's self-consistency layer: when the
  sampled reasoning disagrees with itself, ``abstain`` is True and the caller
  should treat the advice as low-confidence rather than drive on it. Under the
  deterministic DryRun backend every sample is identical, so it agrees trivially
  (abstain False) — the abstention signal only bites against a live backend.
* **Deterministic with no live backend.** With no ``ANTHROPIC_API_KEY`` / local
  model, the kernel resolves to :class:`DryRunBackend`, whose fixtures are
  deterministic; identical inputs therefore yield byte-identical advice
  (``ReasoningAdvice.to_dict()``). Tests pass an explicit ``DryRunBackend()``.
  Any exception degrades to a safe, abstaining no-op — the autonomous loop can
  never be sunk by a reasoning failure.

ROADMAP — the full LLM-driven planning loop (future slices):

  1. **Live backend + budget.** Drive ``reason_step`` under a live
     ``AnthropicBackend`` behind an explicit cost/latency budget (max tokens,
     max calls per engagement, wall-clock cap). Degrade to DryRun advice the
     moment the budget is exhausted, so a run always terminates and stays
     replayable. Budget state lives in ``ctx`` and is threaded call-to-call.
  2. **Self-consistency as a first-class gate.** Raise ``samples`` on the live
     backend and let ``abstain`` (agreement < gate, or entropy penalty) route
     the loop to gather more evidence instead of acting — the anti-hallucination
     P5 signal, carried OUT as advice, never fed back into the oracle/SCE inputs.
  3. **Closed loop.** Feed ``reason_step`` advice into WS-A's action selector,
     then feed the oracle's verdict on that action back as the next
     ``observation`` — a genuine observe→orient→hypothesize→test→update cycle,
     with every hypothesis / advice / outcome mirrored onto the event spine for
     audit. The oracle stays the sole authority throughout.
  4. **Critique + decide bindings.** Add an advisory ``critique`` pass over a
     proposed action (drift / deception check) and a ``decide`` pass for
     severity narration — both advisory, both self-consistent, neither promoting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .kernel import hypothesize_consistent, pivot_consistent
from .kernel.llm import LLMBackend

__all__ = ["ReasoningAdvice", "reason_step"]


# ---------------------------------------------------------------------------
# The advice object — structured, deterministic, decision-bearing.
# ---------------------------------------------------------------------------


@dataclass
class ReasoningAdvice:
    """The output of one bounded reasoning step — ADVICE for the next autonomous
    action, never a verdict.

    Fields:
        next_focus:   one-line human-readable recommendation ("test IDOR on
                      /api/orders/{id}") — the highest-EV next thread.
        focus:        the top-ranked candidate as a dict (surface, bug_class,
                      cheap_test, confidence, oracle_provable) — or None.
        hypotheses:   ranked candidate hypotheses (novel bug-classes first, then
                      oracle-provable, then confidence). Each a plain dict.
        pivots:       lateral moves to reset a stalled thread (populated only
                      when the step judged the current thread stuck).
        abstain:      True when the kernel's self-consistency layer disagreed
                      with itself — treat the advice as low-confidence.
        rationale:    one-line explanation of the recommendation.
        consistency:  the self-consistency summary (agreement / entropy /
                      n_samples / abstained) — an advisory penalty, never a boost.
        is_dryrun:    True when produced by the deterministic DryRun backend
                      (i.e. not a real inference — advice quality is bounded).
    """

    next_focus: str = ""
    focus: dict[str, Any] | None = None
    hypotheses: tuple[dict[str, Any], ...] = ()
    pivots: tuple[dict[str, Any], ...] = ()
    abstain: bool = True
    rationale: str = ""
    consistency: dict[str, Any] = field(default_factory=dict)
    is_dryrun: bool = True

    def to_dict(self) -> dict[str, Any]:
        """A deterministic, JSON-serialisable projection — the decision-bearing
        surface only. Excludes any wallclock/latency trace, so identical inputs
        under a deterministic backend render byte-identically."""
        return {
            "next_focus": self.next_focus,
            "focus": self.focus,
            "hypotheses": [dict(h) for h in self.hypotheses],
            "pivots": [dict(p) for p in self.pivots],
            "abstain": self.abstain,
            "rationale": self.rationale,
            "consistency": dict(self.consistency),
            "is_dryrun": self.is_dryrun,
        }


# ---------------------------------------------------------------------------
# Defensive accessors — `world` / `findings` / `ctx` come from WS-A and may be
# objects, pydantic models, or plain dicts. Read them by duck-typing; never
# assume a concrete type, never mutate.
# ---------------------------------------------------------------------------


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """Read `key` from a mapping OR an attribute of an object, defensively."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _finding_surface(f: Any) -> str:
    return str(_get(f, "surface", "") or "")


def _finding_bug_class(f: Any) -> str:
    # Findings across the codebase spell this `bug_class`; tolerate a couple of
    # aliases so the hook works regardless of which finding shape WS-A passes.
    for k in ("bug_class", "vuln_class", "category"):
        v = _get(f, k, None)
        if v:
            return str(v)
    return ""


def _resolve_backend(ctx: Any, backend: LLMBackend | None) -> LLMBackend | None:
    """Pick the backend: explicit arg > ctx-supplied > None (kernel auto-selects,
    which resolves to the deterministic DryRun backend when no live backend is
    present). Returning None keeps the kernel's own failover path."""
    if backend is not None:
        return backend
    ctx_backend = _get(ctx, "backend", None)
    if isinstance(ctx_backend, LLMBackend):
        return ctx_backend
    return None


def _is_stuck(ctx: Any, findings: list[Any], covered_bug_classes: set[str]) -> bool:
    """Decide whether to also propose lateral moves. Explicit ``ctx['stuck']``
    wins; otherwise a thread looks stalled when work has been done (ctx carries a
    positive request/step count) yet nothing has been confirmed."""
    explicit = _get(ctx, "stuck", None)
    if explicit is not None:
        return bool(explicit)
    if findings:
        return False
    # no findings yet — stuck only if the loop has actually spent effort
    for k in ("requests", "steps", "iterations", "request_count", "step"):
        n = _get(ctx, k, 0)
        try:
            if int(n) > 0:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _world_summary(world: Any) -> str:
    """A short, deterministic description of the world-model for the observation
    string. Defensive: works whether `world` exposes a node count, a `nodes`
    collection, or nothing at all."""
    if world is None:
        return "no world-model attached"
    for attr in ("num_nodes", "node_count"):
        v = _get(world, attr, None)
        if isinstance(v, int):
            return f"{v} world-model node(s)"
    nodes = _get(world, "nodes", None)
    try:
        if nodes is not None:
            return f"{len(nodes)} world-model node(s)"
    except TypeError:
        pass
    return "world-model present"


def _rank_key(h: Any, covered_bug_classes: set[str]) -> tuple[Any, ...]:
    """Deterministic ranking: prefer a NOVEL bug class (one not yet confirmed),
    then an oracle-provable class, then higher confidence, with a stable id
    tiebreak so equal candidates never reorder run-to-run."""
    bug_class = str(getattr(h, "bug_class", ""))
    provable = bool(getattr(h, "oracle_provable", False))
    confidence = float(getattr(h, "confidence", 0.0) or 0.0)
    hid = str(getattr(h, "id", ""))
    return (
        0 if bug_class not in covered_bug_classes else 1,
        0 if provable else 1,
        -confidence,
        hid,
    )


def _hyp_to_dict(h: Any) -> dict[str, Any]:
    return {
        "id": str(getattr(h, "id", "")),
        "surface": str(getattr(h, "surface", "")),
        "bug_class": str(getattr(h, "bug_class", "")),
        "cheap_test": str(getattr(h, "cheap_test", "")),
        "confidence": float(getattr(h, "confidence", 0.0) or 0.0),
        "oracle_provable": bool(getattr(h, "oracle_provable", False)),
    }


def _pivot_to_dict(m: Any) -> dict[str, Any]:
    return {
        "kind": str(getattr(m, "kind", "")),
        "suggestion": str(getattr(m, "suggestion", "")),
        "estimated_effort": str(getattr(m, "estimated_effort", "")),
        "confidence": float(getattr(m, "confidence", 0.0) or 0.0),
    }


def _consistency_summary(cr: Any) -> dict[str, Any]:
    return {
        "n_samples": int(getattr(cr, "n_samples", 0) or 0),
        "agreement": float(getattr(cr, "agreement", 0.0) or 0.0),
        "entropy": float(getattr(cr, "entropy", 0.0) or 0.0),
        "abstained": bool(getattr(cr, "abstained", False)),
    }


# ---------------------------------------------------------------------------
# The hook.
# ---------------------------------------------------------------------------


def reason_step(
    world: Any,
    findings: Any,
    ctx: Any = None,
    *,
    backend: LLMBackend | None = None,
    samples: int = 3,
) -> ReasoningAdvice:
    """Run ONE bounded LLM-in-the-loop reasoning step and return structured
    ADVICE for the next autonomous action.

    Args:
        world:    the run's world-model (any object exposing a node
                  count / ``nodes`` collection, or None). Read-only.
        findings: the findings confirmed so far — an iterable of finding-like
                  objects/dicts exposing ``surface`` and ``bug_class``.
                  Read-only; never mutated.
        ctx:      optional context mapping/object. Recognised (all optional)
                  keys/attrs: ``backend`` (an LLMBackend to use), ``surface``
                  (the surface currently under test), ``posture`` (TEST / AUDIT
                  / EMULATE), ``stuck`` (force lateral-move proposal),
                  ``blockers`` (list[str] for the pivot), and a request/step
                  counter used to infer a stalled thread.
        backend:  test/override hook — an explicit LLMBackend (e.g.
                  ``DryRunBackend()``). Takes precedence over ``ctx['backend']``.
                  Keyword-only so the WS-A call ``reason_step(world, findings,
                  ctx)`` is unaffected.
        samples:  self-consistency sample count for the bounded step.

    Returns:
        :class:`ReasoningAdvice`. Advice only — it never confirms a finding,
        overrides an oracle, or mutates its inputs. On any internal failure it
        returns a safe, abstaining no-op so the caller's loop never breaks.
    """
    try:
        finding_list = list(findings) if findings is not None else []
    except TypeError:
        finding_list = []

    covered_bug_classes = {c for c in (_finding_bug_class(f) for f in finding_list) if c}
    covered_surfaces = {s for s in (_finding_surface(f) for f in finding_list) if s}

    resolved = _resolve_backend(ctx, backend)
    surface_hint = str(_get(ctx, "surface", "") or "")

    observation = (
        f"{len(finding_list)} oracle-confirmed finding(s) so far across "
        f"{len(covered_surfaces)} surface(s); bug classes already confirmed: "
        f"{sorted(covered_bug_classes) or 'none'}. "
        f"{_world_summary(world)}. Decide the highest-EV next surface / bug-class "
        f"/ hypothesis to test — prioritise attack classes NOT yet confirmed."
    )
    context = (
        "You are advising an autonomous scan loop which surface/hypothesis to "
        "probe next. Prove-don't-guess: your output is ADVICE only; a deterministic "
        "oracle, not you, confirms any finding. Confirmed classes so far: "
        f"{sorted(covered_bug_classes) or 'none'}."
    )

    try:
        cr = hypothesize_consistent(
            observation,
            surface=surface_hint,
            context=context,
            bug_classes=sorted(covered_bug_classes),
            samples=max(1, int(samples)),
            backend=resolved,
        )
    except Exception:
        # Degrade to a deterministic, safe no-op — never sink the caller's loop.
        return ReasoningAdvice(
            next_focus="",
            abstain=True,
            rationale="reasoning step unavailable; degraded to abstaining no-op",
            is_dryrun=True,
        )

    hyp_set = cr.modal
    is_dryrun = bool(getattr(getattr(cr, "trace", None), "is_dryrun", True))
    hyps = list(getattr(hyp_set, "hypotheses", []) or [])
    ranked = sorted(hyps, key=lambda h: _rank_key(h, covered_bug_classes))
    ranked_dicts = tuple(_hyp_to_dict(h) for h in ranked)

    focus: dict[str, Any] | None = ranked_dicts[0] if ranked_dicts else None
    if focus:
        novel = focus["bug_class"] not in covered_bug_classes
        next_focus = (
            f"test {focus['bug_class']} on {focus['surface']}"
            if focus.get("surface")
            else f"test {focus['bug_class']}"
        )
        rationale = (
            f"highest-EV lead: {'a not-yet-confirmed' if novel else 'a recurring'} "
            f"class ({focus['bug_class']}), "
            f"{'oracle-provable' if focus['oracle_provable'] else 'exploratory'}, "
            f"prior {focus['confidence']:.2f}; cheap test: {focus['cheap_test']}"
        )
    else:
        next_focus = ""
        rationale = "no candidate hypotheses produced"

    # Lateral moves only when the current thread looks stalled — a bounded second
    # binding call, still advisory. Best-effort: a pivot failure never fails the step.
    pivots: tuple[dict[str, Any], ...] = ()
    if _is_stuck(ctx, finding_list, covered_bug_classes):
        try:
            stuck_desc = (
                f"Autonomous loop has probed {len(covered_surfaces)} surface(s) with "
                f"{len(finding_list)} confirmed finding(s) and needs a new thread."
            )
            blockers = _get(ctx, "blockers", ()) or ()
            posture = str(_get(ctx, "posture", "TEST") or "TEST")
            pr = pivot_consistent(
                stuck_desc,
                last_observation=observation,
                blockers=tuple(blockers) if not isinstance(blockers, str) else (blockers,),
                posture=posture,
                samples=max(1, int(samples)),
                backend=resolved,
            )
            moves = list(getattr(pr.modal, "moves", []) or [])
            pivots = tuple(_pivot_to_dict(m) for m in moves)
        except Exception:
            pivots = ()

    return ReasoningAdvice(
        next_focus=next_focus,
        focus=focus,
        hypotheses=ranked_dicts,
        pivots=pivots,
        abstain=bool(getattr(cr, "abstained", True)),
        rationale=rationale,
        consistency=_consistency_summary(cr),
        is_dryrun=is_dryrun,
    )
