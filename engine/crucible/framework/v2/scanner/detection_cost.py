"""
scanner.detection_cost — stealth ranking via detection ACCOUNTING.

Rank candidate attack paths by how LOUD they are, so the operator can
*prefer the stealthier route* and *understand the footprint* of the one
they take. This is honest self-assessment, reused straight from the DEL
(``defender``): the same telemetry model and severity noisy-OR that
answers "how detectable am I". It never evades a real detector — knowing
a technique trips a WAF signature is defensive awareness (constitution
§ VI), not an evasion recipe. The framework stays correlatable; this
layer only informs and ranks.

A technique's detection cost has two, deliberately-separated, drivers:

  * **its detection_signals** — the observable tells the operator wrote
    into the technique catalog ("200 for an object you don't own",
    "serialized-object magic bytes"). More tells => louder. This is the
    *count* of independent ways a defender could notice.

  * **the DEL telemetry channels it would trip** — mapping the technique
    to an ``ActionKind`` and scoring it with ``defender.score_action``
    gives the *fidelity* of what fires (an injection payload lights a
    high-severity WAF rule; a plain object read only writes an access
    line). This is the severity half.

The two combine by noisy-OR into a cost in ``[0, 1]``. A path's cost is
the noisy-OR over its steps' costs — a route is as loud as the union of
the ways its hops can be seen. ``rank_paths`` sorts least-detectable
first; ``weight_fn`` turns the same accounting into an edge weight for
``worldmodel.pathsearch.best_paths`` so the graph search itself prefers
stealthy edges.

Deterministic: no randomness, no wallclock, read-only over its inputs.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..defender import ActionDescriptor, ActionKind, score_action
from ..knowledge import Operator, by_id

# ---------------------------------------------------------------------------
# Tunables — legible, not fitted. All deterministic.
# ---------------------------------------------------------------------------

# Per detection_signal survival factor: n signals => signal_cost = 1 - DECAY**n
# (strictly increasing in n, saturating below 1). 0.75 keeps a single tell
# modest while a rich set of tells is clearly loud.
_SIGNAL_DECAY = 0.75

# A technique we cannot resolve to an operator: we do not *know* its
# footprint, so we neither call it silent (0.0, misleadingly stealthy) nor
# maximally loud. A neutral mid value keeps ranking honest.
_UNKNOWN_COST = 0.5

# A minimal per-edge traversal floor for weight_fn, so every hop costs
# something (Dijkstra prefers shorter *and* quieter) while louder edges
# still rank strictly higher. Non-negative, as pathsearch requires.
_HOP_FLOOR = 0.05

# ATT&CK/CWE/CAPEC markers that make a technique HTTP-loud: a payload/probe
# a WAF or IDS signature is built to catch. Kept explicit and auditable.
_INJECTION_CWES = frozenset(
    {"CWE-89", "CWE-78", "CWE-79", "CWE-90", "CWE-94", "CWE-502", "CWE-611",
     "CWE-917", "CWE-918"}
)
_INJECTION_TECHNIQUES = frozenset({"T1059", "T1203"})
_LOGIN_TECHNIQUES = frozenset({"T1110"})


# ---------------------------------------------------------------------------
# Resolving a technique argument to an Operator
# ---------------------------------------------------------------------------


def _resolve(technique: object) -> Operator | None:
    """Coerce a technique id, an ``Operator``, or an operator-like duck to an
    ``Operator``; ``None`` when it cannot be resolved."""
    if isinstance(technique, Operator):
        return technique
    if isinstance(technique, str):
        try:
            return by_id(technique)
        except KeyError:
            return None
    if technique is None:
        return None
    # duck-typed: anything exposing the fields we read.
    if hasattr(technique, "detection_signals") and hasattr(technique, "technique_ref"):
        return technique  # type: ignore[return-value]
    return None


# ---------------------------------------------------------------------------
# Technique -> DEL ActionDescriptor
# ---------------------------------------------------------------------------


def _classify(op: Operator) -> ActionDescriptor:
    """Map a planning operator to the DEL action whose telemetry best
    represents executing it. Coarse and explicit: an execution/injection
    technique carries a WAF-visible payload; a credential technique writes
    the auth log; everything else is a plain request that only lands in the
    access log. The mapping keys off intel refs/tactic, never on payloads
    (there are none here)."""
    refs = set(op.technique_ref)
    tactic = (op.tactic or "").lower()
    text = f"{op.name} {op.description}".lower()
    surface = op.id

    if (
        refs & _INJECTION_CWES
        or refs & _INJECTION_TECHNIQUES
        or tactic == "execution"
        or "injection" in text
        or "deserial" in text
        or "ssrf" in text
    ):
        return ActionDescriptor(kind=ActionKind.INJECTION_PROBE, target_surface=surface)

    if tactic == "credential-access" or refs & _LOGIN_TECHNIQUES or "credential" in text:
        # A single reuse/replay attempt, not a brute-force burst: writes the
        # auth log but does not (by itself) trip the failed-count threshold.
        return ActionDescriptor(
            kind=ActionKind.LOGIN_ATTEMPT,
            target_surface=surface,
            attributes={"failed_count": "0", "outcome": "success"},
        )

    return ActionDescriptor(kind=ActionKind.HTTP_REQUEST, target_surface=surface)


def _noisy_or(a: float, b: float) -> float:
    return 1.0 - (1.0 - a) * (1.0 - b)


def _signal_cost(n_signals: int) -> float:
    """Loudness contributed by the *count* of detection tells. Strictly
    increasing in ``n_signals``, saturating below 1."""
    if n_signals <= 0:
        return 0.0
    return 1.0 - _SIGNAL_DECAY ** n_signals


def _telemetry_cost(op: Operator) -> float:
    """Loudness contributed by the DEL channels the technique would trip
    (severity/fidelity). ``check_capability=False``: detection accounting is
    pure self-assessment and must be available to the planner regardless of
    the offensive DEFENDER_TELEMETRY entitlement."""
    score = score_action(_classify(op), check_capability=False)
    return score.detectability


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detection_cost_of_technique(technique: object) -> float:
    """How loud a technique is, in ``[0, 1]`` (0 = silent, 1 = certain to be
    seen). Accepts a catalog technique id, an ``Operator``, or an
    operator-like object. Combines the operator's ``detection_signals`` count
    with the DEL telemetry it would trip (noisy-OR). An unresolvable
    technique returns a neutral ``0.5`` — unknown footprint, not assumed
    silent. Deterministic."""
    op = _resolve(technique)
    if op is None:
        return _UNKNOWN_COST
    signal_cost = _signal_cost(len(op.detection_signals))
    telemetry_cost = _telemetry_cost(op)
    return round(_noisy_or(signal_cost, telemetry_cost), 6)


def _path_techniques(path: object) -> list[object]:
    """Extract the ordered technique ids of a path. Accepts a plain
    ``list[str]`` of technique ids, a single technique-id string, or any
    object exposing ``.steps`` whose items expose ``.technique`` (duck-types
    ``orchestrator.AttackPath`` without importing it)."""
    steps = getattr(path, "steps", None)
    if steps is not None:
        return [getattr(s, "technique", None) for s in steps]
    if isinstance(path, str):
        return [path]
    if isinstance(path, Iterable):
        return list(path)
    return []


def path_detection_cost(path: object) -> float:
    """The detection cost of a whole path, in ``[0, 1]``: the noisy-OR over
    its steps' technique costs — a route is as loud as the union of the ways
    its hops can be observed. Monotonic: adding (or making louder) any step
    never lowers the cost. An empty path costs ``0.0``."""
    cost = 0.0
    for tech in _path_techniques(path):
        cost = _noisy_or(cost, detection_cost_of_technique(tech))
    return round(cost, 6)


def rank_paths(paths: Iterable[object]) -> list[tuple[object, float]]:
    """Rank paths least-detectable first: ``[(path, cost), ...]`` sorted by
    ascending detection cost. Each ``path`` is returned untouched (a
    ``list[str]`` of technique ids or an ``AttackPath``-like object). The
    sort is stable, so ties preserve input order — deterministic."""
    scored = [(path, path_detection_cost(path)) for path in paths]
    return sorted(scored, key=lambda item: item[1])


def _edge_cost(edge: object) -> float:
    """The loudness component of one world-model edge, in ``[0, 1]``. Reads
    ``edge.attrs`` (operator-derived edges carry ``technique`` and
    ``detection_signals``); falls back to parsing an ``operator:<id>``
    provenance. An edge with no technique intel contributes no loudness."""
    attrs = getattr(edge, "attrs", None) or {}
    tech = attrs.get("technique")
    if tech is not None:
        return detection_cost_of_technique(tech)

    provenance = getattr(edge, "provenance", "") or ""
    if provenance.startswith("operator:"):
        return detection_cost_of_technique(provenance.split(":", 1)[1])

    signals = attrs.get("detection_signals")
    if isinstance(signals, (list, tuple, set)):
        return _signal_cost(len(signals))
    if isinstance(signals, int) and not isinstance(signals, bool):
        return _signal_cost(signals)

    return 0.0


def weight_fn(edge: object) -> float:
    """A non-negative edge weight for ``worldmodel.pathsearch.best_paths``
    that makes the graph search prefer stealthy edges: ``_HOP_FLOOR`` plus
    the edge's detection cost, so a louder edge always weighs strictly more
    than a quieter one and every hop still costs something. Reads
    ``edge.attrs['technique']`` / ``['detection_signals']`` (or an
    ``operator:<id>`` provenance). Deterministic and >= 0, as Dijkstra
    requires."""
    return _HOP_FLOOR + _edge_cost(edge)


__all__ = [
    "detection_cost_of_technique",
    "path_detection_cost",
    "rank_paths",
    "weight_fn",
]
