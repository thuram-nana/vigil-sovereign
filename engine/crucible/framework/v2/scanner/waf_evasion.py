"""
scanner.waf_evasion — turn a blocked-but-plausible probe into a confirmed bypass.

``adaptive.waf_adapt`` (an ordered evasion ladder) and ``adaptive.evolve`` (a GA
over payload encodings) and ``fitness`` (oracle-proximity gradients) were real code
that nothing in the live scan loop ever called. This is the bridge: when a check's
canonical payload is REJECTED by a filter/WAF but the sink is plausibly reachable, a
check's ``adapt`` method calls :func:`adaptive_bypass` here to synthesize a form that
gets past the filter AND still fires the oracle — then the finding is confirmed
through the SAME oracle as any other, so precision is unaffected (a bypass that does
not fire the oracle is not a finding).

Two tiers, cheapest first:
  1. the fixed evasion ladder (``waf_adapt``) — a handful of requests,
  2. only if the ladder is exhausted, a small, budgeted genetic search
     (``evolve``) with a real oracle-proximity fitness — novel encodings the fixed
     ladder does not contain.

Both are OFF by default (opt-in per engagement) and every request goes through the
caller's ``send`` — so they stay inside the gated executor's budget and rate limits.
This is a verification aid (prove a filter is bypassable), not an escalation weapon:
the search is bounded and reported, never unbounded evasion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from random import Random
from typing import Callable

from .adaptive import ProbeOutcome, evolve, waf_adapt
from .fitness import unblocked_gate

# A response is the scanner's usual ``{"status": int, "body": str, ...}`` dict.
Response = dict
SendForm = Callable[[str], Response]      # send a transformed form, get the response
SinkPresent = Callable[[Response], bool]  # the oracle proxy: did the sink signal appear?
Proximity = Callable[[Response], float]   # a [0,1] gradient toward firing (for evolve)

_BLOCK_STATUSES = frozenset({403, 406, 429, 501})
_BLOCK_MARKERS = (
    "request blocked", "access denied", "forbidden", "waf",
    "406 not acceptable", "request rejected", "blocked by", "security policy",
)


def _body(resp: Response) -> str:
    return resp.get("body", "") if isinstance(resp, dict) else str(resp)


def looks_blocked(resp: Response) -> bool:
    """True iff a response looks like a filter/WAF rejection: a block status code,
    or a block-page marker in the body. Conservative — a normal 404/500 is NOT a
    block (the request reached the app), so we do not evade past ordinary errors."""
    if isinstance(resp, dict):
        status = int(resp.get("status", 0) or 0)
        if status in _BLOCK_STATUSES:
            return True
    low = _body(resp).lower()
    return any(m in low for m in _BLOCK_MARKERS)


@dataclass
class BypassResult:
    """A synthesized bypass: the working transformed form, the response it drew, and
    how it was found (the evasion ``chain`` for the ladder, or 'evolve')."""

    form: str
    response: Response
    method: str                       # "ladder" | "evolve"
    chain: list[str] = field(default_factory=list)
    attempts: int = 0


def adaptive_bypass(
    payload: str,
    send_form: SendForm,
    sink_present: SinkPresent,
    *,
    proximity: Proximity | None = None,
    evolve_generations: int = 6,
    evolve_population: int = 10,
    seed: int = 0,
) -> BypassResult | None:
    """Find a transformed form of ``payload`` that is NOT blocked AND makes
    ``sink_present`` true, or return None.

    ``sink_present(resp)`` is the check's own oracle proxy (marker reflected, file
    signature present, ...). ``proximity(resp)`` is an optional [0,1] gradient
    (e.g. reflection proximity) that gives the GA fallback something to climb; when
    omitted a binary sink-present gate is used. Determinism: the ladder is fixed and
    the GA is seeded, so given a deterministic target the result is reproducible."""
    attempts = 0

    def attempt(form: str) -> ProbeOutcome:
        nonlocal attempts
        attempts += 1
        resp = send_form(form)
        return ProbeOutcome(blocked=looks_blocked(resp), succeeded=sink_present(resp))

    # Tier 1: the fixed evasion ladder.
    res = waf_adapt(payload, attempt)
    if res.succeeded and res.payload is not None:
        return BypassResult(
            form=res.payload, response=send_form(res.payload),
            method="ladder", chain=list(res.chain), attempts=attempts + 1,
        )
    if not res.exhausted:
        # A form got past the filter but did not fire the oracle — the filter is
        # bypassable but the sink is not this payload's; do not manufacture a finding.
        return None

    # Tier 2: the ladder is exhausted (everything blocked). Search novel encodings
    # with a small, budgeted GA whose fitness rewards "not blocked" AND proximity.
    def fitness(form: str) -> float:
        resp = send_form(form)
        gate = unblocked_gate(_body(resp))
        if gate == 0.0:
            return 0.0
        prox = proximity(resp) if proximity is not None else (1.0 if sink_present(resp) else 0.0)
        return gate * prox

    ev = evolve(
        [payload], fitness,
        generations=evolve_generations, population=evolve_population,
        rng=Random(seed),
    )
    attempts += ev.evaluations
    if ev.improved:
        resp = send_form(ev.best)
        if not looks_blocked(resp) and sink_present(resp):
            return BypassResult(form=ev.best, response=resp, method="evolve", attempts=attempts + 1)
    return None
