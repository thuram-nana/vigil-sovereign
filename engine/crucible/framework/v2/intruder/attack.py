"""
intruder.attack — the four attack-type combinatorics.

Given marked insertion points and payload generators, each attack type defines
which payloads land where, and in what combination:

  * SNIPER        one payload set; into each position one at a time (others held
                  at base). requests = positions × payloads.
  * BATTERING_RAM one payload set; the SAME payload into every position at once.
                  requests = payloads.
  * PITCHFORK     one set per position; iterated in lockstep. requests = length of
                  the shortest set. (correlated pairs, e.g. userid+token rows.)
  * CLUSTER_BOMB  one set per position; the full Cartesian product. requests =
                  product of set sizes. (credential stuffing: user × pass.)

``render_attack`` yields ``(payloads, HttpRequest)`` for each iteration, lazily.
Multi-position placement re-templates sequentially; it is exact for value
insertion points (query/body/cookie/header/path/json-value), which is where
fuzzing lives.
"""

from __future__ import annotations

import enum
import itertools
from collections.abc import Iterable, Iterator

from ..scanner.insertion import HttpRequest, InsertionPoint, RequestTemplate


class AttackType(str, enum.Enum):
    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


def _render_multi(template: RequestTemplate, assignments: list[tuple[InsertionPoint, str]]) -> HttpRequest:
    """Place several (point, payload) pairs on the base request. Applied
    sequentially; each point's locator is a stable index/pointer, so for value
    insertions (the fuzzing case) the placements are independent and exact."""
    req = template.request
    for point, payload in assignments:
        req = RequestTemplate(req).render(point, payload)
    return req


def render_attack(
    template: RequestTemplate,
    positions: list[InsertionPoint],
    generators: list[Iterable[str]],
    attack_type: AttackType,
) -> Iterator[tuple[tuple[str, ...], HttpRequest]]:
    """Yield ``(payloads, rendered_request)`` for each iteration of the attack.

    SNIPER/BATTERING_RAM use ``generators[0]``; PITCHFORK/CLUSTER_BOMB use one
    generator per position (``len(generators) == len(positions)``)."""
    if not positions:
        raise ValueError("attack requires at least one insertion point")
    if not generators:
        raise ValueError("attack requires at least one payload generator")

    if attack_type is AttackType.SNIPER:
        payloads = list(generators[0])
        for point in positions:
            for p in payloads:
                yield (p,), template.render(point, p)

    elif attack_type is AttackType.BATTERING_RAM:
        for p in generators[0]:
            yield (p,), _render_multi(template, [(pt, p) for pt in positions])

    elif attack_type is AttackType.PITCHFORK:
        _require_per_position(positions, generators)
        for combo in zip(*(list(g) for g in generators)):
            yield combo, _render_multi(template, list(zip(positions, combo)))

    elif attack_type is AttackType.CLUSTER_BOMB:
        _require_per_position(positions, generators)
        for combo in itertools.product(*(list(g) for g in generators)):
            yield combo, _render_multi(template, list(zip(positions, combo)))

    else:  # pragma: no cover - enum exhaustive
        raise ValueError(f"unknown attack type {attack_type!r}")


def _require_per_position(positions: list[InsertionPoint], generators: list[Iterable[str]]) -> None:
    if len(generators) != len(positions):
        raise ValueError(
            f"{len(positions)} positions need {len(positions)} generators, got {len(generators)}"
        )
