"""
scanner.fitness — oracle-proximity fitness for payload evolution.

``scanner.adaptive.evolve`` is a real genetic algorithm, but a GA is only as good
as its fitness — and the intended fitness is "how close is this payload to firing
an oracle?" That is the domain knowledge the module docstring says belongs here.
This module supplies continuous proximity signals in [0, 1] so the GA has a
gradient to climb from a blocked/inert payload toward one that confirms, letting
the scanner synthesize a bypass when a canonical probe is plausible but unfired
(reflected-but-filtered, or WAF-blocked) — beyond a static payload list.

All functions are pure over the response bodies they are given (the network I/O
is the caller's ``send``), so fitness evaluation is deterministic and testable.
"""

from __future__ import annotations

import difflib

from ..verify.oracles import reflection_context_oracle, structural_diff


def reflection_proximity(marker: str, body: str) -> float:
    """How close a reflected marker is to an EXECUTABLE XSS context, in [0, 1]:
    0.0 not reflected, 0.4 reflected but inert (encoded/text), 1.0 executable
    (a live tag / script / event handler). A monotone gradient the GA climbs from
    "gets reflected" toward "breaks out"."""
    if not marker or marker.lower() not in (body or "").lower():
        return 0.0
    return 1.0 if reflection_context_oracle(marker, body).fired else 0.4


def differential_proximity(baseline_body: str, mutated_body: str) -> float:
    """How strongly a payload's response diverges from a benign baseline, in
    [0, 1] — the max of the structural (AST) and lexical divergences. A blocked
    payload looks like the baseline (~0); one that gets through and changes the
    result set scores high. The gradient the GA climbs for boolean/injection bugs."""
    structural = structural_diff(baseline_body or "", mutated_body or "")
    lexical = 1.0 - difflib.SequenceMatcher(None, baseline_body or "", mutated_body or "").ratio()
    return max(0.0, min(1.0, max(structural, lexical)))


def unblocked_gate(body: str, *, block_markers: tuple[str, ...] = (
    "request blocked", "access denied", "forbidden", "waf", "406 not acceptable",
)) -> float:
    """1.0 if the response does not look like a WAF/block page, else 0.0 — a hard
    gate to multiply a proximity signal by, so a blocked payload scores 0 no
    matter how good it would otherwise be."""
    low = (body or "").lower()
    return 0.0 if any(m in low for m in block_markers) else 1.0
