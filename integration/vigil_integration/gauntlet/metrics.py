"""
gauntlet.metrics — the ASR (Attack Success Rate) metric + severity banding (VIGIL-FUSION F8).

Adapted from redamon's shared ``_severity(asr)`` bands (MIT; see NOTICE): ``ASR = hits / trials`` and
``high >= 0.5, medium >= 0.3, low > 0, else info``.

DOCTRINE (the load-bearing distinction): **ASR is a METRIC, never a promotion signal.** A high ASR does
not make a finding true and a maxed-out ASR on a ``judge_llm`` category is still a LEAD. Only a
deterministic oracle re-firing mints a FACT (``gauntlet.sensor``). Severity here is descriptive triage
sugar derived from ASR; the veracity (LEAD vs FACT) is decided entirely elsewhere by ``oracle_kind`` +
the injected oracle.

Pure/deterministic, total on malformed input. Import-clean (stdlib only).
"""

from __future__ import annotations

import math


def _coerce_int(v: object) -> int | None:
    """Best-effort int, total. Rejects bools (``True`` is an ``int`` subclass but a boolean count is
    malformed) and non-finite floats; returns ``None`` on anything uncoercible."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v) if math.isfinite(v) else None
    if isinstance(v, str):
        s = v.strip()
        try:
            return int(s)
        except (TypeError, ValueError):
            try:
                f = float(s)
            except (TypeError, ValueError):
                return None
            return int(f) if math.isfinite(f) else None
    return None


def sanitize_counts(hits: object, trials: object) -> tuple[int, int]:
    """Coerce ``(hits, trials)`` to non-negative ints with ``hits <= trials`` (a hit count exceeding
    trials is malformed → clamped, so ASR can never exceed 1.0). Uncoercible → 0. Never raises."""
    h = _coerce_int(hits) or 0
    t = _coerce_int(trials) or 0
    if t < 0:
        t = 0
    if h < 0:
        h = 0
    if h > t:
        h = t
    return h, t


def attack_success_rate(hits: object, trials: object) -> float:
    """``ASR = hits / trials`` in ``[0.0, 1.0]``. Zero (or unknown) trials → ``0.0`` — no signal, never
    a divide-by-zero. Total on malformed input."""
    h, t = sanitize_counts(hits, trials)
    if t <= 0:
        return 0.0
    return h / t


def severity_band(asr: object) -> str:
    """Map an ASR to a triage band: ``high >= 0.5``, ``medium >= 0.3``, ``low > 0``, else ``info``.
    Descriptive only — NEVER a FACT/LEAD promotion signal. Total: a non-numeric ASR → ``info``."""
    try:
        a = float(asr)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return "info"
    if not math.isfinite(a):
        return "info"
    if a >= 0.5:
        return "high"
    if a >= 0.3:
        return "medium"
    if a > 0.0:
        return "low"
    return "info"
