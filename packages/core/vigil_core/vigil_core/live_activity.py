"""Customer-safe engagement ACTIVITY seam — the one format + path the OFFENSE emitter and the SOVEREIGN reader
agree on, so the customer Live Control screen can show "what VIGIL is doing" without ever crossing the FATAL-2
boundary with code.

WHY HERE. ``vigil_core`` is the only module BOTH planes import, so the emit (called by the engine's phase
ledger, offense plane) and the read (called by the sovereign custui adapter) share ONE definition of the file,
its path, and — crucially — its CUSTOMER-SAFE PROJECTION. Data crosses the plane boundary only as this bounded
JSONL file under the shared seam base.

CUSTOMER-SAFE BY CONSTRUCTION. A row is EXACTLY ``{seq, ts, phase, status}`` where ``phase`` is one of a FIXED
allowlist of high-level engagement STAGE names (preflight / scan / reasoning_pass / report / …) and ``status``
one of a fixed set (started / completed / skipped / failed / halted). There is NO free text, NO target detail,
NO IP, NO secret, NO internal path — the emitter writes only these fields and the reader drops anything whose
phase/status is not on the allowlist. So a leak is impossible even if the caller passes extra data.

INCREMENTAL. ``seq`` is the row's line index; :func:`read` takes a ``since`` cursor and returns only rows after
it, so the UI polls for new activity without re-downloading history. Bounded (the reader caps rows; an
engagement emits only ~dozens of transitions). Best-effort + fail-closed: emit NEVER raises into the engine;
read NEVER raises into the edge (a missing/corrupt file reads as empty).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

# The FIXED allowlist of engagement stage names (mirrors framework.v2.phase_ledger.ORDERED_PHASES — kept here as
# a literal so vigil_core imports no framework). A phase not on this list is DROPPED by the reader.
_PHASES: "dict[str, str]" = {
    "preflight": "Preparing the authorized assessment",
    "intel_recon": "Reviewing reachable services",
    "transfer": "Loading the engagement scope",
    "scan": "Running authorized checks",
    "intel_finalize": "Correlating reconnaissance",
    "assess_findings": "Evaluating observations",
    "chaining": "Chaining attack paths",
    "grounding": "Confirming evidence with the oracle",
    "fusion": "Fusing corroborated findings",
    "defender": "Deriving defensive guidance",
    "reasoning_pass": "Recording the assessment evidence",
    "report": "Preparing the final dossier",
}
_STATUSES = frozenset({"started", "completed", "skipped", "failed", "halted"})
_MAX_READ = 500            # bound a single read (an engagement emits ~dozens of transitions)
_MAX_LINE = 256            # a row is tiny; cap the bytes we ever parse per line


def _safe_component(slug: str) -> Optional[str]:
    s = str(slug or "")
    if not s or ".." in s or "/" in s or "\\" in s or s.startswith(".") or len(s) > 128:
        return None
    return s


def _path(base: Any, slug: str) -> Optional[Path]:
    comp = _safe_component(slug)
    if comp is None or base is None:
        return None
    return Path(str(base)) / f"{comp}.activity.jsonl"


def emit(base: Any, slug: str, phase: str, status: str, *, ts: float) -> None:
    """Append ONE customer-safe activity row for ``slug`` under the shared seam ``base``. Only ``phase`` /
    ``status`` on the fixed allowlist are written; anything else is silently ignored. Best-effort: NEVER raises
    (a filesystem error must never perturb the engine). Called by the offense phase ledger."""
    p = _path(base, slug)
    if p is None or phase not in _PHASES or status not in _STATUSES:
        return
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        row = json.dumps({"ts": float(ts), "phase": str(phase), "status": str(status)}, ensure_ascii=False)
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(row + "\n")
    except OSError:
        return


def read(base: Any, slug: str, *, since: int = -1, limit: int = 200) -> "list[dict]":
    """The customer-safe activity rows for ``slug`` with line-index ``seq`` > ``since`` (the cursor is an
    EXCLUSIVE last-seen seq; the default -1 returns from the first row), newest at the end, each
    ``{seq, ts, phase, label, status}`` with a friendly ``label``. Pure-stdlib, bounded, fail-closed: a
    missing/corrupt/oversized file reads as ``[]``; a row whose phase/status is off the allowlist is DROPPED
    (never shown). Called by the sovereign Live Control adapter."""
    p = _path(base, slug)
    if p is None:
        return []
    try:
        with p.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: "list[dict]" = []
    lim = max(1, min(int(limit or 200), _MAX_READ))
    start = int(since if since is not None else -1)
    for seq, line in enumerate(lines):
        if seq <= start or len(line) > _MAX_LINE:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        phase, status = rec.get("phase"), rec.get("status")
        label = _PHASES.get(str(phase))
        if label is None or status not in _STATUSES:          # off-allowlist -> dropped (customer-safe)
            continue
        ts = rec.get("ts")
        out.append({"seq": seq, "ts": float(ts) if isinstance(ts, (int, float)) else 0.0,
                    "phase": str(phase), "label": label, "status": str(status)})
        if len(out) >= lim:
            break
    return out
