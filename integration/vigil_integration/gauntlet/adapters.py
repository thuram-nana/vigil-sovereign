"""
gauntlet.adapters — the subprocess-boundary output normalizer (VIGIL-FUSION F8).

redamon ships four near-identical adapters (garak / PyRIT / Giskard / promptfoo) that each shell out to
a heavy external red-team framework via a shared ``proc.run_streamed`` launcher and fold the tool's
native JSON report into one normalized ``Finding`` schema. This module ports the NORMALIZER half of that
design — but the tools themselves stay **behind a subprocess boundary modelled as an injected
``run_tool(argv) -> raw_output`` callable** (see ``gauntlet.sensor``). We deliberately do NOT import
garak / PyRIT / Giskard / promptfoo: their conflicting, heavy deps stay out of this process, and the
subprocess boundary is the natural chokepoint for env-strip / egress-drop enforcement upstream.

Everything here is TOTAL on untrusted input — a tool's report is attacker-influenceable (a hostile model
can shape strings that land in it), so a malformed / adversarial / truncated report degrades to *no
candidate findings*, never a raise. The extracted category name is used ONLY to look up a TRUSTED
taxonomy row (``owasp_map.map_category``); the raw name never becomes part of an emitted record.

Reuses the F1 fail-closed ``extract_json`` and the F1/F3 redaction+untrusted-framing seam (``safe_preview``).

Import-clean: stdlib + the F1 safety / F3 tools helpers; no external red-team framework, no network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..safety.llm_intake import extract_json
from ..safety.prompt_safety import wrap_untrusted_inline
from ..tools import redact_tool_args
from .metrics import _coerce_int

# The red-team tools we know how to drive through the subprocess boundary. An unknown tool yields no
# findings (fail-closed) rather than a guess.
KNOWN_TOOLS = frozenset({"garak", "pyrit", "giskard", "promptfoo"})

# Tolerant field aliases spanning all four tools' native report shapes (garak jsonl probe rows, PyRIT
# ``results[outcome,objective,turns_used]``, Giskard per-detector ``num_examples``, promptfoo per-plugin).
_NAME_KEYS = ("chip", "category", "probe", "family", "detector", "attack", "plugin", "objective", "name")
_HIT_KEYS = ("hits", "successes", "successful", "success", "failures", "detected", "flagged")
_TRIAL_KEYS = ("trials", "scored", "num_examples", "total", "attempts", "n", "count")
_ASR_KEYS = ("asr", "attack_success_rate", "rate", "success_rate")
_EVIDENCE_KEYS = ("evidence", "raw", "output", "sample", "response", "transcript", "detail", "completion")
# Keys under which a tool report nests its per-category result list.
_CONTAINER_KEYS = ("results", "probes", "issues", "detectors", "plugins", "findings", "records", "tests")

_PREVIEW_MAX = 240


def safe_preview(raw: object, *, limit: int = _PREVIEW_MAX) -> str:
    """A redacted + untrusted-wrapped one-line preview of adapter output, safe to log or hand to an LLM.

    Reuses ONE secret vocabulary (the F3 ``redact_tool_args`` scrubber — ``Bearer``/``api_key=``/
    ``--secret``) and the F1 unforgeable untrusted-nonce boundary (``wrap_untrusted_inline``). The full
    raw evidence a deterministic oracle re-executes over is NEVER written to a record by gauntlet; this
    is the sanctioned way to *display* a snippet of it. Total: any failure yields a wrapped empty body."""
    try:
        s = raw if isinstance(raw, str) else ("" if raw is None else str(raw))
        scrubbed = redact_tool_args({"t": s}).get("t", "")
        if not isinstance(scrubbed, str):
            scrubbed = str(scrubbed)
        lim = limit if isinstance(limit, int) and limit > 0 else _PREVIEW_MAX
        if len(scrubbed) > lim:
            scrubbed = scrubbed[:lim] + "…"
        return wrap_untrusted_inline(scrubbed, label="GAUNTLET_OUTPUT")
    except Exception:  # noqa: BLE001 — preview must never raise on hostile output
        return wrap_untrusted_inline("", label="GAUNTLET_OUTPUT")


@dataclass(frozen=True)
class CandidateFinding:
    """One normalized candidate parsed from a tool report — a PROPOSAL, pre-routing. ``evidence`` is the
    retained raw output a deterministic oracle re-executes over; it is transient (handed only to the
    injected oracle) and is never persisted by gauntlet. Use ``preview`` for any display/log."""

    tool: str
    category: str          # the raw tool category (untrusted; used only to look up a TRUSTED taxonomy row)
    hits: int
    trials: int
    evidence: str = ""

    @property
    def preview(self) -> str:
        return safe_preview(self.evidence)


def _first_str(rec: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _first_int(rec: dict, keys: tuple[str, ...]) -> int | None:
    for k in keys:
        if k in rec:
            n = _coerce_int(rec.get(k))
            if n is not None:
                return n
    return None


def _first_float(rec: dict, keys: tuple[str, ...]) -> float | None:
    for k in keys:
        if k in rec:
            v = rec.get(k)
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                return float(v)
            if isinstance(v, str):
                try:
                    return float(v.strip())
                except (TypeError, ValueError):
                    continue
    return None


def _counts(rec: dict) -> tuple[int, int]:
    """Derive ``(hits, trials)`` from a tolerant union of the four tools' count fields. Prefer explicit
    hits+trials; else derive hits from an explicit ASR × trials; else fall back to a binary present/absent
    (matching Giskard's ``ASR=1.0`` special-case). Unsanitized here — the caller sanitizes."""
    h = _first_int(rec, _HIT_KEYS)
    t = _first_int(rec, _TRIAL_KEYS)
    a = _first_float(rec, _ASR_KEYS)
    if h is not None and t is not None:
        return h, t
    if a is not None and t is not None:
        return int(round(a * t)), t
    if h is not None:
        # hits with unknown trials: assume each recorded hit was one trial (a conservative "present"
        # signal). ASR bands high; the veracity is still decided only by the oracle, never by ASR.
        return h, (h if h > 0 else 1)
    if a is not None:
        return (1 if a > 0 else 0), 1
    return 0, 0


def _records(obj: Any) -> list:
    """Flatten a parsed report into a list of candidate record dicts, tolerant of every tool's shape:
    a bare list, a ``{"results": [...]}``-style container, a single-record dict, or a Giskard-style
    ``{detector: {...}, ...}`` grouping (name injected). Total: anything else → ``[]``."""
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in _CONTAINER_KEYS:
            v = obj.get(key)
            if isinstance(v, list):
                return v
        # a name→record grouping (Giskard defaultdict per detector)
        values = list(obj.values())
        if values and all(isinstance(v, dict) for v in values):
            return [{"name": k, **v} for k, v in obj.items() if isinstance(v, dict)]
        # otherwise treat the dict itself as one record (a single-probe report)
        return [obj]
    return []


def parse_adapter_output(tool: object, raw_output: object) -> list[CandidateFinding]:
    """Parse a red-team tool's raw report (a string from the injected ``run_tool``, or an already-parsed
    list/dict) into normalized candidate findings. TOTAL on untrusted / malformed / truncated /
    adversarial input — anything unparseable yields ``[]`` (no signal), never a raise. Deterministic:
    candidate order follows the report's record order."""
    t = tool if isinstance(tool, str) else ""
    if isinstance(raw_output, str):
        obj = extract_json(raw_output)
    elif isinstance(raw_output, (list, dict)):
        obj = raw_output
    else:
        obj = None
    out: list[CandidateFinding] = []
    for rec in _records(obj):
        if not isinstance(rec, dict):
            continue
        category = _first_str(rec, _NAME_KEYS)
        if not category:
            continue  # a record with no identifiable category carries no usable signal
        hits, trials = _counts(rec)
        evidence = _first_str(rec, _EVIDENCE_KEYS)
        out.append(CandidateFinding(tool=t, category=category, hits=hits, trials=trials, evidence=evidence))
    return out
