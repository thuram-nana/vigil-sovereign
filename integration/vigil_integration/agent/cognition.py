"""
agent.cognition — non-authoritative cognition governors (VIGIL-FUSION F5).

Adapted from redamon's ``agentic/orchestrator_helpers/productivity.py`` (MIT; see NOTICE). These are
the "prove-don't-guess applied to the agent's own honesty" layer: they detect stalls, loops, and
self-deception and escalate the agent's own *governance* (hint → deep-think → require-pivot →
block-next-expensive-call).

**Sovereign doctrine (non-negotiable):** every function here is a BUDGET / SCHEDULING governor only.
A productivity verdict, a stall score, or an anomaly NEVER gates a finding's truth — that is the
deterministic oracle's sole job (``agent.react.intake_result``). These governors may re-rank, defer,
hint, or block an *expensive next call*; they may never promote or suppress a FACT. This module does
not import, construct, or mutate a ``Finding`` or ``AgentState.facts``; it operates only over the
``execution_trace`` (a list of step dicts) and returns scores/verdicts/guidance strings.

Two ports are especially kin to VIGIL's veracity firewall and are the highest-value adds:

  * ``audit_productivity_claim`` — cross-checks the LLM's self-reported "I made progress" against the
    MEASURED state delta (a *non-empty* extracted collection or an appended finding, never a truthy
    scalar) and downgrades a dishonest ``new_info`` to ``no_progress`` (the model can't lie its way to
    looking productive).
  * ``detect_uniform_response_anomaly`` — a same-diagnostic-class + near-identical-size + sub-50ms
    streak means the input is short-circuited BEFORE the layer under test, so the result is
    **INCONCLUSIVE, not NEGATIVE** — it prevents the classic false "vector tested, target safe" (a
    hallucinated negative). Uniformity is a size-SPREAD check (tolerant of echoed-payload jitter), not
    a hard bucket grid.

**Robustness:** ``execution_trace`` steps, ``tool_args`` and ``tool_output`` originate from tool output
(untrusted, attacker-influenceable), so every public function is total on any JSON-representable tool
output — the real untrusted channel — degrading a crafted response to "no signal" rather than raising
(a stall-detector that crashes on a hostile response would be a denial-of-cognition). It does not
defend against an in-process caller passing a hostile Python object (e.g. a ``dict`` subclass whose
``__len__`` raises), which the JSON boundary cannot produce.

Pure/deterministic, stdlib only (hashlib/json/re/collections). No wallclock, no RNG. Import-clean.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Optional, Tuple

# --- defensive coercion (the untrusted-input surface is tool output) ---------------------------


def _safe_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return 0


def _as_text(v) -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    try:
        return str(v)
    except Exception:
        return ""


def _step_output(step) -> str:
    """The step's ``tool_output`` as a string. Tool output can be any type (structured/binary/None);
    coerce rather than trust it is a str."""
    if not isinstance(step, dict):
        return ""
    return _as_text(step.get("tool_output"))


def _safe_json(obj) -> str:
    try:
        return json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        return _as_text(obj)


def _nonempty_collection(v) -> bool:
    """Real state growth is a non-empty collection (a list of ports/services/…), NOT a truthy scalar.
    Closes the honesty-audit bypass where ``extracted_info={"ports": "anything"}`` faked progress.
    ``str``/``bytes`` are deliberately excluded — a string scalar is not evidence the state grew."""
    return isinstance(v, (list, tuple, set, dict)) and len(v) > 0


def _coll_len(v) -> int:
    """Length of ``v`` iff it is a real collection (list/tuple/set/dict), else 0. Used everywhere the
    module compares 'how much state is there' — a ``str``/``bytes``/scalar in a list-slot reads as 0
    (no growth) rather than crashing ``len()`` or faking growth (``len("open") == 4``). Single source
    of truth so the growth invariant is judged identically at all three decision points (the honesty
    audit, the productivity reward, and ``detect_state_growth``)."""
    return len(v) if isinstance(v, (list, tuple, set, dict)) else 0


def _trace_list(execution_trace) -> list:
    """Coerce the execution trace to a list. A truthy non-list container (int/dict/set) would otherwise
    subscript-crash the governors; the totality contract requires it degrade to 'no signal'."""
    return execution_trace if isinstance(execution_trace, list) else []


# Chars that render blank/zero-width but are NOT caught by isspace()/Cc/Cf/Mn — they masquerade as
# Letter(Lo)/Symbol(So), so category alone can't exclude them (U+3164 shares category Lo with real CJK).
_INVISIBLE_CHARS = frozenset(
    "ᅟᅠㅤﾠ"   # Hangul fillers (choseong/jungseong/filler/halfwidth) — Lo, zero-width
    "⠀"                     # Braille pattern blank — So, renders as an empty cell
)
# Categories whose members carry no standalone glyph: control, format, all separators, and non-spacing
# / enclosing combining marks (variation selectors U+FE0F etc. are Mn; a lone acute U+0301 is Mn).
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Zs", "Mn", "Me"})


def _has_visible_text(s: str) -> bool:
    """True iff ``s`` holds at least one glyph-bearing character. ``str.strip()`` only removes
    ``isspace()`` chars, so a citation made only of invisible characters would otherwise read as
    'non-empty'. This rejects: whitespace; control/format/separator chars (U+200B ZWSP, U+FEFF, U+2060,
    U+00AD, tag chars, …, all Cc/Cf/Z*); non-spacing/enclosing combining marks (variation selectors,
    lone accents, Mn/Me); and the known zero-width fillers that masquerade as letters/symbols (Hangul
    fillers, Braille blank). It is a denylist of the invisible classes, not a proof of visibility for
    every conceivable input — a genuine citation carries at least one ordinary letter/number/symbol and
    passes on that character."""
    for c in s:
        if c.isspace() or c in _INVISIBLE_CHARS or unicodedata.category(c) in _INVISIBLE_CATEGORIES:
            continue
        return True
    return False


# --- fingerprint / pattern helpers --------------------------------------------------------------


def _normalize_args_pattern(tool_name, tool_args) -> str:
    """Generalize tool args to a 'shape' so /order/300500 and /order/300600 collapse to one pattern."""
    raw = _safe_json(tool_args or {})
    normalized = re.sub(r"\b\d+\b", "<int>", raw)
    normalized = re.sub(r"\b[a-f0-9]{8,}\b", "<hex>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<ip>", normalized)
    normalized = re.sub(r"=[^&\"'\s]+", "=<val>", normalized)
    return f"{_as_text(tool_name) or '?'}::{normalized[:160]}"


def _output_fingerprint(step) -> str:
    """Stable 8-hex fingerprint of a step's tool output, normalized for trivial (timestamp/uuid) diffs."""
    raw = _step_output(step)[:8000]
    normalized = re.sub(r"\s+", " ", raw).strip()
    normalized = re.sub(r"\d{4}-\d{2}-\d{2}T[\d:.\-+Z]+", "<ts>", normalized)
    normalized = re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "<uuid>", normalized)
    normalized = re.sub(r"\b\d{10,}\b", "<num>", normalized)
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:8]


def _read_productivity(step) -> dict:
    """The LLM's productivity verdict from a step (top-level or nested under output_analysis)."""
    if not isinstance(step, dict):
        return {}
    top = step.get("productivity")
    if isinstance(top, dict) and top:
        return top
    nested = step.get("output_analysis")
    if isinstance(nested, dict):
        p = nested.get("productivity") or {}
        if isinstance(p, dict):
            return p
    return {}


def is_unproductive(step) -> bool:
    p = _read_productivity(step)
    if not p:
        return False
    if p.get("verdict") == "diagnostic_progress":
        return False
    if p.get("verdict") in ("no_progress", "duplicate", "blocked"):
        return True
    return p.get("new_information_gained") is False


def _target_info_grew(before, after) -> bool:
    b = before.get("target_info") if isinstance(before, dict) else None
    a = after.get("target_info") if isinstance(after, dict) else None
    b = b if isinstance(b, dict) else {}
    a = a if isinstance(a, dict) else {}
    for key in ("ports", "services", "technologies", "vulnerabilities",
                "credentials", "sessions", "subdomains", "endpoints"):
        if _coll_len(a.get(key)) > _coll_len(b.get(key)):   # a scalar/str in a list-slot = 0, no fake growth
            return True
    return False


# --- the honesty audit (kin to the veracity firewall) ------------------------------------------

_EXTRACT_KEYS = ("ports", "services", "technologies", "vulnerabilities", "credentials", "sessions")


def audit_productivity_claim(productivity, extracted_info, actionable_findings,
                             findings_grew: bool) -> Optional[str]:
    """Cross-check the LLM's productivity claim against the ACTUAL state delta. Returns a one-line
    discrepancy string if the model over-reported progress, else None. Budget-governor only — the
    outcome downgrades a *verdict* (scheduling), never a finding's truth. State growth requires a
    non-empty extracted collection or an appended finding, not a truthy scalar."""
    productivity = productivity if isinstance(productivity, dict) else {}
    if not productivity:
        return None
    ei = extracted_info if isinstance(extracted_info, dict) else {}
    verdict = productivity.get("verdict")
    claims_new = bool(productivity.get("new_information_gained", False))
    extracted_any = any(_nonempty_collection(ei.get(k)) for k in _EXTRACT_KEYS)
    # growth is a non-empty collection on EITHER evidence channel — never a truthy scalar (a scalar in
    # extracted_info OR actionable_findings is a contract violation, not proof the state grew).
    state_grew = bool(findings_grew or extracted_any or _nonempty_collection(actionable_findings))
    if claims_new and not state_grew:
        return ("Claimed new_information_gained=true but no finding was appended, no extracted_info was "
                "populated, and no actionable finding was produced.")
    if verdict == "new_info" and not state_grew:
        return "Verdict='new_info' but the engagement state did not grow this iteration."
    # a citation must be a NON-EMPTY STRING; a stringified container ("[]"/"{}"/"False"/"0") is not a
    # citation, so require the type explicitly rather than str()-then-strip (which would accept them).
    wwn = productivity.get("what_was_new")
    if verdict == "diagnostic_progress" and not (isinstance(wwn, str) and _has_visible_text(wwn)):
        return ("Verdict='diagnostic_progress' but what_was_new is not a non-empty text citation — cite "
                "the ruled-out cause or the changed result, otherwise this is no_progress.")
    return None


def downgrade_verdict_to_no_progress(productivity, reason: str) -> dict:
    if not isinstance(productivity, dict) or not productivity:
        return {"verdict": "no_progress", "new_information_gained": False, "what_was_new": "",
                "_original_verdict": None, "_downgrade_reason": reason}
    out = dict(productivity)
    out["_original_verdict"] = out.get("verdict")
    out["verdict"] = "no_progress"
    out["new_information_gained"] = False
    out["_downgrade_reason"] = reason
    return out


# --- uniform-response anomaly (INCONCLUSIVE, not NEGATIVE) --------------------------------------

_DIAGNOSTIC_FAILURE_CLASSES = frozenset({
    "shell_parser_error", "transport_error", "tool_internal_error",
    "application_5xx_fast", "application_5xx_networked_fast",
})


def detect_uniform_response_anomaly(execution_trace, *, window: int = 8, min_count: int = 5,
                                    size_tolerance: int = 32, duration_threshold_ms: int = 50) -> Optional[str]:
    """A streak of tool calls with the same diagnostic-failure class, near-identical body size, and all
    <``duration_threshold_ms`` means the input is rejected BEFORE the layer under test → the result is
    INCONCLUSIVE, not NEGATIVE. Returns a warning to inject (so the agent does not mark the vector
    'tested'), or None.

    The duration gate is the workhorse (a real reachable target answers in real time, >50ms, so a
    genuine 404/negative streak never fires); the class gate excludes real application responses (only
    diagnostic short-circuits qualify). Uniformity is a MODAL-CLUSTER check, not a max-min spread: it
    fires when ≥``min_count`` of a class's fast responses cluster within a per-size tolerance of one
    modal size. A robust (majority) statistic means one outlier — a single longer echoed payload or a
    lone truncated body — can no longer suppress an otherwise-uniform short-circuit streak (an
    adversary can't defeat the detector by varying one response). Biased toward firing within the two
    gates, because a missed short-circuit (a hallucinated NEGATIVE) is the dangerous direction and an
    over-warning only prompts the agent to re-verify."""
    trace = _trace_list(execution_trace)
    if len(trace) < min_count:
        return None
    recent = [s for s in trace[-window:] if isinstance(s, dict)]
    if len(recent) < min_count:
        return None
    by_class: dict[str, list[int]] = {}   # diagnostic class -> output sizes among its FAST steps
    for step in recent:
        # coerce error_class: a non-string (list/dict) is unhashable and must degrade to no-signal, not
        # crash the `ec not in frozenset(...)` membership test.
        ec = _as_text(step.get("error_class")) or ("success" if step.get("success", True) else "_legacy")
        if ec not in _DIAGNOSTIC_FAILURE_CLASSES:
            continue
        dur = _safe_int(step.get("duration_ms"))
        if not (0 < dur < duration_threshold_ms):     # excludes slow (reachable) and 0/legacy steps
            continue
        by_class.setdefault(ec, []).append(len(_step_output(step)))
    best_ec: Optional[str] = None
    best_count, best_modal = 0, 0
    for ec in sorted(by_class):        # deterministic: on a tie the alphabetically-first class wins
        sizes = by_class[ec]
        if len(sizes) < min_count:
            continue
        # modal cluster: for each observed size, how many fast responses fall within tolerance of it?
        # tolerance scales with size so echoed-payload jitter clusters while wild variance does not.
        for s in sizes:
            tol = max(size_tolerance, s // 2)
            count = sum(1 for t in sizes if abs(t - s) <= tol)
            if count > best_count or (count == best_count and best_ec is None):
                best_ec, best_count, best_modal = ec, count, s
    if best_ec is None or best_count < min_count:
        return None
    return (f"RESPONSE-UNIFORMITY ANOMALY: {best_count} of your last {len(recent)} tool calls share "
            f"class `{best_ec}`, size ~{best_modal}B, all <{duration_threshold_ms}ms. Every probe is "
            f"short-circuited uniformly — the input is NOT reaching the layer under test. Do NOT mark "
            f"this vector 'tested'; the result is INCONCLUSIVE, not NEGATIVE.")


# --- tested-axes semantic ledger (catch slow session-wide loops) -------------------------------

_UNPRODUCTIVE_VERDICTS = frozenset({"no_progress", "duplicate", "blocked", "hard_failure"})
_BRUTE_HINTS = ("for pw in", "for password in", "rockyou", "wordlist", "10k-most-common",
                "passwords.txt", "common-credentials", "for line in f:")
_RX_USER = re.compile(r"['\"]username['\"]\s*:\s*['\"]([^'\"]{1,64})['\"]")
_RX_TARGET = re.compile(r"https?://([a-zA-Z0-9_.\-:]+(?:/[^\s'\"]*)?)")


def extract_axis(tool_name, tool_args) -> Optional[dict]:
    """The semantic 'axis' (the dials that stay FIXED) of a repeated-attempt tool (brute-force/fuzz/
    automated-injection), so textually-different attempts on the same logical vector dedup. None for a
    one-shot/cheap tool or any malformed/unrecognized shape. Total on untrusted args."""
    if not isinstance(tool_name, str) or not tool_name:
        return None
    args = tool_args if isinstance(tool_args, dict) else {}
    inner_tool, inner_args = tool_name, args
    if tool_name == "job_spawn":
        tn = args.get("tool_name")
        inner_tool = tn.strip() if isinstance(tn, str) else ""
        ia = args.get("args")
        inner_args = ia if isinstance(ia, dict) else {}
        if not inner_tool:
            return None
    if not isinstance(inner_args, dict):
        inner_args = {}
    if inner_tool == "execute_code":
        code = inner_args.get("code")
        if not isinstance(code, str) or not any(h in code.lower() for h in _BRUTE_HINTS):
            return None
        um = _RX_USER.search(code)
        if not um:
            return None
        tm = _RX_TARGET.search(code)
        return {"family": "credential_brute_force", "target": (tm.group(1).split("?")[0][:120] if tm else "<unknown>"),
                "fixed_user": um.group(1)[:64], "varied": "password"}
    if inner_tool == "execute_hydra":
        hargs = inner_args.get("args")
        argstr = hargs if isinstance(hargs, str) else _safe_json(inner_args)
        m = re.search(r"-l\s+([^\s]+)", argstr or "")
        return None if not m else {"family": "credential_brute_force", "target": "<hydra>",
                                   "fixed_user": m.group(1)[:64], "varied": "password"}
    if inner_tool == "execute_ffuf":
        fargs = inner_args.get("args")
        argstr = fargs if isinstance(fargs, str) else _safe_json(inner_args)
        um = re.search(r"-u\s+(\S+)", argstr or "")
        if not um:
            return None
        url = re.sub(r"FUZZ\d*", "FUZZ", um.group(1)).split("?")[0][:140]
        mc = re.search(r"-mc\s+([\d,]+)", argstr or "")
        # canonicalize the match-code SET (sort) so a reordered but identical filter dedups to one axis.
        fixed_filter = ",".join(sorted(mc.group(1).split(","))) if mc else "<default>"
        return {"family": "directory_brute_force", "target": url,
                "fixed_filter": fixed_filter, "varied": "wordlist"}
    if inner_tool == "execute_sqlmap" or (inner_tool == "kali_shell"
                                          and "sqlmap" in _as_text(inner_args.get("command"))):
        cmd = inner_args.get("command") or inner_args.get("args") or ""
        argstr = cmd if isinstance(cmd, str) else _safe_json(cmd)
        um = re.search(r"-u\s+['\"]?(https?://[^\s'\"]+)", argstr)
        return None if not um else {"family": "automated_sqli", "target": um.group(1).split("?")[0][:140],
                                    "varied": "tamper_or_technique"}
    return None


def axis_key(axis) -> str:
    if not isinstance(axis, dict) or not axis:
        return ""
    # sort by the stringified key (mixed-type keys are unorderable) and stringify values defensively so
    # a hostile shape can neither crash the sort nor a value's __str__.
    return "::".join(f"{_as_text(k)}={_as_text(axis.get(k))}" for k in sorted(axis, key=_as_text))


def _iter_entries(entries):
    return entries if isinstance(entries, list) else []


def axis_unproductive_count(tested_axes, key: str) -> int:
    axes = tested_axes if isinstance(tested_axes, dict) else {}
    return sum(1 for e in _iter_entries(axes.get(key)) if isinstance(e, dict)
               and (e.get("verdict") or "") in _UNPRODUCTIVE_VERDICTS)


def record_axis_attempt(tested_axes, key: str, iteration: int, verdict: str, tool: str) -> dict:
    """Immutable update: append an attempt on ``key`` to a copy of the ledger. The modified bucket is
    rebuilt as a fresh list so the input ledger and its buckets are never mutated; untouched buckets
    are shared by reference (append-only — no code path mutates a bucket in place)."""
    if not key:
        return tested_axes if isinstance(tested_axes, dict) else {}
    out = dict(tested_axes) if isinstance(tested_axes, dict) else {}
    out[key] = _iter_entries(out.get(key)) + [
        {"iteration": _safe_int(iteration), "verdict": verdict or "", "tool": tool or ""}]
    return out


def _max_axis_repeats(tested_axes) -> int:
    axes = tested_axes if isinstance(tested_axes, dict) else {}
    best = 0
    for entries in axes.values():
        c = sum(1 for e in _iter_entries(entries) if isinstance(e, dict)
                and (e.get("verdict") or "") in _UNPRODUCTIVE_VERDICTS)
        best = max(best, c)
    return best


# --- the continuous productivity score ---------------------------------------------------------


def _compute_weights(iteration: int, max_iterations: int, phase: str) -> dict:
    """Dynamic weights: early iterations tolerate more; late iterations punish stalls/repeats; the
    exploitation phase bumps axis-repeat and verdict weight (a tolerance→urgency curve)."""
    if not max_iterations or max_iterations <= 0:
        max_iterations = 100
    bracket = max(0.0, min(1.0, iteration / max_iterations))
    w = {
        "w_verdict_count": 1.0,
        "w_state_growth": 1.0 + 2.0 * bracket,   # 1.0 → 3.0
        "w_axis_repeats": 2.0 + 2.0 * bracket,    # 2.0 → 4.0
        "w_same_pattern": 0.5,
        "r_new_info": 2.0 - 1.0 * bracket,        # reward shrinks late: 2.0 → 1.0
        "r_actionable": 1.0 - 0.5 * bracket,      # 1.0 → 0.5
    }
    if phase == "exploitation":
        w["w_axis_repeats"] += 1.0
        w["w_verdict_count"] += 0.5
    return w


def _same_pattern_count(execution_trace, window: int = 6) -> int:
    steps = [s for s in _trace_list(execution_trace)[-window:] if isinstance(s, dict)]
    if not steps:
        return 0
    sigs = [(_normalize_args_pattern(s.get("tool_name"), s.get("tool_args") or {}), _output_fingerprint(s))
            for s in steps]
    return max(Counter(sigs).values()) if sigs else 0


def _unproductive_count(execution_trace, window: int = 6) -> int:
    n = 0
    for step in _trace_list(execution_trace)[-window:]:
        if not isinstance(step, dict):
            continue
        if _read_productivity(step):
            if is_unproductive(step):
                n += 1
            continue
        out_low = _step_output(step)[:500].lower()
        if (not step.get("success", True)) or "failed" in out_low or "error" in out_low:
            n += 1
    return n


def _new_info_events_in_window(execution_trace, window: int = 5) -> Tuple[int, int]:
    new_info = actionable = 0
    for step in _trace_list(execution_trace)[-window:]:
        if not isinstance(step, dict):
            continue
        if _read_productivity(step).get("verdict") == "new_info":
            new_info += 1
        # a reward requires a non-empty collection of findings — a truthy SCALAR must not suppress the
        # stall/deep-think governor (the same growth invariant the honesty audit enforces).
        if _nonempty_collection(step.get("actionable_findings")):
            actionable += 1
    return new_info, actionable


def compute_productivity_score(*, execution_trace, tested_axes, iterations_since_state_grew: int,
                               iteration: int, max_iterations: int, phase: str = "informational",
                               window: int = 6, new_info_window: int = 5) -> dict:
    """The 5-signal weighted stall/loop score (higher = less productive). Returns the score + its
    components + weights. This drives ``tier_for_score`` / ``governance_decision`` — budget only."""
    iteration, max_iterations = _safe_int(iteration), _safe_int(max_iterations)
    weights = _compute_weights(iteration, max_iterations, phase)
    unproductive = _unproductive_count(execution_trace, window=window)
    stall = max(0, min(_safe_int(iterations_since_state_grew), 10))
    axis_max = _max_axis_repeats(tested_axes)
    same_pat = _same_pattern_count(execution_trace, window=window)
    new_info, actionable = _new_info_events_in_window(execution_trace, window=new_info_window)
    weighted = {
        "unproductive_verdicts": weights["w_verdict_count"] * unproductive,
        "iterations_since_state_grew": weights["w_state_growth"] * stall,
        "max_axis_repeats": weights["w_axis_repeats"] * axis_max,
        "same_pattern_count": weights["w_same_pattern"] * same_pat,
        "new_info_events": -weights["r_new_info"] * new_info,
        "actionable_events": -weights["r_actionable"] * actionable,
    }
    score = max(0.0, sum(weighted.values()))
    return {
        "score": round(score, 2),
        "components": {"unproductive_verdicts": unproductive, "iterations_since_state_grew": stall,
                       "max_axis_repeats": axis_max, "same_pattern_count": same_pat,
                       "new_info_events": new_info, "actionable_events": actionable},
        "weights": {k: round(v, 2) for k, v in weights.items()},
        "weighted": {k: round(v, 2) for k, v in weighted.items()},
    }


def tier_for_score(score: float, *, hint: float = 3.0, deepthink: float = 5.0,
                   pivot: float = 7.0, block: float = 9.0) -> str:
    """green (no action) < hint (yellow) < deep-think (orange) < require-pivot (red) < block (critical)."""
    score = score if isinstance(score, (int, float)) and not isinstance(score, bool) else 0.0
    if score >= block:
        return "critical"
    if score >= pivot:
        return "red"
    if score >= deepthink:
        return "orange"
    if score >= hint:
        return "yellow"
    return "green"


# governance action per tier — BUDGET/SCHEDULING ONLY (never touches a finding's truth).
_TIER_ACTION = {
    "green": "none",
    "yellow": "inject_hint",
    "orange": "require_deep_think",
    "red": "require_pivot",
    "critical": "block_next_expensive_call",
}


@dataclass(frozen=True)
class GovernanceVerdict:
    score: float
    tier: str
    action: str        # none | inject_hint | require_deep_think | require_pivot | block_next_expensive_call
    components: dict


def governance_decision(*, execution_trace, tested_axes, iterations_since_state_grew: int,
                        iteration: int, max_iterations: int, phase: str = "informational") -> GovernanceVerdict:
    """The single VIGIL entry point: score the run's productivity and map it to an escalating BUDGET
    governance action. **Never authoritative** — the returned action can only re-rank/defer/hint/block
    an expensive next call; it can never promote, suppress, or gate a finding (the oracle's sole job)."""
    result = compute_productivity_score(
        execution_trace=execution_trace, tested_axes=tested_axes,
        iterations_since_state_grew=iterations_since_state_grew, iteration=iteration,
        max_iterations=max_iterations, phase=phase)
    tier = tier_for_score(result["score"])
    return GovernanceVerdict(result["score"], tier, _TIER_ACTION[tier], result["components"])


# --- deep-think novelty guard (≥2 competing hypotheses; a re-plan can't paraphrase the prior) ---


def _tokens(text) -> set:
    return set(re.findall(r"[a-z0-9]{3,}", _as_text(text).lower()))


def jaccard(a, b) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    inter = len(ta & tb)
    union = len(ta | tb) or 1
    return inter / union


def deep_think_is_novel(new_plan, prior_plan, *, competing_hypotheses: int,
                        min_hypotheses: int = 2, max_jaccard: float = 0.8,
                        max_prior_coverage: float = 0.9) -> Tuple[bool, str]:
    """A deep-think re-plan is accepted only if it articulates ≥``min_hypotheses`` competing hypotheses
    AND does not restate the prior dead approach. Two independent checks, because symmetric Jaccard
    alone is defeatable: a plan that keeps the ENTIRE prior plan verbatim and pads it with novel tokens
    dilutes Jaccard below the threshold yet is a full restatement. So we ALSO reject when the new plan
    CONTAINS ≥``max_prior_coverage`` of the prior plan's tokens (a superset of the dead approach).
    Budget-governor only."""
    if _safe_int(competing_hypotheses) < min_hypotheses:
        return False, f"deep-think needs >= {min_hypotheses} competing hypotheses (got {competing_hypotheses})"
    sim = jaccard(new_plan, prior_plan)
    if sim >= max_jaccard:
        return False, f"deep-think re-plan paraphrases the prior plan (jaccard {sim:.2f} >= {max_jaccard})"
    prior_tokens = _tokens(prior_plan)
    coverage = len(prior_tokens & _tokens(new_plan)) / len(prior_tokens) if prior_tokens else 0.0
    if coverage >= max_prior_coverage:
        return False, (f"deep-think re-plan restates the whole prior plan (covers {coverage:.2f} of its "
                       f"tokens >= {max_prior_coverage}) — it is a padded superset, not a pivot")
    return True, f"novel re-plan (jaccard {sim:.2f}, prior-coverage {coverage:.2f}, {competing_hypotheses} hypotheses)"


# --- stall bookkeeping -------------------------------------------------------------------------


def detect_state_growth(before_state, after_state) -> bool:
    if _target_info_grew(before_state, after_state):
        return True
    before_cf = before_state.get("chain_findings_memory") if isinstance(before_state, dict) else None
    after_cf = after_state.get("chain_findings_memory") if isinstance(after_state, dict) else None
    return _coll_len(after_cf) > _coll_len(before_cf)   # scalar/str in the slot = 0, never fake growth/crash


def update_stall_counters(iterations_since_grew, diagnostic_streak, *, grew: bool, diag: bool,
                          cap: int = 6) -> Tuple[int, int]:
    """(new_iters_since_grew, new_diag_streak). Real growth resets both; diagnostic progress resets the
    stall counter only up to ``cap`` consecutive times between real findings (so debugging a dead
    approach cannot mask a stall forever)."""
    its, ds, cap = _safe_int(iterations_since_grew), _safe_int(diagnostic_streak), _safe_int(cap)
    if grew:
        return 0, 0
    if diag and ds < cap:
        return 0, ds + 1
    return its + 1, ds
