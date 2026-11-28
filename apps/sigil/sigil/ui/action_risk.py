"""action_risk — the DETERMINISTIC-FIRST risk classifier for a proposed customer engagement action.

This is the "approval judge" of VIGIL's per-action approval gate (the richer-and-safer sibling of Strix's
LLM approval judge). Where Strix asks a model to classify every risky action, VIGIL decides risk
DETERMINISTICALLY from a fixed rule/allow-list over the action KIND + its SCOPE + its BLAST-RADIUS, and only
THEN lets an OPTIONAL advisory LLM judge RAISE (never lower) the verdict. The model is advice, not authority:
the deterministic floor already decides whether the gate fires, so a prompt-injected or absent judge can only
ever make the gate MORE cautious, never release an action the rules flagged.

Doctrine, enforced BY CONSTRUCTION here (not by the model's good behaviour):
  * FAIL-CLOSED / unknown ⇒ risky. An action kind this module does not recognise is classified HIGH and
    gated — a new, unreviewed action can never slip past the gate as "not risky".
  * DETERMINISTIC-FIRST. :func:`classify_action` is a pure function of the action kind and a closed set of
    blast-radius FACTS the caller supplies (``out_of_scope`` / ``out_of_window`` / ``spend_crossing`` /
    ``cross_tenant_adjacent`` / ``destructive``). No I/O, no clock, no model.
  * RAISE-ONLY JUDGE. :func:`apply_advisory_judge` folds an OPTIONAL model verdict in with ``max`` over the
    risk level and a UNION over the categories: it can lift a LOW action to HIGH, but it can NEVER lower the
    deterministic floor, and a malformed / unparseable judge verdict RAISES to HIGH (fail-closed), never
    accepts a lower one.

Risk categories mirror Strix's (``changes_target`` / ``disrupts_service`` / ``deletes_data``) and add
VIGIL's own (``out_of_scope`` / ``out_of_window`` / ``spend_crossing``), so the gate's prompt can name WHY an
action was flagged in the operator's own terms.

FATAL-2: sovereign-only, pure-stdlib, ``assert_no_offense`` at import. It imports no offense plane and holds
no key: it is a DECISION module, exactly like ``engagement_flow`` (the brain, never the hands).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

# --- the ordered risk levels (ints so a test can pin the exact ladder; max() composes them) ------------------
NONE = 0
LOW = 1
ELEVATED = 2
HIGH = 3
LEVELS = (NONE, LOW, ELEVATED, HIGH)
_LEVEL_NAME = {NONE: "none", LOW: "low", ELEVATED: "elevated", HIGH: "high"}
_NAME_LEVEL = {v: k for k, v in _LEVEL_NAME.items()}

# At or above this level the gate FIRES (the action pauses for an owner Allow/Block). Below it the action
# proceeds exactly as before.
APPROVAL_LEVEL = ELEVATED
# At this level the Allow additionally requires a FRESH step-up second factor (money / destructive / scope).
STEPUP_LEVEL = HIGH

# --- the risk categories (Strix parity + VIGIL's own) -------------------------------------------------------
CHANGES_TARGET = "changes_target"          # the action acts ON the assessed target
DISRUPTS_SERVICE = "disrupts_service"      # the action could affect the target's availability
DELETES_DATA = "deletes_data"              # the action could destroy data (irreversible)
OUT_OF_SCOPE = "out_of_scope"              # the action reaches outside the proven/authorized scope
OUT_OF_WINDOW = "out_of_window"            # the action falls outside the authorized time window
SPEND_CROSSING = "spend_crossing"          # the action reserves / crosses a spend threshold
CATEGORIES = (CHANGES_TARGET, DISRUPTS_SERVICE, DELETES_DATA, OUT_OF_SCOPE, OUT_OF_WINDOW, SPEND_CROSSING)

# --- the DETERMINISTIC base policy: action kind -> (base level, base categories) ----------------------------
# These action kinds are the ones ``engagement_flow.decide`` may NAME (its ``ACTIONS``). The table is a CLOSED
# allow-list: a kind NOT here is unknown ⇒ HIGH ⇒ gated (fail-closed), so a future action is caught by default.
#
#   * read / safe (NONE)        — a pure read or the DE-RISKING direction (pause/cancel STOP work; gating them
#                                 would be unsafe, so they are never gated).
#   * scope-establishing (LOW)  — verify mints an authority but is ALREADY gated by the explicit "I am
#                                 authorized" affirmation upstream; LOW keeps the gate from double-prompting.
#   * live-steering (ELEVATED)  — instruct / resume re-point or re-enable a LIVE engagement against the target.
#   * launch (HIGH)             — reserve_start spends credits AND acts on the target: the genuinely risky one.
_BASE: "dict[str, tuple[int, tuple[str, ...]]]" = {
    "none": (NONE, ()),
    "assets": (NONE, ()),
    "activity": (NONE, ()),
    "challenge": (NONE, ()),
    "verify": (LOW, (CHANGES_TARGET,)),
    "pause": (NONE, ()),                                   # stopping work is the safe direction — never gated
    "cancel": (NONE, ()),                                  # stopping work is the safe direction — never gated
    "resume": (ELEVATED, (CHANGES_TARGET,)),               # re-enables a live engagement against the target
    "instruct": (ELEVATED, (CHANGES_TARGET,)),             # re-points a live engagement (advisory, but steers scope)
    "reserve_start": (HIGH, (CHANGES_TARGET, SPEND_CROSSING)),  # launch: spends AND acts on the target
}

# A blast-radius FACT the caller may assert about THIS action, each mapping to the category it adds and the
# floor it RAISES the level to (never lowers). The caller derives these facts from the org's OWN scope / window
# / spend reads — never from the model.
_FACT_RULES: "dict[str, tuple[str, int]]" = {
    "out_of_scope": (OUT_OF_SCOPE, HIGH),
    "cross_tenant_adjacent": (OUT_OF_SCOPE, HIGH),
    "destructive": (DELETES_DATA, HIGH),
    "spend_crossing": (SPEND_CROSSING, HIGH),
    "out_of_window": (OUT_OF_WINDOW, ELEVATED),
    "disrupts_service": (DISRUPTS_SERVICE, ELEVATED),
}


def level_name(level: int) -> str:
    """The human name of a risk level (``none`` / ``low`` / ``elevated`` / ``high``); ``unknown`` for an
    out-of-range int (never raises — a label for a UI)."""
    return _LEVEL_NAME.get(int(level), "unknown")


@dataclass(frozen=True)
class RiskClassification:
    """The verdict for ONE proposed action. ``level`` is the numeric risk, ``categories`` the sorted reasons in
    the gate's vocabulary, ``reasons`` short human strings. ``requires_approval`` / ``requires_stepup`` are
    DERIVED from the level so a caller never re-implements the thresholds."""

    action: str
    level: int
    categories: tuple
    reasons: tuple

    @property
    def level_name(self) -> str:
        return level_name(self.level)

    @property
    def requires_approval(self) -> bool:
        return self.level >= APPROVAL_LEVEL

    @property
    def requires_stepup(self) -> bool:
        return self.level >= STEPUP_LEVEL

    def as_dict(self) -> dict:
        """A UI-safe, fixed-field projection (no key, no internal object) for the pending-approval card."""
        return {"action": self.action, "level": self.level, "level_name": self.level_name,
                "categories": list(self.categories), "reasons": list(self.reasons),
                "requires_approval": self.requires_approval, "requires_stepup": self.requires_stepup}


def classify_action(action: str, *, facts: "Optional[dict]" = None) -> RiskClassification:
    """The DETERMINISTIC verdict for ``action`` given a closed set of blast-radius ``facts``. PURE: no I/O, no
    clock, no model. An action kind NOT in the base policy is UNKNOWN ⇒ classified HIGH and gated (fail-closed),
    so a new action can never slip past as "not risky". Each truthy fact ADDS its category and RAISES the level
    to its floor (never lowers); the facts a caller does not assert simply do not apply."""
    kind = str(action or "").strip()
    base = _BASE.get(kind)
    if base is None:
        # Unknown ⇒ risky. A kind the policy does not recognise is HIGH + gated, never a silent NONE.
        return RiskClassification(action=kind or "(empty)", level=HIGH, categories=(CHANGES_TARGET,),
                                  reasons=(f"unrecognised action {kind!r} — gated fail-closed",))
    level, cats = base
    reasons: list = []
    cat_set = set(cats)
    if level >= APPROVAL_LEVEL:
        reasons.append(f"{kind} is a {_LEVEL_NAME[level]}-risk engagement action")
    for name, truthy in (facts or {}).items():
        if not truthy:
            continue
        rule = _FACT_RULES.get(str(name))
        if rule is None:
            continue
        cat, floor = rule
        cat_set.add(cat)
        if floor > level:
            level = floor
        reasons.append(f"blast-radius: {str(name)}")
    if not reasons and level >= APPROVAL_LEVEL:
        reasons.append(f"{kind} requires owner approval")
    return RiskClassification(action=kind, level=level, categories=tuple(sorted(cat_set)),
                              reasons=tuple(reasons))


def apply_advisory_judge(base: RiskClassification, judge: "Optional[Any]", *,
                         enabled: bool = True) -> RiskClassification:
    """Fold an OPTIONAL advisory LLM judge verdict into the deterministic ``base`` — RAISE-ONLY. The judge can
    LIFT a LOW action to HIGH (``max`` over the level, UNION over the categories) but can NEVER lower the
    deterministic floor, so a prompt-injected or over-permissive model can only make the gate MORE cautious.

    ``judge`` is advice in the shape ``{"level": "none|low|elevated|high", "categories": [...], "reason": str}``
    (or None). FAIL-CLOSED:
      * ``enabled is False`` or ``judge is None`` ⇒ return ``base`` unchanged (the judge is purely additive and
        off by default — a deployment with no judge is byte-identical to deterministic-only).
      * a MALFORMED judge (not a dict, or a ``level`` that is not one of the known names) ⇒ RAISE ``base`` to
        HIGH (unknown ⇒ risky), never accept the lower reading. The model's failure makes the gate fire, never
        release.
    The result's level is ``max(base.level, judge_level)`` — the judge is never authority, only an upward nudge."""
    if not enabled or judge is None:
        return base
    if not isinstance(judge, dict) or str(judge.get("level", "")) not in _NAME_LEVEL:
        # A judge we cannot parse is treated as "it thinks this is risky" — raise to HIGH, never lower.
        raised = max(base.level, HIGH)
        return RiskClassification(action=base.action, level=raised, categories=base.categories,
                                  reasons=base.reasons + ("advisory judge verdict unparseable — raised fail-closed",))
    jlevel = _NAME_LEVEL[str(judge.get("level"))]
    new_level = max(base.level, jlevel)                  # RAISE-ONLY: never below the deterministic floor
    jcats = judge.get("categories")
    cat_set = set(base.categories)
    if isinstance(jcats, (list, tuple)):
        cat_set.update(str(c) for c in jcats if str(c) in CATEGORIES)
    reasons = list(base.reasons)
    jreason = judge.get("reason")
    if jlevel > base.level and isinstance(jreason, str) and jreason.strip():
        reasons.append(f"advisory judge raised risk: {jreason.strip()[:200]}")
    return RiskClassification(action=base.action, level=new_level, categories=tuple(sorted(cat_set)),
                              reasons=tuple(reasons))
