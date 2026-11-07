"""
kernel.routing — model-tier routing policy (EC-2a).

Every URK reasoning call runs on ONE model today: the active backend's configured model
(``AnthropicBackend.model`` = ``CRUCIBLE_ANTHROPIC_MODEL``, default ``claude-opus-4-8``). That
is the single largest LLM cost, and the cost-dominant path (self-consistency, N samples over the
no-oracle bindings) pays it on every sample. This module lets an operator route the mechanical /
no-oracle reasoning tasks to a CHEAPER model while the finding-critical tasks stay on the capable
one — the biggest money lever in the engine.

It changes nothing about SOUNDNESS. A FACT is decided by a deterministic oracle re-firing over the
target's bytes, never by the LLM (FACT doctrine); routing touches no oracle. The only properties a
cheaper model can move — recall (worse hypotheses → fewer leads) and lead/narrative precision — are
exactly what the benchmark eval gate (``eval/gate.py``) measures, so the A/B no-regression proof
(EC-2b) is what makes turning routing ON defensible.

Two hard safety rules are structural here:

  * **default-OFF** — ``routing_enabled()`` is False unless the operator sets
    ``CRUCIBLE_MODEL_ROUTING``. With routing off, :func:`resolve_model` returns the backend's own
    configured model for every tier, so the engine is byte-identical to pre-EC-2a.
  * **fail-toward-capable** — routing disabled, an empty/unknown tier, or a tier the operator has
    not explicitly mapped all resolve to the backend's configured (capable) model. A cheaper model
    is used ONLY where the operator deliberately mapped that tier. Nothing ever silently downgrades.

The per-binding tier ASSIGNMENTS (:data:`_BINDING_TIERS`) ship as an auditable table; the
tier→model MAPPING is operator policy (per-tier env vars). So shipping this module changes no
behaviour until an operator opts in.

FATAL-2: this is engine-plane and PURE — stdlib + env only. It imports nothing from ``kernel.llm``
(so it can be imported by it without a cycle), nothing from any backend, and nothing from the
sovereign plane.
"""

from __future__ import annotations

import os

# The tier vocabulary, ordered MOST → LEAST capable. "deep" is the capable default used for the
# finding-critical bindings; "standard"/"cheap" are the operator's cheaper rungs. The vocabulary is
# fixed (an unknown tier name is ignored → default), so a typo can never route to an unintended
# model. EC-7 (tiered Quick/Deep products) reuses this same vocabulary.
TIERS: tuple[str, ...] = ("deep", "standard", "cheap")

# The ONE auditable per-binding default-tier table, keyed on the stable cognitive-doc stem each
# binding passes to ``binding.run``. The finding-GATE (critique), the lead GENERATOR (hypothesize),
# and the severity/worth-reporting DECISION (decide) stay on the capable "deep" tier — these move
# recall and what becomes a finding. The no-oracle framing / mechanical bindings (threat-model draft,
# pivot suggestions, opsec posture guidance) default to "standard". No binding defaults to "cheap";
# it stays available for an operator / EC-7 to assign explicitly.
_BINDING_TIERS: dict[str, str] = {
    # finding-critical → capable
    "self-critique": "deep",       # CritiqueResult — gates findings
    "hypothesis-driven": "deep",   # HypothesisSet — generates the leads oracles then confirm
    "decision-frameworks": "deep", # SeverityDecision — severity + worth_reporting
    # no-oracle framing / mechanical → standard
    "threat-modeling": "standard", # ThreatModel — planning/framing
    "pivot-protocols": "standard", # PivotProposal — next-thread suggestions
    "opsec-discipline": "standard",# OpsecGuidance — posture guidance (advisory)
}

# The capable tier every unmapped binding falls back to. Keeping this named (not a bare literal)
# makes "an unknown binding routes to the CAPABLE tier" an explicit, testable guarantee.
_DEFAULT_TIER = "deep"

_ENABLE_ENV = "CRUCIBLE_MODEL_ROUTING"
_TIER_ENV_PREFIX = "CRUCIBLE_MODEL_TIER_"   # + <TIER>.upper(), e.g. CRUCIBLE_MODEL_TIER_STANDARD


def routing_enabled() -> bool:
    """True iff the operator opted into model-tier routing (``CRUCIBLE_MODEL_ROUTING`` truthy).
    Default OFF — with routing off the engine is byte-identical to pre-EC-2a (every tier resolves
    to the backend's own model). Mirrors the truthy convention used by the other kernel opt-outs."""
    return os.environ.get(_ENABLE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def is_known_tier(tier: str) -> bool:
    """True iff ``tier`` is in the fixed :data:`TIERS` vocabulary (case-insensitive)."""
    return str(tier or "").strip().lower() in TIERS


def _tier_model_override(tier: str) -> str:
    """The operator's model mapping for ``tier`` via ``CRUCIBLE_MODEL_TIER_<TIER>``, or "" if unset.
    The value is honored verbatim (the operator's choice of model string); only emptiness matters."""
    env = f"{_TIER_ENV_PREFIX}{str(tier or '').strip().upper()}"
    return os.environ.get(env, "").strip()


def resolve_model(tier: str, default_model: str) -> str:
    """The concrete model a call declaring ``tier`` should use, given the active backend's own
    ``default_model``. The fail-toward-capable contract, in order:

      1. routing disabled                         → ``default_model``
      2. empty / unknown tier name                → ``default_model``
      3. tier mapped via ``CRUCIBLE_MODEL_TIER_<TIER>`` → that model (operator's explicit choice)
      4. tier known but UNMAPPED                   → ``default_model``

    So a cheaper model is returned ONLY in case 3 — an explicit operator mapping of a recognised
    tier. Every other path returns the backend's configured (capable) model. Pure; never raises
    (a missing ``default_model`` yields ""→ the caller's own model-family logic handles it)."""
    default_model = str(default_model or "")
    if not routing_enabled():
        return default_model
    t = str(tier or "").strip().lower()
    if t not in TIERS:
        return default_model
    override = _tier_model_override(t)
    return override or default_model


def tier_for_binding(key: str) -> str:
    """The default tier for a cognitive binding, keyed on its ``cognitive_doc_stem`` (preferred) or
    ``schema_name``. An unknown/empty key falls back to the CAPABLE :data:`_DEFAULT_TIER` — a new or
    unrecognised binding is never silently routed cheap. Pure lookup; never raises."""
    return _BINDING_TIERS.get(str(key or "").strip(), _DEFAULT_TIER)
