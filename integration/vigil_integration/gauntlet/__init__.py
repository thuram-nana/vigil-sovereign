"""
vigil_integration.gauntlet — the AI-Gauntlet offensive-LLM sensor family (VIGIL-FUSION F8).

A uniform ``run(spec, *, oracle) -> list[Finding]`` that drives an external red-team framework
(garak / PyRIT / Giskard / promptfoo) behind an injected subprocess boundary, normalizes its output, and
routes every candidate by the OWASP-LLM ``oracle_kind``:

  * ``contains`` / ``classifier`` / ``regex`` (DETERMINISTIC) → an injected randomized-challenge oracle
    re-executes → a confirmed one mints a signed FACT (``agent.state.Finding`` with an evidence ref);
  * ``judge_llm`` (NON-DETERMINISTIC) → ALWAYS a LEAD, never auto-promoted.

The sovereign invariant — an LLM-judge result can never become a machine-verified fact — is enforced in
``sensor.route_candidate`` (the judge_llm branch returns before any oracle call). ASR is a metric, never
a promotion signal. Everything is total on untrusted input, deterministic (injected seed), fail-closed,
and import-clean (pydantic/stdlib + the F1 safety / F3 tools seam; no garak/PyRIT import, no network).

Adapted from redamon (MIT; see NOTICE); SCOUT-INVENTORY §5 C7.
"""

from __future__ import annotations

from .adapters import (
    KNOWN_TOOLS,
    CandidateFinding,
    parse_adapter_output,
    safe_preview,
)
from .metrics import (
    attack_success_rate,
    sanitize_counts,
    severity_band,
)
from .owasp_map import (
    CLASSIFIER,
    CONTAINS,
    DEFAULT_ENTRY,
    DETERMINISTIC_KINDS,
    JUDGE_LLM,
    OWASP_MAP,
    REGEX,
    OwaspEntry,
    family_of,
    is_deterministic_category,
    map_category,
    map_family,
    oracle_kind_of,
)
from .sensor import (
    CategoryMetric,
    GauntletOracle,
    GauntletResult,
    GauntletSpec,
    OracleRequest,
    RunTool,
    route_candidate,
    run,
    run_gauntlet,
)

__all__ = [
    # taxonomy / routing seam
    "OwaspEntry", "OWASP_MAP", "DEFAULT_ENTRY", "DETERMINISTIC_KINDS",
    "CONTAINS", "CLASSIFIER", "REGEX", "JUDGE_LLM",
    "map_category", "map_family", "family_of", "oracle_kind_of", "is_deterministic_category",
    # metrics
    "attack_success_rate", "severity_band", "sanitize_counts",
    # adapters (subprocess boundary)
    "KNOWN_TOOLS", "CandidateFinding", "parse_adapter_output", "safe_preview",
    # sensor
    "GauntletSpec", "OracleRequest", "GauntletOracle", "RunTool",
    "CategoryMetric", "GauntletResult", "route_candidate", "run", "run_gauntlet",
]
