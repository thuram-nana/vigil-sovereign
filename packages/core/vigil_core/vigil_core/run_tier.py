"""RUN-TIER derivation — the PURE shared leaf behind EC-7 tiered Quick/Deep launch products.

A launch PRODUCT (``catalog.LaunchProduct``) is one of a small, fixed set of run tiers — ``"quick"`` (a
surface-roster, cheaper-model, small-budget run) or ``"deep"`` (a full-roster, capable-model, large-budget
run). The run tier is NOT a new owner-signed field: it is DERIVED from the launch's already-signed
``units_reserved`` by a fixed units band, so EC-7 adds NO snapshot-schema bump and no new signed record. Both
planes import this leaf — the sovereign catalog (to DEFINE + VALIDATE the products) and the offense engine (to
RESOLVE the run profile / model-routing lever) — over the same two-process boundary as ``token_budget`` /
``run_budget``.

FATAL-2: stdlib ONLY (``os``) — NO ``framework.*``, NO ``sigil.*``, NO offense symbol. The run tier maps to
the engine's engagement-profile vocabulary (``engage`` profiles ``surface|deep|full``) and to the EC-2a
model-routing ON/OFF lever (``kernel.routing``) as plain values — a stable cross-module contract. An
ENGINE-side conformance test pins that the profile name this leaf emits is a real ``engage`` profile, so the
contract can never silently drift.

Fail directions (both SAFE, in different senses):
  * ``run_tier_for_units`` — a malformed / non-positive units resolves to ``"quick"`` (the SMALLER-impact,
    cheaper tier): a bad launch never silently escalates to the fuller/capable/large-budget ``"deep"`` run.
  * ``engage_profile_for`` — an unknown tier ⇒ ``"surface"`` (the smallest-impact roster): never silently the
    fullest scan against the target.
  * ``routing_enabled_for`` — an unknown tier ⇒ ``False`` (routing OFF ⇒ every binding on its CAPABLE model):
    this is the engine's own ``fail-toward-capable`` doctrine — never silently downgrade model quality.

Product numbers (the units band boundary) are an OWNER input — a PLACEHOLDER here + an env override, never a
hardcoded product decision, exactly like the catalog prices. The band must sit between the quick + deep product
unit sizes the catalog offers; the catalog validator enforces that consistency fail-closed at import.
"""
from __future__ import annotations

import os

# The PRODUCT run-tier vocabulary (fixed; an unknown tier is rejected fail-closed by the catalog validator).
RUN_TIERS: tuple[str, ...] = ("quick", "deep")

# The units BAND boundary: a launch whose signed units_reserved is <= this is "quick", else "deep". PLACEHOLDER
# (owner tunes via VIGIL_QUICK_MAX_UNITS); must sit between the quick + deep product unit sizes AND at/above the
# default per-launch units (config.LAUNCH_UNITS, default 10) so a non-tiered default launch classifies as the
# base "quick" tier — whose profile is run_engagement's own defaults, keeping EC-7 byte-identical when off.
_QUICK_MAX_UNITS_DEFAULT = 10

# run_tier → engagement profile (engage profiles: surface|deep|full). "quick" = the surface (low-impact)
# roster; "deep" = the full roster. A plain-string contract; the engine conformance test pins its validity.
_ENGAGE_PROFILE: dict[str, str] = {"quick": "surface", "deep": "full"}

# run_tier → the EC-2a model-routing lever. "quick" turns routing ON (the cheaper per-binding tiers are
# active); "deep" leaves it OFF (every binding stays on its capable model — the fullest, most thorough run).
_ROUTING_ENABLED: dict[str, bool] = {"quick": True, "deep": False}


def quick_max_units() -> int:
    """The units band boundary (``units <= this`` ⇒ quick). Owner-tunable via ``VIGIL_QUICK_MAX_UNITS``; a
    bad / non-positive value falls back to the placeholder (fail-safe: never a 0 band that makes every run
    'deep' / most-expensive)."""
    try:
        v = int(os.environ.get("VIGIL_QUICK_MAX_UNITS", ""))
    except (TypeError, ValueError):
        return _QUICK_MAX_UNITS_DEFAULT
    return v if v >= 1 else _QUICK_MAX_UNITS_DEFAULT


def tiered_products_enabled(env: "dict[str, str] | None" = None) -> bool:
    """True iff EC-7 tiered Quick/Deep run-tiering is ACTIVE (``VIGIL_TIERED_PRODUCTS`` affirmative). Default
    OFF ⇒ byte-identical to pre-EC-7: the keyless engage worker DERIVES + APPLIES no run tier (a launch runs
    ``run_engagement``'s own default roster and the deployment's own model-routing setting, untouched), and the
    sovereign catalog OFFERS no tiered product. The SAME flag both planes read — the sovereign side via
    ``sigil.config.tiered_products_enabled`` (mirrors it), the engine side via THIS shared leaf (FATAL-2: the
    offense-plane worker holds no ``sigil`` import, so the one reader both can reach lives here). The affirmative
    set matches the sovereign ``_OIDC_AFFIRMATIVE`` so the two never disagree on a real on/off value."""
    e = os.environ if env is None else env
    return (e.get("VIGIL_TIERED_PRODUCTS", "") or "").strip().lower() in ("1", "true", "yes", "on", "enabled")


def run_tier_for_units(units: int) -> str:
    """Derive the run tier from the launch's signed ``units_reserved`` (the band). Fail-SAFE toward the
    smaller-impact tier: a non-int / non-positive units resolves to ``"quick"``."""
    try:
        u = int(units)
    except (TypeError, ValueError):
        return "quick"
    # quick_max_units() is always >= 1, so a non-positive u is <= it ⇒ "quick" — the fail-SAFE direction falls
    # out of the band compare itself (no separate <=0 guard needed; a non-int already returned "quick" above).
    return "quick" if u <= quick_max_units() else "deep"


# run_tier → the model effort level a METERED run's grant pins (PRICING design §2.2): Quick = high, Deep = xhigh.
# (Max = max arrives with the Max product, M3.)
_EFFORT: dict[str, str] = {"quick": "high", "deep": "xhigh"}


def effort_for(run_tier: str) -> str:
    """The effort a run of ``run_tier`` is pinned to; an unknown tier resolves to the quick tier's (the cheaper,
    smaller-impact default — never a silent escalation)."""
    return _EFFORT.get(run_tier, _EFFORT["quick"])


def engage_profile_for(run_tier: str) -> str:
    """The engagement profile (``surface|deep|full``) a run tier resolves to. Unknown ⇒ ``"surface"`` (the
    smallest-impact roster)."""
    return _ENGAGE_PROFILE.get(run_tier, "surface")


def routing_enabled_for(run_tier: str) -> bool:
    """Whether a run tier turns the EC-2a model-routing lever ON (cheaper). Unknown ⇒ ``False`` (routing OFF
    ⇒ capable models — fail-toward-capable)."""
    return bool(_ROUTING_ENABLED.get(run_tier, False))


def profile_for_units(units: int) -> str:
    """Convenience: ``units_reserved`` → engagement profile, via the band + the run-tier→profile map."""
    return engage_profile_for(run_tier_for_units(units))
