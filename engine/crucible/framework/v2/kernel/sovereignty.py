"""
kernel.sovereignty — tiered substrate policy for URK backend selection.

Sovereign deployments fall on a ladder, not a binary. Operators
choose where they sit by setting `CRUCIBLE_SOVEREIGNTY_TIER`:

    AIR_GAPPED        — local backends only (Ollama / vLLM /
                        llama-cpp / TGI / DryRun). Cloud refused at
                        construction. Highest sovereignty; lowest
                        reasoning quality.
    SOVEREIGN_CLOUD   — local + jurisdictional cloud (AWS Bedrock
                        with regional restriction, Google Vertex AI
                        with regional restriction, Mistral La
                        Plateforme). Direct consumer Anthropic API
                        and Claude Code OAuth refused. Frontier
                        quality (Claude on Bedrock/Vertex) with
                        data-residency guarantees.
    TRUSTED_CLOUD     — adds Anthropic Enterprise / zero-data-
                        retention offerings. Requires explicit
                        operator attestation that the API key is
                        ZDR-enabled. Direct consumer Anthropic still
                        refused.
    PERMISSIVE        — anything. Default for development. Equivalent
                        to "no policy enforcement" — every backend
                        is reachable.

Why a four-tier ladder rather than a binary:

  Most government workloads need *jurisdictional* sovereignty (data
  residency, regional infrastructure, contractual data-handling) —
  not pure local. Frontier reasoning quality matters too much to
  give up on the demanding URK bindings (especially `critique` and
  `threat_model`). The middle tiers make that trade-off explicit
  rather than forcing it underground.

Legacy compatibility:
  `CRUCIBLE_SOVEREIGN_MODE=1` (Session 7) maps to `AIR_GAPPED`. All
  Session 7 tests, code paths, and operator habits work unchanged.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from typing import Literal

from ..common.errors import SovereigntyViolation


# ---------------------------------------------------------------------------
# Backend classification
# ---------------------------------------------------------------------------

# Each backend is classified into one of four trust classes. The
# tier-permission matrix below derives from this.
BackendTier = Literal[
    "local",            # runs on operator's host; no network egress
    "sovereign_cloud",  # cloud, but jurisdictionally bounded
    "trusted_cloud",    # cloud, with ZDR / contractual data-handling
    "cloud_only",       # cloud, no special data-handling agreement
]


_BACKEND_CLASSIFICATION: dict[str, BackendTier] = {
    # --- local --------------------------------------------------------
    "ollama":       "local",
    "vllm":         "local",
    "llama-cpp":    "local",
    "tgi":          "local",
    "self-hosted":  "local",
    "dryrun":       "local",
    # --- sovereign cloud ----------------------------------------------
    "bedrock":      "sovereign_cloud",
    "vertex":       "sovereign_cloud",
    "mistral":      "sovereign_cloud",
    # --- trusted cloud ------------------------------------------------
    "anthropic-zdr": "trusted_cloud",
    # --- cloud only (least sovereign) ---------------------------------
    "anthropic":    "cloud_only",
    "claude-code":  "cloud_only",
    "azure_openai": "cloud_only",   # BYO: permitted at PERMISSIVE / explicit force; not a sovereign tier
}


def classify(backend_name: str) -> BackendTier:
    """Return the trust class for a backend by name. Unknown backends
    are conservatively classified as `cloud_only` — fail-closed under
    every sovereign tier."""
    return _BACKEND_CLASSIFICATION.get(backend_name.lower(), "cloud_only")


# ---------------------------------------------------------------------------
# Tier
# ---------------------------------------------------------------------------


class Tier(str, enum.Enum):
    AIR_GAPPED       = "AIR_GAPPED"
    SOVEREIGN_CLOUD  = "SOVEREIGN_CLOUD"
    TRUSTED_CLOUD    = "TRUSTED_CLOUD"
    PERMISSIVE       = "PERMISSIVE"


# Each tier permits a monotonically-larger set of backend classes.
_TIER_PERMITS: dict[Tier, frozenset[BackendTier]] = {
    Tier.AIR_GAPPED:      frozenset({"local"}),
    Tier.SOVEREIGN_CLOUD: frozenset({"local", "sovereign_cloud"}),
    Tier.TRUSTED_CLOUD:   frozenset({"local", "sovereign_cloud", "trusted_cloud"}),
    Tier.PERMISSIVE:      frozenset({"local", "sovereign_cloud", "trusted_cloud", "cloud_only"}),
}


# Auto-selection preference per tier. The same names appear across
# tiers; the lower tiers' preferences are subsets in the same order.
_TIER_PREFERENCE: dict[Tier, tuple[str, ...]] = {
    Tier.AIR_GAPPED: (
        "ollama", "vllm", "llama-cpp", "tgi", "self-hosted", "dryrun",
    ),
    # Sovereign-cloud prefers Bedrock first (Claude quality with data
    # residency), then Vertex, then Mistral. Local backends are
    # preserved as last-resort sovereign fallbacks.
    Tier.SOVEREIGN_CLOUD: (
        "bedrock", "vertex", "mistral",
        "ollama", "vllm", "llama-cpp", "tgi", "self-hosted", "dryrun",
    ),
    # Trusted-cloud adds Anthropic-ZDR at the top — it's frontier
    # quality with the strongest contractual data-handling guarantee
    # short of jurisdictional regional infra.
    Tier.TRUSTED_CLOUD: (
        "anthropic-zdr",
        "bedrock", "vertex", "mistral",
        "ollama", "vllm", "llama-cpp", "tgi", "self-hosted", "dryrun",
    ),
    # Permissive matches Sessions 1-6 behaviour: cloud first for
    # quality, local fallbacks at the end.
    Tier.PERMISSIVE: (
        "anthropic", "claude-code", "anthropic-zdr",
        "bedrock", "vertex", "mistral", "azure_openai",
        "ollama", "vllm", "llama-cpp", "tgi", "self-hosted", "dryrun",
    ),
}


# ---------------------------------------------------------------------------
# Env handling
# ---------------------------------------------------------------------------

_TIER_ENV       = "CRUCIBLE_SOVEREIGNTY_TIER"
_LEGACY_ENV     = "CRUCIBLE_SOVEREIGN_MODE"


def _resolve_tier_from_env() -> Tier:
    raw = os.environ.get(_TIER_ENV, "").strip().upper()
    if raw:
        try:
            return Tier(raw)
        except ValueError:
            # Unknown tier name — fail closed to AIR_GAPPED. Operator
            # gets a clear policy explanation when they next probe.
            return Tier.AIR_GAPPED
    # Legacy alias: Session 7's binary flag maps to AIR_GAPPED.
    if os.environ.get(_LEGACY_ENV, "").strip() in ("1", "true", "yes", "on"):
        return Tier.AIR_GAPPED
    return Tier.PERMISSIVE


def is_sovereign_mode() -> bool:
    """Back-compat helper: True for any non-PERMISSIVE tier.

    This is what `egress_guard` checks — the egress allowlist must be
    enforced under every sovereign tier, not only AIR_GAPPED."""
    return _resolve_tier_from_env() != Tier.PERMISSIVE


# ---------------------------------------------------------------------------
# SovereigntyPolicy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SovereigntyPolicy:
    """Active substrate policy. Constructed from env or injected by
    tests via `set_policy()`.

    Two construction styles are supported for back-compat:

      SovereigntyPolicy(tier=Tier.AIR_GAPPED)  # preferred
      SovereigntyPolicy(strict=True)           # Session 7 alias

    `strict` is preserved as a read-only property so the egress guard
    and any operator scripts that reference it keep working."""

    tier: Tier = Tier.PERMISSIVE
    local_preference_order: tuple[str, ...] = field(
        default=("ollama", "vllm", "llama-cpp", "tgi", "dryrun"),
    )
    cloud_preference_order: tuple[str, ...] = field(
        default=("anthropic", "claude-code"),
    )

    # Session 7 legacy: SovereigntyPolicy(strict=True) used to be the
    # only sovereign mode. Translate it.
    def __init__(
        self,
        tier: Tier | None = None,
        *,
        strict: bool | None = None,
        local_preference_order: tuple[str, ...] = (
            "ollama", "vllm", "llama-cpp", "tgi", "self-hosted", "dryrun",
        ),
        cloud_preference_order: tuple[str, ...] = (
            "anthropic", "claude-code",
        ),
    ) -> None:
        if tier is None and strict is True:
            tier = Tier.AIR_GAPPED
        elif tier is None and strict is False:
            tier = Tier.PERMISSIVE
        elif tier is None:
            tier = Tier.PERMISSIVE
        # frozen dataclass: bypass __setattr__ once.
        object.__setattr__(self, "tier", tier)
        object.__setattr__(self, "local_preference_order", tuple(local_preference_order))
        object.__setattr__(self, "cloud_preference_order", tuple(cloud_preference_order))

    # ---- back-compat property --------------------------------------

    @property
    def strict(self) -> bool:
        """Session 7 alias: True for any tier that enforces refusal."""
        return self.tier != Tier.PERMISSIVE

    # ---- construction -----------------------------------------------

    @classmethod
    def from_env(cls) -> "SovereigntyPolicy":
        return cls(tier=_resolve_tier_from_env())

    # ---- queries -----------------------------------------------------

    def permitted_classes(self) -> frozenset[BackendTier]:
        return _TIER_PERMITS[self.tier]

    def permitted_preference(self) -> tuple[str, ...]:
        """Auto-selection order for the current tier, with operator-
        supplied preference overrides applied (local + cloud) for
        Session 7 back-compat tests that override these fields."""
        if self.tier == Tier.AIR_GAPPED:
            # Honour caller-supplied local order if non-default.
            return tuple(self.local_preference_order)
        if self.tier == Tier.PERMISSIVE:
            # Honour caller-supplied cloud + local override for back-compat.
            return tuple(self.cloud_preference_order) + tuple(
                n for n in self.local_preference_order
                if n not in self.cloud_preference_order
            )
        # SOVEREIGN_CLOUD / TRUSTED_CLOUD use the canonical tier order.
        return _TIER_PREFERENCE[self.tier]

    def assert_permitted(self, backend_name: str) -> None:
        """Raise `SovereigntyViolation` if this backend cannot run
        under the current tier. Called at backend *construction* —
        not at call time — so a misconfigured deployment fails closed
        before any prompt is built."""
        klass = classify(backend_name)
        if klass not in self.permitted_classes():
            raise SovereigntyViolation(
                f"backend {backend_name!r} is classified {klass!r} and "
                f"cannot run under sovereignty tier {self.tier.value!r}. "
                f"This tier permits classes: {sorted(self.permitted_classes())}. "
                f"Either change the backend, lower the tier "
                f"(set {_TIER_ENV} or unset {_LEGACY_ENV}), or use a "
                f"different backend variant (e.g. anthropic-zdr if you "
                f"have a ZDR contract). "
                f"See SOVEREIGNTY-THREAT-MODEL.md § 'LLM substrate'."
            )

    def explain(self) -> str:
        """One-line human-readable summary suitable for status output."""
        if self.tier == Tier.AIR_GAPPED:
            return (
                "tier=AIR_GAPPED: local-only backends; cloud refused at "
                f"construction; auto-selection prefers "
                f"{self.local_preference_order[0]}"
            )
        if self.tier == Tier.SOVEREIGN_CLOUD:
            return (
                "tier=SOVEREIGN_CLOUD: local + jurisdictional cloud "
                "(Bedrock/Vertex/Mistral); direct consumer Anthropic "
                "and Claude Code refused; auto-selection prefers Bedrock"
            )
        if self.tier == Tier.TRUSTED_CLOUD:
            return (
                "tier=TRUSTED_CLOUD: local + sovereign cloud + Anthropic-ZDR; "
                "direct consumer Anthropic and Claude Code refused; "
                "auto-selection prefers anthropic-zdr"
            )
        return (
            "tier=PERMISSIVE: full backend lattice available; auto-selection "
            "prefers frontier (anthropic > claude-code) for quality"
        )


# ---------------------------------------------------------------------------
# Egress allowlist composition
# ---------------------------------------------------------------------------


def backend_egress_hosts(backend_name: str) -> tuple[str, ...]:
    """Return the host(s) a backend will reach over httpx.

    Used by `egress_guard.build_engagement_allowlist()` to compose
    the runtime allowlist — the active backend's expected host is
    permitted; everything else is refused.

    Returns an empty tuple for backends that don't issue direct
    httpx calls (claude-code uses a subprocess; dryrun has no
    network).

    For region-parameterised backends (Bedrock, Vertex), the operator
    passes the region via `extra_hosts=` when constructing the
    allowlist — this function returns wildcard suffixes that match
    all valid regional endpoints.
    """
    name = backend_name.lower()
    if name in {"ollama", "vllm", "llama-cpp", "tgi", "self-hosted"}:
        return ("localhost", "127.0.0.1", "::1")
    if name in {"anthropic", "anthropic-zdr"}:
        return ("api.anthropic.com",)
    if name == "azure_openai":
        # the operator's Azure resource resolves to <resource>.openai.azure.com (host-validated at construct)
        return ("*.openai.azure.com",)
    if name == "bedrock":
        # Wildcard — operator's region resolves to e.g.
        # bedrock-runtime.eu-west-1.amazonaws.com
        return ("*.amazonaws.com",)
    if name == "vertex":
        return ("*.googleapis.com",)
    if name == "mistral":
        return ("api.mistral.ai",)
    if name in {"claude-code", "dryrun"}:
        return ()
    return ()


# ---------------------------------------------------------------------------
# Module-level mutable holder
# ---------------------------------------------------------------------------

_active_policy: SovereigntyPolicy | None = None

# X6 — the sovereignty SEAL. By default `current()` re-reads the env each call (dev convenience:
# a tier flip takes effect immediately). On a long-running production process that is a hazard —
# a later env mutation could RELAX the tier mid-engagement. Setting CRUCIBLE_SOVEREIGNTY_SEALED
# latches the env-derived tier ONCE at first use into an immutable value for the process lifetime;
# later env changes are ignored. Opt-in, fail-safe (it can only PIN the tier, never relax it).
_SEAL_ENV = "CRUCIBLE_SOVEREIGNTY_SEALED"
_sealed_policy: SovereigntyPolicy | None = None


def _seal_requested() -> bool:
    return os.environ.get(_SEAL_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def is_sealed() -> bool:
    """True once the sovereignty tier has been latched immutable for the process (X6). Reflects
    the latch state: True after `current()` has latched under CRUCIBLE_SOVEREIGNTY_SEALED."""
    return _sealed_policy is not None


def current() -> SovereigntyPolicy:
    """Return the active policy. An explicitly injected policy always wins. Otherwise, when the
    seal (`CRUCIBLE_SOVEREIGNTY_SEALED`) is requested, the env-derived tier is latched ONCE and
    returned immutably for the process lifetime (a later env flip cannot relax it); without the
    seal it is derived from the environment on each call (so a flip takes effect immediately in a
    long-running shell)."""
    if _active_policy is not None:
        return _active_policy
    global _sealed_policy
    if _sealed_policy is not None:
        return _sealed_policy
    if _seal_requested():
        _sealed_policy = SovereigntyPolicy.from_env()      # latch once, immutable hereafter
        return _sealed_policy
    return SovereigntyPolicy.from_env()


def set_policy(policy: SovereigntyPolicy | None) -> None:
    """Inject a policy (use `None` to revert to env-derived). Tests
    use this; production deployments should set
    `CRUCIBLE_SOVEREIGNTY_TIER` in the systemd unit or container env."""
    global _active_policy, _sealed_policy
    _active_policy = policy
    _sealed_policy = None       # clear the X6 seal latch too, so a revert-to-env is clean
