"""
Tests for kernel.sovereignty.

The sovereignty policy is a load-bearing gate: a misconfigured
deployment must fail closed at backend instantiation, not at first
prompt. These tests cover both modes (permissive default, strict
sovereign) and the env-driven flip.
"""

from __future__ import annotations

import pytest

from framework.v2.common.errors import SovereigntyViolation
from framework.v2.kernel import llm, sovereignty
from framework.v2.kernel.sovereignty import (
    SovereigntyPolicy,
    classify,
    current,
    is_sovereign_mode,
    set_policy,
)


@pytest.fixture(autouse=True)
def _reset_policy():
    """Every test starts with a fresh, env-derived policy."""
    set_policy(None)
    llm.reset_cache()
    yield
    set_policy(None)
    llm.reset_cache()


# ---------------------------------------------------------------------------
# classify()
# ---------------------------------------------------------------------------


def test_classify_known_cloud_backends():
    # Session 8: classification expanded from {local, cloud} to four
    # classes. Plain consumer Anthropic and Claude Code OAuth are
    # `cloud_only` (least sovereign).
    assert classify("anthropic") == "cloud_only"
    assert classify("claude-code") == "cloud_only"


def test_classify_known_sovereign_cloud_backends():
    assert classify("bedrock") == "sovereign_cloud"
    assert classify("vertex") == "sovereign_cloud"
    assert classify("mistral") == "sovereign_cloud"


def test_classify_known_trusted_cloud_backends():
    assert classify("anthropic-zdr") == "trusted_cloud"


def test_classify_known_local_backends():
    assert classify("ollama") == "local"
    assert classify("vllm") == "local"
    assert classify("llama-cpp") == "local"
    assert classify("tgi") == "local"
    assert classify("dryrun") == "local"


def test_classify_unknown_backend_defaults_cloud_only():
    """Fail-closed: an unknown backend is classified `cloud_only` so
    every sovereign tier refuses it. New local backends must be added
    to the registry explicitly."""
    assert classify("future-cloud-thing") == "cloud_only"
    assert classify("") == "cloud_only"


# ---------------------------------------------------------------------------
# is_sovereign_mode() — env handling
# ---------------------------------------------------------------------------


def test_sovereign_mode_default_off(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    assert is_sovereign_mode() is False


def test_sovereign_mode_on_when_env_is_one(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    assert is_sovereign_mode() is True


@pytest.mark.parametrize("val", ["true", "yes", "on", "1"])
def test_sovereign_mode_on_for_truthy_values(monkeypatch, val):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", val)
    assert is_sovereign_mode() is True


@pytest.mark.parametrize("val", ["0", "false", "off", "no", "", "anything-else"])
def test_sovereign_mode_off_for_other_values(monkeypatch, val):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", val)
    assert is_sovereign_mode() is False


# ---------------------------------------------------------------------------
# SovereigntyPolicy
# ---------------------------------------------------------------------------


def test_permissive_policy_allows_cloud_backends():
    p = SovereigntyPolicy(strict=False)
    p.assert_permitted("anthropic")  # must not raise
    p.assert_permitted("claude-code")
    p.assert_permitted("ollama")
    p.assert_permitted("dryrun")


def test_strict_policy_refuses_cloud_backends():
    p = SovereigntyPolicy(strict=True)
    with pytest.raises(SovereigntyViolation) as exc:
        p.assert_permitted("anthropic")
    # The error message must explain the policy and remediation.
    assert "anthropic" in str(exc.value)
    assert "CRUCIBLE_SOVEREIGN_MODE" in str(exc.value)


def test_strict_policy_refuses_claude_code():
    p = SovereigntyPolicy(strict=True)
    with pytest.raises(SovereigntyViolation):
        p.assert_permitted("claude-code")


def test_strict_policy_allows_local_backends():
    p = SovereigntyPolicy(strict=True)
    p.assert_permitted("ollama")
    p.assert_permitted("vllm")
    p.assert_permitted("dryrun")


def test_strict_policy_refuses_unknown_backend():
    """Unknown = classified cloud = refused under strict."""
    p = SovereigntyPolicy(strict=True)
    with pytest.raises(SovereigntyViolation):
        p.assert_permitted("brand-new-cloud-vendor")


# ---------------------------------------------------------------------------
# permitted_preference() — auto-selection order
# ---------------------------------------------------------------------------


def test_permissive_preference_starts_with_cloud():
    p = SovereigntyPolicy(strict=False)
    pref = p.permitted_preference()
    # Cloud first (frontier quality for verification)…
    assert pref[0] == "anthropic"
    assert pref[1] == "claude-code"
    # …then local fallbacks…
    assert "ollama" in pref
    # …with dryrun last.
    assert pref[-1] == "dryrun"


def test_strict_preference_is_local_only():
    p = SovereigntyPolicy(strict=True)
    pref = p.permitted_preference()
    assert "anthropic" not in pref
    assert "claude-code" not in pref
    # Ollama is the recommended sovereign default.
    assert pref[0] == "ollama"
    # DryRun is always available — last-resort fallback.
    assert "dryrun" in pref


def test_explain_strings_diverge():
    permissive = SovereigntyPolicy(strict=False).explain()
    strict = SovereigntyPolicy(strict=True).explain()
    assert "PERMISSIVE" in permissive
    assert "AIR_GAPPED" in strict
    assert permissive != strict


# ---------------------------------------------------------------------------
# Integration with kernel.llm.get_backend()
# ---------------------------------------------------------------------------


def test_get_backend_under_strict_refuses_anthropic_override(monkeypatch):
    """Forced override to a cloud backend must fail at construction
    in strict mode — not pass and explode at first prompt."""
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-for-test")
    with pytest.raises(SovereigntyViolation) as exc:
        llm.get_backend(refresh=True)
    assert "anthropic" in str(exc.value)


def test_get_backend_under_strict_refuses_claude_code_override(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "claude-code")
    with pytest.raises(SovereigntyViolation):
        llm.get_backend(refresh=True)


def test_get_backend_under_strict_falls_back_to_dryrun_when_no_local(monkeypatch):
    """No Ollama daemon, no vLLM, no llama-cpp: strict mode must still
    deliver a working backend — dryrun is the bootstrapping fallback."""
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    monkeypatch.delenv("CRUCIBLE_LLM_BACKEND", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    backend = llm.get_backend(refresh=True)
    # Either a local backend that happens to be available on the host,
    # or dryrun. Never a cloud backend.
    assert backend.name in {"ollama", "vllm", "llama-cpp", "tgi", "dryrun"}


def test_get_backend_permissive_unchanged_for_dryrun(monkeypatch):
    """Backwards-compatibility: existing test environments without
    CRUCIBLE_SOVEREIGN_MODE behave exactly as before."""
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "dryrun")
    backend = llm.get_backend(refresh=True)
    assert backend.name == "dryrun"


# ---------------------------------------------------------------------------
# Policy injection
# ---------------------------------------------------------------------------


def test_set_policy_overrides_env(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    set_policy(SovereigntyPolicy(strict=True))
    try:
        assert current().strict is True
    finally:
        set_policy(None)
    # And after clearing, the env-derived default returns.
    assert current().strict is False


def test_current_reads_env_when_no_policy_set(monkeypatch):
    set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    assert current().strict is True
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "0")
    assert current().strict is False


# ---------------------------------------------------------------------------
# Session 8: tiered policy
# ---------------------------------------------------------------------------


from framework.v2.kernel.sovereignty import Tier, backend_egress_hosts


def test_tier_air_gapped_refuses_all_cloud_classes():
    p = SovereigntyPolicy(tier=Tier.AIR_GAPPED)
    for cloud in ("anthropic", "anthropic-zdr", "bedrock", "vertex", "mistral", "claude-code"):
        with pytest.raises(SovereigntyViolation):
            p.assert_permitted(cloud)
    # Locals pass.
    for local in ("ollama", "vllm", "llama-cpp", "tgi", "dryrun"):
        p.assert_permitted(local)


def test_tier_sovereign_cloud_permits_jurisdictional_cloud():
    p = SovereigntyPolicy(tier=Tier.SOVEREIGN_CLOUD)
    for permitted in ("ollama", "dryrun", "bedrock", "vertex", "mistral"):
        p.assert_permitted(permitted)
    # Plain anthropic, claude-code, anthropic-zdr all refused.
    for refused in ("anthropic", "anthropic-zdr", "claude-code"):
        with pytest.raises(SovereigntyViolation) as exc:
            p.assert_permitted(refused)
        assert "SOVEREIGN_CLOUD" in str(exc.value)


def test_tier_trusted_cloud_permits_zdr_but_not_plain_anthropic():
    p = SovereigntyPolicy(tier=Tier.TRUSTED_CLOUD)
    for permitted in ("ollama", "bedrock", "vertex", "mistral", "anthropic-zdr"):
        p.assert_permitted(permitted)
    # Plain anthropic and claude-code (no ZDR) still refused.
    for refused in ("anthropic", "claude-code"):
        with pytest.raises(SovereigntyViolation):
            p.assert_permitted(refused)


def test_tier_permissive_permits_everything():
    p = SovereigntyPolicy(tier=Tier.PERMISSIVE)
    for any_backend in (
        "ollama", "dryrun", "bedrock", "vertex", "mistral",
        "anthropic", "anthropic-zdr", "claude-code",
    ):
        p.assert_permitted(any_backend)


def test_tier_sovereign_cloud_preference_prefers_bedrock_first():
    p = SovereigntyPolicy(tier=Tier.SOVEREIGN_CLOUD)
    pref = p.permitted_preference()
    assert pref[0] == "bedrock"
    assert pref[1] == "vertex"
    assert pref[2] == "mistral"
    # Local fallbacks still present at the end.
    assert "ollama" in pref
    assert pref[-1] == "dryrun"
    # No cloud-only.
    assert "anthropic" not in pref
    assert "anthropic-zdr" not in pref


def test_tier_trusted_cloud_preference_prefers_zdr_first():
    p = SovereigntyPolicy(tier=Tier.TRUSTED_CLOUD)
    pref = p.permitted_preference()
    assert pref[0] == "anthropic-zdr"
    assert "bedrock" in pref
    assert "anthropic" not in pref


def test_legacy_sovereign_mode_alias_maps_to_air_gapped(monkeypatch):
    """Session 7 compat: CRUCIBLE_SOVEREIGN_MODE=1 must map to
    AIR_GAPPED so existing operator scripts keep working."""
    set_policy(None)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    p = current()
    assert p.tier == Tier.AIR_GAPPED
    assert p.strict is True


def test_explicit_tier_env_overrides_legacy(monkeypatch):
    """If both env vars are set, the new tier var wins."""
    set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "SOVEREIGN_CLOUD")
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")  # legacy says AIR_GAPPED
    p = current()
    assert p.tier == Tier.SOVEREIGN_CLOUD


def test_unknown_tier_string_fails_closed_to_air_gapped(monkeypatch):
    """An operator typo in CRUCIBLE_SOVEREIGNTY_TIER must NOT silently
    fall to PERMISSIVE — that would be a sovereignty regression."""
    set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "WHATEVER")
    p = current()
    assert p.tier == Tier.AIR_GAPPED


def test_tier_permits_classes_are_monotone():
    """SOVEREIGN_CLOUD permits ⊇ AIR_GAPPED; TRUSTED ⊇ SOVEREIGN; PERMISSIVE ⊇ TRUSTED."""
    air = SovereigntyPolicy(tier=Tier.AIR_GAPPED).permitted_classes()
    sov = SovereigntyPolicy(tier=Tier.SOVEREIGN_CLOUD).permitted_classes()
    trust = SovereigntyPolicy(tier=Tier.TRUSTED_CLOUD).permitted_classes()
    perm = SovereigntyPolicy(tier=Tier.PERMISSIVE).permitted_classes()
    assert air <= sov <= trust <= perm


def test_explain_per_tier():
    for tier in Tier:
        msg = SovereigntyPolicy(tier=tier).explain()
        assert tier.value in msg


# ---------------------------------------------------------------------------
# backend_egress_hosts
# ---------------------------------------------------------------------------


def test_egress_hosts_for_local_backend_returns_localhost():
    hosts = backend_egress_hosts("ollama")
    assert "localhost" in hosts


def test_egress_hosts_for_anthropic_returns_api_host():
    assert backend_egress_hosts("anthropic") == ("api.anthropic.com",)
    assert backend_egress_hosts("anthropic-zdr") == ("api.anthropic.com",)


def test_egress_hosts_for_bedrock_returns_amazonaws_wildcard():
    hosts = backend_egress_hosts("bedrock")
    assert any("amazonaws.com" in h for h in hosts)


def test_egress_hosts_for_vertex_returns_googleapis_wildcard():
    hosts = backend_egress_hosts("vertex")
    assert any("googleapis.com" in h for h in hosts)


def test_egress_hosts_for_mistral_returns_api_mistral():
    assert backend_egress_hosts("mistral") == ("api.mistral.ai",)


def test_egress_hosts_for_subprocess_or_dryrun_is_empty():
    assert backend_egress_hosts("claude-code") == ()
    assert backend_egress_hosts("dryrun") == ()
