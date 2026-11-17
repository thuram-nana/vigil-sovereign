"""M1c-2b — a METERED Strix codebase run reaches the model through the LOOPBACK gateway with its grant.

The Strix codebase agent is a model-egress site gated by ``kernel.sovereignty``: ``anthropic/<model>`` classifies
``cloud_only`` and is REFUSED under a sovereign tier (AIR_GAPPED / SOVEREIGN_CLOUD / TRUSTED_CLOUD). M1c-2b adds
ONE carve-out: when a model grant is in scope (a metered run) AND the resolved Strix ``api_base`` is the LOOPBACK
model gateway, ``anthropic/<model>`` classifies ``local`` — the child's egress is on-host (to the sovereign
gateway that holds the key + meters) — so it is permitted under every tier and the alias guard pins the gateway +
strips the siblings. It does NOT widen the cloud allowlist: a non-metered ``anthropic/`` pick, or a metered one
whose base is not the loopback gateway, stays cloud and is refused exactly as before.

Mutation-verify targets (each neuter reds a NAMED test here):
  * drop the metered-loopback carve-out (metered anthropic stays cloud)        -> test_metered_anthropic_at_the_loopback_gateway_is_permitted_under_air_gap
  * the carve-out ignores whether the run is metered (any loopback anthropic)  -> test_non_metered_anthropic_at_a_loopback_base_stays_cloud
"""
from __future__ import annotations

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.kernel import sovereignty as _sov

GATEWAY = "http://127.0.0.1:8742"
MODEL = "anthropic/claude-opus-4-8"


@pytest.fixture()
def air_gapped(monkeypatch):
    """Force the AIR_GAPPED tier deterministically, and clear every ambient model/grant var."""
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    for v in ("STRIX_LLM", "LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL",
              "OLLAMA_API_BASE", "VIGIL_MODEL_GRANT", "ANTHROPIC_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr(actions_mod, "_strix_config_json_path", lambda: __import__("pathlib").Path("/nonexistent"))
    yield
    _sov.set_policy(None)


def _metered(monkeypatch, base=GATEWAY):
    monkeypatch.setenv("VIGIL_MODEL_GRANT", "vmg1.grant-one")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", base)


def test_metered_anthropic_at_the_loopback_gateway_is_permitted_under_air_gap(air_gapped, monkeypatch):
    _metered(monkeypatch)
    env = {"STRIX_LLM": MODEL, "LLM_API_BASE": GATEWAY}
    # classifies LOCAL (an on-host loopback-gateway egress) → permitted under AIR_GAPPED
    assert _sov.classify(actions_mod._strix_sovereignty_backend(env)) == "local"
    assert actions_mod._strix_sovereignty_refusal(env) == ""


def test_the_alias_guard_pins_the_gateway_and_strips_siblings_for_a_metered_run(air_gapped, monkeypatch):
    _metered(monkeypatch)
    env = {"STRIX_LLM": MODEL, "LLM_API_BASE": GATEWAY}
    extra, remove = actions_mod._strix_child_alias_guard(env)
    assert extra.get("LLM_API_BASE") == GATEWAY                     # PIN the loopback gateway (highest precedence)
    assert "OPENAI_BASE_URL" in remove and "LLM_API_BASE" not in remove  # strip every sibling, never LLM_API_BASE


def test_non_metered_anthropic_at_a_loopback_base_stays_cloud(air_gapped, monkeypatch):
    # NO widening: without a grant, anthropic/<model> at a loopback base is STILL cloud_only → refused. The
    # carve-out needs the metered grant, not merely a loopback base.
    monkeypatch.setenv("ANTHROPIC_BASE_URL", GATEWAY)              # a loopback gateway base, but NO grant
    env = {"STRIX_LLM": MODEL, "LLM_API_BASE": GATEWAY}
    assert _sov.classify(actions_mod._strix_sovereignty_backend(env)) == "cloud_only"
    assert actions_mod._strix_sovereignty_refusal(env)             # a non-empty refusal


def test_metered_anthropic_at_a_remote_base_stays_cloud(air_gapped, monkeypatch):
    # metered, but the STRIX api_base is REMOTE (not the loopback gateway) ⇒ cloud → refused (fail-closed).
    _metered(monkeypatch, base=GATEWAY)
    env = {"STRIX_LLM": MODEL, "LLM_API_BASE": "https://api.anthropic.com"}
    assert _sov.classify(actions_mod._strix_sovereignty_backend(env)) == "cloud_only"
    assert actions_mod._strix_sovereignty_refusal(env)


def test_metered_is_byte_identical_for_a_local_ollama_pick(air_gapped, monkeypatch):
    # the carve-out touches ONLY anthropic/: a local ollama pick is permitted exactly as before, metered or not.
    _metered(monkeypatch)
    env = {"STRIX_LLM": "ollama/qwen", "LLM_API_BASE": "http://127.0.0.1:11434"}
    assert _sov.classify(actions_mod._strix_sovereignty_backend(env)) == "local"
    assert actions_mod._strix_sovereignty_refusal(env) == ""
