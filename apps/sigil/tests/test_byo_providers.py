"""A2b — bring-your-own-model provider picker + delivery.

Proves: set_provider routes CRUCIBLE_LLM_BACKEND + the model var + config + Strix and CLEARS the rest;
required-config + endpoint validation fail-closed; set_model delegates + the built-in highlight still works;
settings_status exposes the provider registry/current/config; and the offense-delivery path DELIVERS the
llm/cloud provider keys but EXCLUDES the auto-patch signing key + GitHub token.
"""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    # NOTE: SIGIL_HOME is import-time bound in config, so setenv can't redirect the store; the SecretStore
    # envfile backend reads os.environ, so we CLEAR every managed secret + provider var before AND after each
    # test — no state leaks into (or out of) this file. (tmpdir set for any path-derived writes.)
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    from sigil.ui import settings as S
    keys = tuple(S.SECRET_NAMES) + tuple(S.PROVIDER_ENV_VARS)
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k in keys:
        os.environ.pop(k, None)


def _sa():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    return {"store": SpineStore(), "owner_key": ensure_owner_keypair()}


def test_set_provider_routes_and_clears_others():
    from sigil.ui import settings as S
    S.set_provider("bedrock", "anthropic.claude-opus-5", {"CRUCIBLE_BEDROCK_REGION": "eu-west-1"}, **_sa())
    assert os.environ["CRUCIBLE_LLM_BACKEND"] == "bedrock"
    assert os.environ["CRUCIBLE_BEDROCK_MODEL"] == "anthropic.claude-opus-5"
    assert os.environ["CRUCIBLE_BEDROCK_REGION"] == "eu-west-1"
    assert os.environ["STRIX_LLM"] == "bedrock/anthropic.claude-opus-5"
    # switch → the previous provider's vars are cleared
    S.set_provider("self-hosted", "qwen", {"CRUCIBLE_SELFHOSTED_ENDPOINT": "http://localhost:8000/v1"}, **_sa())
    assert os.environ["CRUCIBLE_LLM_BACKEND"] == "self-hosted"
    assert os.environ.get("CRUCIBLE_BEDROCK_REGION", "") == ""      # cleared
    assert os.environ["LLM_API_BASE"] == "http://localhost:8000/v1"
    assert os.environ["STRIX_LLM"] == "openai/qwen"


def test_required_config_and_endpoint_validation_fail_closed():
    from sigil.ui import settings as S
    with pytest.raises(ValueError):
        S.set_provider("bedrock", "m", {}, **_sa())                 # missing required region
    with pytest.raises(ValueError):
        S.set_provider("azure_openai", "dep", {"AZURE_OPENAI_ENDPOINT": "http://x.openai.azure.com"}, **_sa())
    with pytest.raises(ValueError):
        S.set_provider("self-hosted", "m", {"CRUCIBLE_SELFHOSTED_ENDPOINT": "ftp://x"}, **_sa())
    with pytest.raises(ValueError):
        S.set_provider("not-a-provider", "m", {}, **_sa())          # unknown provider
    # model must get the SAME control-char/length guard as config/secrets — no envfile line-injection
    with pytest.raises(ValueError):
        S.set_provider("anthropic", "x\nVIGIL_DESTRUCTION_OWNER_KEY=planted", {}, **_sa())
    with pytest.raises(ValueError):
        S.set_provider("anthropic", "z" * 9000, {}, **_sa())        # oversize


def test_set_model_delegates_and_highlight_works():
    from sigil.ui import settings as S
    S.set_model("claude-opus-5", **_sa())
    st = S.settings_status()
    assert st["selected_provider"] == "anthropic"
    assert st["selected_model"] == "claude-opus-5"        # built-in picker highlight still resolves
    S.set_model("claude-code", **_sa())
    st2 = S.settings_status()
    assert st2["selected_provider"] == "claude-code" and st2["selected_model"] == "claude-code"


def test_settings_status_exposes_provider_registry_and_config():
    from sigil.ui import settings as S
    S.set_provider("azure_openai", "gpt4o",
                   {"AZURE_OPENAI_ENDPOINT": "https://r.openai.azure.com", "CRUCIBLE_AZURE_OPENAI_API_VERSION": "2024-06-01"},
                   **_sa())
    st = S.settings_status()
    assert st["selected_provider"] == "azure_openai"
    ids = [p["id"] for p in st["providers"]]
    assert {"anthropic", "bedrock", "vertex", "azure_openai", "self-hosted", "ollama", "claude-code"} <= set(ids)
    az = next(p for p in st["providers"] if p["id"] == "azure_openai")
    assert az["keys"] == ["AZURE_OPENAI_API_KEY"] and any(c["env"] == "AZURE_OPENAI_ENDPOINT" for c in az["config"])
    assert st["provider_config"]["AZURE_OPENAI_ENDPOINT"] == "https://r.openai.azure.com"   # non-secret config shown


def test_delivery_includes_provider_keys_but_never_the_signing_key():
    from sigil.ui import settings as S
    from sigil.platform.secrets import SecretStore
    ss = SecretStore()
    for n, v in (("ANTHROPIC_API_KEY", "sk-ant"), ("MISTRAL_API_KEY", "m"), ("AWS_ACCESS_KEY_ID", "AKIA"),
                 ("AWS_SECRET_ACCESS_KEY", "sss"), ("VIGIL_DESTRUCTION_OWNER_KEY", "OWNERKEY"),
                 ("GITHUB_TOKEN", "ghp_x"), ("ELEVENLABS_API_KEY", "el")):
        ss.set(n, v)
    S.set_provider("bedrock", "anthropic.claude-opus-5", {"CRUCIBLE_BEDROCK_REGION": "eu-west-1"}, **_sa())
    env = S.export_runtime_env(include_secrets=True)
    assert env.get("ANTHROPIC_API_KEY") and env.get("AWS_SECRET_ACCESS_KEY")   # llm/cloud keys delivered
    assert env.get("GITHUB_TOKEN")                                             # PR token delivered (LAP)
    assert env.get("CRUCIBLE_BEDROCK_MODEL") and env.get("STRIX_LLM")          # provider vars delivered
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in env                            # the ONE hard exclusion
    assert "ELEVENLABS_API_KEY" not in env                                     # voice = sovereign, not offense


def test_offense_env_allowlist_excludes_only_the_signing_key():
    # the uiproxy consumer allowlist (defense-in-depth) must exclude the destruction SIGNING key, while still
    # passing the provider keys + the GitHub token the offense engine legitimately needs.
    from vigil_integration.uiproxy import _OFFENSE_ENV_ALLOWLIST
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in _OFFENSE_ENV_ALLOWLIST
    assert {"ANTHROPIC_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "STRIX_LLM",
            "CRUCIBLE_BEDROCK_REGION"} <= _OFFENSE_ENV_ALLOWLIST


def test_claude_code_provider_is_keyless_no_model_var():
    from sigil.ui import settings as S
    S.set_provider("claude-code", "", {}, **_sa())
    assert os.environ["CRUCIBLE_LLM_BACKEND"] == "claude-code"
    assert os.environ.get("CRUCIBLE_ANTHROPIC_MODEL", "") == ""     # no model id fed to a backend name
    assert os.environ.get("STRIX_LLM", "") == ""
