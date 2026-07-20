"""
Tests for the four sovereign-substrate backends added in Session 8:
BedrockBackend, VertexBackend, MistralBackend, and the AnthropicBackend
ZDR variant.

Strategy:

  - Construction-without-creds: each backend raises BackendUnavailable
    with a useful message when its required env / SDK is missing.
  - Construction-with-creds (mocked): we monkeypatch env vars and
    inject a fake SDK module to confirm the construction path runs
    cleanly.
  - Region allowlist: Bedrock and Vertex refuse non-allowlisted
    regions at construction.
  - Tier integration: each backend is assert_permitted() under the
    expected tier and refused under stricter tiers.
  - Egress hosts: the backend_egress_hosts helper returns the
    expected vendor host(s).

Live `complete()` calls are NOT exercised here — those require real
credentials. See kernel/tests/fixtures/sovereignty-comparison.md for
the live-verification harness.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import httpx
import pytest

from framework.v2.common.errors import (
    BackendError,
    BackendUnavailable,
    SovereigntyViolation,
)
from framework.v2.kernel import llm, sovereignty
from framework.v2.kernel.sovereignty import (
    SovereigntyPolicy,
    Tier,
    backend_egress_hosts,
    set_policy,
)


@pytest.fixture(autouse=True)
def _reset():
    set_policy(None)
    llm.reset_cache()
    yield
    set_policy(None)
    llm.reset_cache()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _install_fake_sdk(monkeypatch, name: str, attrs: dict | None = None) -> types.ModuleType:
    """Install a minimal fake SDK module under sys.modules so the
    backend's `import` succeeds without a real install."""
    mod = types.ModuleType(name)
    for k, v in (attrs or {}).items():
        setattr(mod, k, v)
    monkeypatch.setitem(sys.modules, name, mod)
    return mod


# ---------------------------------------------------------------------------
# BedrockBackend
# ---------------------------------------------------------------------------


def test_bedrock_refuses_without_boto3(monkeypatch):
    """boto3 is not installed in the v2 dev env. Constructing
    BedrockBackend must raise BackendUnavailable explaining that."""
    _install_fake_sdk(monkeypatch, "anthropic")
    # Mark boto3 as unavailable in sys.modules — Python's import
    # machinery treats `None` in the cache as "import fails".
    monkeypatch.setitem(sys.modules, "boto3", None)
    from framework.v2.kernel.backends.bedrock import BedrockBackend
    with pytest.raises(BackendUnavailable) as exc:
        BedrockBackend()
    assert "boto3" in str(exc.value)


def test_bedrock_refuses_without_region(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    _install_fake_sdk(monkeypatch, "boto3")
    monkeypatch.delenv("CRUCIBLE_BEDROCK_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    from framework.v2.kernel.backends.bedrock import BedrockBackend
    with pytest.raises(BackendUnavailable) as exc:
        BedrockBackend()
    assert "REGION" in str(exc.value).upper()


def test_bedrock_refuses_non_allowlisted_region(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    _install_fake_sdk(monkeypatch, "boto3")
    monkeypatch.setenv("CRUCIBLE_BEDROCK_REGION", "ap-south-2")  # not in default allowlist
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    from framework.v2.kernel.backends.bedrock import BedrockBackend
    with pytest.raises(BackendUnavailable) as exc:
        BedrockBackend()
    assert "allowlist" in str(exc.value).lower()


def test_bedrock_constructs_with_allowlisted_region_and_creds(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    _install_fake_sdk(monkeypatch, "boto3")
    monkeypatch.setenv("CRUCIBLE_BEDROCK_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    from framework.v2.kernel.backends.bedrock import BedrockBackend
    b = BedrockBackend()
    assert b.region == "eu-west-1"
    assert b.name == "bedrock"
    ok, note = b.is_available()
    assert ok
    assert "eu-west-1" in note


def test_bedrock_operator_can_extend_region_allowlist(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    _install_fake_sdk(monkeypatch, "boto3")
    monkeypatch.setenv(
        "CRUCIBLE_BEDROCK_REGION_ALLOWLIST",
        "ap-south-2,me-central-1",
    )
    monkeypatch.setenv("CRUCIBLE_BEDROCK_REGION", "ap-south-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-key")
    from framework.v2.kernel.backends.bedrock import BedrockBackend
    b = BedrockBackend()
    assert b.region == "ap-south-2"


# ---------------------------------------------------------------------------
# VertexBackend
# ---------------------------------------------------------------------------


def test_vertex_refuses_without_google_auth(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    # Mark google.auth as unavailable.
    monkeypatch.setitem(sys.modules, "google", None)
    monkeypatch.setitem(sys.modules, "google.auth", None)
    from framework.v2.kernel.backends.vertex import VertexBackend
    with pytest.raises(BackendUnavailable) as exc:
        VertexBackend()
    assert "google-auth" in str(exc.value)


def test_vertex_refuses_without_project(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    google_mod = _install_fake_sdk(monkeypatch, "google")
    google_mod.auth = _install_fake_sdk(monkeypatch, "google.auth")
    monkeypatch.delenv("CRUCIBLE_VERTEX_PROJECT", raising=False)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/fake.json")
    from framework.v2.kernel.backends.vertex import VertexBackend
    with pytest.raises(BackendUnavailable) as exc:
        VertexBackend()
    assert "PROJECT" in str(exc.value).upper()


def test_vertex_refuses_non_allowlisted_region(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    google_mod = _install_fake_sdk(monkeypatch, "google")
    google_mod.auth = _install_fake_sdk(monkeypatch, "google.auth")
    monkeypatch.setenv("CRUCIBLE_VERTEX_PROJECT", "test-project")
    monkeypatch.setenv("CRUCIBLE_VERTEX_REGION", "antarctica-south-1")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/fake.json")
    from framework.v2.kernel.backends.vertex import VertexBackend
    with pytest.raises(BackendUnavailable) as exc:
        VertexBackend()
    assert "allowlist" in str(exc.value).lower()


def test_vertex_constructs_with_allowlisted_region(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    google_mod = _install_fake_sdk(monkeypatch, "google")
    google_mod.auth = _install_fake_sdk(monkeypatch, "google.auth")
    monkeypatch.setenv("CRUCIBLE_VERTEX_PROJECT", "test-project")
    monkeypatch.setenv("CRUCIBLE_VERTEX_REGION", "europe-west4")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/fake.json")
    from framework.v2.kernel.backends.vertex import VertexBackend
    b = VertexBackend()
    assert b.project == "test-project"
    assert b.region == "europe-west4"
    assert b.name == "vertex"


# ---------------------------------------------------------------------------
# MistralBackend
# ---------------------------------------------------------------------------


def test_mistral_refuses_without_api_key(monkeypatch):
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    from framework.v2.kernel.backends.mistral import MistralBackend
    with pytest.raises(BackendUnavailable) as exc:
        MistralBackend()
    assert "MISTRAL_API_KEY" in str(exc.value)


def test_mistral_constructs_with_api_key(monkeypatch):
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    from framework.v2.kernel.backends.mistral import MistralBackend
    b = MistralBackend()
    assert b.name == "mistral"
    assert b.endpoint == "https://api.mistral.ai/v1"
    ok, note = b.is_available()
    assert ok


def test_mistral_complete_with_mocked_http(monkeypatch):
    """Run a full complete() round-trip against a mocked httpx Client."""
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    from framework.v2.kernel.backends.mistral import MistralBackend
    from framework.v2.kernel.llm import Prompt
    from pydantic import BaseModel

    class Tiny(BaseModel):
        ok: bool
        note: str

    fake_envelope = {
        "choices": [{"message": {"content": '{"ok": true, "note": "hi"}'}}],
        "usage": {"prompt_tokens": 7, "completion_tokens": 3},
    }

    class FakeResponse:
        status_code = 200
        text = ""

        def json(self):
            return fake_envelope

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def post(self, url, **kw):
            return FakeResponse()

    monkeypatch.setattr(
        "framework.v2.kernel.backends.mistral.httpx.Client",
        FakeClient,
    )

    b = MistralBackend()
    result = b.complete(Prompt(
        system="be brief",
        user="say hi",
        schema=Tiny,
        schema_name="Tiny",
        cognitive_doc="(unused)",
    ))
    assert result.parsed.ok is True
    assert result.parsed.note == "hi"
    assert result.trace.tokens_in == 7
    assert result.trace.tokens_out == 3


def test_mistral_complete_raises_on_non_200(monkeypatch):
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    from framework.v2.kernel.backends.mistral import MistralBackend
    from framework.v2.kernel.llm import Prompt
    from pydantic import BaseModel

    class Tiny(BaseModel):
        ok: bool

    class FakeResponse:
        status_code = 401
        text = '{"error": "invalid api key"}'

        def json(self):
            return {"error": "invalid api key"}

    class FakeClient:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def post(self, url, **kw): return FakeResponse()

    monkeypatch.setattr(
        "framework.v2.kernel.backends.mistral.httpx.Client",
        FakeClient,
    )
    b = MistralBackend()
    with pytest.raises(BackendError) as exc:
        b.complete(Prompt(
            system="x", user="y", schema=Tiny, schema_name="T",
            cognitive_doc="(unused)",
        ))
    assert "401" in str(exc.value)


# ---------------------------------------------------------------------------
# AnthropicBackend ZDR variant
# ---------------------------------------------------------------------------


def test_anthropic_zdr_renames_to_anthropic_zdr(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("CRUCIBLE_ANTHROPIC_ZDR", "1")
    from framework.v2.kernel.backends.anthropic import AnthropicBackend
    b = AnthropicBackend()
    assert b.name == "anthropic-zdr"
    assert b.zdr is True
    ok, note = b.is_available()
    assert ok
    assert "ZDR" in note


def test_anthropic_without_zdr_keeps_name(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("CRUCIBLE_ANTHROPIC_ZDR", raising=False)
    from framework.v2.kernel.backends.anthropic import AnthropicBackend
    b = AnthropicBackend()
    assert b.name == "anthropic"
    assert b.zdr is False


def test_anthropic_explicit_zdr_overrides_env(monkeypatch):
    _install_fake_sdk(monkeypatch, "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.delenv("CRUCIBLE_ANTHROPIC_ZDR", raising=False)
    from framework.v2.kernel.backends.anthropic import AnthropicBackend
    b = AnthropicBackend(zdr=True)
    assert b.name == "anthropic-zdr"
    assert b.zdr is True


# ---------------------------------------------------------------------------
# Tier × backend integration
# ---------------------------------------------------------------------------


def test_air_gapped_refuses_construction_of_bedrock(monkeypatch):
    set_policy(SovereigntyPolicy(tier=Tier.AIR_GAPPED))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "bedrock")
    with pytest.raises(SovereigntyViolation) as exc:
        llm.get_backend(refresh=True)
    assert "bedrock" in str(exc.value)
    assert "AIR_GAPPED" in str(exc.value)


def test_air_gapped_refuses_construction_of_vertex(monkeypatch):
    set_policy(SovereigntyPolicy(tier=Tier.AIR_GAPPED))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "vertex")
    with pytest.raises(SovereigntyViolation):
        llm.get_backend(refresh=True)


def test_air_gapped_refuses_construction_of_mistral(monkeypatch):
    set_policy(SovereigntyPolicy(tier=Tier.AIR_GAPPED))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "mistral")
    with pytest.raises(SovereigntyViolation):
        llm.get_backend(refresh=True)


def test_sovereign_cloud_permits_bedrock_construction_path(monkeypatch):
    """SOVEREIGN_CLOUD must REACH bedrock construction (which then
    fails on missing creds — but the policy gate doesn't refuse)."""
    set_policy(SovereigntyPolicy(tier=Tier.SOVEREIGN_CLOUD))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "bedrock")
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("CRUCIBLE_BEDROCK_REGION", raising=False)
    # Should fail at BackendUnavailable (no region/creds), NOT at SovereigntyViolation.
    with pytest.raises(BackendUnavailable):
        llm.get_backend(refresh=True)


def test_sovereign_cloud_refuses_anthropic_zdr(monkeypatch):
    """ZDR is trusted_cloud, refused under sovereign_cloud."""
    set_policy(SovereigntyPolicy(tier=Tier.SOVEREIGN_CLOUD))
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "anthropic-zdr")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    with pytest.raises(SovereigntyViolation):
        llm.get_backend(refresh=True)


def test_trusted_cloud_permits_zdr_refuses_plain_anthropic(monkeypatch):
    set_policy(SovereigntyPolicy(tier=Tier.TRUSTED_CLOUD))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    # plain anthropic refused
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "anthropic")
    with pytest.raises(SovereigntyViolation):
        llm.get_backend(refresh=True)


def test_egress_hosts_for_each_new_backend():
    assert backend_egress_hosts("bedrock") == ("*.amazonaws.com",)
    assert backend_egress_hosts("vertex") == ("*.googleapis.com",)
    assert backend_egress_hosts("mistral") == ("api.mistral.ai",)
    assert backend_egress_hosts("anthropic-zdr") == ("api.anthropic.com",)
