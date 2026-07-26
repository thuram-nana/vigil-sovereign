"""A2a — bring-your-own-model kernel backends: Azure OpenAI + self-hosted OpenAI-compatible.

Proves: construction is fail-closed on missing env; the Azure endpoint is HOST-validated (SSRF-safe, like
the settings health probe); a full complete() round-trip works against a mocked httpx client with the right
URL/headers; and the sovereignty ladder classifies + gates them correctly (azure=cloud_only, self-hosted=local).
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel

from framework.v2.common.errors import BackendError, BackendUnavailable
from framework.v2.kernel import sovereignty as SV
from framework.v2.kernel.llm import Prompt


class Tiny(BaseModel):
    ok: bool
    note: str = ""


def _fake_httpx(monkeypatch, module_path, *, status=200, content='{"ok": true, "note": "hi"}', capture=None):
    fake_env = {"choices": [{"message": {"content": content}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2}}

    class _Resp:
        status_code = status
        text = "" if status == 200 else '{"error":"bad"}'
        def json(self):
            return fake_env

    class _Client:
        def __init__(self, *a, **kw):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def post(self, url, **kw):
            if capture is not None:
                capture["url"] = url
                capture["headers"] = kw.get("headers", {})
            return _Resp()
    monkeypatch.setattr(module_path, _Client)


def _prompt():
    return Prompt(system="be brief", user="say hi", schema=Tiny, schema_name="Tiny", cognitive_doc="(unused)")


# --- fail-closed construction ---------------------------------------------------------------------

def test_azure_construct_fail_closed(monkeypatch):
    from framework.v2.kernel.backends.azure_openai import AzureOpenAIBackend
    for k in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "CRUCIBLE_AZURE_OPENAI_DEPLOYMENT"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(BackendUnavailable):
        AzureOpenAIBackend()
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "k")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://myres.openai.azure.com")
    with pytest.raises(BackendUnavailable):          # deployment still missing
        AzureOpenAIBackend()


def test_selfhosted_construct_fail_closed(monkeypatch):
    from framework.v2.kernel.backends.self_hosted import SelfHostedOpenAIBackend
    for k in ("CRUCIBLE_SELFHOSTED_ENDPOINT", "LLM_API_BASE"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(BackendUnavailable):
        SelfHostedOpenAIBackend()


# --- Azure endpoint host validation (SSRF-safe) ----------------------------------------------------

def test_azure_endpoint_host_validation():
    from framework.v2.kernel.backends.azure_openai import _validated_azure_base
    assert _validated_azure_base("https://myres.openai.azure.com/x?y=1") == "https://myres.openai.azure.com"
    for bad in ("https://evil.com/.openai.azure.com", "https://x.openai.azure.com.evil.com",
                "https://real.openai.azure.com@evil.com", "http://myres.openai.azure.com",
                "https://169.254.169.254/.openai.azure.com", "https://openai.azure.com.evil.com"):
        with pytest.raises(BackendUnavailable):
            _validated_azure_base(bad)


def test_selfhosted_base_validation():
    from framework.v2.kernel.backends.self_hosted import _validated_base
    assert _validated_base("http://localhost:8000/v1") == "http://localhost:8000/v1"      # local http ok
    assert _validated_base("https://gpu.lan:8000/v1") == "https://gpu.lan:8000/v1"
    for bad in ("file:///etc/passwd", "notaurl", "javascript:alert(1)", "ftp://h/x"):
        with pytest.raises(BackendUnavailable):
            _validated_base(bad)


# --- complete() round-trip (mocked httpx) ----------------------------------------------------------

def test_azure_complete_hits_deployment_url_with_api_key_header(monkeypatch):
    from framework.v2.kernel.backends.azure_openai import AzureOpenAIBackend
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://myres.openai.azure.com")
    monkeypatch.setenv("CRUCIBLE_AZURE_OPENAI_DEPLOYMENT", "gpt4o")
    cap = {}
    _fake_httpx(monkeypatch, "framework.v2.kernel.backends.azure_openai.httpx.Client", capture=cap)
    res = AzureOpenAIBackend().complete(_prompt())
    assert res.parsed.ok is True and res.trace.tokens_in == 5
    assert cap["url"].startswith("https://myres.openai.azure.com/openai/deployments/gpt4o/chat/completions")
    assert cap["headers"].get("api-key") == "az-key"       # Azure uses api-key, not Bearer


def test_selfhosted_complete_hits_base_and_optional_bearer(monkeypatch):
    from framework.v2.kernel.backends.self_hosted import SelfHostedOpenAIBackend
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_ENDPOINT", "http://localhost:8000/v1")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_API_KEY", "local-key")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_MODEL", "qwen")
    cap = {}
    _fake_httpx(monkeypatch, "framework.v2.kernel.backends.self_hosted.httpx.Client", capture=cap)
    res = SelfHostedOpenAIBackend().complete(_prompt())
    assert res.parsed.ok is True
    assert cap["url"] == "http://localhost:8000/v1/chat/completions"
    assert cap["headers"].get("Authorization") == "Bearer local-key"


def test_azure_complete_raises_on_non_200(monkeypatch):
    from framework.v2.kernel.backends.azure_openai import AzureOpenAIBackend
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "az-key")
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://myres.openai.azure.com")
    monkeypatch.setenv("CRUCIBLE_AZURE_OPENAI_DEPLOYMENT", "gpt4o")
    _fake_httpx(monkeypatch, "framework.v2.kernel.backends.azure_openai.httpx.Client", status=401)
    with pytest.raises(BackendError):
        AzureOpenAIBackend().complete(_prompt())


# --- sovereignty wiring ----------------------------------------------------------------------------

def test_sovereignty_classification_and_egress():
    assert SV.classify("azure_openai") == "cloud_only"
    assert SV.classify("self-hosted") == "local"
    assert SV.backend_egress_hosts("azure_openai") == ("*.openai.azure.com",)
    assert SV.backend_egress_hosts("self-hosted") == ("localhost", "127.0.0.1", "::1")
    assert "azure_openai" in SV._TIER_PREFERENCE[SV.Tier.PERMISSIVE]
    assert "self-hosted" in SV._TIER_PREFERENCE[SV.Tier.AIR_GAPPED]


def test_air_gapped_refuses_azure_permits_selfhosted():
    pol = SV.SovereigntyPolicy(tier=SV.Tier.AIR_GAPPED)
    with pytest.raises(Exception):                   # cloud_only refused at AIR_GAPPED
        pol.assert_permitted("azure_openai")
    pol.assert_permitted("self-hosted")              # local permitted (no raise)


def test_construct_runs_sovereignty_gate_before_sdk(monkeypatch):
    # a cloud_only backend must be refused at AIR_GAPPED before any construction/env read
    from framework.v2.kernel import llm as LLM
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    with pytest.raises(Exception):
        LLM._construct("azure_openai")
