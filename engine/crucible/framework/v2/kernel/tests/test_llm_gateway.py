"""M4.1 conformance — the URK egress path routes through the ONE gateway chokepoint.

The URK funnel (``complete_with_failover``) now composes its call through ``vigil_core.ai_gateway.egress``.
These tests pin the conformance invariants ON THE REAL URK PATH, each with a positive + a safe-negative
control so no assertion is a no-op:

  * symmetric redaction — a planted secret in the prompt is masked BEFORE the backend sees it (the gap the
    URK path had); an ordinary prompt is delivered unchanged;
  * AIR_GAPPED refuses a cloud backend BEFORE the invoke closure runs — hence before any provider SDK is
    imported (the SDK import lives inside backend construction, inside invoke);
  * the model is reached ONLY inside the egress context (a bypass of the chokepoint fails closed);
  * one unified provenance/audit record is produced, attributing the output to an UNTRUSTED provider.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from framework.v2.common.errors import SovereigntyViolation
from framework.v2.kernel import llm
from vigil_core import ai_gateway

_SECRET = "sk-ant-PLANTED-urk-secret-value-abc123"


class _Schema(BaseModel):
    pass


def _prompt(system: str, user: str) -> "llm.Prompt":
    return llm.Prompt(system=system, user=user, schema=_Schema, schema_name="x", cognitive_doc="")


def _capturing_backend(name: str, captured: dict):
    """A fake URK backend whose ``complete`` records the prompt it actually received + whether it ran inside
    the egress context."""
    b = SimpleNamespace()
    b.name = name
    b.is_available = lambda: (True, "ready")

    def _complete(prompt):
        captured["system"] = getattr(prompt, "system", None)
        captured["user"] = getattr(prompt, "user", None)
        captured["in_egress"] = ai_gateway.in_egress()
        return SimpleNamespace(parsed="ok",
                               trace=SimpleNamespace(backend=name, tokens_in=3, tokens_out=5, is_dryrun=False))

    b.complete = _complete
    return b


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(llm._ENV_OVERRIDE, raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    ai_gateway.reset_audit()
    yield
    ai_gateway.reset_audit()


# ── conformance 3: symmetric redaction on the URK path ────────────────────────────────────────────

def test_planted_secret_is_redacted_before_the_backend_sees_it(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(llm, "get_backend", lambda: _capturing_backend("ollama", captured))
    p = _prompt(system="be precise", user=f"the target returned Authorization: Bearer {_SECRET}")
    res = llm.complete_with_failover(p)
    assert res.parsed == "ok"
    assert _SECRET not in (captured["user"] or "")      # the credential never reached the backend
    assert "<redacted" in (captured["user"] or "")       # … it was masked in flight


def test_ordinary_prompt_is_delivered_unchanged(monkeypatch):
    # SAFE-NEGATIVE control: redaction must not eat ordinary prompt content.
    captured: dict = {}
    monkeypatch.setattr(llm, "get_backend", lambda: _capturing_backend("ollama", captured))
    p = _prompt(system="be precise", user="probe http://127.0.0.1:8080/search?q=test")
    llm.complete_with_failover(p)
    assert captured["user"] == "probe http://127.0.0.1:8080/search?q=test"
    assert captured["system"] == "be precise"


# ── conformance 2: AIR_GAPPED refuses a cloud backend BEFORE any SDK import ────────────────────────

def test_air_gapped_refuses_cloud_before_backend_construction(monkeypatch):
    constructed: list = []
    # if construction (which imports the SDK) is ever reached, this records it — it must NOT be.
    monkeypatch.setattr(llm, "_construct", lambda name: constructed.append(name))
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    monkeypatch.setenv(llm._ENV_OVERRIDE, "anthropic")   # operator pins a cloud backend under AIR_GAPPED
    p = _prompt(system="s", user="u")
    with pytest.raises(SovereigntyViolation):
        llm.complete_with_failover(p)
    assert constructed == []                              # backend never constructed ⇒ SDK never imported
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "urk" and rec.outcome == "refused_sovereignty" and rec.invoked is False


def test_air_gapped_permits_a_local_backend(monkeypatch):
    # POSITIVE control: the same tier permits a LOCAL backend — the refusal above is about the cloud class,
    # not a blanket block.
    captured: dict = {}
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    monkeypatch.setenv(llm._ENV_OVERRIDE, "ollama")
    monkeypatch.setattr(llm, "get_backend", lambda: _capturing_backend("ollama", captured))
    res = llm.complete_with_failover(_prompt("s", "u"))
    assert res.parsed == "ok" and captured["in_egress"] is True


# ── conformance 1: the backend is reached only inside the egress context ───────────────────────────

def test_backend_is_reached_only_inside_the_egress_context(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(llm, "get_backend", lambda: _capturing_backend("ollama", captured))
    assert ai_gateway.in_egress() is False               # not in egress out here
    llm.complete_with_failover(_prompt("s", "u"))
    assert captured["in_egress"] is True                  # the model call happened INSIDE the chokepoint


def test_raw_assert_in_egress_fails_closed_outside_the_gateway():
    # the chokepoint guard itself: a model-touching helper that asserts the context fails closed when called
    # outside egress (the direct-bypass control, shared by both paths).
    with pytest.raises(ai_gateway.EgressBypass):
        ai_gateway.assert_in_egress("urk-bypass")


# ── conformance 5: a unified provenance/audit record is produced ──────────────────────────────────

def test_unified_record_marks_the_provider_untrusted(monkeypatch):
    captured: dict = {}
    monkeypatch.setattr(llm, "get_backend", lambda: _capturing_backend("ollama", captured))
    llm.complete_with_failover(_prompt("s", "u"))
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "urk" and rec.invoked is True and rec.outcome == "completed"
    assert rec.provider_authoritative is False           # a model's output is never authoritative
    assert rec.provider_in_trust_root is False           # the provider is never a trust anchor
    assert rec.extra.get("answered_backend") == "ollama" and rec.extra.get("tokens_out") == 5
