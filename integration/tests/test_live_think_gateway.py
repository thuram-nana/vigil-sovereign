"""M4.1 conformance — the live cloud think path routes through the ONE gateway chokepoint.

``think_claude._think_via_client`` now composes its SDK round-trip through ``vigil_core.ai_gateway.egress``.
These tests pin the conformance invariants ON THE REAL LIVE PATH, each with a positive + safe-negative
control, and finish with the explicit cross-path proof the task asks for: the SAME planted secret is
redacted whichever egress path is used.
"""
from __future__ import annotations

import json

import pytest

# The live cloud path's sovereignty gate imports the framework policy lazily; the cross-path test needs the
# URK funnel. Both live behind importorskip so this SKIPS (never errors) in the sovereign leg.
pytest.importorskip("framework.v2.kernel.sovereignty")

from vigil_core import ai_gateway                                   # noqa: E402
from vigil_integration.agent.state import ActionType, AgentState, Phase  # noqa: E402
from vigil_integration.live import think_claude                    # noqa: E402

_SECRET = "sk-ant-PLANTED-cross-path-secret-value-xyz789"


class _Block:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _Msgs:
    def __init__(self, outer: "FakeClient") -> None:
        self._outer = outer

    def create(self, **kwargs):
        self._outer.captured = kwargs
        return type("R", (), {"content": [_Block(self._outer.text)], "usage": None})()


class FakeClient:
    def __init__(self, text: str) -> None:
        self.text = text
        self.captured: dict = {}
        self.messages = _Msgs(self)


def _state() -> AgentState:
    return AgentState(engagement_slug="m41", objective="probe", phase=Phase.INFORMATIONAL,
                      target="http://127.0.0.1:18080/")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    ai_gateway.reset_audit()
    yield
    ai_gateway.reset_audit()


# ── conformance 3: symmetric redaction — a secret in the context is masked before the model sees it ──

def test_planted_secret_in_context_is_redacted_before_the_model(monkeypatch):
    fc = FakeClient(text=json.dumps({"action": "ask_user", "question": "ok"}))
    think_claude.think(_state(), f"the host replied Authorization: Bearer {_SECRET}", client=fc)
    content = fc.captured["messages"][0]["content"]
    assert _SECRET not in content                        # the gateway masked the context secret …
    assert "<redacted" in content                         # … which the live path did NOT do before M4.1


def test_ordinary_context_is_delivered_unchanged(monkeypatch):
    # SAFE-NEGATIVE control: ordinary context (incl. the in-scope target URL) is not eaten by redaction.
    fc = FakeClient(text=json.dumps({"action": "ask_user", "question": "ok"}))
    think_claude.think(_state(), "banner: nginx 1.25 on http://127.0.0.1:18080/", client=fc)
    content = fc.captured["messages"][0]["content"]
    assert "http://127.0.0.1:18080/" in content and "nginx 1.25" in content


# ── conformance 2: AIR_GAPPED refuses a direct cloud call BEFORE the SDK is imported ───────────────

def test_air_gapped_refuses_the_key_path_before_building_a_client(monkeypatch):
    built = {"n": 0}

    def _spy_build(_key):
        built["n"] += 1                                   # building the client is what imports the SDK
        return FakeClient(text="{}")

    monkeypatch.setattr(think_claude, "_build_live_client", _spy_build)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    d = think_claude.think(_state(), "ctx")
    assert d.action == ActionType.ASK_USER                # refused to the safest action …
    assert built["n"] == 0                                # … and the client (SDK import) was never built


def test_permissive_key_path_builds_the_client(monkeypatch):
    # POSITIVE control: on a permitting tier the same key path DOES build + call the client.
    built = {"n": 0}

    def _spy_build(_key):
        built["n"] += 1
        return FakeClient(text=json.dumps({"action": "complete", "summary": "done"}))

    monkeypatch.setattr(think_claude, "_build_live_client", _spy_build)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")     # tier env unset ⇒ PERMISSIVE
    d = think_claude.think(_state(), "ctx")
    assert built["n"] == 1 and d.action == ActionType.COMPLETE


# ── conformance 1: the SDK round-trip runs ONLY inside the egress context ──────────────────────────

def test_raw_think_via_client_fails_closed_outside_the_gateway():
    with pytest.raises(ai_gateway.EgressBypass):
        think_claude._think_via_client_raw(FakeClient(text="{}"), "s", "u",
                                           model="claude-opus-5", max_tokens=64)


def test_think_via_client_wrapper_routes_through_the_gateway():
    # POSITIVE control: the wrapper (what think() calls) goes through egress, so the same raw call succeeds.
    fc = FakeClient(text=json.dumps({"action": "ask_user", "question": "ok"}))
    d = think_claude._think_via_client(fc, "s", "u", model="claude-opus-5", max_tokens=64)
    assert d.action == ActionType.ASK_USER


# ── conformance 5: a unified provenance/audit record is produced, provider marked untrusted ────────

def test_unified_record_for_the_live_path(monkeypatch):
    fc = FakeClient(text=json.dumps({"action": "complete", "summary": "x"}))
    think_claude.think(_state(), "ctx", client=fc)
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "live_think" and rec.invoked is True and rec.outcome == "completed"
    assert rec.provider_authoritative is False and rec.provider_in_trust_root is False
    assert rec.extra.get("decision_action") == "complete"


# ── conformance 3 (the explicit cross-path proof): the SAME secret is masked on BOTH paths ─────────

def test_same_secret_is_redacted_on_both_paths(monkeypatch):
    from types import SimpleNamespace

    from pydantic import BaseModel

    from framework.v2.kernel import llm

    # --- URK path ---
    urk_seen: dict = {}

    class _S(BaseModel):
        pass

    def _urk_backend():
        b = SimpleNamespace(name="ollama", is_available=lambda: (True, "ready"))

        def _complete(prompt):
            urk_seen["user"] = getattr(prompt, "user", None)
            return SimpleNamespace(parsed="ok", trace=SimpleNamespace(backend="ollama", tokens_in=1,
                                                                       tokens_out=1, is_dryrun=False))
        b.complete = _complete
        return b

    monkeypatch.delenv(llm._ENV_OVERRIDE, raising=False)
    monkeypatch.setattr(llm, "get_backend", _urk_backend)
    llm.complete_with_failover(llm.Prompt(system="s", user=f"Authorization: Bearer {_SECRET}",
                                          schema=_S, schema_name="x", cognitive_doc=""))

    # --- live path ---
    fc = FakeClient(text=json.dumps({"action": "ask_user", "question": "ok"}))
    think_claude.think(_state(), f"Authorization: Bearer {_SECRET}", client=fc)
    live_user = fc.captured["messages"][0]["content"]

    # the identical planted secret is absent from what EITHER model received
    assert _SECRET not in (urk_seen["user"] or ""), "URK path leaked the secret"
    assert _SECRET not in live_user, "live path leaked the secret"
    assert "<redacted" in (urk_seen["user"] or "") and "<redacted" in live_user
