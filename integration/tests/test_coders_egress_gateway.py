"""M4.1 conformance — the codebase-edit coders + their shared egress helpers route through the ONE gateway.

Before M4.1 ``dev_edit`` and ``codefix_runner`` reached ``client.messages.create`` / ``backend.complete``
DIRECTLY, with no classification, no symmetric redaction, and no shared audit. These tests pin the
conformance invariants on the REAL helpers (``think_claude.egress_cloud_create`` / ``egress_local_complete``,
used by both coders) and on ``dev_edit.propose_dev_edit`` end-to-end, each with a positive + a safe-negative
control so no assertion is a no-op:

  * a planted secret in the prompt is masked BEFORE the fake provider sees it (the gap the coders had);
  * ordinary content is delivered unchanged (redaction is not eating non-secrets);
  * one unified provenance/audit record is produced, attributing the output to an UNTRUSTED provider;
  * the raw round-trip runs ONLY inside the egress context — a direct call fails closed.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

# The gateway's model-route hook imports the framework sovereignty policy lazily; skip (never error) in the
# sovereign leg where the engine is deliberately absent.
pytest.importorskip("framework.v2.kernel.sovereignty")

from vigil_core import ai_gateway                              # noqa: E402
from vigil_integration.live import think_claude               # noqa: E402

_SECRET = "sk-ant-PLANTED-coder-secret-value-abc123"


class _Block:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]
        self.usage = None


class _Msgs:
    def __init__(self, outer: "FakeClient") -> None:
        self._outer = outer

    def create(self, **kw):
        self._outer.captured = kw
        return _Resp(self._outer.text)


class FakeClient:
    def __init__(self, text: str = "--- a/x\n+++ b/x\n") -> None:
        self.text = text
        self.captured: dict = {}
        self.messages = _Msgs(self)


class FakeBackend:
    """A loopback-local backend double: records the prompt it received + that it ran inside the egress context."""

    def __init__(self) -> None:
        self.name = "ollama"
        self.seen: dict = {}

    def complete(self, prompt):
        self.seen["prompt"] = prompt
        self.seen["in_egress"] = ai_gateway.in_egress()
        return SimpleNamespace(parsed=SimpleNamespace(diff="d", reply="r", decision="x"), trace=None)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    ai_gateway.reset_audit()
    yield
    ai_gateway.reset_audit()


# ── the shared CLOUD helper (used by dev_edit + codefix) ────────────────────────────────────────────

def test_cloud_create_masks_a_planted_secret_before_the_model():
    fc = FakeClient()
    think_claude.egress_cloud_create(fc, path="codefix", model="claude-opus-5", max_tokens=16,
                                     user=f"fix this: Authorization: Bearer {_SECRET}")
    sent = fc.captured["messages"][0]["content"]
    assert _SECRET not in sent                       # the credential never reached the provider …
    assert "<redacted" in sent                        # … it was masked in flight (the symmetric guarantee)


def test_cloud_create_leaves_ordinary_source_unchanged():
    # SAFE-NEGATIVE control: redaction must not eat ordinary source.
    fc = FakeClient()
    src = "def add(a, b):\n    return a + b\n"
    think_claude.egress_cloud_create(fc, path="codefix", model="claude-opus-5", max_tokens=16, user=src)
    assert fc.captured["messages"][0]["content"] == src


def test_cloud_create_emits_one_unified_record_marking_provider_untrusted():
    fc = FakeClient()
    think_claude.egress_cloud_create(fc, path="dev_edit", model="claude-opus-5", max_tokens=16, user="x")
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "dev_edit" and rec.invoked is True and rec.outcome == "completed"
    assert rec.provider_authoritative is False and rec.provider_in_trust_root is False
    assert rec.extra.get("model") == "claude-opus-5"


def test_cloud_create_raw_fails_closed_outside_the_gateway():
    with pytest.raises(ai_gateway.EgressBypass):
        think_claude._cloud_create_raw(FakeClient(), model="m", max_tokens=4, user="u")


# ── the shared LOOPBACK-LOCAL helper (used by think + dev_edit local) ───────────────────────────────

def test_local_complete_masks_a_planted_secret_before_the_backend():
    be = FakeBackend()
    prompt = SimpleNamespace(system="be precise", user=f"token={_SECRET}")
    think_claude.egress_local_complete(be, prompt, path="live.think.local", backend_name="ollama")
    assert _SECRET not in be.seen["prompt"].user and "<redacted" in be.seen["prompt"].user
    assert be.seen["prompt"].system == "be precise"   # ordinary field untouched (negative control)
    assert be.seen["in_egress"] is True               # the backend ran INSIDE the chokepoint


def test_local_complete_emits_a_unified_record():
    be = FakeBackend()
    think_claude.egress_local_complete(be, SimpleNamespace(system="s", user="u"),
                                       path="live.think.local", backend_name="ollama")
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "live.think.local" and rec.invoked is True and rec.outcome == "completed"
    assert rec.extra.get("backend") == "ollama"
    assert rec.provider_authoritative is False         # a local model's output is a proposal too


def test_local_complete_raw_fails_closed_outside_the_gateway():
    with pytest.raises(ai_gateway.EgressBypass):
        think_claude._local_complete_raw(FakeBackend(), SimpleNamespace(system="s", user="u"))


# ── dev_edit end-to-end routes through the gateway ──────────────────────────────────────────────────

def test_propose_dev_edit_cloud_routes_and_redacts(tmp_path, monkeypatch):
    monkeypatch.setattr("vigil_integration.live.dev_edit.llm_egress_refusal", lambda *_: None)  # permit
    from vigil_integration.live import dev_edit
    fc = FakeClient(text="--- a/x\n+++ b/x\n")
    # a secret rides the change instruction; it must be masked before the model is called.
    out = dev_edit.propose_dev_edit(str(tmp_path), f"rotate the key Authorization: Bearer {_SECRET}",
                                    files=None, client=fc)
    assert out == "--- a/x\n+++ b/x\n"                  # the model's returned diff is passed through verbatim
    sent = fc.captured["messages"][0]["content"]
    assert _SECRET not in sent and "<redacted" in sent  # the planted secret was masked before egress
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "dev_edit" and rec.invoked is True
