"""M4.1 meet-up — the SIGIL sovereign plane's cloud LLM egress routes through the SHARED gateway chokepoint.

BLOCK-2 (overclaim) fix: the gateway docstring claimed "every LLM egress" and the no-bypass guard claimed the
sovereign plane "has no direct provider egress", yet ``consolidate.extract.ApiProvider`` and
``perception.vision.ClaudeVision`` reached ``api.anthropic.com`` directly — no classification, no symmetric
redaction, no unified audit. These tests pin the MEET-UP: both sites now route through
``vigil_core.ai_gateway.egress`` (via ``sigil.sovereignty.egress_via_gateway``), so a recognised credential
SHAPE in the prompt/question is masked before the model sees it and ONE unified audit record is emitted — while
the SIGIL sovereignty tier still refuses a cloud call air-gapped (pinned in ``test_sovereignty_sigil_plane``).

Scope note (honest): the plane's NON-LLM provider egress (ElevenLabs voice; credential probes) is NOT routed
here — it is sovereignty-tier-governed and registered as a documented limitation
(``LIMIT-sigil-voice-probe-egress-not-gatewayed``). This file covers the two LLM sites that WERE met up.

No numpy needed (vision/extract are numpy-free), so this runs in either env; vigil_core must be importable.
"""
from __future__ import annotations

import base64
import json
import tempfile
import urllib.request
from pathlib import Path

import pytest

ai_gateway = pytest.importorskip("vigil_core.ai_gateway")

from sigil.consolidate.extract import ApiProvider
from sigil.perception.capture import Frame
from sigil.perception.vision import ClaudeVision
from sigil.spine.store import SpineStore


class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def _capturing_urlopen(cap: dict, body: bytes):
    def _fake(req, timeout=0):
        cap["url"] = req.full_url if hasattr(req, "full_url") else getattr(req, "_url", str(req))
        cap["body"] = req.data.decode("utf-8", "replace") if getattr(req, "data", None) else ""
        return _FakeResp(body)
    return _fake


_ANTHROPIC_OK = json.dumps({"content": [{"type": "text", "text": "[]"}], "usage": {}}).encode()


@pytest.fixture(autouse=True)
def _permissive_and_clean_audit(monkeypatch):
    # PERMISSIVE so the sovereignty tier permits the (mocked) cloud call; isolate the audit ring.
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    ai_gateway.reset_audit()
    yield
    ai_gateway.reset_audit()


# ── memory consolidation (text prompt) ───────────────────────────────────────────────────────────────

def test_consolidation_routes_through_gateway_and_masks_a_recognised_secret(monkeypatch):
    cap: dict = {}
    monkeypatch.setattr(urllib.request, "urlopen", _capturing_urlopen(cap, _ANTHROPIC_OK))
    secret = "api_key=sk-ant-SIGIL-CONSOLIDATE-SECRET-7788"
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    store.append(kind="message", source="claude-code", actor="user",
                 payload={"session_id": "s1", "project": "-x", "text": f"we set {secret} in prod"})
    recs = list(store.iter_records())

    ApiProvider(api_key="k").extract(recs)

    assert "api.anthropic.com" in cap["url"], "the egress did not reach the provider endpoint"
    assert secret not in cap["body"], "a recognised secret shape egressed UNMASKED from the sovereign plane"
    assert "<redacted" in cap["body"], "the prompt was not run through the gateway masker"
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "sigil_consolidate" and rec.invoked is True and rec.outcome == "completed"
    assert rec.redaction_count >= 1
    assert rec.provider_authoritative is False and rec.provider_in_trust_root is False


# ── frontier vision (image + text) ───────────────────────────────────────────────────────────────────

def test_vision_routes_through_gateway_masks_text_and_passes_image_bytes(monkeypatch):
    cap: dict = {}
    img = b"\x89PNG\r\n\x1a\nFAKE-IMAGE-BYTES-UNIQUE-MARKER-xyz"
    p = tempfile.mktemp(suffix=".png")
    Path(p).write_bytes(img)
    frame = Frame.from_image("screen", p)
    monkeypatch.setattr(urllib.request, "urlopen",
                        _capturing_urlopen(cap, json.dumps({"content": [{"type": "text", "text": "a mug"}],
                                                            "usage": {}}).encode()))
    secret = "Authorization: Bearer sk-ant-SIGIL-VISION-SECRET-9999"

    out = ClaudeVision(api_key="k").describe(frame, f"what is on screen? also {secret}")

    assert out == "a mug"
    assert secret not in cap["body"], "the accompanying question egressed UNMASKED"
    assert "<redacted" in cap["body"], "the question was not run through the gateway masker"
    # the IMAGE BYTES themselves pass through (binary, not text-maskable) — the honest carve-out
    assert base64.b64encode(img).decode("ascii") in cap["body"], "the image bytes should pass unredacted"
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "sigil_vision" and rec.invoked is True and rec.outcome == "completed"
    assert rec.redaction_count >= 1


# ── calibration: routing is unconditional, not keyed on secret presence ───────────────────────────────

def test_ordinary_prompt_still_routes_and_audits_with_zero_redactions(monkeypatch):
    cap: dict = {}
    monkeypatch.setattr(urllib.request, "urlopen", _capturing_urlopen(cap, _ANTHROPIC_OK))
    store = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    store.append(kind="message", source="claude-code", actor="user",
                 payload={"session_id": "s1", "project": "-x", "text": "we chose Qdrant for vectors"})
    ApiProvider(api_key="k").extract(list(store.iter_records()))
    rec = ai_gateway.audit_log()[-1]
    assert rec.path == "sigil_consolidate" and rec.invoked is True
    assert rec.redaction_count == 0            # nothing to mask, but it STILL routed + audited
