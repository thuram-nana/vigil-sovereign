"""W16-9 — the SIGIL plane's OWN model calls are under the sovereignty tier.

Before this change, the offense engine honoured `CRUCIBLE_SOVEREIGNTY_TIER` but the
SIGIL plane's own model calls — vision (`ClaudeVision`), memory consolidation
(`consolidate.extract.ApiProvider`) and voice (`voice.backends.ElevenLabsTts` /
`ElevenLabsAsr`) — read `SIGIL_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY` /
`ELEVENLABS_API_KEY` and reached the cloud INDEPENDENTLY of the tier. Fatal to an
air-gap claim. This suite pins the fix:

  * Voice, vision AND memory consolidation each REFUSE a cloud call under AIR_GAPPED
    — three separate assertions, and the refusal happens BEFORE any socket is opened.
  * NEGATIVE CONTROL — the gate keys on the RESOLVED ENDPOINT, not a declared backend
    label: a client declaring the "ollama"/local class while pointing at a cloud host
    is refused; and (the gate is not a blanket block) a genuinely LOCAL endpoint is
    PERMITTED under AIR_GAPPED, and every cloud call PROCEEDS under PERMISSIVE.
  * A STRUCTURAL test (pure source scan — no offense import, FATAL-2 safe) enumerates
    every model-egress site in BOTH planes and asserts each is tier-checked.

fail-before/pass-after: revert only the `assert_endpoint_permitted(...)` hunks and the
AIR_GAPPED refusal tests fail — the cloud call proceeds and `pytest.raises` sees no
`SovereigntyRefusal` (and the recorded egress URL list is non-empty).

Run: ~/.sigil/venv/bin/python -m pytest tests/test_sovereignty_sigil_plane.py
"""
from __future__ import annotations

import ast
import json
import tempfile
import urllib.request
from pathlib import Path

import pytest

# W16-9 red-pen fix: numpy is absent in the sigil-governor CI job; importorskip makes this module SKIP
# (not error) there, and — being module-level — it also guards the sigil.voice.backends import below,
# which triggers numpy at collection. Matches the suite's numpy-optional convention.
np = pytest.importorskip("numpy")

from sigil import sovereignty as sv
from sigil.consolidate.extract import ApiProvider, LocalProvider
from sigil.perception.capture import Frame
from sigil.perception.vision import ClaudeVision, MoondreamVision
from sigil.spine.store import SpineStore
from sigil.voice.backends import ElevenLabsAsr, ElevenLabsTts

_REPO = Path(__file__).resolve().parents[3]          # apps/sigil/tests -> repo root


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------

class _FakeResp:
    """A canned HTTP response usable as a context manager (mirrors urlopen's return)."""
    def __init__(self, body: bytes):
        self._body = body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self):
        return self._body


def _recording_urlopen(sink: list, body: bytes):
    """A urlopen stand-in that RECORDS the URL it was asked to open and returns `body`.
    If the sovereignty gate does its job the recorder stays EMPTY (no egress attempted)."""
    def _fake(req, timeout=0):
        url = req.full_url if hasattr(req, "full_url") else getattr(req, "_url", str(req))
        sink.append(url)
        return _FakeResp(body)
    return _fake


_ANTHROPIC_OK = json.dumps({"content": [{"type": "text", "text": "[]"}]}).encode()
_OLLAMA_OK = json.dumps({"response": "a red coffee mug"}).encode()
_ELEVEN_ASR_OK = json.dumps({"text": "hello there"}).encode()
_ELEVEN_TTS_OK = (b"\x00\x00" * 320)     # raw pcm_16000 bytes


@pytest.fixture()
def png_frame():
    p = tempfile.mktemp(suffix=".png")
    Path(p).write_bytes(b"\x89PNG\r\n\x1a\nfakebytes")
    return Frame.from_image("screen", p)


@pytest.fixture()
def one_record():
    s = SpineStore(tempfile.mktemp(suffix=".jsonl"))
    s.append(kind="message", source="claude-code", actor="user",
             payload={"session_id": "s1", "project": "-x", "text": "We decided to use Qdrant."})
    return list(s.iter_records())


def _air_gapped(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)


def _permissive(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)


# --------------------------------------------------------------------------------------
# 1/2/3 — voice, vision, memory consolidation each REFUSE a cloud call under AIR_GAPPED
#         (three separate assertions; each proves NO socket was opened)
# --------------------------------------------------------------------------------------

def test_vision_cloud_refused_under_air_gapped(monkeypatch, png_frame):
    _air_gapped(monkeypatch)
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ANTHROPIC_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        ClaudeVision(api_key="test-key").describe(png_frame, "what?")
    assert calls == [], "vision must refuse BEFORE opening the socket — no egress"


def test_memory_consolidation_cloud_refused_under_air_gapped(monkeypatch, one_record):
    _air_gapped(monkeypatch)
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ANTHROPIC_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        ApiProvider(api_key="test-key").extract(one_record)
    assert calls == [], "memory consolidation must refuse BEFORE opening the socket — no egress"


def test_voice_cloud_refused_under_air_gapped(monkeypatch):
    _air_gapped(monkeypatch)
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ELEVEN_TTS_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        list(ElevenLabsTts(api_key="test-key").synth("hello"))      # synth is a generator
    assert calls == [], "voice TTS must refuse BEFORE opening the socket — no egress"

    calls2: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls2, _ELEVEN_ASR_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        ElevenLabsAsr(api_key="test-key").transcribe([np.zeros(160, dtype=np.int16)])
    assert calls2 == [], "voice STT must refuse BEFORE opening the socket — no egress"


# --------------------------------------------------------------------------------------
# 4 — NEGATIVE CONTROL: the check is on the ENDPOINT, not the declared backend label.
#     A "local"/ollama-class client pointed at a cloud endpoint is REFUSED.
# --------------------------------------------------------------------------------------

def test_negctrl_ollama_label_cloud_endpoint_refused(monkeypatch, png_frame, one_record):
    _air_gapped(monkeypatch)
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _OLLAMA_OK))

    # MoondreamVision advertises egresses=False ("local"), but its host points at a cloud endpoint.
    assert MoondreamVision.egresses is False
    with pytest.raises(sv.SovereigntyRefusal):
        MoondreamVision(host="https://api.anthropic.com").describe(png_frame, "what?")

    # LocalProvider is the "--provider local" (ollama) memory extractor — same rule.
    with pytest.raises(sv.SovereigntyRefusal):
        LocalProvider(host="https://api.anthropic.com").extract(one_record)

    assert calls == [], "the label is 'local' but the endpoint is cloud — refused, no egress"


def test_negctrl_classifier_discriminates_not_a_no_op():
    """The gate is not a blanket 'always cloud' block: the classifier genuinely
    discriminates, so a PASS is meaningful."""
    assert sv.classify_endpoint("https://api.anthropic.com/v1/messages") == "cloud"
    assert sv.classify_endpoint("https://api.elevenlabs.io/v1/x") == "cloud"
    assert sv.classify_endpoint("http://127.0.0.1:11434/api/generate") == "local"
    assert sv.classify_endpoint("http://localhost:11434/x") == "local"
    assert sv.classify_endpoint("http://[::1]:11434/x") == "local"
    assert sv.classify_endpoint("http://192.168.1.9:11434/x") == "local"
    assert sv.classify_endpoint("dns-name-we-do-not-resolve:11434") == "cloud"  # fail-closed


# --------------------------------------------------------------------------------------
# 5 — the gate is SELECTIVE: a LOCAL backend works under AIR_GAPPED, and every cloud
#     call PROCEEDS under PERMISSIVE (proving refusal is tier-gated, not always-on).
# --------------------------------------------------------------------------------------

def test_local_backend_works_under_air_gapped(monkeypatch, png_frame, one_record):
    _air_gapped(monkeypatch)
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _OLLAMA_OK))
    # loopback endpoint -> permitted even air-gapped
    assert MoondreamVision(host="http://127.0.0.1:11434").describe(png_frame, "?") == "a red coffee mug"
    assert calls and calls[0].startswith("http://127.0.0.1:11434"), "local egress must proceed"


def test_cloud_calls_proceed_under_permissive(monkeypatch, png_frame, one_record):
    _permissive(monkeypatch)
    assert sv.current_tier() == sv.Tier.PERMISSIVE
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ANTHROPIC_OK))
    # cloud vision + cloud consolidation both complete without a refusal
    ClaudeVision(api_key="k").describe(png_frame, "?")
    ApiProvider(api_key="k").extract(one_record)
    assert any("api.anthropic.com" in u for u in calls), "cloud egress must proceed under PERMISSIVE"


def test_legacy_sovereign_mode_maps_to_air_gapped(monkeypatch, png_frame):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGN_MODE", "1")
    assert sv.current_tier() == sv.Tier.AIR_GAPPED
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ANTHROPIC_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        ClaudeVision(api_key="k").describe(png_frame, "?")
    assert calls == []


def test_unknown_tier_fails_closed_to_air_gapped(monkeypatch, png_frame):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "BOGUS-NOT-A-TIER")
    assert sv.current_tier() == sv.Tier.AIR_GAPPED
    calls: list = []
    monkeypatch.setattr(urllib.request, "urlopen", _recording_urlopen(calls, _ANTHROPIC_OK))
    with pytest.raises(sv.SovereigntyRefusal):
        ClaudeVision(api_key="k").describe(png_frame, "?")
    assert calls == []


# --------------------------------------------------------------------------------------
# 6 — STRUCTURAL: every model-egress function in the SIGIL plane is tier-checked.
#     AST walk (no import of the offense engine): a NEW unguarded `urlopen` fails here.
# --------------------------------------------------------------------------------------

_SIGIL_EGRESS_MODULES = [
    _REPO / "apps/sigil/sigil/perception/vision.py",
    _REPO / "apps/sigil/sigil/consolidate/extract.py",
    _REPO / "apps/sigil/sigil/voice/backends.py",
]


def _calls_name(node: ast.AST, name: str) -> bool:
    """True if `node`'s own body calls `name` (bare or attribute, e.g.
    `urllib.request.urlopen`), NOT counting calls inside a nested function def."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue                       # a nested def owns its own egress/gate
        if isinstance(child, ast.Call):
            f = child.func
            fn = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if fn == name:
                return True
        if _calls_name(child, name):
            return True
    return False


def _qualified_egress_functions(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    """Every function/method that DIRECTLY calls urlopen, as (Class.method, node) —
    qualified so two same-named methods (ClaudeVision.describe vs MoondreamVision.describe)
    are BOTH counted, never collapsed."""
    out: list[tuple[str, ast.AST]] = []

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                walk(child, f"{prefix}{child.name}.")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _calls_name(child, "urlopen"):
                    out.append((f"{prefix}{child.name}", child))
                walk(child, f"{prefix}{child.name}.")
            else:
                walk(child, prefix)

    walk(tree, "")
    return out


def test_structural_every_sigil_egress_function_is_gated():
    seen = 0
    for path in _SIGIL_EGRESS_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        egress_funcs = _qualified_egress_functions(tree)
        assert egress_funcs, f"no urlopen egress found in {path.name} — did the scan target move?"
        for qual, node in egress_funcs:
            assert _calls_name(node, "assert_endpoint_permitted"), (
                f"{path.name}:{qual} opens a socket (urlopen) but is NOT guarded by "
                f"assert_endpoint_permitted — an ungated SIGIL model egress (the W16-9 defect class)"
            )
            seen += 1
    assert seen >= 7, f"expected >=7 gated SIGIL egress sites, found {seen}"


# --------------------------------------------------------------------------------------
# 7 — STRUCTURAL cross-plane: the OFFENSE model-egress modules reference the offense
#     sovereignty gate too. Pure file reads (text only) — no offense import (FATAL-2 safe).
# --------------------------------------------------------------------------------------

_OFFENSE_EGRESS = {
    _REPO / "engine/crucible/framework/v2/kernel/llm.py": ("assert_permitted",),
    _REPO / "integration/vigil_integration/live/think_claude.py": ("assert_permitted", "sovereignty"),
    _REPO / "integration/vigil_integration/live/codefix_runner.py": ("assert_permitted", "sovereignty"),
    _REPO / "engine/crucible/framework/v2/console/actions.py": ("assert_permitted",),
}


def test_structural_offense_egress_modules_reference_the_gate():
    for path, tokens in _OFFENSE_EGRESS.items():
        assert path.exists(), f"offense egress module moved: {path} (update SECURITY.md + this map)"
        text = path.read_text(encoding="utf-8")
        assert any(t in text for t in tokens), (
            f"{path.name} performs model egress but references none of {tokens} — untier-checked?"
        )


def test_structural_sigil_modules_reference_the_sigil_gate():
    for path in _SIGIL_EGRESS_MODULES:
        text = path.read_text(encoding="utf-8")
        assert "assert_endpoint_permitted" in text, f"{path.name} missing the SIGIL sovereignty gate"


# --------------------------------------------------------------------------------------
# 8 — DOC-TRUTH: SECURITY.md's honest statement is TRUE of the code. Claims are derived
#     from the code so they cannot drift.
# --------------------------------------------------------------------------------------

_SECURITY_MD = _REPO / "engine/crucible/SECURITY.md"


def test_doc_truth_security_md_matches_code():
    doc = _SECURITY_MD.read_text(encoding="utf-8")
    # the honest limit MUST still be present, for BOTH planes
    assert "a tier is not a network control" in doc.lower(), (
        "the honest 'a tier is not a network control' statement must remain in SECURITY.md"
    )
    # code-mirrored claims: the env var the SIGIL gate reads, and the gate symbol, must be named
    assert sv._TIER_ENV in doc, f"SECURITY.md must name the tier env var {sv._TIER_ENV}"
    assert "assert_endpoint_permitted" in doc, "SECURITY.md must name the SIGIL gate function"
    # each SIGIL egress module named in the doc must actually exist (claim ⇒ code)
    for rel in ("sigil/perception/vision.py", "sigil/consolidate/extract.py", "sigil/voice/backends.py"):
        assert rel in doc, f"SECURITY.md must list the gated SIGIL egress site {rel}"
        assert (_REPO / "apps/sigil" / rel).exists(), f"doc names {rel} but the file is absent"
    # the stale claim (SIGIL calls run "independently of CRUCIBLE_SOVEREIGNTY_TIER") must be GONE
    assert "independently of `CRUCIBLE_SOVEREIGNTY_TIER`" not in doc, (
        "the stale 'SIGIL plane runs independently of the tier' claim must be removed — it is now false"
    )
