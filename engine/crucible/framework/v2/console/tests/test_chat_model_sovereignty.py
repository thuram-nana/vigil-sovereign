"""E3 — per-session model sovereignty. The chat's reasoning model is the operator's choice, and that choice
is a SOVEREIGNTY control: a LOCAL model means an uploaded codebase never leaves the machine. These tests pin:

  * ``chat_models()`` surfaces each model's trust class, whether the current tier permits it (and why not),
    and the plain-language consequence; the default is Opus 5;
  * under AIR_GAPPED a local model is permitted and a cloud model is refused WITH A REASON (told up front,
    not at send time);
  * a CLOUD choice uses the CHOSEN model string (Sonnet), not a hardcoded one;
  * a LOCAL choice routes through the kernel provider layer, needs NO API key, and — the crux — a local
    that cannot be reached (or whose call fails) REFUSES with NO cloud fallback: the direct-SDK path is
    never invoked, so nothing egresses.

No network call is ever made.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import chat

CHAT = "model-sov-chat"


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    # start from a known tier; individual tests override
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_SEALED", raising=False)
    yield tmp_path


# ── the cloud SDK fake — records create() kwargs (incl. the model) and answers with a fixed text ──────────
@pytest.fixture()
def captured(monkeypatch: pytest.MonkeyPatch) -> dict:
    cap: dict = {}
    mod = types.ModuleType("anthropic")

    class _Block:
        type = "text"

        def __init__(self, text):
            self.text = text

    class _Resp:
        stop_reason = "end_turn"

        def __init__(self, text):
            self.content = [_Block(text)]

    class _Client:
        def __init__(self, api_key=None, **kw):
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp("A cloud lead.")

    mod.Anthropic = _Client
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    return cap


# ── a fake kernel provider layer — _reason_local routes HERE, never to the SDK ────────────────────────────
def _fake_llm(monkeypatch, *, available=True, reply="LOCAL ANSWER", raise_on_complete=False,
              endpoint="http://localhost:11434"):
    # `endpoint` is the backend's OWN resolved URL (base/host); the loopback default lets the routing tests
    # proceed, and a remote value drives the BLOCK-1 negative control (a remote "local" endpoint must refuse).
    seen = {"complete_called": False, "avail_called": False, "force": None, "prompt": None}
    import framework.v2.kernel.llm as llm_mod

    class _Parsed:
        def __init__(self, r):
            self.reply = r

    class _Result:
        def __init__(self, r):
            self.parsed = _Parsed(r)
            self.trace = None
            self.raw_response = r

    class _Backend:
        name = "ollama"
        base = endpoint     # the resolved endpoint _endpoint_host_is_local reads (base first, then host)
        host = endpoint

        def is_available(self):
            seen["avail_called"] = True
            return (available, "" if available else "connection refused")

        def complete(self, prompt):
            seen["complete_called"] = True
            seen["prompt"] = prompt
            if raise_on_complete:
                raise RuntimeError("local model exploded")
            return _Result(reply)

    def _get_backend(force=None, refresh=False):
        seen["force"] = force
        return _Backend()

    monkeypatch.setattr(llm_mod, "get_backend", _get_backend)
    return seen


def _forbid_cloud(monkeypatch) -> dict:
    """Trip a flag if the direct-SDK cloud call is ever reached — a local pick must NEVER touch it."""
    flag = {"called": False}

    def _boom(*a, **k):
        flag["called"] = True
        raise AssertionError("the cloud SDK path was reached on a LOCAL model pick — that is a fallback")

    monkeypatch.setattr(chat, "_chat_call_with_backoff", _boom)
    return flag


# ── chat_models() picker data ─────────────────────────────────────────────────────────────────────────────

def test_chat_models_surfaces_trust_class_and_consequence():
    d = chat.chat_models()
    assert d["default"] == "claude-opus-5"
    by = {m["id"]: m for m in d["models"]}
    assert "claude-opus-5" in by and "ollama" in by
    loc = by["ollama"]
    assert loc["kind"] == "local" and loc["trust_class"] == "local"
    assert "nothing leaves this machine" in loc["consequence"]
    cloud = by["claude-opus-5"]
    assert cloud["kind"] == "cloud" and "third-party" in cloud["consequence"]
    for m in d["models"]:
        assert isinstance(m["permitted"], bool) and m["trust_class"] and "why_not" in m


def test_air_gapped_permits_local_and_refuses_cloud_with_a_reason(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    d = chat.chat_models()
    assert d["tier"] == "AIR_GAPPED"
    by = {m["id"]: m for m in d["models"]}
    assert by["ollama"]["permitted"] is True and by["ollama"]["why_not"] == ""
    assert by["claude-opus-5"]["permitted"] is False and by["claude-opus-5"]["why_not"]
    assert by["claude-sonnet-5"]["permitted"] is False


# ── cloud choice uses the CHOSEN model ────────────────────────────────────────────────────────────────────

def test_cloud_choice_uses_the_chosen_model(captured):
    # attachments make this a reasoning turn; the create() call must carry the chosen model string
    out = chat._reason(CHAT, "any weakness?", model="claude-sonnet-5")
    assert out["ok"] is True
    assert captured["create_kw"]["model"] == "claude-sonnet-5"


def test_forbidden_cloud_tier_refuses_before_asking_for_a_key(monkeypatch):
    """RED-PEN LOW: under a sovereign tier a cloud pick is refused for SOVEREIGNTY even with NO key — not
    'add a key', which would imply a key is all that stands between the operator and a forbidden egress."""
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    cloud = _forbid_cloud(monkeypatch)
    out = chat._reason(CHAT, "any weakness?", model="claude-opus-5")
    assert out["ok"] is False and not out.get("need_key")
    assert "tier" in out["error"].lower() or "sovereign" in out["error"].lower()
    assert cloud["called"] is False


def test_blank_model_defaults_to_opus5(captured):
    out = chat._reason(CHAT, "hi", model="")
    assert out["ok"] is True and captured["create_kw"]["model"] == "claude-opus-5"


def test_unknown_model_degrades_to_the_default_cloud(captured):
    out = chat._reason(CHAT, "hi", model="totally-made-up-9000")
    assert out["ok"] is True and captured["create_kw"]["model"] == "claude-opus-5"


# ── local choice routes through the provider layer, keyless, NO cloud fallback ────────────────────────────

def test_local_choice_routes_to_provider_layer_no_key_needed(monkeypatch):
    seen = _fake_llm(monkeypatch, available=True, reply="LOCAL ANSWER about the code")
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)   # a local pick must NOT need a cloud key
    out = chat._reason(CHAT, "review the auth", model="ollama")
    assert out["ok"] is True and "LOCAL ANSWER" in out["reply"]
    assert seen["complete_called"] is True and seen["force"] == "ollama"
    assert cloud["called"] is False
    # the honesty note about local's limits + no egress rides the answer
    assert any("nothing left this machine" in n for n in out.get("notes", []))


def test_local_unreachable_refuses_with_no_cloud_fallback(monkeypatch):
    """THE sovereignty guarantee: a local model that cannot be reached REFUSES. It never falls back to a
    cloud model, so nothing egresses — even with a cloud key sitting right there."""
    seen = _fake_llm(monkeypatch, available=False)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")  # a key is present; it must STILL not be used
    out = chat._reason(CHAT, "review the auth", model="ollama")
    assert out["ok"] is False
    assert "cloud" in out["error"].lower() and "reach" in out["error"].lower()
    assert seen["complete_called"] is False        # never even attempted the call
    assert cloud["called"] is False                # and never touched the cloud SDK


def test_local_call_failure_refuses_with_no_cloud_fallback(monkeypatch):
    """A local model that is reachable but whose CALL fails also refuses with no fallback."""
    seen = _fake_llm(monkeypatch, available=True, raise_on_complete=True)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    out = chat._reason(CHAT, "review the auth", model="self-hosted")
    assert out["ok"] is False and "no cloud fallback" in out["error"].lower()
    assert seen["complete_called"] is True and cloud["called"] is False


def test_local_with_a_REMOTE_endpoint_refuses_and_sends_nothing(monkeypatch):
    """RED-PEN BLOCK-1: a name-classed 'local' backend whose resolved endpoint is REMOTE must REFUSE — it
    would otherwise POST the prompt + codebase off-host while the UI claims nothing left the machine. The
    guarantee is enforced (endpoint must be loopback), not merely asserted. Nothing is sent: neither the
    local call (complete) NOR even the availability probe (which for Ollama would itself reach the host)
    runs, and the cloud SDK is never touched."""
    seen = _fake_llm(monkeypatch, available=True, endpoint="https://vllm.evil-remote-cloud.example.com/v1")
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")   # the tier where the operator most trusts "local"
    out = chat._reason(CHAT, "review the private codebase", model="self-hosted")
    assert out["ok"] is False
    assert "not on this machine" in out["error"] and "loopback" in out["error"]
    assert seen["complete_called"] is False      # the prompt was never sent to the remote
    assert seen["avail_called"] is False         # not even the probe reached it (checked before is_available)
    assert cloud["called"] is False


def test_local_with_a_hostname_endpoint_refuses(monkeypatch):
    """A hostname (not a loopback literal) is refused even though it could resolve to loopback right now —
    DNS can point anywhere later, so we never assert a locality we cannot back."""
    seen = _fake_llm(monkeypatch, available=True, endpoint="http://my-gpu-box.lan:11434")
    out = chat._reason(CHAT, "review", model="ollama")
    assert out["ok"] is False and "not on this machine" in out["error"]
    assert seen["complete_called"] is False


def test_local_loopback_ip_literal_is_accepted(monkeypatch):
    """A loopback IP literal (127.0.0.x, not just 'localhost') is accepted — the guarantee holds and the call
    proceeds through the provider layer."""
    seen = _fake_llm(monkeypatch, available=True, reply="LOCAL OK", endpoint="http://127.0.0.5:8000/v1")
    cloud = _forbid_cloud(monkeypatch)
    out = chat._reason(CHAT, "review", model="self-hosted")
    assert out["ok"] is True and "LOCAL OK" in out["reply"]
    assert seen["complete_called"] is True and cloud["called"] is False


# ══════════════════════════════════════════════════════════════════════════════════════════════════════════
# GAP-1 — the per-session pick is threaded into SPAWNED work (agentic engage, fireteam, codebase edit), not
# just the chat's own turn. Before GAP-1 a LOCAL pick on a cloud-permitting tier still egressed to a cloud
# model in the work the chat launched. These tests pin the console half of the fix: the id→(cloud/backend)
# resolver, the engage argv, the launch threading, the session pin, and the codebase-edit routing.
# ══════════════════════════════════════════════════════════════════════════════════════════════════════════

from framework.v2.console import sessions as sessions_mod  # noqa: E402


def test_resolve_session_model_maps_local_cloud_and_no_pick():
    # a CLOUD pick → (model_string, "")
    assert chat.resolve_session_model("claude-sonnet-5") == ("claude-sonnet-5", "")
    # a LOCAL pick → ("", backend_name) — the loopback-enforced backend the spawned work must route through
    assert chat.resolve_session_model("ollama") == ("", "ollama")
    assert chat.resolve_session_model("self-hosted") == ("", "self-hosted")
    # blank → no explicit pick (the child keeps its ambient default under the tier gate)
    assert chat.resolve_session_model("") == ("", "")
    assert chat.resolve_session_model("   ") == ("", "")
    # an UNKNOWN non-blank id degrades to the tested cloud default (same as the chat's own reasoning path),
    # never to a fabricated local backend that would skip the cloud gate
    assert chat.resolve_session_model("totally-made-up-9000") == ("claude-opus-5", "")


def test_integration_engage_cmd_local_pick_emits_backend_flag_not_model(monkeypatch):
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    cmd = actions_mod._integration_engage_cmd("http://127.0.0.1:8080", "s", "sess", "standard",
                                              backend="ollama")
    assert cmd is not None
    assert "--backend" in cmd and cmd[cmd.index("--backend") + 1] == "ollama"
    assert "--model" not in cmd            # a LOCAL pick NEVER also carries a cloud model


def test_integration_engage_cmd_cloud_pick_emits_model_flag_not_backend(monkeypatch):
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    cmd = actions_mod._integration_engage_cmd("http://127.0.0.1:8080", "s", "sess", "standard",
                                              model="claude-sonnet-5")
    assert cmd is not None
    assert "--model" in cmd and cmd[cmd.index("--model") + 1] == "claude-sonnet-5"
    assert "--backend" not in cmd


def test_integration_engage_cmd_no_pick_emits_neither(monkeypatch):
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    cmd = actions_mod._integration_engage_cmd("http://127.0.0.1:8080", "s", "sess", "standard")
    assert cmd is not None and "--model" not in cmd and "--backend" not in cmd


def test_integration_engage_cmd_backend_wins_over_model_failclosed(monkeypatch):
    """If both are somehow set, the LOCAL backend wins — never silently prefer the cloud model (an egress the
    operator did not intend). (The CLI additionally refuses both-at-once; this is defence in depth.)"""
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    cmd = actions_mod._integration_engage_cmd("http://127.0.0.1:8080", "s", "sess", "standard",
                                              model="claude-opus-5", backend="ollama")
    assert "--backend" in cmd and "--model" not in cmd


def test_session_model_pin_persists_and_survives_a_blank_turn():
    sessions_mod.set_session_model("pin-sess", "ollama")
    assert sessions_mod.session_model("pin-sess") == "ollama"
    # a later turn that omits the pick does NOT clear the pin (chat_send only pins on a non-blank pick)
    assert sessions_mod.session_model("pin-sess") == "ollama"
    # an explicit change re-pins
    sessions_mod.set_session_model("pin-sess", "claude-sonnet-5")
    assert sessions_mod.session_model("pin-sess") == "claude-sonnet-5"
    # an unknown / never-set session has no pin (→ "no pick", never a silent cloud substitution)
    assert sessions_mod.session_model("never-set-sess") == ""


def test_launch_assessment_local_pick_threads_backend_into_the_child_engage(monkeypatch):
    """chat_send → launch_assessment → engage CHILD: a LOCAL pick reaches the spawned agentic engage as
    ``--backend ollama`` (so the child routes local-or-refuse, never cloud). The launcher itself constructs
    no cloud client; the child's no-cloud guarantee is pinned in the integration suite."""
    spawned: dict = {}
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    monkeypatch.setattr(actions_mod, "_spawn_background",
                        lambda run_id, rd, cmd, meta, **kw: spawned.update(cmd=cmd, meta=meta))
    out = actions_mod.launch_assessment({
        "mode": "url", "target": "http://127.0.0.1:8080", "objective": "check it",
        "session_id": "launch-local-sess", "agentic": True, "model": "ollama",
    })
    assert out.get("engine") == "integration"
    cmd = spawned["cmd"]
    assert "--backend" in cmd and cmd[cmd.index("--backend") + 1] == "ollama"
    assert "--model" not in cmd
    assert spawned["meta"].get("model_backend") == "ollama"


def test_launch_assessment_cloud_pick_threads_model_into_the_child_engage(monkeypatch):
    spawned: dict = {}
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    monkeypatch.setattr(actions_mod, "_spawn_background",
                        lambda run_id, rd, cmd, meta, **kw: spawned.update(cmd=cmd, meta=meta))
    out = actions_mod.launch_assessment({
        "mode": "url", "target": "http://127.0.0.1:8080", "objective": "check it",
        "session_id": "launch-cloud-sess", "agentic": True, "model": "claude-sonnet-5",
    })
    assert out.get("engine") == "integration"
    cmd = spawned["cmd"]
    assert "--model" in cmd and cmd[cmd.index("--model") + 1] == "claude-sonnet-5"
    assert "--backend" not in cmd


def test_launch_assessment_falls_back_to_the_session_pin_when_the_turn_omits_the_model(monkeypatch):
    """A launch whose body omits ``model`` still stays pinned to the session's LOCAL pick — the guarantee
    holds across a mid-run steer / later launch, not just the first turn that set it."""
    spawned: dict = {}
    sessions_mod.set_session_model("pinned-launch-sess", "self-hosted")
    monkeypatch.setattr(actions_mod, "_vigil_bin", lambda: "vigil")
    monkeypatch.setattr(actions_mod, "_spawn_background",
                        lambda run_id, rd, cmd, meta, **kw: spawned.update(cmd=cmd))
    actions_mod.launch_assessment({
        "mode": "url", "target": "http://127.0.0.1:8080", "objective": "check it",
        "session_id": "pinned-launch-sess", "agentic": True,   # NO "model" in the body
    })
    cmd = spawned["cmd"]
    assert "--backend" in cmd and cmd[cmd.index("--backend") + 1] == "self-hosted"


def test_propose_codebase_edit_local_pick_passes_backend_and_never_cloud(monkeypatch, tmp_path):
    """A codebase edit in a chat pinned to a LOCAL model passes ``backend`` (not a cloud model) to
    propose_dev_edit — so the edit routes local-or-refuse, never a silent cloud egress of the source."""
    import sys
    import types

    CHATID = "edit-local-chat"
    sessions_mod.set_session_model(CHATID, "ollama")

    # a real clone dir under THIS chat's confined clone area (edits are confined to repos the chat cloned)
    clone = Path(actions_mod._live_base()) / "clones" / CHATID / "repo"
    clone.mkdir(parents=True, exist_ok=True)

    # fake the offense-plane dev_edit toolchain (not on the console test path) with a spy that records kwargs
    captured: dict = {}
    vi = types.ModuleType("vigil_integration")
    vi_live = types.ModuleType("vigil_integration.live")
    vi_dev = types.ModuleType("vigil_integration.live.dev_edit")

    def _spy_propose_dev_edit(workdir, instruction, files=None, *, client=None,
                              model="claude-opus-5", backend="", max_tokens=4000):
        captured.update(model=model, backend=backend, workdir=workdir)
        return "--- a/x\n+++ b/x\n"

    vi_dev.propose_dev_edit = _spy_propose_dev_edit
    vi.live = vi_live
    vi_live.dev_edit = vi_dev
    monkeypatch.setitem(sys.modules, "vigil_integration", vi)
    monkeypatch.setitem(sys.modules, "vigil_integration.live", vi_live)
    monkeypatch.setitem(sys.modules, "vigil_integration.live.dev_edit", vi_dev)

    # instruction with NO file-path token → _files_in_instruction returns [] without importing codefix
    out = actions_mod.propose_codebase_edit(CHATID, str(clone), "make the login flow safer")
    assert out.get("ok") is True
    assert captured["backend"] == "ollama"                 # the LOCAL pick was threaded through
    assert captured["model"] == "claude-opus-5"            # the CLOUD model default was NOT selected/sent


def test_propose_codebase_edit_cloud_pick_passes_the_chosen_model(monkeypatch, tmp_path):
    import sys
    import types

    CHATID = "edit-cloud-chat"
    sessions_mod.set_session_model(CHATID, "claude-sonnet-5")
    clone = Path(actions_mod._live_base()) / "clones" / CHATID / "repo"
    clone.mkdir(parents=True, exist_ok=True)

    captured: dict = {}
    vi = types.ModuleType("vigil_integration")
    vi_live = types.ModuleType("vigil_integration.live")
    vi_dev = types.ModuleType("vigil_integration.live.dev_edit")

    def _spy(workdir, instruction, files=None, *, client=None, model="claude-opus-5", backend="",
             max_tokens=4000):
        captured.update(model=model, backend=backend)
        return "--- a/x\n+++ b/x\n"

    vi_dev.propose_dev_edit = _spy
    vi.live = vi_live
    vi_live.dev_edit = vi_dev
    monkeypatch.setitem(sys.modules, "vigil_integration", vi)
    monkeypatch.setitem(sys.modules, "vigil_integration.live", vi_live)
    monkeypatch.setitem(sys.modules, "vigil_integration.live.dev_edit", vi_dev)

    out = actions_mod.propose_codebase_edit(CHATID, str(clone), "improve the code")
    assert out.get("ok") is True
    assert captured["model"] == "claude-sonnet-5" and captured["backend"] == ""
