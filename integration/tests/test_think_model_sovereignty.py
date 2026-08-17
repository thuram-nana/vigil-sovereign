"""GAP-1 — end-to-end model sovereignty in the SPAWNED offense work.

The console chat's per-session model pick is a SOVEREIGNTY control: a LOCAL pick promises "nothing leaves
this machine". Before GAP-1 that promise held only for the chat's OWN reasoning turn — the work the chat
SPAWNED (the agentic ``vigil engage`` OODA loop, its fireteam members, the codebase edit) dropped the pick
and fell back to a tier-default CLOUD model, gated only by the coarse sovereignty tier ladder. On a
cloud-permitting tier a LOCAL pick therefore still egressed the operator's prompt + source to a cloud model.

These tests pin the offense/integration half of the fix — the think seam and the dev-edit path:

  * a LOCAL ``backend`` routes ``think`` through the loopback-enforced kernel provider with NO cloud
    failover, and it is classified BEFORE any anthropic client could be built — so even on TRUSTED_CLOUD
    with an ``ANTHROPIC_API_KEY`` sitting in the env, a LOCAL pick NEVER constructs a cloud client;
  * a LOCAL backend that is unreachable / remote-endpoint / hostname-endpoint / fails mid-call REFUSES
    (the safest ASK_USER) — it never falls back to cloud, so nothing egresses;
  * a fireteam member (which reuses the SAME think seam) inherits the pick: a LOCAL pick → the member's
    think is local, never a cloud client;
  * a CLOUD pick reaches the think step with the CHOSEN model string (positive control, no regression);
  * ``dev_edit.propose_dev_edit`` with a LOCAL backend proposes on the local provider (or refuses), never
    a cloud call; a CLOUD pick sends the chosen model string;
  * ``vigil engage`` accepts ``--model`` / ``--backend`` (mutually exclusive), threaded into EngineConfig.

No network call is ever made; the anthropic SDK is never imported on any LOCAL path.
"""
from __future__ import annotations

import pytest

# The whole file exercises the kernel provider layer (get_backend) — it can only run where `framework` is
# importable (the offense CI leg). Behind importorskip so it SKIPS (never errors) in the sovereign leg, and
# is listed in the offense leg of ci.yml (guarded by test_ci_framework_tests_run_in_offense_leg.py).
pytest.importorskip("framework.v2.kernel.llm")

from vigil_integration.agent.state import ActionType, AgentState, Phase  # noqa: E402
from vigil_integration.live import dev_edit, think_claude  # noqa: E402


# ── a fake LOCAL kernel backend — the LOCAL think/dev-edit path routes HERE, never to the cloud SDK ──────────
def _install_fake_backend(monkeypatch, *, available=True, endpoint="http://localhost:11434",
                          reply='{"action": "complete", "summary": "local decision"}',
                          raise_on_complete=False) -> dict:
    """Patch ``framework.v2.kernel.llm.get_backend`` to return a fake LOCAL backend. ``endpoint`` is the
    backend's OWN resolved URL (``base``/``host``) the loopback check reads; a remote/hostname value drives
    the refuse-negative-controls. The parsed result exposes the reply on ``.decision`` (think) AND ``.diff``
    (dev-edit) so one fake serves both callers."""
    import framework.v2.kernel.llm as llm_mod

    seen = {"complete": False, "avail": False, "force": None, "prompt": None}

    class _Parsed:
        def __init__(self, r):
            self.decision = r
            self.diff = r
            self.reply = r

    class _Result:
        def __init__(self, r):
            self.parsed = _Parsed(r)
            self.trace = None
            self.raw_response = r

    class _Backend:
        name = "ollama"
        base = endpoint
        host = endpoint

        def is_available(self):
            seen["avail"] = True
            return (available, "" if available else "connection refused")

        def complete(self, prompt):
            seen["complete"] = True
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
    """Trip a flag if the direct-Anthropic client is EVER built — a LOCAL pick must never reach it. Patching
    ``_build_live_client`` covers the key path; the injected-client path is not used on any LOCAL route."""
    flag = {"built": 0}

    def _boom(key):
        flag["built"] += 1
        raise AssertionError("_build_live_client was called on a LOCAL pick — that is a cloud fallback")

    monkeypatch.setattr(think_claude, "_build_live_client", _boom)
    return flag


def _state() -> AgentState:
    return AgentState(engagement_slug="gap1", objective="assess loopback", phase=Phase.INFORMATIONAL)


@pytest.fixture(autouse=True)
def _clean_tier(monkeypatch):
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGN_MODE", raising=False)
    yield


# ── think: LOCAL routing, NO cloud failover ────────────────────────────────────────────────────────────────

def test_think_local_pick_routes_local_and_never_builds_a_cloud_client(monkeypatch):
    """THE non-negotiable: a LOCAL pick on a CLOUD-permitting tier, with a cloud key in the env, routes to
    the local provider and NEVER constructs a cloud client."""
    seen = _install_fake_backend(monkeypatch, available=True,
                                 reply='{"action": "complete", "summary": "done locally"}')
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "TRUSTED_CLOUD")   # cloud is permitted here …
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")          # … and a key is sitting right there
    d = think_claude.think(_state(), "prior tool output", backend="ollama")
    assert d.action == ActionType.COMPLETE            # the LOCAL backend's decision was used
    assert seen["complete"] is True and seen["force"] == "ollama"
    assert cloud["built"] == 0                         # cloud client NEVER built


def test_think_local_unreachable_refuses_with_no_cloud_fallback(monkeypatch):
    seen = _install_fake_backend(monkeypatch, available=False)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    d = think_claude.think(_state(), "ctx", backend="ollama")
    assert d.action == ActionType.ASK_USER            # fail-closed pause, not a cloud call
    assert seen["complete"] is False                  # never attempted the local call
    assert cloud["built"] == 0


def test_think_local_call_failure_refuses_with_no_cloud_fallback(monkeypatch):
    seen = _install_fake_backend(monkeypatch, available=True, raise_on_complete=True)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    d = think_claude.think(_state(), "ctx", backend="self-hosted")
    assert d.action == ActionType.ASK_USER
    assert seen["complete"] is True and cloud["built"] == 0


def test_think_local_remote_endpoint_refuses_and_sends_nothing(monkeypatch):
    """RED-PEN mirror of the console BLOCK-1: a name-classed 'local' backend whose resolved endpoint is
    REMOTE must REFUSE before even the availability probe — nothing is sent, no cloud fallback."""
    seen = _install_fake_backend(monkeypatch, available=True,
                                 endpoint="https://vllm.evil-remote.example.com/v1")
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    d = think_claude.think(_state(), "the private source", backend="self-hosted")
    assert d.action == ActionType.ASK_USER
    assert seen["complete"] is False and seen["avail"] is False   # not even the probe reached the remote
    assert cloud["built"] == 0


def test_think_local_hostname_endpoint_refuses(monkeypatch):
    seen = _install_fake_backend(monkeypatch, available=True, endpoint="http://my-gpu-box.lan:11434")
    cloud = _forbid_cloud(monkeypatch)
    d = think_claude.think(_state(), "ctx", backend="ollama")
    assert d.action == ActionType.ASK_USER and seen["complete"] is False and cloud["built"] == 0


def test_think_ollama_remote_host_refused_BEFORE_construction(monkeypatch):
    """GAP-1 BLOCK-1 (the sharp one): the REAL ``OllamaBackend.__init__`` PROBES its host (httpx GET
    /api/version) DURING construction — so a remote ``CRUCIBLE_OLLAMA_HOST`` must be refused BEFORE
    ``get_backend`` constructs it, or the probe egresses off-host. Faithfully model ``get_backend`` as a
    constructor that probes; assert it is NEVER reached for a remote host (no construction ⇒ no probe ⇒
    nothing sent), even on a cloud-permitting tier with a key present, and with no cloud fallback."""
    import os as _os
    import framework.v2.kernel.llm as llm_mod
    probed: list = []

    def _get_backend_that_probes(force=None, refresh=False):
        probed.append(_os.environ.get("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434"))   # the off-host dial
        raise AssertionError("construction reached for a REMOTE ollama host — the __init__ probe would egress")

    monkeypatch.setattr(llm_mod, "get_backend", _get_backend_that_probes)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://gpu-box.lan:11434")     # REMOTE
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "TRUSTED_CLOUD")           # cloud PERMITTED — still no egress
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    backend, refusal = think_claude.local_backend_or_refusal("ollama")
    assert backend is None and refusal and "non-loopback" in refusal.lower()
    assert probed == []                       # get_backend/construction NEVER reached ⇒ no off-host probe
    assert cloud["built"] == 0                # and no cloud fallback


def test_think_ollama_loopback_host_constructs(monkeypatch):
    """Positive control: a loopback ``CRUCIBLE_OLLAMA_HOST`` passes the pre-check, so construction proceeds
    (and here fails closed because no daemon is up — never a cloud fallback)."""
    import framework.v2.kernel.llm as llm_mod
    reached = {"n": 0}

    def _get_backend(force=None, refresh=False):
        reached["n"] += 1
        raise RuntimeError("daemon down")     # construction reached (pre-check passed) → fail closed

    monkeypatch.setattr(llm_mod, "get_backend", _get_backend)
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://127.0.0.1:11434")       # LOOPBACK
    backend, refusal = think_claude.local_backend_or_refusal("ollama")
    assert reached["n"] == 1                   # pre-check PASSED → construction was attempted
    assert backend is None and "could not be initialised" in (refusal or "")   # then failed closed


def test_think_local_loopback_ip_literal_is_accepted(monkeypatch):
    seen = _install_fake_backend(monkeypatch, available=True, endpoint="http://127.0.0.5:8000/v1",
                                 reply='{"action": "ask_user", "question": "what next?"}')
    cloud = _forbid_cloud(monkeypatch)
    d = think_claude.think(_state(), "ctx", backend="self-hosted")
    assert d.action == ActionType.ASK_USER and seen["complete"] is True and cloud["built"] == 0


def test_think_unknown_backend_is_not_treated_as_local(monkeypatch):
    """An UNKNOWN backend name is NOT silently routed local (which would skip the cloud gate) — it falls to
    the ordinary cloud path, which is itself sovereignty-gated. Here: no key, no client → the safest action,
    and the local provider is never consulted."""
    seen = _install_fake_backend(monkeypatch, available=True)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    d = think_claude.think(_state(), "ctx", backend="totally-made-up-backend")
    assert d.action == ActionType.ASK_USER
    assert seen["force"] is None and seen["complete"] is False   # local provider never touched


# ── fireteam members reuse the same think seam → they inherit the LOCAL pick ────────────────────────────────

def test_fireteam_member_inherits_local_pick_no_cloud(monkeypatch):
    """A fireteam member runs the parent's injected think seam. When that seam carries a LOCAL pick (as
    ``wiring.think_seam`` now does via ``config.backend``), the member's think is LOCAL — never a cloud
    client. Modelled here by wrapping ``think`` exactly as ``think_seam`` does and driving one member."""
    from types import SimpleNamespace

    from vigil_integration.fireteam.member import FireteamMember
    from vigil_integration.fireteam.member_runner import build_member_runner
    from vigil_integration.fireteam.models import FireteamMemberSpec

    seen = _install_fake_backend(monkeypatch, available=False)   # unreachable local → member ends its turn
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "TRUSTED_CLOUD")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")

    # this is the shape wiring.think_seam takes: it closes over the per-session pick and forwards it.
    def seam(state):
        return think_claude.think(state, "", model=None, backend="ollama")

    def run_tool(tool, phase, seq, *, approved=False):   # never reached (member only ever gets ASK_USER)
        raise AssertionError("run_tool must not run on a refused local member step")

    runner = build_member_runner(think=seam, run_tool=run_tool, parent_objective="assess")
    member = FireteamMember(spec=FireteamMemberSpec(member_id="m1", role="recon"), wave_id="w1")
    result = runner(member, SimpleNamespace(seq=0, gate=None, hints=(), spine=None))
    assert result is not None
    assert seen["force"] == "ollama"        # the member's think routed through the LOCAL provider
    assert cloud["built"] == 0              # and never built a cloud client


# ── cloud positive control — the CHOSEN model string reaches the think step ─────────────────────────────────

def test_think_cloud_pick_sends_the_chosen_model_string(monkeypatch):
    cap: dict = {}

    class _Block:
        type = "text"

        def __init__(self, t):
            self.text = t

    class _Resp:
        def __init__(self, t):
            self.content = [_Block(t)]
            self.usage = None

    class _Client:
        def __init__(self):
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp('{"action": "ask_user", "question": "next?"}')

    monkeypatch.setattr(think_claude, "_build_live_client", lambda key: _Client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")     # PERMISSIVE tier (env unset) permits cloud
    d = think_claude.think(_state(), "ctx", model="claude-sonnet-5", backend="")
    assert d.action == ActionType.ASK_USER
    assert cap["create_kw"]["model"] == "claude-sonnet-5"        # the CHOSEN model, not a hardcoded default


def test_think_no_pick_still_uses_the_default_cloud_path(monkeypatch):
    """No pick (backend=None, model=None) is byte-identical to the pre-GAP-1 behaviour: the cloud path with
    the ambient default model — a regression guard that GAP-1 did not break the ordinary run."""
    cap: dict = {}

    class _Resp:
        content = [type("B", (), {"type": "text", "text": '{"action": "complete", "summary": "x"}'})()]
        usage = None

    class _Client:
        def __init__(self):
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp()

    monkeypatch.setattr(think_claude, "_build_live_client", lambda key: _Client())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    d = think_claude.think(_state(), "ctx")
    assert d.action == ActionType.COMPLETE
    assert cap["create_kw"]["model"] == think_claude.DEFAULT_MODEL


# ── dev_edit: LOCAL routing (no cloud), CLOUD positive control ──────────────────────────────────────────────

def test_dev_edit_local_pick_routes_local_no_cloud(monkeypatch, tmp_path):
    seen = _install_fake_backend(monkeypatch, available=True,
                                 reply="--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n")
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "TRUSTED_CLOUD")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    diff = dev_edit.propose_dev_edit(str(tmp_path), "rename a to b", backend="ollama")
    assert diff.startswith("--- a/x.py") and seen["complete"] is True and seen["force"] == "ollama"
    assert cloud["built"] == 0


def test_dev_edit_local_unreachable_returns_no_proposal_no_cloud(monkeypatch, tmp_path):
    seen = _install_fake_backend(monkeypatch, available=False)
    cloud = _forbid_cloud(monkeypatch)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-present")
    diff = dev_edit.propose_dev_edit(str(tmp_path), "rename a to b", backend="self-hosted")
    assert diff == "" and seen["complete"] is False and cloud["built"] == 0


def test_dev_edit_cloud_pick_sends_the_chosen_model(monkeypatch, tmp_path):
    cap: dict = {}

    class _Resp:
        content = [type("B", (), {"type": "text", "text": "--- a/x\n+++ b/x\n"})()]
        usage = None

    class _Client:
        def __init__(self):
            self.messages = self

        def create(self, **kw):
            cap["create_kw"] = kw
            return _Resp()

    monkeypatch.setattr(dev_edit, "_build_live_client", lambda key: _Client())
    monkeypatch.setattr(dev_edit, "_resolve_key", lambda k: "sk-ant-present")
    diff = dev_edit.propose_dev_edit(str(tmp_path), "do the thing", model="claude-sonnet-5")
    assert cap["create_kw"]["model"] == "claude-sonnet-5" and diff.startswith("--- a/x")


# ── cli: --model / --backend are threaded into EngineConfig, mutually exclusive ─────────────────────────────

def test_cli_engage_parser_accepts_model_and_backend():
    from vigil_integration.cli import build_parser
    args = build_parser().parse_args(["engage", "http://127.0.0.1", "--backend", "ollama"])
    assert args.backend == "ollama" and args.model == ""
    args2 = build_parser().parse_args(["engage", "http://127.0.0.1", "--model", "claude-sonnet-5"])
    assert args2.model == "claude-sonnet-5" and args2.backend == ""


def test_cli_engage_refuses_both_model_and_backend():
    """A cloud model AND a local backend at once is contradictory — fail-closed (return 2) rather than
    silently preferring one (which could be the cloud egress the operator did not intend)."""
    from vigil_integration.cli import _cmd_engage, build_parser
    args = build_parser().parse_args(
        ["engage", "http://127.0.0.1", "--model", "claude-sonnet-5", "--backend", "ollama"])
    assert _cmd_engage(args) == 2


def test_engine_config_carries_model_and_backend():
    from vigil_integration.live.wiring import EngineConfig
    cfg = EngineConfig(slug="s", backend="ollama")
    assert cfg.backend == "ollama" and cfg.model is None
    cfg2 = EngineConfig(slug="s", model="claude-sonnet-5")
    assert cfg2.model == "claude-sonnet-5" and cfg2.backend is None
