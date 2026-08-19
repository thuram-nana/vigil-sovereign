"""GAP-1 (Strix sovereignty) — the per-session model pick must reach the STRIX CODEBASE AGENT.

The confirmed defect: Strix's model comes from ``STRIX_LLM`` (default CLOUD ``anthropic/claude-opus-4-8``),
written ONLY by the GLOBAL persisted provider selection and never per-session. So a Strix codebase scan
launched in a nominally-LOCAL session still egressed to CLOUD via that global default — a real sovereignty
gap. These tests pin the fix: ``launch_assessment``'s codebase branch resolves the per-session pick into
``STRIX_LLM`` / ``LLM_API_BASE`` for that run only, mirroring the #365 ``local_backend_or_refusal``
discipline — a LOCAL pick pins its LOOPBACK endpoint or REFUSES (never the cloud default), while a
cloud/no-pick run is byte-identical (the global default flows through unchanged).

No network call is ever made; ``_spawn_background`` is stubbed so nothing is actually launched.
"""

from __future__ import annotations

import pytest

from framework.v2.console import actions as actions_mod
from framework.v2.console import sessions as sessions_mod

# the CLOUD global default that sits in the parent env — the thing a LOCAL session must never leak to.
CLOUD_DEFAULT = "anthropic/claude-opus-4-8"


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_LIVE_DIR", str(tmp_path / "live"))
    monkeypatch.setattr(actions_mod, "console_dir", lambda: tmp_path / ".console")
    (tmp_path / ".console" / "runs").mkdir(parents=True, exist_ok=True)
    # the global CLOUD STRIX_LLM default is present in the parent env — the defect is a LOCAL session
    # inheriting THIS. Start every local-model config var cleared so each test sets exactly what it means.
    monkeypatch.setenv("STRIX_LLM", CLOUD_DEFAULT)
    for v in ("LLM_API_BASE", "CRUCIBLE_OLLAMA_MODEL", "CRUCIBLE_OLLAMA_HOST",
              "CRUCIBLE_SELFHOSTED_MODEL", "CRUCIBLE_SELFHOSTED_ENDPOINT"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    yield tmp_path


# ══ the resolver helper in isolation ═════════════════════════════════════════════════════════════════════

def test_no_pick_keeps_global_default_byte_identical():
    # ACCEPTANCE (4): no per-session pick → {} → the global STRIX_LLM default flows unchanged.
    assert actions_mod._strix_session_llm_env("", "") == ({}, "")


def test_cloud_pick_keeps_global_default():
    # a cloud pick is cloud by the operator's own choice — no override; the global default flows unchanged.
    assert actions_mod._strix_session_llm_env("claude-sonnet-5", "") == ({}, "")


def test_local_ollama_pins_loopback_and_leaks_no_cloud(monkeypatch):
    # ACCEPTANCE (1): a LOCAL pick → STRIX_LLM/LLM_API_BASE at the LOOPBACK endpoint; NO cloud string leaks.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")
    env, refusal = actions_mod._strix_session_llm_env("ollama", "")
    assert refusal == ""
    assert env["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"
    assert env["LLM_API_BASE"] == "http://localhost:11434"
    assert "anthropic" not in env["STRIX_LLM"] and env["STRIX_LLM"] != CLOUD_DEFAULT


def test_local_self_hosted_pins_loopback(monkeypatch):
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_MODEL", "qwen")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_ENDPOINT", "http://127.0.0.1:8000/v1")
    env, refusal = actions_mod._strix_session_llm_env("self-hosted", "")
    assert refusal == "" and env["STRIX_LLM"] == "openai/qwen"     # LiteLLM openai/ prefix, per settings.py
    assert env["LLM_API_BASE"] == "http://127.0.0.1:8000/v1"


def test_local_no_model_refuses_not_cloud(monkeypatch):
    # ACCEPTANCE (2): a LOCAL pick that cannot be EXPRESSED (no model) REFUSES — never the cloud default.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")   # endpoint fine, but no model
    env, refusal = actions_mod._strix_session_llm_env("ollama", "")
    assert env == {} and refusal
    assert "cloud" in refusal.lower() and "STRIX_LLM" in refusal


def test_local_self_hosted_no_endpoint_refuses(monkeypatch):
    # ACCEPTANCE (2): a LOCAL pick with NO configured endpoint REFUSES fail-closed.
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_MODEL", "qwen")
    env, refusal = actions_mod._strix_session_llm_env("self-hosted", "")
    assert env == {} and refusal and "no configured endpoint" in refusal


def test_local_non_loopback_endpoint_refuses(monkeypatch):
    # ACCEPTANCE (3): a non-loopback "local" endpoint is REFUSED (it would send the source off-host).
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "https://ollama.evil-remote.example.com")
    env, refusal = actions_mod._strix_session_llm_env("ollama", "")
    assert env == {} and refusal
    assert "non-loopback" in refusal.lower() and "off-host" in refusal.lower()


def test_local_hostname_endpoint_refuses(monkeypatch):
    # a hostname (not a loopback LITERAL) is refused — DNS can point anywhere later.
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_MODEL", "qwen")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_ENDPOINT", "http://my-gpu-box.lan:8000/v1")
    env, refusal = actions_mod._strix_session_llm_env("self-hosted", "")
    assert env == {} and refusal and "off-host" in refusal.lower()


def test_resolver_refuses_an_indicated_pick_that_fails_to_resolve(monkeypatch):
    # ADVISORY-1 (no fail-open bias): a pick that is INDICATED (model_id non-empty) but cannot be resolved to a
    # confirmed cloud/local backend must REFUSE — it must NOT silently degrade to the global CLOUD default, which
    # would re-open the leak for a local-indicating pick.
    monkeypatch.setattr(actions_mod, "_resolve_launch_model",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    env, refusal = actions_mod._strix_session_llm_env("ollama", "")
    assert env == {} and refusal and "cloud" in refusal.lower()


def test_resolver_degrades_only_a_genuinely_empty_pick(monkeypatch):
    # the honest carve-out: a GENUINELY empty pick (no turn model, no session pin) still degrades to the global
    # default even if the resolver would fail — because no local pick was ever made.
    monkeypatch.setattr(actions_mod, "_resolve_launch_model",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert actions_mod._strix_session_llm_env("", "") == ({}, "")


# ══ the full launch_assessment codebase path (env reaches the child; refusals abort the launch) ══════════

@pytest.fixture()
def spawn(monkeypatch):
    """Stub Docker-ready + capture what _spawn_background is handed (or leave empty if never called)."""
    monkeypatch.setattr(actions_mod, "_docker_ready", lambda: (True, "ready"))
    cap: dict = {}
    monkeypatch.setattr(actions_mod, "_spawn_background",
                        lambda run_id, rd, cmd, meta, **kw: cap.update(
                            env_extra=kw.get("env_extra"), meta=meta, run_id=run_id))
    return cap


def _proj(tmp_path):
    src = tmp_path / "proj"
    src.mkdir()
    return str(src)


def test_launch_codebase_local_pick_pins_loopback_env_not_cloud(spawn, monkeypatch, tmp_path):
    # ACCEPTANCE (1) end-to-end: the assembled Strix env points at the loopback local endpoint, not cloud.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    assert r["status"] == "running" and r["mode"] == "codebase"
    env = spawn["env_extra"]
    assert env["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"
    assert env["LLM_API_BASE"] == "http://localhost:11434"
    assert "anthropic" not in env["STRIX_LLM"]           # the cloud default never reaches the child's STRIX_LLM
    assert env["VIGIL_PROOF_RUN_DIR"] and env["VIGIL_ENGAGEMENT"]   # existing wiring is untouched
    assert spawn["meta"]["model_backend"] == "local" and spawn["meta"]["strix_llm"] == "ollama/qwen2.5-coder:32b"


def test_launch_codebase_local_pick_no_model_refuses_no_spawn(spawn, monkeypatch, tmp_path):
    # ACCEPTANCE (2) end-to-end: a LOCAL pick that cannot run local REFUSES — nothing is spawned.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")   # no model configured
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    assert "error" in r and "cloud" in r["error"].lower()
    assert spawn == {}                                    # fail-closed: never spawned, never egressed to cloud


def test_launch_codebase_non_loopback_local_refuses(spawn, monkeypatch, tmp_path):
    # ACCEPTANCE (3) end-to-end: a non-loopback "local" endpoint aborts the launch.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://10.0.0.5:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    assert "error" in r and "off-host" in r["error"].lower()
    assert spawn == {}


def test_launch_codebase_cloud_default_unchanged_no_regression(spawn, tmp_path):
    # ACCEPTANCE (4) end-to-end: no per-session pick → no STRIX_LLM/LLM_API_BASE injected (global default flows),
    # and the meta carries no per-session model fields — byte-identical to before the fix.
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert r["status"] == "running"
    env = spawn["env_extra"]
    assert "STRIX_LLM" not in env and "LLM_API_BASE" not in env
    assert env["VIGIL_PROOF_RUN_DIR"] and env["VIGIL_ENGAGEMENT"]
    assert "model_backend" not in spawn["meta"] and "strix_llm" not in spawn["meta"]


def test_launch_codebase_cloud_pick_keeps_global_default(spawn, tmp_path):
    # a per-session CLOUD pick also keeps the global default (cloud is cloud by the operator's choice).
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path),
                                       "model": "claude-sonnet-5"})
    assert r["status"] == "running"
    assert "STRIX_LLM" not in spawn["env_extra"]


def test_launch_codebase_falls_back_to_session_pin(spawn, monkeypatch, tmp_path):
    # the LOCAL pin survives a launch that omits ``model`` — mirrors the URL branch's session-pin fallback.
    sessions_mod.set_session_model("strix-pin-sess", "ollama")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://127.0.0.1:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path),
                                       "session_id": "strix-pin-sess"})
    assert r["status"] == "running"
    assert spawn["env_extra"]["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"


# ══ RETRY / RESUME path (red-pen BLOCK-1) — a retried strix run must RE-APPLY the pin, never cloud ════════

def _finish(run_id):
    """Mark a run finished so retry_run will relaunch it (retry refuses a still-'running' run)."""
    m = actions_mod._read_run_meta(run_id)
    actions_mod._write_meta(run_id, **{**m, "status": "done"})


def test_retry_local_codebase_reapplies_local_pin_not_cloud(spawn, monkeypatch, tmp_path):
    # red-pen repro CLOSED: launch a LOCAL codebase run, finish it, RETRY it → the retried child env must carry
    # the LOCAL STRIX_LLM/LLM_API_BASE, NOT the global cloud default it would otherwise inherit.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    _finish(r["run_id"])
    spawn.clear()
    r2 = actions_mod.retry_run(r["run_id"])
    assert r2["ok"] is True
    env = spawn["env_extra"]
    assert env["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"           # the LOCAL pin was RE-APPLIED on retry
    assert env["LLM_API_BASE"] == "http://localhost:11434"
    assert "anthropic" not in env["STRIX_LLM"]                      # NOT the global cloud default
    assert env["VIGIL_PROOF_RUN_DIR"] and env["VIGIL_ENGAGEMENT"]   # proof env still re-pointed at the new run
    assert spawn["meta"]["model_backend"] == "local"


def test_retry_local_codebase_via_session_pin_reapplies_pin(spawn, monkeypatch, tmp_path):
    # a launch that used a SESSION PIN (no turn model) also re-pins on retry (the id is re-resolved via session).
    sessions_mod.set_session_model("retry-pin-sess", "self-hosted")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_MODEL", "qwen")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_ENDPOINT", "http://127.0.0.1:8000/v1")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path),
                                       "session_id": "retry-pin-sess"})
    _finish(r["run_id"])
    spawn.clear()
    r2 = actions_mod.retry_run(r["run_id"])
    assert r2["ok"] is True
    assert spawn["env_extra"]["STRIX_LLM"] == "openai/qwen"
    assert "anthropic" not in spawn["env_extra"]["STRIX_LLM"]


def test_retry_local_codebase_refuses_when_local_cannot_run_local(spawn, monkeypatch, tmp_path):
    # retry re-enforces loopback FRESH: if the local endpoint was moved REMOTE between the run and the retry,
    # the retry REFUSES (no re-spawn) — it does NOT fall back to the cloud default.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    _finish(r["run_id"])
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "https://ollama.evil-remote.example.com")   # moved off-host
    spawn.clear()
    r2 = actions_mod.retry_run(r["run_id"])
    assert r2["ok"] is False and "off-host" in r2["error"].lower()
    assert spawn == {}                                             # nothing re-spawned → no cloud egress


def test_retry_cloud_codebase_stays_global_default_no_regression(spawn, tmp_path):
    # a cloud/no-pick codebase run's retry env is byte-identical (Proof-Studio env only; no STRIX_LLM override).
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    _finish(r["run_id"])
    spawn.clear()
    r2 = actions_mod.retry_run(r["run_id"])
    assert r2["ok"] is True
    env = spawn["env_extra"]
    assert "STRIX_LLM" not in env and "LLM_API_BASE" not in env
    assert env["VIGIL_PROOF_RUN_DIR"] and env["VIGIL_ENGAGEMENT"]


# ══ W0-7 (Strix sovereignty gate) — the codebase agent is a MODEL EGRESS; a sovereign tier refuses the ═════
# ══ cloud default at construction, exactly like every OTHER egress site. Local stays permitted. ══════════

from framework.v2.kernel import sovereignty as _sov


@pytest.fixture()
def air_gapped(monkeypatch):
    """Force the AIR_GAPPED tier deterministically (env-derived; no leaked injected policy either side)."""
    _sov.set_policy(None)                                    # start from env-derived, not a stale injection
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
    yield
    _sov.set_policy(None)                                    # never leak a latched/injected policy to later tests


# -- the gate helper in isolation --------------------------------------------------------------------------

def test_gate_refuses_cloud_default_under_air_gap(air_gapped):
    # empty env → Strix's built-in CLOUD default → REFUSED under AIR_GAPPED.
    refusal = actions_mod._strix_sovereignty_refusal({})
    assert refusal and "AIR_GAPPED" in refusal

def test_gate_refuses_ambient_cloud_strix_llm_under_air_gap(air_gapped):
    # the ambient global STRIX_LLM (=CLOUD_DEFAULT from the fixture) is classified + refused under AIR_GAPPED.
    refusal = actions_mod._strix_sovereignty_refusal({})
    assert refusal and "cannot run under sovereignty tier 'AIR_GAPPED'" in refusal

def test_gate_permits_local_ollama_pin_under_air_gap(air_gapped):
    # a LOCAL loopback pin classifies `local` → permitted under EVERY tier (the local path is untouched).
    env = {"STRIX_LLM": "ollama/qwen2.5-coder:32b", "LLM_API_BASE": "http://localhost:11434"}
    assert actions_mod._strix_sovereignty_refusal(env) == ""

def test_gate_permits_local_self_hosted_loopback_pin_under_air_gap(air_gapped):
    env = {"STRIX_LLM": "openai/qwen", "LLM_API_BASE": "http://127.0.0.1:8000/v1"}
    assert actions_mod._strix_sovereignty_refusal(env) == ""

# -- RED-PEN MEDIUM (air-gap gap): a caller-injected ollama pointing at a REMOTE base must NOT be trusted --
# -- as `local` on the PROVIDER NAME alone — mirror the openai sibling's loopback check on the ollama path. --

def test_gate_remote_pointed_ollama_classifies_cloud_only():
    # the backend NAME for a remote-pointed ollama is the cloud-only sentinel (fail-closed) — NOT `ollama`/local.
    name = actions_mod._strix_sovereignty_backend(
        {"STRIX_LLM": "ollama/x", "LLM_API_BASE": "http://evil.example:11434"})
    assert _sov.classify(name) == "cloud_only"

def test_gate_refuses_remote_pointed_ollama_under_air_gap(air_gapped, monkeypatch):
    # REPRO: a no-pick run inherits the AMBIENT STRIX_LLM/LLM_API_BASE. A caller-injected ollama pointed at a
    # REMOTE host would egress the source under AIR_GAPPED if `local` were decided by the provider NAME alone.
    # The loopback check on the ollama path fail-closes it to cloud_only → REFUSED (like the openai sibling).
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    monkeypatch.setenv("LLM_API_BASE", "http://evil.example:11434")
    refusal = actions_mod._strix_sovereignty_refusal({})
    assert refusal and "AIR_GAPPED" in refusal

def test_gate_refuses_remote_ip_ollama_under_air_gap(air_gapped):
    # a non-loopback IP base is likewise refused (not just a hostname).
    refusal = actions_mod._strix_sovereignty_refusal(
        {"STRIX_LLM": "ollama/x", "LLM_API_BASE": "http://10.0.0.5:11434"})
    assert refusal and "AIR_GAPPED" in refusal

def test_gate_permits_bare_ollama_no_base_under_air_gap(air_gapped, monkeypatch):
    # PRESERVE the legitimate path: a bare ollama with NO base = the default localhost daemon → local → PERMITTED.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    assert actions_mod._strix_sovereignty_refusal({}) == ""

def test_gate_permits_loopback_base_ollama_under_air_gap(air_gapped):
    # a loopback-pinned ollama base still classifies local → PERMITTED (the per-session resolver's happy path).
    assert actions_mod._strix_sovereignty_refusal(
        {"STRIX_LLM": "ollama/x", "LLM_API_BASE": "http://127.0.0.1:11434"}) == ""

# -- RED-PEN MEDIUM (air-gap gap, part 2): the loopback gate must cover EVERY local-classified backend, not --
# -- just ollama/openai. `vllm` / `tgi` / `llama-cpp` / `self-hosted` / `dryrun` classify `local` by NAME via --
# -- the raw-name fall-through; before the SHARED gate they were trusted local with a REMOTE base and leaked --
# -- the source under AIR_GAPPED. Route every classify()=='local' name through the ONE loopback check. --------

# every provider prefix whose sovereignty backend name classifies `local` (the whole air-gap-sensitive set).
_LOCAL_PROVIDERS = ["ollama", "vllm", "tgi", "llama-cpp", "self-hosted", "dryrun"]

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_every_local_provider_is_local_classified(provider):
    # sanity/drift guard: each of these names really does classify `local` (so the gate below is the only thing
    # standing between a remote-pointed base and an AIR_GAPPED source leak).
    assert _sov.classify(provider) == "local"

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_gate_remote_base_refused_for_every_local_provider(air_gapped, provider):
    # THE FIX: a caller-injected local NAME pointed at a REMOTE base is fail-closed to the cloud sentinel →
    # classify() cloud_only → REFUSED at construction under AIR_GAPPED. (Before the shared gate, only ollama
    # was covered; vllm/tgi/llama-cpp/self-hosted/dryrun leaked because they classified `local` on the NAME.)
    env = {"STRIX_LLM": f"{provider}/x", "LLM_API_BASE": "http://evil.example:11434"}
    assert _sov.classify(actions_mod._strix_sovereignty_backend(env)) == "cloud_only"
    refusal = actions_mod._strix_sovereignty_refusal(env)
    assert refusal and "AIR_GAPPED" in refusal

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_gate_remote_ip_base_refused_for_every_local_provider(air_gapped, provider):
    # a non-loopback IP base (not just a hostname) is likewise refused for every local provider.
    env = {"STRIX_LLM": f"{provider}/x", "LLM_API_BASE": "http://10.0.0.5:11434"}
    assert actions_mod._strix_sovereignty_refusal(env) and "AIR_GAPPED" in actions_mod._strix_sovereignty_refusal(env)

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_gate_bare_base_runs_for_every_local_provider(air_gapped, monkeypatch, provider):
    # PRESERVE the legitimate path: a bare local pick with NO base = its default localhost daemon → local →
    # PERMITTED under AIR_GAPPED (must not over-block a legitimately-local backend).
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    assert actions_mod._strix_sovereignty_refusal({"STRIX_LLM": f"{provider}/x"}) == ""

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_gate_loopback_base_runs_for_every_local_provider(air_gapped, provider):
    # a loopback-pinned base still classifies local → PERMITTED for every local provider.
    env = {"STRIX_LLM": f"{provider}/x", "LLM_API_BASE": "http://127.0.0.1:11434"}
    assert actions_mod._strix_sovereignty_refusal(env) == ""

def test_gate_backend_classification_matches_settings_prefixes():
    # the LiteLLM prefix → sovereignty backend name mirror is correct (drift guard for the two differing spellings).
    assert actions_mod._strix_sovereignty_backend({"STRIX_LLM": "bedrock/anthropic.claude-opus-5"}) == "bedrock"
    assert actions_mod._strix_sovereignty_backend({"STRIX_LLM": "vertex_ai/claude-opus-5"}) == "vertex"
    assert actions_mod._strix_sovereignty_backend({"STRIX_LLM": "mistral/mistral-large-latest"}) == "mistral"
    assert actions_mod._strix_sovereignty_backend({"STRIX_LLM": "azure/dep"}) == "azure_openai"
    assert actions_mod._strix_sovereignty_backend({"STRIX_LLM": "anthropic/claude-opus-4-8"}) == "anthropic"
    # openai/ with a NON-loopback base is NOT trusted local → classify() fail-closes it to cloud_only.
    assert _sov.classify(
        actions_mod._strix_sovereignty_backend({"STRIX_LLM": "openai/x", "LLM_API_BASE": "https://api.openai.com/v1"})
    ) == "cloud_only"

def test_gate_permits_sovereign_cloud_bedrock_under_sovereign_cloud_tier(monkeypatch):
    # not a blanket block: a jurisdictional-cloud STRIX_LLM is PERMITTED at SOVEREIGN_CLOUD (tier semantics honoured).
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "SOVEREIGN_CLOUD")
    try:
        assert actions_mod._strix_sovereignty_refusal({"STRIX_LLM": "bedrock/anthropic.claude-opus-5"}) == ""
        # …but a direct consumer-Anthropic STRIX_LLM is still refused at SOVEREIGN_CLOUD.
        assert actions_mod._strix_sovereignty_refusal({"STRIX_LLM": "anthropic/claude-opus-4-8"})
    finally:
        _sov.set_policy(None)


# -- the full launch_assessment codebase path under AIR_GAPPED ---------------------------------------------

def test_launch_codebase_cloud_default_REFUSED_under_air_gap(spawn, air_gapped, tmp_path):
    # THE FIX: no per-session pick under AIR_GAPPED → the CLOUD default would ship the source to Anthropic →
    # the run is REFUSED at construction and NOTHING is spawned.
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert "error" in r and "AIR_GAPPED" in r["error"]
    assert spawn == {}                                      # never spawned → the source never left the host

def test_launch_codebase_cloud_pick_REFUSED_under_air_gap(spawn, air_gapped, tmp_path):
    # an explicit CLOUD per-session pick under AIR_GAPPED is likewise refused (cloud is refused by the tier).
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path),
                                       "model": "claude-sonnet-5"})
    assert "error" in r and "AIR_GAPPED" in r["error"]
    assert spawn == {}

def test_launch_codebase_local_pick_RUNS_under_air_gap(spawn, air_gapped, monkeypatch, tmp_path):
    # the LOCAL/Ollama path is UNTOUCHED: a loopback-pinned local pick runs normally under AIR_GAPPED.
    monkeypatch.setenv("CRUCIBLE_OLLAMA_MODEL", "qwen2.5-coder:32b")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://localhost:11434")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path), "model": "ollama"})
    assert r["status"] == "running"
    assert spawn["env_extra"]["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"

def test_launch_codebase_cloud_default_PERMITTED_under_permissive(spawn, monkeypatch, tmp_path):
    # NEGATIVE CONTROL: the SAME cloud-default run is NOT refused under PERMISSIVE — the gate is tier-specific,
    # not a blanket block (proves the refusal above is caused by the tier, not by an always-on guard).
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE")
    try:
        r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
        assert r["status"] == "running" and spawn.get("env_extra") is not None
    finally:
        _sov.set_policy(None)

def test_retry_codebase_cloud_default_REFUSED_under_air_gap(spawn, monkeypatch, tmp_path):
    # the retry path is gated too: a cloud-default codebase run finished under PERMISSIVE, then retried after the
    # tier is lowered to AIR_GAPPED, is REFUSED on retry (no re-spawn) rather than re-shipping the source.
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE")
    try:
        r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
        _finish(r["run_id"])
        spawn.clear()
        monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
        r2 = actions_mod.retry_run(r["run_id"])
        assert r2["ok"] is False and "AIR_GAPPED" in r2["error"]
        assert spawn == {}
    finally:
        _sov.set_policy(None)
