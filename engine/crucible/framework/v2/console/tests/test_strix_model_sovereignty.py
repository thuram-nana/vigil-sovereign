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

import threading

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
              "CRUCIBLE_SELFHOSTED_MODEL", "CRUCIBLE_SELFHOSTED_ENDPOINT",
              # the sibling api_base aliases Strix's AliasChoices ALSO honors — cleared so every test starts
              # from a known base state and an ambient one from the runner can't perturb the gate (RE-RED-PEN).
              "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.delenv("CRUCIBLE_SOVEREIGNTY_TIER", raising=False)
    # HERMETIC (RE-RE-RED-PEN, the NON-env JSON channel): point the Strix child's JSON config path at a
    # NON-EXISTENT temp file by default, so no test reads the operator's real ~/.strix/cli-config.json (a
    # persisted remote base there would otherwise perturb the gate). A test that exercises the JSON channel
    # overrides this seam explicitly via the `strix_json` helper below.
    monkeypatch.setattr(actions_mod, "_strix_config_json_path",
                        lambda: tmp_path / "no-such-strix-cli-config.json")
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


# ══ RE-RED-PEN HIGH — the sibling api_base ALIAS air-gap leak ═════════════════════════════════════════════
# Strix's LlmSettings.api_base honors AliasChoices(LLM_API_BASE, OPENAI_API_BASE, OPENAI_BASE_URL,
# LITELLM_BASE_URL, OLLAMA_API_BASE) — FIRST present wins. The gate resolved the base from LLM_API_BASE ALONE,
# so with LLM_API_BASE UNSET and a sibling alias pointed at a REMOTE host the gate saw NO base, trusted the
# local NAME, and PERMITTED — while the spawned child dialed the remote host and egressed the source under
# AIR_GAPPED. OPENAI_BASE_URL / OPENAI_API_BASE are common AMBIENT vars, so it fires as benign misconfig too.
# Two legs close it: (1) the gate resolves the base over the WHOLE alias set in the child's precedence; (2) the
# spawn path STRIPS the unvalidated siblings so only the loopback-validated LLM_API_BASE can point the child.

# the sibling aliases (LLM_API_BASE excluded — that one is the validated/canonical one).
_SIBLING_ALIASES = ["OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"]
REMOTE = "http://evil.example:11434"


# -- the alias-resolution helpers in isolation -------------------------------------------------------------

def test_api_base_aliases_matches_strix_settings():
    # DRIFT GUARD: our alias list equals Strix's own AliasChoices (sourced from settings.py, or the replica).
    assert actions_mod._strix_api_base_aliases() == [
        "LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"]


def test_resolved_base_follows_child_precedence(monkeypatch):
    # PRECEDENCE mirrors the child: OPENAI_BASE_URL precedes OLLAMA_API_BASE in the alias set → wins.
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", "http://a:11434")
    monkeypatch.setenv("OLLAMA_API_BASE", "http://b:11434")
    assert actions_mod._strix_resolved_base({}) == "http://a:11434"
    # a per-session pin's LLM_API_BASE is FIRST of all → wins over any ambient sibling (env_extra over env).
    assert actions_mod._strix_resolved_base({"LLM_API_BASE": "http://pin:11434"}) == "http://pin:11434"


def test_resolved_base_is_case_insensitive(monkeypatch):
    # Strix uses case_sensitive=False, so a lowercase alias is honored by the child — the gate matches it too.
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv("ollama_api_base", REMOTE)
    try:
        assert actions_mod._strix_resolved_base({}) == REMOTE
    finally:
        monkeypatch.delenv("ollama_api_base", raising=False)


# -- LEG 1: the gate resolves the base over the whole alias set --------------------------------------------

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
@pytest.mark.parametrize("alias", _SIBLING_ALIASES)
def test_gate_refuses_remote_sibling_alias_for_every_local_provider(air_gapped, monkeypatch, provider, alias):
    # THE FIX (leg 1): LLM_API_BASE UNSET + a SIBLING alias pointed REMOTE → the gate resolves the base from the
    # alias set (child precedence) → cloud_only → REFUSED under AIR_GAPPED. Before: base=LLM_API_BASE only →
    # empty → the local NAME was trusted → PERMITTED → the child egressed the source via the sibling alias.
    monkeypatch.setenv("STRIX_LLM", f"{provider}/qwen")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv(alias, REMOTE)
    assert _sov.classify(actions_mod._strix_sovereignty_backend({})) == "cloud_only"
    refusal = actions_mod._strix_sovereignty_refusal({})
    assert refusal and "AIR_GAPPED" in refusal


@pytest.mark.parametrize("alias", _SIBLING_ALIASES)
def test_gate_refuses_remote_sibling_alias_openai_prefix(air_gapped, monkeypatch, alias):
    # the openai (OpenAI-compatible self-hosted) prefix: a remote sibling base → NOT loopback → 'openai'
    # sentinel → cloud_only → REFUSED. Its default (no base) is api.openai.com — CLOUD — so it must fail closed.
    monkeypatch.setenv("STRIX_LLM", "openai/qwen")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv(alias, REMOTE)
    assert _sov.classify(actions_mod._strix_sovereignty_backend({})) == "cloud_only"
    assert actions_mod._strix_sovereignty_refusal({})


@pytest.mark.parametrize("alias", _SIBLING_ALIASES)
def test_gate_permits_loopback_sibling_alias(air_gapped, monkeypatch, alias):
    # PRESERVE the legit case: a LOOPBACK sibling alias (LLM_API_BASE still unset) is a real local endpoint →
    # classifies local → PERMITTED under AIR_GAPPED (must not over-block a legitimately-local backend).
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv(alias, "http://127.0.0.1:11434")
    assert actions_mod._strix_sovereignty_refusal({}) == ""


def test_gate_llm_api_base_loopback_wins_over_remote_sibling(air_gapped, monkeypatch):
    # PRECEDENCE (happy path): LLM_API_BASE is FIRST in the alias set → a loopback LLM_API_BASE wins even with a
    # remote sibling present → PERMITTED (matches the child, which also honors LLM_API_BASE first).
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")
    monkeypatch.setenv("OPENAI_API_BASE", REMOTE)               # lower precedence — ignored by child AND gate
    assert actions_mod._strix_sovereignty_refusal({}) == ""


def test_gate_remote_llm_api_base_refused_even_with_loopback_sibling(air_gapped, monkeypatch):
    # the inverse: a REMOTE LLM_API_BASE wins (first alias) even if a lower sibling is loopback → REFUSED.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("LLM_API_BASE", REMOTE)
    monkeypatch.setenv("OLLAMA_API_BASE", "http://127.0.0.1:11434")
    assert actions_mod._strix_sovereignty_refusal({}) and "AIR_GAPPED" in actions_mod._strix_sovereignty_refusal({})


# -- LEG 1 end-to-end: the launch/retry path does NOT spawn -----------------------------------------------

@pytest.mark.parametrize("alias", _SIBLING_ALIASES)
def test_launch_codebase_remote_sibling_alias_REFUSED_no_spawn(spawn, air_gapped, monkeypatch, alias, tmp_path):
    # END-TO-END (the CONFIRMED exploit): STRIX_LLM=ollama + LLM_API_BASE UNSET + <sibling>=REMOTE under
    # AIR_GAPPED. The launch is REFUSED and NOTHING spawns — before the fix it spawned and shipped the source.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv(alias, REMOTE)
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert "error" in r and "AIR_GAPPED" in r["error"]
    assert spawn == {}                                          # never spawned → the source never left the host


# -- LEG 2 (defense-in-depth): the child env the SPAWN receives carries no unvalidated remote alias --------

@pytest.fixture()
def real_spawn(monkeypatch):
    """Run the REAL _spawn_background but stub subprocess.Popen so nothing execs — capture the child ``env``
    the child would TRULY receive (os.environ merged with env_extra, THEN env_remove stripped)."""
    monkeypatch.setattr(actions_mod, "_docker_ready", lambda: (True, "ready"))
    envs: list = []
    ev = threading.Event()

    class _FakeProc:
        def __init__(self, *a, env=None, **kw):
            envs.append(env)
            self.pid = 4242
            self.returncode = 0
            ev.set()

        def communicate(self, timeout=None):
            return ("", "")

        def kill(self):  # pragma: no cover — timeout path not exercised
            pass

    monkeypatch.setattr(actions_mod.subprocess, "Popen", lambda *a, **kw: _FakeProc(*a, **kw))

    class _Handle:
        def wait(self, timeout=5):
            ok = ev.wait(timeout)
            ev.clear()
            return ok

        @property
        def last(self):
            return envs[-1] if envs else None

    return _Handle()


def test_child_env_strips_remote_sibling_leg2(real_spawn, air_gapped, monkeypatch, tmp_path):
    # LEG 2: a LOCAL run permitted via a loopback LLM_API_BASE (first alias), but with an ambient REMOTE sibling
    # of LOWER precedence. The child the SPAWN actually receives must carry NO remote sibling — so even if
    # Strix's alias precedence ever drifted, the child cannot be repointed off-host. LLM_API_BASE survives.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")   # first alias, loopback → PERMITTED
    monkeypatch.setenv("OLLAMA_API_BASE", REMOTE)                  # lower-precedence ambient remote sibling
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert r["status"] == "running"
    assert real_spawn.wait()
    env = real_spawn.last
    assert env is not None
    for a in _SIBLING_ALIASES:
        assert a not in env, f"{a} must be stripped from the child env"
    assert env["LLM_API_BASE"] == "http://127.0.0.1:11434"        # the validated loopback base survives
    assert env["STRIX_LLM"] == "ollama/qwen2.5-coder:32b"


def test_child_env_bare_daemon_strips_remote_sibling_leg2(real_spawn, air_gapped, monkeypatch, tmp_path):
    # LEG 2 with a BARE default-localhost daemon (no base at all set legitimately) but a stray ambient remote
    # sibling of a DIFFERENT spelling than what leg-1 resolved first: here LLM_API_BASE unset, and only
    # LITELLM_BASE_URL=loopback (permits), plus OLLAMA_API_BASE=REMOTE (lower precedence, stray). The child
    # must be stripped of every sibling; leg-1 canonicalizes the loopback base into LLM_API_BASE.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv("LITELLM_BASE_URL", "http://127.0.0.1:11434")   # first-present loopback → PERMITTED
    monkeypatch.setenv("OLLAMA_API_BASE", REMOTE)                      # lower precedence, stray remote
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert r["status"] == "running"
    assert real_spawn.wait()
    env = real_spawn.last
    for a in _SIBLING_ALIASES:
        assert a not in env, f"{a} must be stripped from the child env"
    assert env["LLM_API_BASE"] == "http://127.0.0.1:11434"            # canonicalized from the loopback alias


def test_child_env_byte_identical_under_permissive(real_spawn, monkeypatch, tmp_path):
    # PERMISSIVE: leg 2 is a NO-OP — the child env is byte-identical to today. A sibling alias (even a
    # non-default loopback the operator legitimately set) is NOT stripped or rewritten. Proves the strip is
    # tier-gated: the operator has allowed cloud egress, so nothing is enforced or perturbed.
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE")
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.delenv("LLM_API_BASE", raising=False)
    monkeypatch.setenv("OLLAMA_API_BASE", "http://127.0.0.1:9999")     # a non-default loopback the operator set
    try:
        r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
        assert r["status"] == "running"
        assert real_spawn.wait()
        env = real_spawn.last
        assert env["OLLAMA_API_BASE"] == "http://127.0.0.1:9999"       # preserved under PERMISSIVE — untouched
        assert "LLM_API_BASE" not in env                               # not injected either (byte-identical)
    finally:
        _sov.set_policy(None)


# -- the leg-2 guard helper in isolation -------------------------------------------------------------------

def test_child_alias_guard_local_under_air_gap(air_gapped, monkeypatch):
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")
    monkeypatch.setenv("OLLAMA_API_BASE", REMOTE)
    overrides, remove = actions_mod._strix_child_alias_guard({})
    assert overrides == {"LLM_API_BASE": "http://127.0.0.1:11434"}
    assert set(remove) == set(_SIBLING_ALIASES)


def test_child_alias_guard_noop_under_permissive(monkeypatch):
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE")
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("OLLAMA_API_BASE", REMOTE)
    try:
        assert actions_mod._strix_child_alias_guard({}) == ({}, [])
    finally:
        _sov.set_policy(None)


# ══ RE-RE-RED-PEN — the NON-env air-gap channel: the JSON config file + persist auto-write ════════════════
# Strix's config.loader.load_settings() resolves api_base with precedence env > ~/.strix/cli-config.json
# (_read_json_overrides) > field defaults, and persist_current() on every CLI startup AUTO-WRITES any set
# api_base env var back into that JSON file. So a JSON-planted (or prior-run-persisted) REMOTE base repoints
# the spawned child under AIR_GAPPED with a byte-CLEAN env — the env-only gate saw no base, trusted the local
# NAME, and permitted; the child then dialed the remote host and egressed the source. Two independent defenses
# close it: (POSITIVE CONTROL) the guard PINS LLM_API_BASE — highest precedence — to the loopback base (or the
# provider's local default when bare), so the JSON file / persist / defaults can no longer win; and
# (DEFENSE-IN-DEPTH) the refusal classifies the child's ACTUAL full resolution (env > JSON > defaults) and
# refuses a remote result pre-spawn. Every endpoint channel is now closed: env aliases, the JSON file, the
# persist auto-write, and the field defaults.

import json as _json

# the JSON file can carry ANY of Strix's api_base aliases (persist writes the FIRST-present one).
_JSON_ALIASES = ["LLM_API_BASE", "OPENAI_API_BASE", "OPENAI_BASE_URL", "LITELLM_BASE_URL", "OLLAMA_API_BASE"]


def _plant_strix_json(tmp_path, env_block, monkeypatch):
    """Write a Strix cli-config.json ({"env": {...}}) and point the gate's JSON seam at it — exactly the file
    _read_json_overrides reads and persist_current writes. Returns the path."""
    p = tmp_path / "planted-cli-config.json"
    p.write_text(_json.dumps({"env": env_block}), encoding="utf-8")
    monkeypatch.setattr(actions_mod, "_strix_config_json_path", lambda: p)
    return p


# -- the JSON-channel helpers in isolation -----------------------------------------------------------------

def test_json_config_base_reads_planted_file(tmp_path, monkeypatch):
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    assert actions_mod._strix_json_config_base() == REMOTE


def test_json_config_base_first_present_alias_wins(tmp_path, monkeypatch):
    # PRECEDENCE within the file mirrors the child: OPENAI_BASE_URL precedes OLLAMA_API_BASE in the alias set.
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": "http://a:11434", "OLLAMA_API_BASE": "http://b:11434"},
                      monkeypatch)
    assert actions_mod._strix_json_config_base() == "http://a:11434"


def test_json_config_base_absent_file_is_empty():
    # the autouse _isolate seam points at a non-existent path → no base from this channel.
    assert actions_mod._strix_json_config_base() == ""


def test_resolved_base_env_wins_over_json(tmp_path, monkeypatch):
    # env alias present → env value (the child skips the JSON file for a field whose env var is set).
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")
    assert actions_mod._strix_resolved_base({}, include_json=True) == "http://127.0.0.1:11434"


def test_resolved_base_falls_through_to_json_when_env_clean(tmp_path, monkeypatch):
    # no env alias + include_json → the child falls through to the JSON file (env > JSON > defaults).
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    assert actions_mod._strix_resolved_base({}, include_json=True) == REMOTE
    # env-only resolution (the guard's classification) deliberately IGNORES the JSON file so the pin wins.
    assert actions_mod._strix_resolved_base({}, include_json=False) == ""


# -- DEFENSE-IN-DEPTH: the refusal classifies the child's full env>JSON>defaults resolution -----------------

@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
@pytest.mark.parametrize("alias", _JSON_ALIASES)
def test_gate_refuses_json_planted_remote_for_every_local_provider(air_gapped, monkeypatch, tmp_path,
                                                                    provider, alias):
    # THE FIX: env byte-CLEAN, but the JSON file carries a REMOTE api_base under <alias> → the gate resolves
    # the base through env>JSON>defaults → cloud_only → REFUSED under AIR_GAPPED. Before: env-only base → ""
    # → the local NAME was trusted → PERMITTED → the child read the JSON remote and egressed the source.
    monkeypatch.setenv("STRIX_LLM", f"{provider}/qwen")
    _plant_strix_json(tmp_path, {alias: REMOTE}, monkeypatch)
    assert _sov.classify(actions_mod._strix_sovereignty_backend({})) == "cloud_only"
    refusal = actions_mod._strix_sovereignty_refusal({})
    assert refusal and "AIR_GAPPED" in refusal


@pytest.mark.parametrize("alias", _JSON_ALIASES)
def test_gate_refuses_json_planted_remote_openai_prefix(air_gapped, monkeypatch, tmp_path, alias):
    # openai (OpenAI-compatible self-hosted): a JSON-remote base → NOT loopback → 'openai' → cloud_only → REFUSED.
    monkeypatch.setenv("STRIX_LLM", "openai/qwen")
    _plant_strix_json(tmp_path, {alias: REMOTE}, monkeypatch)
    assert _sov.classify(actions_mod._strix_sovereignty_backend({})) == "cloud_only"
    assert actions_mod._strix_sovereignty_refusal({})


@pytest.mark.parametrize("alias", _JSON_ALIASES)
def test_gate_permits_json_planted_loopback(air_gapped, monkeypatch, tmp_path, alias):
    # PRESERVE the legit case: a LOOPBACK base in the JSON file is a real local endpoint → local → PERMITTED.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    _plant_strix_json(tmp_path, {alias: "http://127.0.0.1:11434"}, monkeypatch)
    assert actions_mod._strix_sovereignty_refusal({}) == ""


def test_gate_env_loopback_wins_over_json_remote(air_gapped, monkeypatch, tmp_path):
    # env LLM_API_BASE (loopback) is set → env wins over the JSON file (mirrors the child) → PERMITTED.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    assert actions_mod._strix_sovereignty_refusal({}) == ""


def test_gate_env_remote_refused_even_with_json_loopback(air_gapped, monkeypatch, tmp_path):
    # the inverse: env LLM_API_BASE remote wins over a JSON loopback → REFUSED (env is higher precedence).
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("LLM_API_BASE", REMOTE)
    _plant_strix_json(tmp_path, {"OLLAMA_API_BASE": "http://127.0.0.1:11434"}, monkeypatch)
    assert actions_mod._strix_sovereignty_refusal({}) and "AIR_GAPPED" in actions_mod._strix_sovereignty_refusal({})


def test_persist_auto_write_remote_is_refused(air_gapped, monkeypatch, tmp_path):
    # THE persist_current() CASE: a prior run had OPENAI_BASE_URL=REMOTE in env; Strix's startup persist_current
    # wrote {"env": {"OPENAI_BASE_URL": REMOTE}} into the cli-config.json. A LATER run with a byte-clean env
    # reads it back → REFUSED. (Same file shape _read_json_overrides consumes; covered by the JSON channel.)
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)   # what persist_current would have written
    assert _sov.classify(actions_mod._strix_sovereignty_backend({})) == "cloud_only"
    assert actions_mod._strix_sovereignty_refusal({}) and "AIR_GAPPED" in actions_mod._strix_sovereignty_refusal({})


# -- GROUNDING: the planted JSON really does repoint the REAL Strix child (env > JSON > defaults) -----------

def test_real_strix_child_dials_json_planted_remote(tmp_path, monkeypatch):
    # Prove the leak is REAL against Strix's own resolver, and that the env pin defeats it — not a mock of it.
    loader = pytest.importorskip("strix.config.loader")
    settings = pytest.importorskip("strix.config").load_settings
    for v in _JSON_ALIASES:
        monkeypatch.delenv(v, raising=False)
    cfg = tmp_path / "cli-config.json"
    cfg.write_text(_json.dumps({"env": {"OPENAI_BASE_URL": REMOTE}}), encoding="utf-8")
    saved_override, saved_cached = loader._override, loader._cached
    try:
        loader.apply_config_override(cfg)                       # point the real loader at the planted file
        assert settings().llm.api_base == REMOTE                # CLEAN env + JSON-planted remote → child dials REMOTE
        monkeypatch.setenv("LLM_API_BASE", "http://127.0.0.1:11434")
        loader._cached = None                                   # a fresh child re-resolves
        assert settings().llm.api_base == "http://127.0.0.1:11434"   # the env pin (highest precedence) DEFEATS the JSON
    finally:
        loader._override, loader._cached = saved_override, saved_cached


# -- POSITIVE CONTROL: the guard PINS LLM_API_BASE over the JSON channel (never leaves it unset) ------------

def test_child_alias_guard_pins_default_over_json_remote(air_gapped, monkeypatch, tmp_path):
    # env byte-CLEAN, JSON carries a REMOTE base. The guard's classification is JSON-BLIND (local by NAME), so
    # it PINS LLM_API_BASE to the provider's loopback default and STRIPS the siblings — env beats the JSON file.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    overrides, remove = actions_mod._strix_child_alias_guard({})
    assert overrides == {"LLM_API_BASE": "http://localhost:11434"}    # PINNED loopback default (not the JSON remote)
    assert REMOTE not in overrides.values()
    assert set(remove) == set(_SIBLING_ALIASES)


def test_child_alias_guard_bare_daemon_pins_default_not_unset(air_gapped, monkeypatch):
    # THE CORE POSITIVE-CONTROL CHANGE: a truly BARE local daemon (no base env, no JSON) must PIN LLM_API_BASE
    # to the loopback default — NEVER leave it unset (unset lets the JSON file / persist / defaults win).
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    overrides, remove = actions_mod._strix_child_alias_guard({})
    assert overrides.get("LLM_API_BASE") == "http://localhost:11434"
    assert "LLM_API_BASE" in overrides                               # explicitly SET, not absent
    assert set(remove) == set(_SIBLING_ALIASES)


def test_child_alias_guard_bare_daemon_respects_configured_loopback_host(air_gapped, monkeypatch):
    # the pin prefers the console's configured loopback endpoint (CRUCIBLE_OLLAMA_HOST) when it is loopback.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://127.0.0.1:9999")
    overrides, _ = actions_mod._strix_child_alias_guard({})
    assert overrides == {"LLM_API_BASE": "http://127.0.0.1:9999"}


@pytest.mark.parametrize("provider", _LOCAL_PROVIDERS)
def test_child_alias_guard_pins_loopback_for_every_local_provider(air_gapped, monkeypatch, provider):
    # every local-classified provider gets a LOOPBACK pin (never unset) so no non-env channel can repoint it.
    from framework.v2.console import chat as chat_mod
    monkeypatch.setenv("STRIX_LLM", f"{provider}/qwen")
    overrides, remove = actions_mod._strix_child_alias_guard({})
    base = overrides.get("LLM_API_BASE", "")
    ok, _host = chat_mod._url_host_is_local(base)
    assert base and ok, f"{provider}: LLM_API_BASE must be pinned to a loopback base, got {base!r}"
    assert set(remove) == set(_SIBLING_ALIASES)


# -- END-TO-END: a JSON-planted remote REFUSES the launch (no spawn); a bare daemon runs with the pin -------

@pytest.mark.parametrize("alias", _JSON_ALIASES)
def test_launch_codebase_json_planted_remote_REFUSED_no_spawn(spawn, air_gapped, monkeypatch, tmp_path, alias):
    # END-TO-END (the CONFIRMED exploit via the NON-env channel): env byte-CLEAN, JSON carries a remote base.
    # The launch is REFUSED and NOTHING spawns — before the fix it spawned and the child dialed the JSON remote.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    _plant_strix_json(tmp_path, {alias: REMOTE}, monkeypatch)
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert "error" in r and "AIR_GAPPED" in r["error"]
    assert spawn == {}                                             # never spawned → the source never left the host


def test_retry_codebase_json_planted_remote_REFUSED(spawn, monkeypatch, tmp_path):
    # a run launched under PERMISSIVE, retried after the tier is lowered to AIR_GAPPED with a JSON-planted
    # remote, is REFUSED on retry (no re-spawn) rather than re-shipping the source via the JSON channel.
    _sov.set_policy(None)
    try:
        r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
        _finish(r["run_id"])
        spawn.clear()
        monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "AIR_GAPPED")
        monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
        _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
        r2 = actions_mod.retry_run(r["run_id"])
        assert r2["ok"] is False and "AIR_GAPPED" in r2["error"]
        assert spawn == {}
    finally:
        _sov.set_policy(None)


def test_child_env_bare_daemon_pins_default_endpoint(real_spawn, air_gapped, monkeypatch, tmp_path):
    # LOOPBACK/BARE STILL RUNS: env byte-CLEAN, no JSON → the child the SPAWN receives has LLM_API_BASE PINNED
    # to the loopback default (never unset), no remote sibling present, and the run proceeds normally.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen2.5-coder:32b")
    r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
    assert r["status"] == "running"
    assert real_spawn.wait()
    env = real_spawn.last
    assert env["LLM_API_BASE"] == "http://localhost:11434"           # PINNED default (positive control)
    for a in _SIBLING_ALIASES:
        assert a not in env
    assert REMOTE not in env.values()


def test_child_env_json_remote_pin_beats_the_file(real_spawn, air_gapped, monkeypatch, tmp_path):
    # POSITIVE CONTROL end-to-end via the guard directly (the refusal is the primary defense end-to-end, but
    # this proves the SECOND, independent defense): even with the JSON file carrying a remote base, the child
    # env the guard builds pins LLM_API_BASE to loopback with no remote value present.
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    overrides, remove = actions_mod._strix_child_alias_guard({})
    child = {**{k: v for k, v in __import__("os").environ.items()}, **overrides}
    for k in list(child):
        if k.upper() in {a.upper() for a in remove}:
            child.pop(k, None)
    assert child["LLM_API_BASE"] == "http://localhost:11434"
    assert REMOTE not in child.values()


# -- PERMISSIVE stays byte-identical (the operator allowed cloud there) -------------------------------------

def test_json_remote_permissive_permits_and_byte_identical(real_spawn, monkeypatch, tmp_path):
    # PERMISSIVE: the JSON channel is the operator's OWN config and cloud is allowed — the refusal does NOT
    # fire and the guard is a NO-OP: no LLM_API_BASE injected, no sibling stripped, the child env is byte-identical.
    _sov.set_policy(None)
    monkeypatch.setenv("CRUCIBLE_SOVEREIGNTY_TIER", "PERMISSIVE")
    monkeypatch.setenv("STRIX_LLM", "ollama/qwen")
    _plant_strix_json(tmp_path, {"OPENAI_BASE_URL": REMOTE}, monkeypatch)
    try:
        assert actions_mod._strix_sovereignty_refusal({}) == ""
        assert actions_mod._strix_child_alias_guard({}) == ({}, [])
        r = actions_mod.launch_assessment({"mode": "codebase", "target": _proj(tmp_path)})
        assert r["status"] == "running"
        assert real_spawn.wait()
        env = real_spawn.last
        assert "LLM_API_BASE" not in env                            # not injected (byte-identical)
    finally:
        _sov.set_policy(None)
