"""VIGIL COMMAND P4 — the owner-signed Settings plane (API key + model).

The load-bearing invariants (a false-green here would leak a secret or make the picker a placebo):
  • a secret value NEVER appears in the action return, the redacted status, or the append-only spine —
    only a non-reversible fingerprint;
  • the picker is a REAL, bounded control — a closed model allowlist persisted to the canonical env vars
    both planes read, and the model catalog is SERVED (the UI hard-codes no model list);
  • fail-closed — an unknown secret name, an empty/oversized value, or an unknown model is refused.
"""
from __future__ import annotations

import json

import pytest

from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from sigil.ui import actions
from sigil.ui import settings as smod

SECRET = "sk-ant-TOPSECRET-do-not-leak-1234567890"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolate SIGIL_HOME + force the keyring OFF so secrets land in a temp envfile, never a real OS
    keyring; snapshot the env vars the code writes so they are restored after the test."""
    from sigil.platform import secrets as secmod
    monkeypatch.setattr(smod, "SIGIL_HOME", tmp_path)
    monkeypatch.setattr(secmod, "SIGIL_HOME", tmp_path)
    orig_init = secmod.SecretStore.__init__

    def _no_kr(self):
        orig_init(self)
        self._kr = None                     # no OS keyring in tests → the envfile tier under tmp_path

    monkeypatch.setattr(secmod.SecretStore, "__init__", _no_kr)
    for var in (*smod.MODEL_ENV_VARS, smod._CHOICE_ENV, *smod.SECRET_NAMES, "SIGIL_ANTHROPIC_API_KEY"):
        monkeypatch.setenv(var, "")         # monkeypatch restores the ORIGINAL after the test
        monkeypatch.delenv(var, raising=False)
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    owner = ensure_owner_keypair()
    return store, owner, tmp_path


# --- set_secret: fingerprint-only, no leak anywhere ---------------------------

def test_set_secret_returns_fingerprint_never_value(env):
    store, owner, _ = env
    out = smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    assert out["ok"] and out["name"] == "ANTHROPIC_API_KEY"
    assert out["fingerprint"].startswith("sha256:")
    assert SECRET not in json.dumps(out)            # the value never rides back to the caller/browser


def test_secret_value_never_on_the_spine(env):
    store, owner, _ = env
    out = smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    rec = store.get(out["recorded_seq"])
    assert rec is not None and rec.payload.get("fp") == out["fingerprint"]
    assert SECRET not in json.dumps(rec.payload)     # fingerprint-only event
    # and nowhere in the whole spine file
    assert SECRET not in (store.path.read_text(encoding="utf-8") if hasattr(store, "path") else "")


def test_status_is_redacted_and_reports_set(env):
    store, owner, _ = env
    smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    st = smod.settings_status()
    assert SECRET not in json.dumps(st)
    sec = [s for s in st["secrets"] if s["name"] == "ANTHROPIC_API_KEY"][0]
    assert sec["set"] is True and sec["fingerprint"].startswith("sha256:")
    assert st["keyless"] is False


def test_status_keyless_when_unset(env):
    st = smod.settings_status()
    assert st["keyless"] is True
    assert [s for s in st["secrets"] if s["name"] == "ANTHROPIC_API_KEY"][0]["set"] is False


def test_fingerprint_deterministic_and_non_reversible(env):
    a = smod._fingerprint(SECRET)
    b = smod._fingerprint(SECRET)
    assert a == b and SECRET not in a and len(a) < 40


def test_unknown_secret_name_refused(env):
    store, owner, _ = env
    with pytest.raises(ValueError):
        smod.set_secret("EVIL_ENV_VAR", "x", store=store, owner_key=owner)


def test_empty_and_oversized_secret_refused(env):
    store, owner, _ = env
    with pytest.raises(ValueError):
        smod.set_secret("ANTHROPIC_API_KEY", "   ", store=store, owner_key=owner)
    with pytest.raises(ValueError):
        smod.set_secret("ANTHROPIC_API_KEY", "x" * 9000, store=store, owner_key=owner)


def test_github_token_is_a_managed_secret(env):
    # LAP-2b: the auto-patch GitHub token is sealed + exported + redacted exactly like the LLM key.
    store, owner, _ = env
    assert "GITHUB_TOKEN" in smod.SECRET_NAMES and "GITHUB_TOKEN" in smod.SECRET_META
    out = smod.set_secret("GITHUB_TOKEN", "ghp_SECRET_TOKEN_xyz", store=store, owner_key=owner)
    assert out["ok"] and out["name"] == "GITHUB_TOKEN"
    assert "ghp_SECRET_TOKEN_xyz" not in json.dumps(out)          # value never returned
    st = smod.settings_status()
    gh = [s for s in st["secrets"] if s["name"] == "GITHUB_TOKEN"][0]
    assert gh["set"] is True and gh["fingerprint"].startswith("sha256:") and gh["label"] and gh["purpose"]
    assert "ghp_SECRET_TOKEN_xyz" not in json.dumps(st)           # never in the redacted status
    e = smod.export_runtime_env(include_secrets=True)
    assert e.get("GITHUB_TOKEN") == "ghp_SECRET_TOKEN_xyz"        # the launcher feeds it to the offense engine
    assert "GITHUB_TOKEN" not in smod.export_runtime_env(include_secrets=False)  # withheld without the flag


def test_control_chars_refused_no_envfile_injection(env):
    # a newline in the value must not smuggle a second env line into the envfile tier
    store, owner, tmp = env
    with pytest.raises(ValueError):
        smod.set_secret("ANTHROPIC_API_KEY", "sk-good\nEVIL_INJECTED=pwned", store=store, owner_key=owner)
    envfile = tmp / "sigil.env"
    assert not envfile.exists() or "EVIL_INJECTED" not in envfile.read_text(encoding="utf-8")


# --- set_model: real bounded control -----------------------------------------

def test_api_model_sets_model_ids_and_clears_backend(env):
    store, owner, tmp = env
    out = smod.set_model("claude-opus-5", store=store, owner_key=owner)
    assert out["ok"] and out["model"] == "claude-opus-5" and out["backend"] == "anthropic"
    import os
    # the MODEL ID goes into the anthropic + sovereign model vars (real: AnthropicBackend / scholar read them)
    assert os.environ.get("CRUCIBLE_ANTHROPIC_MODEL") == "claude-opus-5"
    assert os.environ.get("SIGIL_LLM_MODEL") == "claude-opus-5"
    # and NO forced backend (so offense availability picks the anthropic SDK when a key is present)
    assert not os.environ.get("CRUCIBLE_LLM_BACKEND")
    envfile = (tmp / "sigil.env").read_text(encoding="utf-8")
    assert "CRUCIBLE_ANTHROPIC_MODEL=claude-opus-5" in envfile
    assert "CRUCIBLE_LLM_BACKEND=" not in envfile        # cleared, not left as a stale/empty line
    st = smod.settings_status()
    assert st["selected_model"] == "claude-opus-5" and st["offense_model"] == "claude-opus-5"


def test_claude_code_routes_backend_never_a_model_id(env):
    # the P4 red-pen BLOCK: claude-code is a BACKEND, not a model id. It must set CRUCIBLE_LLM_BACKEND
    # and must NEVER be stuffed into a model-id var (which the anthropic SDK / `claude --model` would
    # reject → every reasoning call errors). This test fails if that regresses.
    import os
    store, owner, _ = env
    out = smod.set_model("claude-code", store=store, owner_key=owner)
    assert out["backend"] == "claude-code"
    assert os.environ.get("CRUCIBLE_LLM_BACKEND") == "claude-code"    # backend routed
    assert not os.environ.get("CRUCIBLE_ANTHROPIC_MODEL")             # model-id vars CLEARED, not "claude-code"
    assert not os.environ.get("SIGIL_LLM_MODEL")
    st = smod.settings_status()
    assert st["selected_model"] == "claude-code"                     # picker still reflects the choice
    assert st["offense_backend"] == "claude-code" and "claude-code" not in (st["sovereign_model"] or "")
    e = smod.export_runtime_env(include_secrets=False)
    assert e.get("CRUCIBLE_LLM_BACKEND") == "claude-code"
    assert "CRUCIBLE_ANTHROPIC_MODEL" not in e                       # a backend name never rides as a model id


def test_switching_off_claude_code_clears_the_forced_backend(env):
    import os
    store, owner, _ = env
    smod.set_model("claude-code", store=store, owner_key=owner)
    assert os.environ.get("CRUCIBLE_LLM_BACKEND") == "claude-code"
    smod.set_model("claude-sonnet-5", store=store, owner_key=owner)  # switch to an API model
    assert not os.environ.get("CRUCIBLE_LLM_BACKEND")                # no stale forced backend lingers
    assert os.environ.get("CRUCIBLE_ANTHROPIC_MODEL") == "claude-sonnet-5"


def test_unknown_model_refused(env):
    store, owner, _ = env
    with pytest.raises(ValueError):
        smod.set_model("gpt-4o", store=store, owner_key=owner)


def test_model_catalog_is_served_and_closed(env):
    st = smod.settings_status()
    ids = [m["id"] for m in st["models"]]
    assert ids and "claude-opus-5" in ids
    assert any(m["keyless"] for m in st["models"])      # the local Claude Code option needs no key
    # every served id is accepted by set_model; nothing outside the catalog is
    assert frozenset(ids) == smod._MODEL_IDS


# --- export_runtime_env: the cross-plane bridge data --------------------------

def test_export_runtime_env_model_only_without_secrets(env):
    store, owner, _ = env
    smod.set_model("claude-sonnet-5", store=store, owner_key=owner)
    smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    e = smod.export_runtime_env(include_secrets=False)
    assert e.get("CRUCIBLE_ANTHROPIC_MODEL") == "claude-sonnet-5"
    assert "ANTHROPIC_API_KEY" not in e                 # secret withheld unless explicitly requested


def test_export_runtime_env_includes_secret_when_asked(env):
    store, owner, _ = env
    smod.set_model("claude-sonnet-5", store=store, owner_key=owner)
    smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    e = smod.export_runtime_env(include_secrets=True)
    assert e.get("ANTHROPIC_API_KEY") == SECRET         # the launcher feeds this to the offense child env


# --- the owner-signed action broker routes both -------------------------------

def test_broker_routes_set_secret_and_set_model(env):
    store, _, _ = env
    assert "set_secret" in actions.ACTIONS and "set_model" in actions.ACTIONS
    r1 = actions.do_action("set_model", {"model": "claude-haiku-4-5-20251001"}, store=store)
    assert r1["ok"] and r1["model"] == "claude-haiku-4-5-20251001"
    r2 = actions.do_action("set_secret", {"name": "ANTHROPIC_API_KEY", "value": SECRET}, store=store)
    assert r2["ok"] and SECRET not in json.dumps(r2)
    # an unknown action is still refused by the broker (fail-closed)
    with pytest.raises(ValueError):
        actions.do_action("set_everything", {}, store=store)


# --- F1: the Neo4j knowledge-graph credential plane ---------------------------

def test_neo4j_password_is_a_managed_graph_secret_delivered_to_offense(env):
    # NEO4J_PASSWORD is a sealed graph-category secret. It IS delivered to the keyless offense engine (it
    # opens its own driver to project the per-session graph) — unlike the destruction key, which never is.
    assert "NEO4J_PASSWORD" in smod.SECRET_NAMES
    assert smod.SECRET_META["NEO4J_PASSWORD"]["category"] == "graph"
    assert "graph" in smod._SECRET_CATEGORY_ORDER and "graph" in smod._SECRET_CATEGORY_LABEL
    assert "NEO4J_PASSWORD" in smod._OFFENSE_DELIVERED_SECRETS
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in smod._OFFENSE_DELIVERED_SECRETS   # still excluded


def test_neo4j_uri_and_username_are_shown_config_not_secrets(env):
    # the URI + username are identifiers (shown config), only the password is sealed.
    assert {"NEO4J_URI", "NEO4J_USERNAME"} <= set(smod.CLOUD_CONFIG_VARS)
    assert "NEO4J_URI" not in smod.SECRET_NAMES and "NEO4J_USERNAME" not in smod.SECRET_NAMES


def test_neo4j_uri_scheme_is_validated(env):
    # only bolt/neo4j (+s/+ssc) schemes; an http/file/tcp URI is refused (defence-in-depth vs the probe).
    for good in ("bolt://h:7687", "neo4j://h", "neo4j+s://x.databases.neo4j.io", "bolt+ssc://h"):
        assert smod._validate_config_value("NEO4J_URI", good) == good
    for bad in ("http://evil", "file:///etc/passwd", "tcp://h", "javascript:1", "h:7687"):
        with pytest.raises(ValueError):
            smod._validate_config_value("NEO4J_URI", bad)
    # inline userinfo is refused — a password must never ride in the NON-secret URI (which is persisted
    # to the envfile + recorded on the spine); the sealed password field is the only place for it.
    for creds in ("neo4j://user:pass@host", "bolt+s://neo4j:secret@x.databases.neo4j.io"):
        with pytest.raises(ValueError):
            smod._validate_config_value("NEO4J_URI", creds)


def test_settings_status_exposes_the_graph_provider(env):
    st = smod.settings_status()
    graph = [p for p in st["cloud_providers"] if p["id"] == "graph"]
    assert len(graph) == 1
    g = graph[0]
    assert g["category"] == "graph" and g["probe_env"] == "NEO4J_PASSWORD"
    field_envs = [f["env"] for f in g["fields"]]
    assert field_envs == ["NEO4J_URI", "NEO4J_USERNAME", "NEO4J_PASSWORD"]
    # the password field is a SECRET (masked), the URI/username are CONFIG (shown)
    kinds = {f["env"]: f["kind"] for f in g["fields"]}
    assert kinds["NEO4J_PASSWORD"] == "secret" and kinds["NEO4J_URI"] == "config"
    # the "graph" secret category is advertised so the UI renders a section for it
    assert any(c["id"] == "graph" for c in st["secret_categories"])


def test_neo4j_password_sealed_and_never_leaked(env):
    store, owner, _ = env
    secret = "neo4j-TOPSECRET-pw-9999"
    out = smod.set_secret("NEO4J_PASSWORD", secret, store=store, owner_key=owner)
    assert out["ok"] and out["fingerprint"].startswith("sha256:")
    assert secret not in json.dumps(out)
    st = smod.settings_status()
    assert secret not in json.dumps(st)                 # never in the redacted view
    g = [p for p in st["cloud_providers"] if p["id"] == "graph"][0]
    pw = [f for f in g["fields"] if f["env"] == "NEO4J_PASSWORD"][0]
    assert pw["set"] is True and pw["probeable"] is True


def test_neo4j_probe_is_fail_closed(env):
    # the live probe never returns a false ok: no URI/username → unknown (honest), a bad scheme → fail,
    # and a well-formed config with the neo4j driver absent → unknown ("install the driver"), never ok.
    store, _, _ = env
    from sigil.platform import secret_probes as sp
    assert sp.has_probe("NEO4J_PASSWORD")
    assert sp._probe_neo4j("pw", store, {})[0] == "unknown"
    assert sp._probe_neo4j("pw", store, {"NEO4J_URI": "neo4j://h"})[0] == "unknown"   # no username
    assert sp._probe_neo4j("pw", store, {"NEO4J_URI": "http://x", "NEO4J_USERNAME": "neo4j"})[0] == "fail"
    ok_ctx = {"NEO4J_URI": "neo4j+s://x", "NEO4J_USERNAME": "neo4j"}
    status, reason = sp._probe_neo4j("pw", store, ok_ctx)
    assert status in ("ok", "unknown", "fail")          # never crashes
    if status == "unknown":
        assert "driver" in reason                       # honest "install the neo4j driver", not a false ok
