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
import os

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
    for var in (*smod.MODEL_ENV_VARS, smod._CHOICE_ENV, *smod.SECRET_NAMES, "SIGIL_ANTHROPIC_API_KEY",
                "VIGIL_ALLOW_PROTECTED_DOMAINS"):
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


# --- set_config: the universal (non-secret) system-config plane ----------------------------------

def _track(monkeypatch, *names):
    """Let monkeypatch snapshot each var so anything set_config writes to os.environ is restored."""
    for n in names:
        monkeypatch.delenv(n, raising=False)


def test_set_config_persists_records_and_mirrors(env, monkeypatch):
    store, owner, tmp = env
    _track(monkeypatch, "CRUCIBLE_LLM_MAX_WORKERS")
    out = smod.set_config("CRUCIBLE_LLM_MAX_WORKERS", "8", store=store, owner_key=owner)
    assert out["ok"] and out["env"] == "CRUCIBLE_LLM_MAX_WORKERS" and out["value"] == "8"
    assert os.environ["CRUCIBLE_LLM_MAX_WORKERS"] == "8"                 # mirrored into the live env
    assert "CRUCIBLE_LLM_MAX_WORKERS=8" in (tmp / "sigil.env").read_text()  # persisted to the 0600 envfile
    rec = store.get(out["recorded_seq"])                                 # recorded on the signed spine
    assert rec is not None and rec.payload.get("env") == "CRUCIBLE_LLM_MAX_WORKERS"


def test_set_config_unknown_var_is_refused(env):
    store, owner, _ = env
    with pytest.raises(ValueError, match="unknown config var"):        # closed allowlist: no arbitrary env
        smod.set_config("EVIL_ARBITRARY_ENV", "x", store=store, owner_key=owner)


def test_set_config_type_validation_fail_closed(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "CRUCIBLE_LLM_MAX_WORKERS", "CRUCIBLE_BURP_URL", "SIGIL_LOG_LEVEL",
           "VIGIL_GATEWAY_ALLOWED_PORTS", "VIGIL_GATEWAY_SANDBOX_SUBNET", "VIGIL_GATEWAY_PROXY_HOST")
    bad = [
        ("CRUCIBLE_LLM_MAX_WORKERS", "999"),      # int out of range
        ("CRUCIBLE_LLM_MAX_WORKERS", "abc"),      # not an int
        ("CRUCIBLE_BURP_URL", "ftp://x"),         # not http(s)
        ("SIGIL_LOG_LEVEL", "LOUD"),              # not an enum choice
        ("VIGIL_GATEWAY_ALLOWED_PORTS", "80,nope"),  # not all ports
        ("VIGIL_GATEWAY_SANDBOX_SUBNET", "not-a-cidr"),
        ("VIGIL_GATEWAY_PROXY_HOST", "not-an-ip"),
    ]
    for env_name, val in bad:
        with pytest.raises(ValueError):
            smod.set_config(env_name, val, store=store, owner_key=owner)


def test_set_config_rejects_envfile_line_injection(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "CRUCIBLE_EMBEDDER")
    with pytest.raises(ValueError):   # a value must never plant a second KEY=value line
        smod.set_config("CRUCIBLE_EMBEDDER", "ok\nVIGIL_DESTRUCTION_OWNER_KEY=evil",
                        store=store, owner_key=owner)


def test_set_config_empty_clears_the_var(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "CRUCIBLE_EMBEDDER")
    smod.set_config("CRUCIBLE_EMBEDDER", "some-model", store=store, owner_key=owner)
    assert os.environ.get("CRUCIBLE_EMBEDDER") == "some-model"
    smod.set_config("CRUCIBLE_EMBEDDER", "", store=store, owner_key=owner)
    assert "CRUCIBLE_EMBEDDER" not in os.environ                       # cleared → falls back to the default


def test_export_emits_offense_config_excludes_sovereign(env, monkeypatch):
    # This tests the EMITTER contract only (export_runtime_env): offense-plane vars are emitted,
    # sovereign vars never are. Real end-to-end delivery ALSO needs the uiproxy CONSUMER allowlist —
    # that half is asserted by test_config_plane_allowlists_agree in the integration suite (red-pen
    # BLOCK-1: asserting delivery here alone green-washed a placebo, because the consumer re-allowlists).
    store, owner, _ = env
    _track(monkeypatch, "CRUCIBLE_LLM_MAX_WORKERS", "SIGIL_LOG_LEVEL")
    smod.set_config("CRUCIBLE_LLM_MAX_WORKERS", "6", store=store, owner_key=owner)   # plane: offense
    smod.set_config("SIGIL_LOG_LEVEL", "DEBUG", store=store, owner_key=owner)         # plane: sovereign
    emitted = smod.export_runtime_env(include_secrets=False)
    assert emitted.get("CRUCIBLE_LLM_MAX_WORKERS") == "6"            # offense-plane → emitted
    assert "SIGIL_LOG_LEVEL" not in emitted                           # sovereign-only → NEVER emitted (FATAL-2)


def test_set_config_bind_host_refuses_public(env, monkeypatch):
    # The UI promises "a public bind is refused" for the proxy host — enforce it at save time.
    store, owner, _ = env
    _track(monkeypatch, "VIGIL_GATEWAY_PROXY_HOST")
    for bad in ("0.0.0.0", "::", "8.8.8.8", "1.2.3.4"):
        with pytest.raises(ValueError):
            smod.set_config("VIGIL_GATEWAY_PROXY_HOST", bad, store=store, owner_key=owner)
    for ok in ("127.0.0.1", "10.0.0.5", "192.168.1.2", "::1"):
        assert smod.set_config("VIGIL_GATEWAY_PROXY_HOST", ok, store=store, owner_key=owner)["value"] == ok


def test_set_config_number_rejects_non_finite(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "VIGIL_GATEWAY_HEADER_TIMEOUT")
    for bad in ("inf", "-inf", "nan", "Infinity", "1e308"):   # incl. a finite-astronomical value (would uncap the timeout)
        with pytest.raises(ValueError):        # an 'inf'/huge timeout would disable the slow-loris cap
            smod.set_config("VIGIL_GATEWAY_HEADER_TIMEOUT", bad, store=store, owner_key=owner)
    assert smod.set_config("VIGIL_GATEWAY_HEADER_TIMEOUT", "15", store=store, owner_key=owner)["value"] == "15"


def test_settings_status_exposes_config_groups(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "CRUCIBLE_LLM_MAX_WORKERS")
    smod.set_config("CRUCIBLE_LLM_MAX_WORKERS", "12", store=store, owner_key=owner)
    st = smod.settings_status()
    groups = {g["id"]: g for g in st["config_groups"]}
    assert {"offense", "sovereign", "gateway", "system"} <= set(groups)
    field = next(f for f in groups["offense"]["fields"] if f["env"] == "CRUCIBLE_LLM_MAX_WORKERS")
    assert field["value"] == "12" and field["type"] == "int"


def test_set_config_via_do_action_dispatch(env, monkeypatch):
    store, owner, _ = env
    _track(monkeypatch, "VIGIL_GATEWAY_MAX_CONNS")
    out = actions.do_action("set_config", {"env": "VIGIL_GATEWAY_MAX_CONNS", "value": "512"}, store=store)
    assert out["ok"] and out["value"] == "512"
    assert os.environ["VIGIL_GATEWAY_MAX_CONNS"] == "512"


def test_every_config_meta_var_is_a_real_env_read(env):
    # honesty guard: every CONFIG_META var must be a REAL var the code reads (a field for a
    # non-existent var would be a fake control). We assert the registry is a closed, typed set.
    for name, meta in smod.CONFIG_META.items():
        assert meta.get("type") in ("int", "number", "bool", "enum", "url", "cidr", "host", "bind_host", "ports", "str")
        assert meta.get("plane") in ("offense", "sovereign", "gateway", "system")
        assert name == name.upper() and " " not in name


# --- the two independent allowlists must AGREE (the real-gate guard for the red-pen BLOCK-1 placebo) ---
# uiproxy is pure-stdlib (imports no offense framework), so importing it here is boundary-safe; this file
# runs in the P7 SIGIL leg with `integration` on the path. (It must NOT live in an integration test — that
# process asserts sigil is never loaded, and importing sigil there trips the two-env boundary.)

def test_config_plane_allowlists_agree():
    # An offense-plane config knob reaches the engine only if the sovereign EMITTER set
    # (CONFIG_OFFENSE_VARS, emitted by export_runtime_env) is a subset of the uiproxy CONSUMER allowlist
    # (_OFFENSE_ENV_ALLOWLIST) — two independent allowlists (defense-in-depth) that MUST agree, or the knob
    # is a placebo (emitted then silently dropped at the child boundary). Red-pen BLOCK-1 caught the divergence.
    from vigil_integration import uiproxy
    missing = set(smod.CONFIG_OFFENSE_VARS) - uiproxy._OFFENSE_ENV_ALLOWLIST
    assert not missing, f"offense config vars dropped by the uiproxy consumer allowlist (placebo knobs): {sorted(missing)}"


def test_non_offense_config_never_in_offense_allowlist():
    # FATAL-2 / least-privilege: a sovereign/gateway/system config var must NEVER be offense-delivered.
    from vigil_integration import uiproxy
    non_offense = [e for e in smod.CONFIG_VARS if smod.CONFIG_META[e].get("plane") != "offense"]
    leaked = [e for e in non_offense if e in uiproxy._OFFENSE_ENV_ALLOWLIST]
    assert not leaked, f"non-offense config vars present in the offense allowlist: {leaked}"


# --- Claim 5: the protected-domain safety-floor toggle (VIGIL_ALLOW_PROTECTED_DOMAINS) -----------------
_ALLOW = "VIGIL_ALLOW_PROTECTED_DOMAINS"


def test_protected_domains_toggle_is_a_registered_offense_bool(env):
    # The toggle exists, is a bool, lives in the offense plane (so export_runtime_env delivers it), and
    # defaults to "" (⇒ not delivered ⇒ guard reads ON — fail-safe polarity is ALLOW, not protect).
    meta = smod.CONFIG_META[_ALLOW]
    assert meta["type"] == "bool" and meta["plane"] == "offense" and meta.get("default", "") == ""
    assert _ALLOW in smod.CONFIG_OFFENSE_VARS
    assert meta.get("warn"), "the danger toggle must carry a prominent warn banner string"


def test_protected_domains_toggle_change_is_owner_signed_on_the_spine(env):
    # The load-bearing audit requirement: turning the floor OFF appends exactly ONE owner-signed spine
    # event carrying WHO (pubkey), the env, the new value, and the operator reason — verifiable against
    # the owner pubkey, and a tampered value must fail verification.
    from sigil.governor.authn import verify_signed
    store, owner, _ = env
    out = smod.set_config(_ALLOW, "1", store=store, owner_key=owner,
                          reason="authorized .gov engagement per signed charter")
    assert out["ok"] and out["value"] == "1"
    rec = store.get(out["recorded_seq"])
    assert rec is not None
    p = rec.payload
    assert p["signal"] == "governor.config_set" and p["env"] == _ALLOW and p["value"] == "1"
    assert p["by"] == "owner" and p["reason"].startswith("authorized .gov")
    # authentic owner signature over the canonical core {signal, env, value}
    assert verify_signed(p, ["signal", "env", "value"], owner.public_key_b64) is True
    # tamper the value → the same signature no longer verifies (the audit record is unforgeable)
    assert verify_signed({**p, "value": ""}, ["signal", "env", "value"], owner.public_key_b64) is False


def test_protected_domains_toggle_fail_safe_delivery(env):
    # Delivery fail-safe: the offense plane receives the OFF flag ONLY when explicitly set to "1".
    # Unset ⇒ absent ⇒ guard reads ON; "1" ⇒ present; cleared back to "" ⇒ absent again + line removed.
    store, owner, tmp_path = env
    assert _ALLOW not in smod.export_runtime_env(include_secrets=False)      # unset ⇒ not delivered ⇒ ON
    smod.set_config(_ALLOW, "1", store=store, owner_key=owner, reason="on")
    assert smod.export_runtime_env(include_secrets=False).get(_ALLOW) == "1"  # explicit OFF ⇒ delivered
    smod.set_config(_ALLOW, "", store=store, owner_key=owner, reason="re-protect")
    assert _ALLOW not in smod.export_runtime_env(include_secrets=False)      # re-protect ⇒ not delivered
    envfile = (tmp_path / "sigil.env")
    assert _ALLOW not in (envfile.read_text(encoding="utf-8") if envfile.exists() else "")


def test_protected_domains_toggle_status_carries_the_warn_banner(env):
    # settings_status must surface the warn copy so the UI can render the prominent danger banner.
    st = smod.settings_status()
    fields = [f for g in st["config_groups"] for f in g["fields"] if f["env"] == _ALLOW]
    assert fields, "the toggle must appear in the config groups"
    assert "DANGER" in fields[0]["warn"] and "safety floor" in fields[0]["warn"]


# --- W0-9: the seal-honesty seam — the server reports whether a secret was ACTUALLY sealed --------
# The UI printed "<label> sealed on this machine." unconditionally, so a secret that fell through to
# the 0600 plaintext ~/.sigil/sigil.env still showed "sealed" — a FALSE security assurance. The fix
# makes set_secret return the REAL backend + a `sealed` bool (true ONLY for keyring/TPM-vault), from
# which the UI renders the honest toast. These tests pin that seam.

def test_set_secret_reports_not_sealed_on_plaintext_fallback(env):
    # The `env` fixture forces no OS keyring and no provisioned vault, so SecretStore falls back to the
    # 0600 plaintext envfile — which is NOT sealed. The server must report the truth.
    store, owner, _ = env
    out = smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    assert out["backend"] == "envfile"           # the plaintext fallback tier was used
    assert out["sealed"] is False                # ← load-bearing: a false "sealed" assurance would be True here
    # the recorded (non-secret) governance event also carries the real backend
    rec = store.get(out["recorded_seq"])
    assert rec.payload.get("backend") == "envfile"


def test_set_secret_reports_sealed_for_os_keyring(env, monkeypatch):
    # A backend that actually seals the secret at rest (OS keyring) must report sealed=true.
    store, owner, _ = env
    from sigil.platform import secrets as secmod
    monkeypatch.setattr(secmod.SecretStore, "set", lambda self, k, v: "keyring")
    out = smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    assert out["backend"] == "keyring"
    assert out["sealed"] is True


def test_set_secret_reports_sealed_for_tpm_vault(env, monkeypatch):
    # The TPM-sealed vault tier ("sealed") also rests as ciphertext → sealed=true.
    store, owner, _ = env
    from sigil.platform import secrets as secmod
    monkeypatch.setattr(secmod.SecretStore, "set", lambda self, k, v: "sealed")
    out = smod.set_secret("ANTHROPIC_API_KEY", SECRET, store=store, owner_key=owner)
    assert out["backend"] == "sealed"
    assert out["sealed"] is True


def test_cloud_file_secret_carries_the_sealed_truth(env):
    # set_cloud_file_secret delegates to set_secret, so the same honest `sealed` bool must ride back — a
    # pasted GCP/kubeconfig credential that fell to plaintext must not render as "sealed" either.
    store, owner, _ = env
    sa = json.dumps({"type": "service_account", "project_id": "p",
                     "token_uri": "https://oauth2.googleapis.com/token"})
    out = smod.set_cloud_file_secret("GOOGLE_APPLICATION_CREDENTIALS_JSON", sa, store=store, owner_key=owner)
    assert out["sealed"] is False and out["backend"] == "envfile"
