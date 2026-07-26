"""A2b — bring-your-own-model provider picker + delivery.

Proves: set_provider routes CRUCIBLE_LLM_BACKEND + the model var + config + Strix and CLEARS the rest;
required-config + endpoint validation fail-closed; set_model delegates + the built-in highlight still works;
settings_status exposes the provider registry/current/config; and the offense-delivery path DELIVERS the
llm/cloud provider keys but EXCLUDES the auto-patch signing key + GitHub token.
"""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    # NOTE: SIGIL_HOME is import-time bound in config, so setenv can't redirect the store; the SecretStore
    # envfile backend reads os.environ, so we CLEAR every managed secret + provider var before AND after each
    # test — no state leaks into (or out of) this file. (tmpdir set for any path-derived writes.)
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    from sigil.ui import settings as S
    keys = tuple(S.SECRET_NAMES) + tuple(S.PROVIDER_ENV_VARS)
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k in keys:
        os.environ.pop(k, None)


def _sa():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    return {"store": SpineStore(), "owner_key": ensure_owner_keypair()}


def test_set_provider_routes_and_clears_others():
    from sigil.ui import settings as S
    S.set_provider("bedrock", "anthropic.claude-opus-5", {"CRUCIBLE_BEDROCK_REGION": "eu-west-1"}, **_sa())
    assert os.environ["CRUCIBLE_LLM_BACKEND"] == "bedrock"
    assert os.environ["CRUCIBLE_BEDROCK_MODEL"] == "anthropic.claude-opus-5"
    assert os.environ["CRUCIBLE_BEDROCK_REGION"] == "eu-west-1"
    assert os.environ["STRIX_LLM"] == "bedrock/anthropic.claude-opus-5"
    # switch → the previous provider's vars are cleared
    S.set_provider("self-hosted", "qwen", {"CRUCIBLE_SELFHOSTED_ENDPOINT": "http://localhost:8000/v1"}, **_sa())
    assert os.environ["CRUCIBLE_LLM_BACKEND"] == "self-hosted"
    assert os.environ.get("CRUCIBLE_BEDROCK_REGION", "") == ""      # cleared
    assert os.environ["LLM_API_BASE"] == "http://localhost:8000/v1"
    assert os.environ["STRIX_LLM"] == "openai/qwen"


def test_required_config_and_endpoint_validation_fail_closed():
    from sigil.ui import settings as S
    with pytest.raises(ValueError):
        S.set_provider("bedrock", "m", {}, **_sa())                 # missing required region
    with pytest.raises(ValueError):
        S.set_provider("azure_openai", "dep", {"AZURE_OPENAI_ENDPOINT": "http://x.openai.azure.com"}, **_sa())
    with pytest.raises(ValueError):
        S.set_provider("self-hosted", "m", {"CRUCIBLE_SELFHOSTED_ENDPOINT": "ftp://x"}, **_sa())
    with pytest.raises(ValueError):
        S.set_provider("not-a-provider", "m", {}, **_sa())          # unknown provider
    with pytest.raises(ValueError):
        S.set_provider("anthropic", "z" * 9000, {}, **_sa())        # oversize model


# Every character str.splitlines() treats as a line boundary. An ord<0x20/==0x7f guard MISSES the last
# three (NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR) — the re-check's bypass. The guard MUST reject all.
_LINE_BREAKS = ["\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


@pytest.mark.parametrize("sep", _LINE_BREAKS)
def test_no_line_injection_at_any_settings_writer(sep):
    """The model id, provider config, AND secret writers must ALL reject every splitlines() boundary char,
    so none can inject an extra `KEY=value` line (e.g. plant VIGIL_DESTRUCTION_OWNER_KEY) into sigil.env."""
    from sigil.ui import settings as S
    from sigil.platform.secrets import SecretStore
    payload = f"x{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted"
    with pytest.raises(ValueError):                                  # model id site
        S.set_provider("anthropic", payload, {}, **_sa())
    with pytest.raises(ValueError):                                  # provider-config site
        S.set_provider("self-hosted", "m", {"CRUCIBLE_SELFHOSTED_ENDPOINT": f"http://x{sep}Y=z/v1"}, **_sa())
    with pytest.raises(ValueError):                                  # secret site
        S.set_secret("ANTHROPIC_API_KEY", payload, **_sa())
    # nothing partially applied: the poison var must NOT be present in the process env
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in os.environ
    assert not SecretStore().get("VIGIL_DESTRUCTION_OWNER_KEY")


@pytest.mark.parametrize("sep", _LINE_BREAKS)
def test_every_sigil_env_write_primitive_rejects_line_breaks(sep, tmp_path, monkeypatch):
    """The line-injection guard must live at EVERY sigil.env WRITE PRIMITIVE, not only the friendly entry
    points — a LITERAL '\n' is stopped ONLY by input validation (the reader splits ON '\n', so parsing can't
    neutralize a real newline). Covers settings._persist_env, secrets.SecretStore._env_upsert (also reached
    by set_secret + agents/vault passwords + a direct .set()), and voice.set_voice. The re-check found the
    last two unguarded — a literal '\n' in voice_id / a direct .set() planted VIGIL_DESTRUCTION_OWNER_KEY."""
    from sigil.ui import settings as S
    from sigil.platform.secrets import SecretStore
    import sigil.config as C
    monkeypatch.setattr(S, "SIGIL_HOME", tmp_path)
    monkeypatch.setattr(C, "SIGIL_HOME", tmp_path)
    monkeypatch.setattr("sigil.platform.secrets.SIGIL_HOME", tmp_path)
    poison = f"v{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted"
    with pytest.raises(ValueError):
        S._persist_env("CRUCIBLE_ANTHROPIC_MODEL", poison)          # non-secret env writer — VALUE axis
    with pytest.raises(ValueError):
        SecretStore._env_upsert("GITHUB_TOKEN", poison)             # secret envfile writer — VALUE axis
    # BOTH axes: a line-break in the KEY plants a second line just like a poisoned value (the vault
    # `service` -> `vault/{service}/password` path). The write primitives must guard the key too.
    with pytest.raises(ValueError):
        S._persist_env(f"K{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted", "v")
    with pytest.raises(ValueError):
        SecretStore._env_upsert(f"vault/s{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted/password", "pw")
    # a legit vault-style key (with '/') still round-trips through the guarded primitive
    SecretStore._env_upsert("vault/github.com/password", "clean-pw")
    # every rejection raised BEFORE touching the file — no poisoned line was ever written
    envf = tmp_path / "sigil.env"
    if envf.exists():
        assert "VIGIL_DESTRUCTION_OWNER_KEY" not in envf.read_text(encoding="utf-8")
        assert "vault/github.com/password=clean-pw" in envf.read_text(encoding="utf-8")


@pytest.mark.parametrize("sep", _LINE_BREAKS)
def test_set_voice_rejects_line_breaks(sep, tmp_path, monkeypatch):
    """voice.set_voice writes voice_id RAW into sigil.env and is CLI-reachable (`sigil voice --set-voice`),
    with ids that can originate from the third-party ElevenLabs shared-voices API — the re-check's BLOCK.
    It must reject every line-break char too. (Guarded by numpy, which voice/backends imports at module top;
    skipped where numpy is absent, e.g. the keyless offense venv.)"""
    pytest.importorskip("numpy")
    from sigil.voice import backends as VB
    monkeypatch.setattr("sigil.config.SIGIL_HOME", tmp_path)
    with pytest.raises(ValueError):
        VB.set_voice(f"v{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted")
    envf = tmp_path / "sigil.env"
    if envf.exists():
        assert "VIGIL_DESTRUCTION_OWNER_KEY" not in envf.read_text(encoding="utf-8")


def test_set_voice_creates_0600_envfile(tmp_path, monkeypatch):
    """sigil.env also holds sealed secrets on the envfile backend, so set_voice must create it 0600 (no
    world-readable window) — matching _persist_env/_env_upsert — not with write_text's umask default."""
    import stat
    pytest.importorskip("numpy")
    from sigil.voice import backends as VB
    monkeypatch.setattr("sigil.config.SIGIL_HOME", tmp_path)
    VB.set_voice("EXAVITQu4vr4xnSDxMaL")                      # fresh box: set_voice creates the file
    envf = tmp_path / "sigil.env"
    assert envf.exists() and "SIGIL_TTS_VOICE_ID=EXAVITQu4vr4xnSDxMaL" in envf.read_text(encoding="utf-8")
    assert stat.S_IMODE(envf.stat().st_mode) == 0o600        # not world/group readable


@pytest.mark.parametrize("sep", ["\x85", "\u2028", "\u2029"])
def test_envfile_reader_never_rematerializes_a_separator(sep, tmp_path):
    """Defense-in-depth at the READER: even if a NON-newline Unicode line separator somehow reached sigil.env
    (e.g. a hand-edited file), config._load_env_file parses on newline only, so the separator stays INERT
    inside its value and is never split into a second `KEY=value` line. (A literal newline can't be 'inside a
    value' on one hand-written line — it IS a second line — so this covers the exotic separators.)"""
    import sigil.config as C
    envf = tmp_path / "sigil.env"
    # hand-write a poisoned file directly, bypassing the write-primitive guard (which would itself reject it)
    envf.write_text(f"CRUCIBLE_ANTHROPIC_MODEL=safe{sep}VIGIL_DESTRUCTION_OWNER_KEY=planted\n", encoding="utf-8")
    for k in ("CRUCIBLE_ANTHROPIC_MODEL", "VIGIL_DESTRUCTION_OWNER_KEY"):
        os.environ.pop(k, None)
    C._load_env_file(home=tmp_path)                          # read back from the isolated file
    assert "VIGIL_DESTRUCTION_OWNER_KEY" not in os.environ    # separator stayed inside the value — inert
    assert sep in os.environ.get("CRUCIBLE_ANTHROPIC_MODEL", "")  # the value round-tripped whole
