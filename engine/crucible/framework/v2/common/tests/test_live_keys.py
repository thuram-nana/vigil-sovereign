"""Hot-reload of the Anthropic key: the RUNNING offense engine re-reads a key re-sealed through the UI
(settings.set_secret -> ~/.sigil/sigil.env) with NO Stop->Start. These pin the shared reader + the in-place
env refresh + the one caching consumer (the kernel Anthropic backend rebuilds its client on a key change)."""

from __future__ import annotations

import os

import pytest

from framework.v2.common.live_keys import read_persisted_anthropic_key, refresh_live_anthropic_key


@pytest.fixture
def sigil_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    return tmp_path / "sigil.env"


def test_read_persisted_key_precedence_and_missing(sigil_env):
    assert read_persisted_anthropic_key() is None                       # no file -> None (never raises)
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-a\n", encoding="utf-8")
    assert read_persisted_anthropic_key() == "sk-a"
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-a\nSIGIL_ANTHROPIC_API_KEY=sk-sigil\n", encoding="utf-8")
    assert read_persisted_anthropic_key() == "sk-sigil"                 # SIGIL_ wins (mirrors sigil.config)
    sigil_env.write_text("# no key here\nOTHER=x\n", encoding="utf-8")
    assert read_persisted_anthropic_key() is None


def test_refresh_is_flag_gated_and_reports_change(sigil_env, monkeypatch):
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-fresh\n", encoding="utf-8")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-frozen")
    monkeypatch.delenv("VIGIL_LIVE_KEY_RELOAD", raising=False)
    assert refresh_live_anthropic_key() is False                        # flag off -> no-op
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-frozen"
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    assert refresh_live_anthropic_key() is True                         # UI-sealed key picked up (changed)
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-fresh"
    assert refresh_live_anthropic_key() is False                        # unchanged on the next call
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-fresh-2\n", encoding="utf-8")
    assert refresh_live_anthropic_key() is True                         # a later re-seal -> changed
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-fresh-2"


def test_refresh_is_a_noop_when_nothing_is_persisted(sigil_env, monkeypatch):
    # A shell-only operator (key in the env, none in sigil.env) is unaffected: the frozen env is kept.
    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-only")
    sigil_env.write_text("# nothing\n", encoding="utf-8")
    assert refresh_live_anthropic_key() is False
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-env-only"


def test_kernel_anthropic_backend_rebuilds_client_on_key_change(sigil_env, monkeypatch):
    """The ONE caching consumer: AnthropicBackend builds anthropic.Anthropic() (which reads the env) once and
    caches it. On a UI re-seal the backend must refresh the env AND invalidate the cached client so the next
    call rebuilds with the fresh key — proving the hot-reload reaches the kernel/brain path too."""
    anthropic = pytest.importorskip("anthropic")
    import framework.v2.kernel.backends.anthropic as be

    monkeypatch.setenv("VIGIL_LIVE_KEY_RELOAD", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-frozen")
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-frozen\n", encoding="utf-8")
    built: list = []

    class _StubClient:
        def __init__(self, **_kw):
            built.append(os.environ.get("ANTHROPIC_API_KEY"))   # the SDK reads the env at construction

    monkeypatch.setattr(anthropic, "Anthropic", _StubClient)
    b = be.AnthropicBackend()
    c1 = b._client_obj()
    assert built == ["sk-frozen"]                               # first build uses the current key
    assert b._client_obj() is c1 and built == ["sk-frozen"]     # unchanged -> cached, no rebuild
    sigil_env.write_text("ANTHROPIC_API_KEY=sk-resealed\n", encoding="utf-8")   # UI re-seal
    c3 = b._client_obj()
    assert c3 is not c1, "a re-sealed key must rebuild the cached client"
    assert built == ["sk-frozen", "sk-resealed"], "the rebuilt client must read the FRESH key from the env"
