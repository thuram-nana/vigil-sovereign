"""A3 — reasoning-effort control (settings plane + offense delivery + uiproxy allowlist)."""
from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _home(monkeypatch):
    # SIGIL_HOME is import-bound; the SecretStore/envfile reads os.environ, so clear the effort/model vars
    # before AND after each test so no state leaks (same pattern as test_byo_providers).
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    for k in ("CRUCIBLE_EFFORT", "CRUCIBLE_LLM_BACKEND", "VIGIL_MODEL_CHOICE"):
        os.environ.pop(k, None)
    yield
    for k in ("CRUCIBLE_EFFORT", "CRUCIBLE_LLM_BACKEND", "VIGIL_MODEL_CHOICE"):
        os.environ.pop(k, None)


def _sa():
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    return {"store": SpineStore(), "owner_key": ensure_owner_keypair()}


def test_set_effort_allowlist_and_persist():
    from sigil.ui import settings as S
    S.set_effort("high", **_sa())
    assert os.environ["CRUCIBLE_EFFORT"] == "high"
    S.set_effort("MAX", **_sa())                      # case-insensitive
    assert os.environ["CRUCIBLE_EFFORT"] == "max"
    for bad in ("turbo", "9", "extreme"):
        with pytest.raises(ValueError):
            S.set_effort(bad, **_sa())
    # empty clears it → model default
    S.set_effort("", **_sa())
    assert os.environ.get("CRUCIBLE_EFFORT", "") == ""


def test_settings_status_exposes_effort():
    from sigil.ui import settings as S
    st = S.settings_status()
    assert st["effort_levels"] == ["low", "medium", "high", "xhigh", "max"]
    assert st["selected_effort"] is None             # unset → model default
    S.set_effort("xhigh", **_sa())
    assert S.settings_status()["selected_effort"] == "xhigh"


def test_effort_is_delivered_to_offense_but_not_in_provider_clear_set():
    from sigil.ui import settings as S
    S.set_effort("high", **_sa())
    assert S.export_runtime_env(include_secrets=False).get("CRUCIBLE_EFFORT") == "high"
    # switching provider must NOT clear the operator's effort choice (effort is orthogonal to provider)
    assert "CRUCIBLE_EFFORT" not in S.PROVIDER_ENV_VARS
    S.set_provider("anthropic", "claude-opus-5", {}, **_sa())
    assert os.environ.get("CRUCIBLE_EFFORT") == "high"       # survived the provider switch
    assert S.export_runtime_env(include_secrets=False).get("CRUCIBLE_EFFORT") == "high"


def test_uiproxy_allowlist_carries_effort():
    from vigil_integration.uiproxy import _OFFENSE_ENV_ALLOWLIST
    assert "CRUCIBLE_EFFORT" in _OFFENSE_ENV_ALLOWLIST
