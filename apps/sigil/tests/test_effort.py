"""A3 — reasoning-effort control (settings plane + offense delivery + uiproxy allowlist)."""
from __future__ import annotations

import ast
import os
import pathlib
import re
import tempfile

import pytest


def _repo_root() -> pathlib.Path:
    for anc in pathlib.Path(__file__).resolve().parents:
        if (anc / "engine" / "crucible").is_dir() and (anc / "integration").is_dir():
            return anc
    raise AssertionError("repo root not found")


def _tuple_literal(path: pathlib.Path, name: str) -> tuple:
    """Extract `name = (..)`/`[..]` from a source file WITHOUT importing it (the two-env boundary forbids
    loading the offense kernel into this sovereign test process)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found in {path}")


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
    assert "STRIX_REASONING_EFFORT" in _OFFENSE_ENV_ALLOWLIST


def test_effort_also_drives_the_strix_agent():
    from sigil.ui import settings as S
    # the operator's choice mirrors onto Strix's own knob; "max" maps to Strix's top "xhigh" (it has no "max")
    S.set_effort("high", **_sa())
    assert os.environ["STRIX_REASONING_EFFORT"] == "high"
    S.set_effort("max", **_sa())
    assert os.environ["CRUCIBLE_EFFORT"] == "max" and os.environ["STRIX_REASONING_EFFORT"] == "xhigh"
    # delivered to the offense process (where Strix runs) and cleared together
    env = S.export_runtime_env(include_secrets=False)
    assert env.get("CRUCIBLE_EFFORT") == "max" and env.get("STRIX_REASONING_EFFORT") == "xhigh"
    S.set_effort("", **_sa())
    assert os.environ.get("STRIX_REASONING_EFFORT", "") == ""       # cleared → Strix default ("high")
    # every mapped value must be inside Strix's ReasoningEffort Literal (else Strix config fails to load)
    strix_settings = _repo_root() / "vendor/strix/strix/config/settings.py"
    line = next(ln for ln in strix_settings.read_text(encoding="utf-8").splitlines()
                if ln.strip().startswith("ReasoningEffort"))
    strix_valid = set(re.findall(r'"([^"]+)"', line))
    for lvl in S.EFFORT_LEVELS:
        assert S._STRIX_EFFORT_MAP[lvl] in strix_valid, f"{lvl}->{S._STRIX_EFFORT_MAP[lvl]} not a Strix effort"


def test_model_family_and_effort_lists_do_not_drift_across_the_boundary():
    """The current-model prefix list + effort levels are DUPLICATED across the two-env boundary (the kernel
    can't be imported into the sovereign think path). Pin them by source so a future model added to only one
    copy — which would send effort+temperature or neither — is caught."""
    root = _repo_root()
    from sigil.ui import settings as S
    kernel_prefixes = _tuple_literal(root / "engine/crucible/framework/v2/kernel/llm.py", "_CURRENT_MODEL_PREFIXES")
    think_prefixes = _tuple_literal(root / "integration/vigil_integration/live/think_claude.py", "_CURRENT_MODEL_PREFIXES")
    assert set(kernel_prefixes) == set(think_prefixes), "current-model prefix lists drifted across the boundary"
    kernel_levels = _tuple_literal(root / "engine/crucible/framework/v2/kernel/llm.py", "EFFORT_LEVELS")
    think_levels = _tuple_literal(root / "integration/vigil_integration/live/think_claude.py", "_EFFORT_LEVELS")
    assert set(kernel_levels) == set(think_levels) == set(S.EFFORT_LEVELS), "EFFORT_LEVELS drifted across planes"
