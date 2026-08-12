"""The universal Settings "System configuration" plane must actually REACH the offense engine.

Two INDEPENDENT allowlists gate an offense-plane config var end-to-end:
  * the sovereign EMITTER — settings.CONFIG_OFFENSE_VARS, emitted by export_runtime_env;
  * the uiproxy CONSUMER — _OFFENSE_ENV_ALLOWLIST, re-applied when injecting the child env
    (integration/vigil_integration/uiproxy.py) so the boundary can never become an arbitrary
    env-injection channel even if the emitter changed.

They must AGREE, or an offense-tuning UI knob is a placebo: the sovereign side emits the value and
the consumer silently drops it, so the operator's change never reaches the engine. Red-pen BLOCK-1
caught exactly that divergence (the emitter grew 9 vars the consumer allowlist did not). These tests
run on the sovereign path (both planes importable) in the P5 integration CI leg.
"""
from __future__ import annotations


def test_config_plane_allowlists_agree():
    from sigil.ui import settings
    from vigil_integration import uiproxy

    missing = set(settings.CONFIG_OFFENSE_VARS) - uiproxy._OFFENSE_ENV_ALLOWLIST
    assert not missing, (
        "offense-plane config vars the sovereign side emits are DROPPED by the uiproxy consumer "
        f"allowlist — they would never reach the offense engine (placebo UI knobs): {sorted(missing)}")


def test_non_offense_config_vars_never_in_the_offense_allowlist():
    # A sovereign / gateway / system config var must NEVER be offense-delivered (FATAL-2 /
    # least-privilege): a mis-tagged var could otherwise cross into the keyless offense children.
    from sigil.ui import settings
    from vigil_integration import uiproxy

    non_offense = [e for e in settings.CONFIG_VARS if settings.CONFIG_META[e].get("plane") != "offense"]
    leaked = [e for e in non_offense if e in uiproxy._OFFENSE_ENV_ALLOWLIST]
    assert not leaked, f"non-offense config vars present in the offense allowlist: {leaked}"
