"""APEX PR-1 — the flag-off golden for the autonomous-driver flag + its FATAL-2 (offense-free) property.

``VIGIL_APEX_AUTONOMOUS`` is OFF by default. This pins that default, the affirmative-value parsing (it must
agree with the offense engine's reader so both planes mean the same thing by "on"), and — load-bearing —
that the SOVEREIGN accessor is a PURE ENV READ: importing ``sigil.config`` and calling it loads NO offense
module (``framework`` / ``strix``), so flipping the flag can never drag the offense engine into the key-
holding sovereign process. The offense engine reads the SAME env var itself (it never imports sigil).
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from sigil import config


def test_apex_flag_is_off_by_default(monkeypatch):
    monkeypatch.delenv("VIGIL_APEX_AUTONOMOUS", raising=False)
    assert config.apex_autonomous_enabled() is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", "yes", "on", "enabled", " On "])
def test_apex_flag_affirmative_values_turn_it_on(monkeypatch, val):
    monkeypatch.setenv("VIGIL_APEX_AUTONOMOUS", val)
    assert config.apex_autonomous_enabled() is True


@pytest.mark.parametrize("val", ["", "0", "false", "no", "off", "disabled", "nope"])
def test_apex_flag_non_affirmative_values_keep_it_off(monkeypatch, val):
    monkeypatch.setenv("VIGIL_APEX_AUTONOMOUS", val)
    assert config.apex_autonomous_enabled() is False


def test_apex_flag_accessor_is_offense_free_fatal2():
    """FATAL-2: a subprocess that imports sigil.config and calls the accessor must NOT have loaded the offense
    engine — the sovereign flag is a pure env read, not a bridge to framework/strix."""
    probe = (
        "import sys; from sigil import config; "
        "config.apex_autonomous_enabled(); "
        "assert 'framework' not in sys.modules, 'config imported framework'; "
        "assert 'strix' not in sys.modules, 'config imported strix'; "
        "print('offense-free')"
    )
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "offense-free" in r.stdout
