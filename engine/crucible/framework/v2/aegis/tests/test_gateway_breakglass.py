"""AS-27a — break-glass is availability-first: an UNREADABLE control plane must fail toward NOT blocking.

Two fail-safe terms of the ``enforce`` gate are exercised here, both for the case the honest-status /
entitlement tests cannot reach — the control plane being *unreadable* rather than merely clear or set:

  * KILL-SWITCH: ``KillSwitch.is_tripped`` is itself fail-closed (ambiguous stat ⇒ TRIPPED), but the
    gateway's wrapper has to cover the one case it cannot — the kill-switch SUBSYSTEM being unreadable
    (import / path error). That must read as TRIPPED (break-glass engaged ⇒ pass-through), never CLEAR;
    returning CLEAR would keep the gateway blocking on a kill-switch it cannot read (fail-open).
  * MODE FILE: a PRESENT-but-unreadable mode file is a glitch, not "no override". It must fall back to the
    last cleanly-read override, and if none, to OBSERVE — never silently escalate to the startup --mode,
    which may itself be enforce.

These are unit-level: they drive the ``GatewaySettings`` gate directly, with the kill-switch subsystem and
the mode-file path monkeypatched, so the assertions are about the gate's fail direction, not sockets.
"""
from __future__ import annotations

import pytest

from framework.v2.aegis.gateway import GatewaySettings
from framework.v2.aegis.models import AegisConfig

_UP = "http://127.0.0.1:9"


def _settings(mode: str) -> GatewaySettings:
    return GatewaySettings(_UP, AegisConfig(deployment_secret="k", mode=mode))


@pytest.fixture()
def mode_path(tmp_path, monkeypatch):
    """Isolate the live mode-override control file in a tmp dir so these tests never read the operator's real
    authority dir. Returns the Path the gateway will read; absent by default (= no live override)."""
    p = tmp_path / "aegis-gateway.mode"
    monkeypatch.setattr("framework.v2.common.paths.aegis_mode_path", lambda slug: p)
    return p


# ---------------------------------------------------------------------------- kill-switch: unreadable ⇒ tripped

def test_an_unreadable_killswitch_subsystem_reads_as_tripped(monkeypatch, mode_path):
    """A kill-switch SUBSYSTEM error (here: ``is_tripped`` raises) must read as TRIPPED, so the break-glass
    engages when the switch cannot be read — the opposite of the pre-AS-27a fail-open."""
    def _boom(self):
        raise RuntimeError("authority dir unreadable")
    monkeypatch.setattr("framework.v2.authority.killswitch.KillSwitch.is_tripped", _boom)

    s = _settings("enforce")
    assert s._killswitch_tripped() is True


def test_an_unreadable_killswitch_never_keeps_the_gateway_blocking(monkeypatch, mode_path):
    """The real-world impact: under enforce + entitled, an unreadable kill-switch must drop the gateway to
    pass-through (``enforce`` is False) and ``enforcement_status`` must HONESTLY name the kill-switch as the
    reason — a downgrade, never silent, never a spurious block."""
    def _boom(self):
        raise OSError("symlink loop")
    monkeypatch.setattr("framework.v2.authority.killswitch.KillSwitch.is_tripped", _boom)

    s = _settings("enforce")
    monkeypatch.setattr(s, "_enforce_authorized", True)   # entitled: isolate the kill-switch term

    assert s.enforce is False                             # does NOT block on an unreadable kill-switch
    es = s.enforcement_status()
    assert es["enforcing"] is False
    assert es["kill_switch_tripped"] is True
    assert es["downgraded"] is True
    assert "kill-switch" in (es["downgrade_reason"] or "")


# ---------------------------------------------------------------------------- mode file: glitch never escalates

def test_absent_mode_file_falls_back_to_the_startup_mode(mode_path):
    """The NORMAL path: no live override file (FileNotFoundError) is not a glitch — it yields the configured
    startup --mode unchanged, for both startup values."""
    assert not mode_path.exists()
    assert _settings("observe").intended_mode() == "observe"
    assert _settings("enforce").intended_mode() == "enforce"


def test_a_valid_mode_file_overrides_the_startup_mode(mode_path):
    """A cleanly-read valid override wins over the startup --mode (the live observe<->enforce switch)."""
    mode_path.write_text("observe", encoding="utf-8")
    assert _settings("enforce").intended_mode() == "observe"
    mode_path.write_text("enforce", encoding="utf-8")
    assert _settings("observe").intended_mode() == "enforce"


def test_invalid_mode_file_content_is_ignored(mode_path):
    """Present-but-garbage content is not a read error; the override is ignored and the startup --mode stands
    (the pre-existing contract, unchanged by AS-27a)."""
    mode_path.write_text("ENFORCE-NOW-PLEASE", encoding="utf-8")
    assert _settings("observe").intended_mode() == "observe"


def test_an_unreadable_mode_file_never_escalates_to_enforce(mode_path):
    """THE AS-27a fix: a PRESENT-but-unreadable mode file (here a directory at the path ⇒ IsADirectoryError)
    with no last-known-good must drop to OBSERVE, never to the startup --mode even when that is enforce.
    Before the fix this returned None ⇒ the enforce startup mode ⇒ the glitch silently kept blocking."""
    mode_path.mkdir()                                     # read_text on a dir raises (OSError, not FileNotFound)
    s = _settings("enforce")
    assert s.intended_mode() == "observe"                # the glitch does NOT escalate to the startup enforce


def test_a_mode_file_glitch_falls_back_to_the_last_known_good(tmp_path, monkeypatch):
    """When a clean override was read before the glitch, the gateway holds that last-known-good rather than
    dropping all the way to observe — so a transient read blip does not flap a deliberately-set mode."""
    p = tmp_path / "aegis-gateway.mode"
    monkeypatch.setattr("framework.v2.common.paths.aegis_mode_path", lambda slug: p)
    s = _settings("enforce")

    p.write_text("observe", encoding="utf-8")
    assert s.intended_mode() == "observe"                # clean read -> remembered as last-known-good

    p.unlink()
    p.mkdir()                                            # now a glitch at the same path
    assert s.intended_mode() == "observe"               # held at the last-known-good 'observe', not startup enforce
