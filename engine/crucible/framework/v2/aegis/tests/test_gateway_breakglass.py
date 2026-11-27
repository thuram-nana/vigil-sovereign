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

import errno

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


# ---------------------------------------------------------------------------- the resurrection guard (the HIGH)

def test_a_cleared_override_is_not_resurrected_by_a_later_glitch(mode_path):
    """THE AS-27a resurrection guard. Once the operator CLEARS the live override (the file is removed), a
    later read glitch must NOT bring the previously-set mode back from cache. With startup=enforce: a clean
    'enforce' read caches it; the delete is observed (absent ⇒ startup mode AND cache cleared); a subsequent
    glitch must read 'observe' — not the stale, resurrected 'enforce'. Before the cache-invalidation fix this
    returned 'enforce' and the gateway silently resumed blocking against current intent."""
    s = _settings("enforce")
    mode_path.write_text("enforce", encoding="utf-8")
    assert s.intended_mode() == "enforce"                # clean read -> caches 'enforce'
    mode_path.unlink()
    assert s.intended_mode() == "enforce"                # absent (ENOENT) -> startup 'enforce', and clears the cache
    mode_path.mkdir()                                    # now a present-but-unreadable glitch at the same path
    assert s.intended_mode() == "observe"               # cache forgotten -> observe, NOT a resurrected 'enforce'


def test_an_invalidated_override_is_not_resurrected_by_a_later_glitch(mode_path):
    """Same guard via the invalid-content path: a clean 'enforce' read, then the file is overwritten with a
    value that is not a valid mode (so there is no longer a valid live override), then a glitch — the gate
    must read 'observe', never the stale 'enforce'. Startup is 'observe' here so a resurrected enforce would
    be unmistakable."""
    s = _settings("observe")
    mode_path.write_text("enforce", encoding="utf-8")
    assert s.intended_mode() == "enforce"                # caches 'enforce'
    mode_path.write_text("garbage-not-a-mode", encoding="utf-8")
    assert s.intended_mode() == "observe"                # invalid content -> startup 'observe', and clears the cache
    mode_path.unlink(); mode_path.mkdir()               # glitch
    assert s.intended_mode() == "observe"               # not resurrected to 'enforce'


# ---------------------------------------------------------------------------- the glitch branches, by cause

def test_a_mode_subsystem_failure_is_a_glitch_not_an_absent_override(monkeypatch):
    """The first except branch: if resolving the mode path itself fails (import / path-construction error),
    that is an ambiguous glitch, not a reliable 'no override' — it must hold last-known-good / observe, never
    fall through to a startup enforce."""
    monkeypatch.setattr("framework.v2.common.paths.aegis_mode_path",
                        lambda slug: (_ for _ in ()).throw(RuntimeError("path subsystem down")))
    s = _settings("enforce")
    assert s.intended_mode() == "observe"                # subsystem glitch, no last-known-good -> observe, not enforce
    s._last_good_mode = "enforce"                        # once a value has been observed, the glitch holds it
    assert s.intended_mode() == "enforce"


def test_enotdir_is_treated_as_absent_like_the_killswitch(tmp_path, monkeypatch):
    """errno parity with KillSwitch._ABSENT_ERRNOS: a path whose PARENT is a regular file yields ENOTDIR on
    read — a proof the override cannot exist there — so it is 'absent' (⇒ startup mode + cache cleared), NOT a
    glitch that would hold a stale cached value. Startup 'observe' + a stale cached 'enforce' makes the two
    classifications give different answers."""
    parent_file = tmp_path / "not-a-dir"
    parent_file.write_text("x", encoding="utf-8")
    p = parent_file / "aegis-gateway.mode"               # reading beneath a regular file -> ENOTDIR
    monkeypatch.setattr("framework.v2.common.paths.aegis_mode_path", lambda slug: p)
    s = _settings("observe")
    s._last_good_mode = "enforce"                        # a stale cached enforce...
    assert s.intended_mode() == "observe"                # ...ENOTDIR is ABSENT -> startup observe, not a glitch-hold
    assert getattr(s, "_last_good_mode", None) is None   # ...and absent classification cleared the cache


def test_a_mode_file_permission_error_is_a_glitch_not_absent(tmp_path, monkeypatch):
    """The docstring's primary 'permission glitch': a PermissionError (EACCES, not in the absent set) is a
    glitch ⇒ never escalate. With no last-known-good and startup=enforce, it drops to observe."""
    p = tmp_path / "aegis-gateway.mode"
    p.write_text("enforce", encoding="utf-8")
    monkeypatch.setattr("framework.v2.common.paths.aegis_mode_path", lambda slug: p)
    s = _settings("enforce")

    def _denied(self, *a, **k):
        raise PermissionError(errno.EACCES, "Permission denied")
    monkeypatch.setattr("pathlib.Path.read_text", _denied)
    assert s.intended_mode() == "observe"                # EACCES glitch, no last-good -> observe (never startup enforce)


# ---------------------------------------------------------------------------- kill-switch: subsystem construction

def test_an_unreadable_killswitch_via_construction_failure_reads_as_tripped(monkeypatch, mode_path):
    """Not only is_tripped() raising: if constructing the KillSwitch itself fails (path construction / import),
    that subsystem-unreadable case must ALSO read as TRIPPED ⇒ pass-through — the gateway never keeps blocking
    on a kill-switch it cannot even instantiate."""
    def _boom_init(self, slug, **kw):
        raise RuntimeError("authority path construction failed")
    monkeypatch.setattr("framework.v2.authority.killswitch.KillSwitch.__init__", _boom_init)

    s = _settings("enforce")
    assert s._killswitch_tripped() is True
