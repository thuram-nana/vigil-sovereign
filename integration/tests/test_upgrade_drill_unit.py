"""DEP-3 (#73) — structural invariants of the opt-in ``vigil-upgrade-drill`` systemd unit + timer that a
systemd smoke test cannot check on a PR runner: it runs the drill in the SOVEREIGN venv (FATAL-2 — never the
offense one), the real sovereign home is READ-ONLY to it (kernel-enforced, on top of the drill's own
work-dir isolation), it has no network, it is a non-restarting oneshot, and its timer is weekly + ships disabled.
"""
from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_UNIT = _REPO / "infra" / "systemd" / "vigil-upgrade-drill.service"
_TIMER = _REPO / "infra" / "systemd" / "vigil-upgrade-drill.timer"


def _directives(p: Path) -> list[str]:
    return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_runs_the_sovereign_drill_in_the_sovereign_venv():
    d = _directives(_UNIT)
    exec_start = [ln for ln in d if ln.startswith("ExecStart=")]
    assert exec_start == ["ExecStart=%h/vigil/.venv-sovereign/bin/python -m sigil.spine.upgrade_drill"]
    assert not exec_start[0].startswith("ExecStart=-"), "a failed drill must FAIL the unit"


def test_the_real_home_is_read_only_and_there_is_no_network():
    d = _directives(_UNIT)
    assert "ReadOnlyPaths=%h/.sigil" in d
    assert not any(ln.startswith("ReadWritePaths=") and ".sigil" in ln for ln in d)
    assert "PrivateNetwork=yes" in d and "PrivateTmp=yes" in d and "ProtectSystem=strict" in d
    assert "Environment=TMPDIR=/var/tmp" in d          # disk-backed scratch (~3x the spine), still private


def test_is_a_non_restarting_oneshot_with_a_heartbeat():
    d = _directives(_UNIT)
    assert "Type=oneshot" in d and not any(ln.startswith("Restart=") for ln in d)
    assert any(ln.startswith("ExecStopPost=") and "unit-heartbeat %n" in ln for ln in d)


def test_timer_is_weekly_and_targets_the_drill():
    d = _directives(_TIMER)
    assert "OnCalendar=weekly" in d and "Unit=vigil-upgrade-drill.service" in d and "Persistent=true" in d


def test_the_unit_text_matches_the_drill_verdicts():
    """Audit E4c: the header once said a changed source FAILS while the drill returned INCONCLUSIVE (exit 4).
    The text must describe the real exit codes, and say a busy box is not a failure."""
    import re

    text = _UNIT.read_text(encoding="utf-8")
    header = "\n".join(ln for ln in text.splitlines() if ln.startswith("#"))
    flat = re.sub(r"\s*\n#\s*", " ", header)
    assert "or the drill FAILS" not in flat
    assert "0 PASS · 1 FAIL · 3 NOT-RUN" in flat and "4 INCONCLUSIVE (no consistent snapshot could be taken" in flat
    assert "A BUSY BOX STILL GETS A VERDICT" in flat
    assert "NEVER HOLDS THE OWNER KEY" in flat
    assert "before/after digest" not in flat and "`source_changed_during_drill`), never a guard" in flat
