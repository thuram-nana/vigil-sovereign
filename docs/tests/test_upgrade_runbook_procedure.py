"""The upgrade procedure in RELEASE-UPGRADE-ROLLBACK.md §2 installs a release BY ITS TAG (only a commit on main),
stops EVERY shipped unit — timers first, then the oneshots already running, then the services with the cockpit
last — quiesces money in flight, backs up with the old build after the writers stopped, and starts exactly the
recorded units again, the cockpit first.

Stdlib-only (reads files), so it rides the docs CI job.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNBOOK = REPO / "docs" / "runbooks" / "RELEASE-UPGRADE-ROLLBACK.md"
UNIT_DIRS = (REPO / "infra" / "systemd", REPO / "apps" / "sigil" / "deploy" / "systemd")


def _upgrade() -> str:
    text = RUNBOOK.read_text(encoding="utf-8")
    a = text.index("## 2. Upgrade")
    return text[a: text.index("## 3. Rollback", a)]


def _code(text: str) -> str:
    return "\n".join(re.findall(r"```\n(.*?)```", text, re.S))


def _at(code: str, needle: str) -> int:
    assert needle in code, f"the upgrade procedure lacks {needle!r}"
    return code.index(needle)


def test_a_release_is_installed_by_its_tag_and_only_from_main():
    code = _code(_upgrade())
    assert 'git merge-base --is-ancestor "$TAG^{commit}" origin/main' in code
    assert 'git checkout --detach "$SHA"' in code
    assert _at(code, "git merge-base --is-ancestor") < _at(code, 'git checkout --detach "$SHA"')
    assert "git pull" not in code and "checkout main" not in code


def test_the_procedure_runs_in_the_safe_order():
    code = _code(_upgrade())
    order = [
        "vigil doctor",                                              # preflight
        "jobs/running/",                                             # quiesce: engagements
        "spool/settle/incoming/",                                    # quiesce: settles
        "--type=timer --state=active",                               # record the timers ...
        'xargs -r systemctl --user stop < "$U/timers"',              # ... and stop them first
        "--state=activating",                                        # wait for running oneshots
        "--type=service --state=running",                            # record the services
        "systemctl --user stop sigil-customer.service",              # edges and console
        "systemctl --user stop sigil-cockpit.service",               # the writer last
        "systemctl --user start vigil-backup-push.service",          # back up with the OLD build, writers stopped
        'git checkout --detach "$SHA"',                              # only now change the code
        "./bootstrap.sh",
        'cp "$d/${u##*/}" "$u"',                                     # the release's units, before any start
        "vigil upgrade --check",
        "vigil upgrade\n",
        "systemctl --user daemon-reload",                            # systemd reads the re-installed units
        "systemctl --user start sigil-cockpit.service",              # the cockpit first
        'xargs -r systemctl --user start < "$U/timers"',             # then the drains
        'xargs -r systemctl --user start < "$U/services"',           # then exactly the recorded services
        "vigil verify-integrity",
    ]
    pos = [_at(code, n) for n in order]
    out_of_order = [(order[i], order[i + 1]) for i in range(len(order) - 1) if pos[i] > pos[i + 1]]
    assert not out_of_order, out_of_order


def test_the_ha_mirror_is_paused_and_named():
    up = _upgrade()
    assert "vigil-ha-mirror.timer" in up


def _units(suffix: str) -> list[str]:
    out = []
    for d in UNIT_DIRS:
        out += [p.name for p in sorted(d.glob(f"*{suffix}"))]
    return out


def _system_unit(name: str) -> bool:
    for d in UNIT_DIRS:
        p = d / name
        if p.is_file():
            return bool(re.search(r"^EnvironmentFile=-?/etc/", p.read_text(encoding="utf-8"), re.M))
    return False


def _long_running(name: str) -> bool:
    for d in UNIT_DIRS:
        p = d / name
        if p.is_file():
            return not re.search(r"^Type=oneshot\s*$", p.read_text(encoding="utf-8"), re.M)
    return False


def _recorded_patterns(code: str, selector: str) -> list[str]:
    """The unit globs the runbook's own `systemctl list-units <selector> ... '<glob>'...` record command uses."""
    line = next(ln for ln in code.splitlines() if selector in ln)
    pats = re.findall(r"'([^']+)'", line)
    assert pats, f"no unit patterns on the {selector!r} record command"
    return pats


def test_every_shipped_timer_and_service_is_covered_by_the_stop_list():
    up = _upgrade()
    code = _code(up)
    timer_pats = _recorded_patterns(code, "--type=timer --state=active")
    service_pats = _recorded_patterns(code, "--type=service --state=running")
    for timer in _units(".timer"):
        assert any(fnmatch.fnmatch(timer, pat) for pat in timer_pats), f"{timer} escapes the recorded timer list"
    for svc in _units(".service"):
        if not _long_running(svc):
            continue
        if _system_unit(svc):
            # a system-level unit (root-owned config under /etc) sits outside the user manager: the procedure
            # must name it so the operator stops and records it with sudo
            assert svc.split("@")[0] in up, f"system unit {svc} is not named by the upgrade procedure"
            continue
        # a user unit is restarted from the recorded list, so it must match the record command's patterns
        assert any(fnmatch.fnmatch(svc, pat) for pat in service_pats), \
            f"long-running {svc} escapes the recorded service list (it would not be started again)"


def test_the_upgrade_no_longer_stops_only_the_console():
    up = _upgrade()
    assert "vigil down" not in _code(up)
    assert "stop **all** of them" in up
