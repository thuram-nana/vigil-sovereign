"""The upgrade procedure in RELEASE-UPGRADE-ROLLBACK.md §2 installs a release BY ITS TAG (only a commit on main),
stops EVERY shipped unit — timers first, then the oneshots already running, then the services with the cockpit
last — quiesces money in flight, backs up with the old build after the writers stopped, and starts exactly the
recorded units again, the cockpit first.

Stdlib-only (reads files), so it rides the docs CI job.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

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
        "--type=service --state=activating",                         # wait for running oneshots
        "--type=service --state=running",                            # record the services
        "systemctl --user stop sigil-customer.service",              # edges and console
        "systemctl --user stop sigil-cockpit.service",               # the writer last
        "systemctl --user start vigil-backup-push.service",          # back up with the OLD build, writers stopped
        'git checkout --detach "$SHA"',                              # only now change the code
        "./bootstrap.sh",
        'cp -a "$UD" "$U/units-before"',                             # keep the old unit set ...
        'cp "$d/$rel" "$f"',                                         # ... and install the release's units
        "vigil upgrade --check",
        "vigil upgrade\n",
        "systemctl --user daemon-reload",                            # load the release's units
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


# ── the runbook's own shell, run against a fake systemctl / sleep and a fake unit directory ──────────────────────
def _snippet(start: str, end: str) -> str:
    code = _code(_upgrade())
    a = code.index(start)
    return code[a: code.index(end, a)]


def _shim(bindir: Path, name: str, body: str) -> None:
    f = bindir / name
    f.write_text("#!/bin/sh\n" + body)
    f.chmod(0o755)


def _run_wait(tmp_path: Path, activating: str) -> "tuple[str, int]":
    """Run step 2 of 2.4 with `systemctl` answering ``activating`` (the n-th call prints line n of it, the last line
    from then on; an empty line means nothing is activating) and a `sleep` that only counts."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "answers").write_text(activating)
    _shim(bindir, "systemctl", 'n=$(cat "$T/calls" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$T/calls"\n'
                               'case "$*" in *--state=activating*) '
                               'total=$(wc -l < "$T/answers"); [ $n -gt $total ] && n=$total; '
                               'sed -n "${n}p" "$T/answers" ;; esac\n')
    _shim(bindir, "sleep", 'echo "$1" >> "$T/sleeps"\n')
    script = _snippet("# 2. wait", "# 3. record")
    env = dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}", T=str(tmp_path))
    cp = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    assert cp.returncode == 0, cp.stderr
    sleeps = (tmp_path / "sleeps").read_text().split() if (tmp_path / "sleeps").exists() else []
    assert set(sleeps) <= {"5"}
    return cp.stdout, len(sleeps)


_RESTARTING = "vigil-command.service loaded activating auto-restart VIGIL command\n"
_ONESHOT = "vigil-backup-push.service loaded activating start VIGIL backup push\n"


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_oneshot_wait_does_not_wait_for_a_unit_restarting_after_a_failure(tmp_path):
    out, sleeps = _run_wait(tmp_path, _RESTARTING)
    assert "no oneshot running" in out and "waiting for" not in out and sleeps == 0


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_oneshot_wait_waits_for_a_running_oneshot_and_names_it(tmp_path):
    out, sleeps = _run_wait(tmp_path, _ONESHOT + _ONESHOT + _RESTARTING)
    assert out.count("waiting for: vigil-backup-push.service") == 2 and sleeps == 2
    assert out.rstrip().endswith("no oneshot running")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_oneshot_wait_is_bounded_to_thirty_minutes(tmp_path):
    out, sleeps = _run_wait(tmp_path, _ONESHOT)
    assert sleeps * 5 == 30 * 60
    assert out.rstrip().endswith("STOP: still running after 30 minutes: vigil-backup-push.service")


@pytest.mark.skipif(not all(shutil.which(t) for t in ("bash", "cmp", "diff")), reason="needs bash, cmp, diff")
def test_the_release_units_replace_the_installed_copies(tmp_path):
    home, u = tmp_path / "home", tmp_path / "u"
    ud = home / ".config" / "systemd" / "user"
    (ud / "vigil-command.service.d").mkdir(parents=True)
    u.mkdir()
    shipped_cmd = (REPO / "infra" / "systemd" / "vigil-command.service").read_text(encoding="utf-8")
    shipped_dropin = (REPO / "infra" / "systemd" / "vigil-command.service.d" / "production.conf").read_text()
    shipped_cockpit = (REPO / "apps" / "sigil" / "deploy" / "systemd" / "sigil-cockpit.service").read_text()
    (ud / "vigil-command.service").write_text("[Service]\nExecStart=/home/kali/vigil up\n")      # an older release
    (ud / "vigil-command.service.d" / "production.conf").write_text("[Service]\n")
    (ud / "sigil-cockpit.service").write_text(shipped_cockpit)                                # already current
    (ud / "sigil-public.service").symlink_to("/dev/null")                                     # masked
    (ud / "operator-own.service").write_text("[Service]\nExecStart=/bin/true\n")               # not shipped
    elsewhere = tmp_path / "linked.service"
    elsewhere.write_text("[Service]\nExecStart=/bin/true\n")
    (ud / "sigil-checkpoint.service").symlink_to(elsewhere)                                   # linked
    script = _code(_upgrade())
    script = script[script.index("UD=~/.config/systemd/user"):]
    script = script[: script.index("\ndone\n") + len("\ndone\n")]
    env = dict(os.environ, HOME=str(home), U=str(u))
    cp = subprocess.run(["bash", "-c", script], env=env, cwd=REPO, capture_output=True, text=True, timeout=60)
    assert cp.returncode == 0, cp.stderr
    assert (ud / "vigil-command.service").read_text() == shipped_cmd
    assert (ud / "vigil-command.service.d" / "production.conf").read_text() == shipped_dropin
    assert (ud / "sigil-cockpit.service").read_text() == shipped_cockpit
    assert os.readlink(ud / "sigil-public.service") == "/dev/null"
    assert os.readlink(ud / "sigil-checkpoint.service") == str(elsewhere)
    assert elsewhere.read_text() == "[Service]\nExecStart=/bin/true\n"
    assert (ud / "operator-own.service").read_text() == "[Service]\nExecStart=/bin/true\n"
    assert not (ud / "sigil-customer.service").exists()                                      # nothing new installed
    assert (u / "units-before" / "vigil-command.service").read_text() == "[Service]\nExecStart=/home/kali/vigil up\n"
    diff = (u / "units.diff").read_text()
    headers = [ln for ln in diff.splitlines() if ln.startswith(("--- ", "+++ "))]
    assert len(headers) == 4 and not any("sigil-cockpit.service" in h for h in headers), headers
    assert sorted(cp.stdout.split("\n")) == sorted(["", "updated vigil-command.service",
                                                    "updated vigil-command.service.d/production.conf"])


def test_a_unit_restarting_after_a_failure_is_recorded_with_the_services():
    # the wait skips it (SUB auto-restart, ACTIVE activating); the record keeps it, so 2.8 starts it again
    line = next(ln for ln in _code(_upgrade()).splitlines() if "--type=service --state=running" in ln)
    states = re.search(r"--state=(\S+)", line).group(1).split(",")
    assert set(states) == {"running", "activating"}


def test_a_code_rollback_installs_the_previous_releases_units():
    text = RUNBOOK.read_text(encoding="utf-8")
    rb = text[text.index("### 3a."): text.index("### 3b.")]
    assert "install its units (2.6)" in rb
