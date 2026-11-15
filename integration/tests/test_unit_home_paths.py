"""Every shipped systemd unit resolves its paths from the service user's home (`%h`), never a hard-coded
`/home/<user>`, so the units work for whichever account installs them; `tools/deploy-console.sh` defaults to
`$HOME/vigil` for the same reason.

Framework-free (reads files only), so it runs in every CI leg.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_UNIT_DIRS = (_REPO / "infra" / "systemd", _REPO / "apps" / "sigil" / "deploy" / "systemd")
_HOME_LITERAL = re.compile(r"/home/[A-Za-z0-9_.-]+")


def _unit_files() -> list[Path]:
    out: list[Path] = []
    for d in _UNIT_DIRS:
        out += sorted(d.glob("*.service")) + sorted(d.glob("*.timer")) + sorted(d.glob("*.service.d/*.conf"))
    return out


def _directive_lines(text: str):
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith(("#", ";")):
            yield n, line


def _home_literals(text: str) -> list[str]:
    return [f"{n}: {line}" for n, line in _directive_lines(text) if _HOME_LITERAL.search(line)]


def test_the_scan_sees_the_units_it_guards():
    names = {p.name for p in _unit_files()}
    for unit in ("vigil-command.service", "vigil-ready.service", "vigil-bringup.service",
                 "sigil-cockpit.service", "vigil-settle-drain.service"):
        assert unit in names, f"{unit} is not scanned"


@pytest.mark.parametrize("unit", _unit_files(), ids=lambda p: str(p.relative_to(_REPO)))
def test_no_unit_directive_names_a_fixed_home(unit):
    bad = _home_literals(unit.read_text(encoding="utf-8"))
    assert not bad, f"{unit.relative_to(_REPO)} hard-codes a home directory (use %h):\n" + "\n".join(bad)


@pytest.mark.parametrize("unit", ["vigil-command.service", "vigil-ready.service", "vigil-bringup.service"])
def test_the_console_units_run_from_the_users_checkout(unit):
    text = (_REPO / "infra" / "systemd" / unit).read_text(encoding="utf-8")
    directives = dict(line.split("=", 1) for _n, line in _directive_lines(text) if "=" in line
                      and not line.startswith("["))
    assert directives["WorkingDirectory"] == "%h/vigil"
    assert directives["EnvironmentFile"] == "-%h/vigil/.vigil-live/service.env"
    assert "%h/vigil/.venv-offense/bin/vigil " in directives["ExecStart"]


def test_the_guard_flags_a_hard_coded_home():
    # negative control: the detector is not vacuous
    assert _home_literals("[Service]\nWorkingDirectory=/home/alice/vigil\n") == ["2: WorkingDirectory=/home/alice/vigil"]
    assert _home_literals("# WorkingDirectory=/home/alice/vigil\n[Service]\nWorkingDirectory=%h/vigil\n") == []


def test_deploy_console_defaults_to_the_users_home():
    body = (_REPO / "tools" / "deploy-console.sh").read_text(encoding="utf-8")
    assert 'DEST="${VIGIL_DEPLOY_DIR:-$HOME/vigil}"' in body
    code = "\n".join(line for _n, line in _directive_lines(body))
    assert not _HOME_LITERAL.search(code), "deploy-console.sh hard-codes a home directory"
