"""GO-LIVE installs the hash-locked sovereign venv through bootstrap and runs exactly one cockpit on
127.0.0.1:8733: the console runs proxy-only in front of `sigil-cockpit.service` via the shipped drop-in.

Stdlib-only (reads files), so it rides the docs CI job.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNBOOK = REPO / "docs" / "runbooks" / "GO-LIVE-quickstart.md"
DROPIN = REPO / "infra" / "systemd" / "vigil-command.service.d" / "production.conf"


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start: nxt if nxt != -1 else len(text)]


def _code(text: str) -> str:
    return "\n".join(re.findall(r"```(?:bash)?\n(.*?)```", text, re.S))


def test_install_builds_the_locked_venvs_and_installs_nothing_unpinned():
    s1 = _section(RUNBOOK.read_text(encoding="utf-8"), "## 1. Install & build the planes")
    code = _code(s1)
    assert "./bootstrap.sh" in code
    assert not re.search(r"\bpip3? install\b", code), "GO-LIVE §1 installs packages outside the hash-locked build"
    assert not re.search(r"-m venv\b", code), "GO-LIVE §1 creates a venv outside envs/build_envs.sh"


def test_the_console_is_installed_proxy_only_beside_the_cockpit_unit():
    s6 = _section(RUNBOOK.read_text(encoding="utf-8"), "## 6. Run the planes")
    code = _code(s6)
    assert "enable --now sigil-cockpit" in code
    assert "infra/systemd/vigil-command.service.d/production.conf" in code
    assert "enable --now vigil-command" in code
    assert code.index("production.conf") < code.index("enable --now vigil-command"), \
        "the drop-in must be in place before the console unit is enabled"


def test_the_dropin_replaces_execstart_with_a_proxy_only_console_against_8733():
    text = DROPIN.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert lines[0] == "[Service]"
    starts = [ln for ln in lines if ln.startswith("ExecStart=")]
    assert starts[0] == "ExecStart=", "the drop-in must clear the unit's own ExecStart first"
    assert len(starts) == 2
    cmd = starts[1]
    assert " up --proxy-only " in cmd and "--sovereign-addr 127.0.0.1:8733" in cmd and "--port 8770" in cmd
    assert cmd.startswith("ExecStart=%h/vigil/.venv-offense/bin/vigil ")


def test_both_ways_to_share_the_settle_settings_reach_the_ops_sweep_shell():
    s6 = _section(RUNBOOK.read_text(encoding="utf-8"), "## 6. Run the planes")
    para = s6[s6.index("**Settings every settling process must share.**"):]
    opt1 = para[para.index("1. "):para.index("2. ")]
    opt2 = para[para.index("2. "):para.index("`vigil doctor` reads only")]
    assert "$SIGIL_HOME/sigil.env" in opt1 and "exports the cockpit's `SIGIL_HOME`" in opt1
    assert "settle-drain.env" in opt2
    assert "export it" in opt2 and "sigil ops-sweep" in opt2 and "export VIGIL_SETTLE_SPINE_RECORD=1" in opt2
    assert "never its own environment" in para and "vigil-ready.service" in para


def test_no_install_guide_builds_the_unit_venv_by_hand():
    # every sigil unit runs ~/.sigil/venv: the guides build it only through ./bootstrap.sh (the hash-locked link)
    sigil = REPO / "apps" / "sigil"
    guides = [RUNBOOK, sigil / "RUNBOOK.md", sigil / "README.md", *sorted((sigil / "deploy" / "systemd").iterdir())]
    by_hand = re.compile(r"-m venv ~/\.sigil/venv|\.sigil/venv/bin/pip3? install")
    offenders = [g.relative_to(REPO).as_posix() for g in guides if g.is_file()
                 and by_hand.search(g.read_text(encoding="utf-8"))]
    assert offenders == [], offenders
    for g in (sigil / "RUNBOOK.md", sigil / "README.md"):
        assert "./bootstrap.sh" in g.read_text(encoding="utf-8"), g
