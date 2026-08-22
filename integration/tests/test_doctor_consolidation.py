"""W6-6 — ONE doctor, ONE shared check registry, honoured exit code (the `vigil doctor` side).

`vigil doctor` and `sigil doctor` were two disjoint self-checks. They now share the registry in
``vigil_core.doctor``: the same ``REQUIRED_CONTROLS`` spec and the same fail-closed, opt-in gate decision.
This file proves the integration entry point:

* the registry is literally the SHARED one (`_PRODUCTION_GATE is vigil_core.doctor.REQUIRED_CONTROLS`) —
  this is the assertion that FAILS WITHOUT THE CHANGE (on a tree without the fix `_PRODUCTION_GATE` was a
  private literal tuple, not the shared object);
* `security_report()` — the ONE security block both doctors render — returns the posture + gate;
* the CLI `_cmd_doctor` honours the gate exit code: armed + a bad posture ⇒ non-zero, and the NEGATIVE
  CONTROL, armed + a good posture ⇒ 0, so the exit is READ, not constant.

Pure-stdlib / integration plane — imports neither ``sigil`` nor ``framework`` — so it runs in the required
"integration two-env boundary (P5)" CI job.
"""
from __future__ import annotations

import pathlib
from types import SimpleNamespace

import vigil_core.doctor as core_doctor
from vigil_integration import cli as climod
from vigil_integration import doctor as dmod


def test_the_registry_is_the_shared_vigil_core_one():
    # THE consolidation invariant: the integration gate spec IS the shared registry object, not a copy.
    assert dmod._PRODUCTION_GATE is core_doctor.REQUIRED_CONTROLS


def test_security_report_returns_the_shared_block(tmp_path):
    rep = dmod.security_report(tmp_path)
    assert set(rep) == {"posture", "backup_timers", "production_gate"}
    controls = {p["control"] for p in rep["posture"]}
    # the posture block carries the per-control lines the README quotes verbatim.
    assert {"egress-gate", "vault", "sovereignty", "entitlement", "backups", "charter"} <= controls


def _run_doctor(monkeypatch, capsys, *, posture_env, gate_ok):
    """Drive `_cmd_doctor` with a controlled gate verdict and return its exit code."""
    if posture_env is None:
        monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    else:
        monkeypatch.setenv("VIGIL_POSTURE", posture_env)

    good = {c: (sorted(g)[0], "") for (c, g, _r) in core_doctor.REQUIRED_CONTROLS}
    bad = {c: ("UNKNOWN", "unreadable") for (c, _g, _r) in core_doctor.REQUIRED_CONTROLS}
    states = good if gate_ok else bad
    # a minimal report: no venvs/dirs failures — isolate the gate's effect on the exit code.
    fake = {
        "ok": True, "issues": [], "notes": [], "binaries": {}, "docker_compose": True,
        "venvs": {}, "dirs": {}, "ui_ports": {}, "docker_services": {},
        "posture": [{"control": c, "state": s, "detail": d} for c, (s, d) in states.items()],
        "backup_timers": [],
    }
    gate = core_doctor.evaluate(states, armed=(posture_env is not None))
    if gate["armed"]:
        fake["production_gate"] = gate
        if not gate["ok"]:
            fake["ok"] = False
            fake["issues"] = [f"PRODUCTION posture: {u['control']} is {u['state']}" for u in gate["unmet"]]
    monkeypatch.setattr(dmod, "collect", lambda repo: fake)
    rc = climod._cmd_doctor(SimpleNamespace(json=False))
    capsys.readouterr()
    return rc


def test_cli_exit_nonzero_on_bad_posture_when_armed(monkeypatch, capsys):
    assert _run_doctor(monkeypatch, capsys, posture_env="production", gate_ok=False) != 0


def test_cli_exit_zero_on_good_posture_when_armed(monkeypatch, capsys):
    # NEGATIVE CONTROL: same armed path, a GOOD posture ⇒ exit 0 (the exit is read, not always non-zero).
    assert _run_doctor(monkeypatch, capsys, posture_env="production", gate_ok=True) == 0


def test_cli_exit_zero_when_posture_unset(monkeypatch, capsys):
    # OPT-IN: with VIGIL_POSTURE unset the gate is inert even with a bad posture ⇒ exit 0 (byte-identical).
    assert _run_doctor(monkeypatch, capsys, posture_env=None, gate_ok=False) == 0


_REPO = pathlib.Path(__file__).resolve().parents[2]


def test_readme_posture_block_is_ci_regenerated_from_the_registry():
    """AC3 anti-rot guard (REQUIRED job P5): README.md must contain, VERBATIM, the canonical
    PRODUCTION-posture-gate block regenerated from ``REQUIRED_CONTROLS`` + ``evaluate`` on a fixed
    misconfigured fixture — the SAME formatter `vigil doctor` prints. If the registry changes (a control
    added / removed / reordered, or a requirement-text edit) the rendered block changes and this fails
    until README.md is regenerated, so the documented block can never drift from the code.

    This FAILS WITHOUT the fix: before this slice the README block was hand-authored and no generator
    existed, so `render_readme_posture_block` was undefined and no verbatim block was present."""
    block = core_doctor.render_readme_posture_block()
    readme = (_REPO / "README.md").read_text(encoding="utf-8")
    assert block in readme, (
        "README.md does not contain the canonical doctor posture block verbatim — regenerate it with "
        "`vigil_core.doctor.render_readme_posture_block()`. Expected block:\n\n" + block)


def test_readme_regenerated_block_is_the_doctors_own_output():
    """The regenerated block is not a lookalike: it is exactly what `vigil doctor`'s renderer emits for
    the same gate verdict — both go through the ONE shared ``render_gate_block`` formatter."""
    gate = dict(core_doctor.evaluate(core_doctor.README_POSTURE_FIXTURE, armed=True))
    gate["posture"] = "production"
    assert core_doctor.render_readme_posture_block() == "\n".join(core_doctor.render_gate_block(gate))


def test_readme_guard_would_catch_a_registry_change():
    """NEGATIVE CONTROL: the guard is not a no-op — a registry edit (here, a mutated requirement string)
    yields a block that is NOT in README.md, so the guard would fail. Proves it actually pins the text."""
    fixture = dict(core_doctor.README_POSTURE_FIXTURE)
    gate = dict(core_doctor.evaluate(fixture, armed=True))
    gate["posture"] = "production"
    controls = [dict(c) for c in gate["controls"]]
    controls[0]["requirement"] = "MUTATED requirement text that is not in the README zzz"
    gate["controls"] = controls
    mutated = "\n".join(core_doctor.render_gate_block(gate))
    readme = (_REPO / "README.md").read_text(encoding="utf-8")
    assert mutated not in readme
