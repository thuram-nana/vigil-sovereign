"""The offense CLI and `vigil up` meet the sovereign plane in ONE seam base.

The sovereign plane publishes leases, target authorizations, eval grants / attestations (with their rollback
floors) and approval tokens under the seam base it resolves through ``vigil_core.seam_base``
($VIGIL_BASE_DIR, else ./.vigil-live). The offense side has to read the same tree:

* every ``vigil <verb> --base-dir`` defaults to that resolver (not a bare relative ``.vigil-live`` that ignores
  $VIGIL_BASE_DIR), so a verb run in a shell that exports VIGIL_BASE_DIR reads what the cockpit wrote;
* ``vigil up`` refuses an explicit --base-dir that names another directory than $VIGIL_BASE_DIR (or a literal
  systemd specifier), and pins its base into EVERY child's VIGIL_BASE_DIR — the cockpit it spawns publishes
  where the console and the engines it launches (handed the same base as VIGIL_LIVE_DIR / --base-dir) read.

Mutation-verify targets (each neuter reds a NAMED test here):
  * build_parser's ``seam = resolve_seam_base()`` (-> ".vigil-live")    -> test_every_base_dir_default_follows_vigil_base_dir
  * _cmd_up's require_seam_base refusal                                -> test_vigil_up_refuses_*
  * run_up's ``_track`` seam merge                                     -> test_run_up_pins_the_seam_into_every_child
  * run_up's cockpit seam merge                                        -> test_run_up_pins_the_seam_into_every_child
  * the console / api static (restart) env seam                        -> test_run_up_pins_the_seam_into_every_child

Integration-guard leg (no framework): PYTHONPATH=integration:apps/sigil:packages/core/vigil_core.
"""
from __future__ import annotations

import argparse
import os
from queue import Queue
from types import SimpleNamespace

import pytest

from vigil_integration import cli as climod
from vigil_integration import uiproxy


# `--base-dir` options that do NOT name the seam: a governance-key home that defaults to the run dir.
_NOT_THE_SEAM = {"proof-export", "dossier"}


def _base_dir_actions(parser: argparse.ArgumentParser, prefix: str = ""):
    """(verb path, action) for every optional ``--base-dir`` that names the seam / engine home, on every
    (nested) subparser (``launch-drain`` takes it as a REQUIRED argument, so it has no default to follow)."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for verb, sp in action.choices.items():
                path = f"{prefix} {verb}".strip()
                yield from _base_dir_actions(sp, path)
        elif "--base-dir" in action.option_strings and not action.required and prefix not in _NOT_THE_SEAM:
            yield prefix, action


def test_every_base_dir_default_follows_vigil_base_dir(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    parser = climod.build_parser()
    found = list(_base_dir_actions(parser))
    assert len(found) >= 35, found                       # engage, up/down/panic, backup/restore, approve, ...
    wrong = {verb: a.default for verb, a in found if a.default != str(tmp_path / "seam")}
    assert wrong == {}, wrong
    for argv in (["engage"], ["up"], ["down"], ["panic"], ["backup"], ["restore", "some-backup"], ["ledger", "who"]):
        assert parser.parse_args(argv).base_dir == str(tmp_path / "seam"), argv
    assert parser.parse_args(["ledger", "who"]).path == str(tmp_path / "seam" / "usage-ledger.jsonl")


def test_with_vigil_base_dir_unset_the_default_is_the_same_directory_as_before(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    parser = climod.build_parser()
    for verb, a in _base_dir_actions(parser):
        assert a.default == str(tmp_path / ".vigil-live"), verb           # ./.vigil-live, made absolute


# ---- vigil up -------------------------------------------------------------------------------------------

def _up_args(**over) -> SimpleNamespace:
    base = dict(services=False, host="127.0.0.1", port=8770, domain="", base_dir=".vigil-live", no_browser=True)
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def _run_up_calls(monkeypatch):
    monkeypatch.delenv("VIGIL_POSTURE", raising=False)
    calls: list = []

    def _fake_run_up(**kw):
        calls.append(kw)
        return 0
    monkeypatch.setattr("vigil_integration.uiproxy.run_up", _fake_run_up)
    return calls


def test_vigil_up_refuses_a_base_dir_contradicting_vigil_base_dir(monkeypatch, tmp_path, capsys, _run_up_calls):
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    assert climod._cmd_up(_up_args(base_dir=str(tmp_path / "other"))) == 2
    assert _run_up_calls == []                                          # refused before anything is brought up
    err = capsys.readouterr().err
    assert "REFUSED" in err and "contradictory seam base settings" in err


def test_vigil_up_refuses_an_unexpanded_specifier(monkeypatch, tmp_path, capsys, _run_up_calls):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", "%h/.sigil/credit-lease")
    assert climod._cmd_up(climod.build_parser().parse_args(["up"])) == 2
    assert _run_up_calls == [] and "unexpanded systemd specifier" in capsys.readouterr().err


def test_vigil_up_hands_run_up_the_one_seam_base(monkeypatch, tmp_path, _run_up_calls):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "seam"))
    assert climod._cmd_up(climod.build_parser().parse_args(["up"])) == 0
    assert climod._cmd_up(_up_args(base_dir=str(tmp_path / "seam") + "/")) == 0       # same dir, other spelling
    monkeypatch.delenv("VIGIL_BASE_DIR")
    assert climod._cmd_up(_up_args()) == 0                                            # nothing set: ./.vigil-live
    assert [c["base_dir"] for c in _run_up_calls] == [str(tmp_path / "seam"), str(tmp_path / "seam"),
                                                       str(tmp_path / ".vigil-live")]


class _FakeProc:
    pid = 4242

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


def test_run_up_pins_the_seam_into_every_child(monkeypatch, tmp_path):
    """Whatever VIGIL_BASE_DIR the parent inherited, every backend `vigil up` spawns (the cockpit, the offense
    console + api — at boot AND in the restart spec — and the SaaS planes) is handed run_up's base."""
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "ambient-elsewhere"))
    bins = {}
    for name in ("sigil", "crucible"):
        bins[name] = tmp_path / "bin" / name
        bins[name].parent.mkdir(exist_ok=True)
        bins[name].write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(uiproxy.dispatch, "resolve", lambda n: bins[n])
    monkeypatch.setattr(uiproxy, "_port_free", lambda h, p: True)
    monkeypatch.setattr(uiproxy, "_wait_listening", lambda h, p, d: True)
    monkeypatch.setattr(uiproxy, "_await_token", lambda q, proc, *a, **k: "tok")
    monkeypatch.setattr(uiproxy, "_resolve_offense_llm_env", lambda *a, **k: {})
    monkeypatch.setattr(uiproxy, "_console_vigil_bin", lambda b: "")
    envs: dict = {}

    def _fake_capture(argv, log_path, *, extra_env=None):
        envs[argv[1]] = dict(extra_env or {})
        return _FakeProc(), Queue()

    def _fake_spawn(argv, log_path, *, extra_env=None):
        envs[argv[1]] = dict(extra_env or {})
        if argv[1] == "serve-customer":
            raise OSError("stop here")                                # aborts run_up cleanly after the capture
        return _FakeProc()

    specs: list = []

    class _RecordingPlaneControl:
        def __init__(self, s, **_kw):
            specs.extend(s)

    monkeypatch.setattr(uiproxy, "_spawn_capture", _fake_capture)
    monkeypatch.setattr(uiproxy, "_spawn", _fake_spawn)
    monkeypatch.setattr(uiproxy, "PlaneControl", _RecordingPlaneControl)

    base = tmp_path / "base"
    rc = uiproxy.run_up(host="127.0.0.1", port=0, domain="", base_dir=str(base), no_browser=True, with_saas=True)
    assert rc == 1
    want = str(base.resolve())
    got = {child: env.get("VIGIL_BASE_DIR") for child, env in envs.items()}
    assert got == {"serve": want, "console": want, "api": want, "serve-customer": want}, got
    assert envs["console"]["VIGIL_LIVE_DIR"] == want                  # the engines' --base-dir: the same tree
    restart = {name: env.get("VIGIL_BASE_DIR") for name, _argv, _log, env, _h, _p in specs}
    assert restart == {"offense-console": want, "offense-api": want}, restart
    assert os.environ["VIGIL_BASE_DIR"] == str(tmp_path / "ambient-elsewhere")   # the parent env is untouched


def test_the_ambient_value_still_reaches_children_outside_run_up(monkeypatch, tmp_path):
    # _child_env itself is unchanged: only run_up pins the seam (via extra_env), so other callers keep the
    # inherited value — the pin is scoped to the process tree `vigil up` owns.
    monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "x"))
    assert uiproxy._child_env()["VIGIL_BASE_DIR"] == str(tmp_path / "x")
