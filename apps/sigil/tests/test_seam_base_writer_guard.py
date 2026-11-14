"""An operator-run sovereign command that WRITES the cross-plane seam writes the tree the configured units use.

`sigil eval-grant arm|revoke|reconcile` publish the eval grant / attestation (and raise its rollback floor) under
the seam base this process resolves; the keyless offense plane reads the one the shipped units set
(VIGIL_BASE_DIR=%h/.sigil/credit-lease). Run from a shell without that export, a revoke would land in another tree
(the offense plane keeps honouring the old publication) and a reconcile would confirm an empty tree and clear the
`vigil doctor` alarm. `sigil ops-sweep reservations` without --base-dir would read settlement markers from the
wrong tree. Each now refuses — before anything is appended, published or cleared — when the seam it resolves is
not the one the configured units agree on; with nothing configured on the host it behaves exactly as before.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the "not the units' seam" refusal in ``_writer_seam_base``   -> test_*_refuses_*_the_units_seam
  * the "units disagree" refusal                                 -> test_units_that_disagree_refuse_every_writer
  * the eval-grant wiring                                        -> test_eval_grant_*_refuses_*
  * the ops-sweep wiring (only without an explicit --base-dir)   -> test_ops_sweep_*
  * the eval publishers' ``_base_dir`` through the shared resolver -> test_the_eval_publishers_write_the_tree_*
"""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigil import cli

_REPO = Path(__file__).resolve().parents[3]
_COCKPIT = _REPO / "apps/sigil/deploy/systemd/sigil-cockpit.service"
_SETTLE = _REPO / "infra/systemd/vigil-settle-drain.service"


@pytest.fixture
def home(monkeypatch, tmp_path):
    h = tmp_path / "home"
    (h / ".config" / "systemd" / "user").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("SIGIL_HOME", tempfile.mkdtemp())
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    monkeypatch.delenv("VIGIL_SETTLE_BASE_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    return h


def _install(home: Path, *units: Path) -> None:
    for u in units:
        shutil.copy(u, home / ".config" / "systemd" / "user" / u.name)


def _units_seam(home: Path) -> str:
    return str(home / ".sigil" / "credit-lease")


def test_nothing_configured_is_the_resolver_unchanged(home, tmp_path):
    assert cli._writer_seam_base("x") == str(tmp_path / ".vigil-live")


def test_the_units_seam_exported_is_accepted(home, monkeypatch):
    _install(home, _COCKPIT, _SETTLE)
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    assert cli._writer_seam_base("x") == _units_seam(home)


def test_a_shell_without_the_export_refuses_away_from_the_units_seam(home, capsys):
    _install(home, _COCKPIT)
    with pytest.raises(SystemExit) as ei:
        cli._writer_seam_base("eval-grant revoke")
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert f"export VIGIL_BASE_DIR={_units_seam(home)}" in err and err.startswith("eval-grant revoke: refusing")


def test_units_that_disagree_refuse_every_writer(home, monkeypatch, capsys):
    _install(home, _COCKPIT, _SETTLE)
    env = home / ".config" / "vigil" / "settle-drain.env"
    env.parent.mkdir(parents=True)
    env.write_text(f"VIGIL_BASE_DIR={home / 'elsewhere'}\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))       # even agreeing with ONE of them
    with pytest.raises(SystemExit) as ei:
        cli._writer_seam_base("eval-grant reconcile")
    assert ei.value.code == 2 and "disagree on the seam base" in capsys.readouterr().err


def test_a_contradictory_setting_is_refused_as_for_the_drain(home, monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_BASE_DIR", "%h/.sigil/credit-lease")
    with pytest.raises(SystemExit):
        cli._writer_seam_base("x")
    assert "unexpanded systemd specifier" in capsys.readouterr().err


# ---- the wiring -----------------------------------------------------------------------------------------

def _store(monkeypatch, tmp_path):
    from sigil.spine.store import SpineStore
    store = SpineStore(str(tmp_path / "spine.jsonl"))
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    return store


def _ns(action, **kw):
    base = dict(action=action, engagement="eng-x", target=None, reason=None, overrides=None, evaluator=None,
                evaluator_pubkey=None, evaluator_pop=None, max_covered_actions="0", issued_anchor=None,
                charter_hash=None, environment="live")
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.mark.parametrize("action", ["arm", "revoke", "reconcile"])
def test_eval_grant_writers_refuse_away_from_the_units_seam(home, monkeypatch, tmp_path, capsys, action):
    _install(home, _COCKPIT)
    store = _store(monkeypatch, tmp_path)
    before = sum(1 for _ in store.iter_records())
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns(action))
    assert ei.value.code == 2 and f"eval-grant {action}: refusing" in capsys.readouterr().err
    assert sum(1 for _ in store.iter_records()) == before               # nothing appended (no owner key minted)
    assert not (tmp_path / ".vigil-live").exists()                      # nothing published in the wrong tree


def test_eval_grant_reconcile_refuses_to_clear_the_alarm_from_the_wrong_tree(home, monkeypatch, tmp_path):
    from sigil.governor.seam_publish import raise_close_alarm, read_close_alarm
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    assert raise_close_alarm("a revoke was not confirmed", cause="seam_unreconciled", failed=["grant:eng-x"])
    with pytest.raises(SystemExit):
        cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert read_close_alarm() is not None                               # the doctor alarm still stands


def test_eval_grant_reconcile_runs_on_the_units_seam(home, monkeypatch, tmp_path, capsys):
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_eval_grant_status_reads_only_and_is_not_guarded(home, monkeypatch, tmp_path, capsys):
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    cli.cmd_eval_grant(_ns("status"))
    assert json.loads(capsys.readouterr().out)["armed"] is False


def _sweep(base_dir=""):
    return SimpleNamespace(sweep_cmd="reservations", apply=False, base_dir=base_dir, completion_spool="",
                           ttl=86400.0, now=None)


def test_ops_sweep_without_base_dir_refuses_away_from_the_units_seam(home, monkeypatch, tmp_path, capsys):
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_ops_sweep(_sweep())
    assert ei.value.code == 2 and "ops-sweep reservations: refusing" in capsys.readouterr().err


def test_ops_sweep_with_an_explicit_base_dir_is_the_operators_choice(home, monkeypatch, tmp_path, capsys):
    """An explicit --base-dir (e.g. an older install's tree the runbook says to sweep) is used as given."""
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    try:
        cli.cmd_ops_sweep(_sweep(base_dir=str(home / ".sigil" / ".vigil-live")))
    except SystemExit:
        pass                                                            # e.g. no owner identity here
    assert "refusing" not in capsys.readouterr().err


# ---- the eval publishers (writer) and the offense verifier (reader) resolve ONE path -----------------------

@pytest.mark.parametrize("env", ["", "rel/seam", "ABS"], ids=["unset", "relative", "absolute"])
def test_the_eval_publishers_write_the_tree_and_floor_the_offense_reader_resolves(home, monkeypatch, tmp_path, env):
    """The sovereign eval-grant / eval-attestation publishers and the offense plane's verifier both go through
    vigil_core.seam_base: the publication directory and the shared rollback floor the sovereign raises are the
    ones the offense reader (conjunctive gate: ``resolve_seam_base(base_dir)``) looks at — as absolute paths."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.eval_offense_attestation import EvalOffenseAttestation
    from vigil_core.seam_base import resolve_seam_base
    from vigil_integration.live import eval_attestation, eval_capability_grant
    if env:
        monkeypatch.setenv("VIGIL_BASE_DIR", str(tmp_path / "abs-seam") if env == "ABS" else env)
    store = _store(monkeypatch, tmp_path)
    want = resolve_seam_base(None)
    assert Path(want).is_absolute()
    for pub, live in ((EvalCapabilityGrant(store), eval_capability_grant),
                      (EvalOffenseAttestation(store), eval_attestation)):
        assert pub._base_dir() == want
        floor = live._shared_floor_path(pub._base_dir(), "eng-x")
        assert floor == live._shared_floor_path(resolve_seam_base(None), "eng-x")
        assert floor is not None and floor.is_absolute()
