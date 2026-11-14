"""An operator-run sovereign command that WRITES the cross-plane seam writes the tree the configured units use.

`sigil eval-grant arm|revoke|reconcile` publish the eval grant / attestation (and raise its rollback floor) under
the seam base this process resolves; the keyless offense plane reads the one the shipped units set
(VIGIL_BASE_DIR=%h/.sigil/credit-lease). An arm or a reconcile writes only to the tree the configured seam WRITER
units agree on (the cockpit, the settle drain, the console; the backup units only capture the seam): run from a
shell that resolves another tree, or while those units disagree, it refuses — before anything is appended,
published or cleared — and `sigil ops-sweep reservations` without --base-dir does too. A REVOKE (the safe direction)
is never refused for that: it is published to every writer unit's seam, so it reaches whichever tree an offense
plane reads. With nothing configured on the host every verb behaves exactly as before.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the "not the units' seam" refusal in ``_writer_seam_base``   -> test_*_refuses_*_the_units_seam
  * the "units disagree" refusal                                 -> test_units_that_disagree_refuse_every_writer
  * the backup units compared as writers                         -> test_a_backup_units_seam_never_blocks_a_writer
  * the eval-grant wiring                                        -> test_eval_grant_*_refuses_*
  * a revoke refused, or published to one seam only             -> test_a_revoke_reaches_every_writer_units_seam
  * one failing seam stops the others / reports success          -> test_a_revoke_is_tried_on_every_seam_when_one_fails
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
_BACKUP = _REPO / "infra/systemd/vigil-backup.service"


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


@pytest.mark.parametrize("action", ["arm", "reconcile"])
def test_eval_grant_writers_refuse_away_from_the_units_seam(home, monkeypatch, tmp_path, capsys, action):
    _install(home, _COCKPIT)
    store = _store(monkeypatch, tmp_path)
    before = sum(1 for _ in store.iter_records())
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns(action))
    assert ei.value.code == 2 and f"eval-grant {action}: refusing" in capsys.readouterr().err
    assert sum(1 for _ in store.iter_records()) == before               # nothing appended (no owner key minted)
    assert not (tmp_path / ".vigil-live").exists()                      # nothing published in the wrong tree


def _revoked_on(seam: str, slug: str = "eng-x") -> bool:
    """The seam carries an owner-sealed publication of ``slug`` (at or above its floor) holding the revoke."""
    from sigil.governor.identity import owner_pubkey
    from sigil.seam_migrate import _publication_verifies
    from vigil_integration.live.eval_capability_grant import read_eval_capability_grants
    return (_publication_verifies("eval_grants", seam, slug, owner_pubkey())
            and any(r.get("state") == "revoked" for r in read_eval_capability_grants(seam, slug)))


def test_a_revoke_lands_on_the_units_seam_from_any_shell(home, monkeypatch, tmp_path, capsys):
    """A shell without the export: the revoke is published where the units (and so the offense plane) read, with a
    warning, and nothing lands in the shell's own tree."""
    _install(home, _COCKPIT)
    store = _store(monkeypatch, tmp_path)
    cli.cmd_eval_grant(_ns("revoke"))
    err = capsys.readouterr().err
    assert "WARNING" in err and _units_seam(home) in err
    assert any((r.payload or {}).get("state") == "revoked" for r in store.iter_records())
    assert _revoked_on(_units_seam(home)) and not (tmp_path / ".vigil-live").exists()


def test_a_revoke_reaches_every_writer_units_seam(home, monkeypatch, tmp_path, capsys):
    """While the cockpit and the settle drain disagree, an arm or a reconcile still refuses, and a revoke is
    published to both seams (one spine record)."""
    _install(home, _COCKPIT, _SETTLE)
    other = home / "elsewhere"
    env = home / ".config" / "vigil" / "settle-drain.env"
    env.parent.mkdir(parents=True)
    env.write_text(f"VIGIL_BASE_DIR={other}\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    store = _store(monkeypatch, tmp_path)
    for action in ("arm", "reconcile"):
        with pytest.raises(SystemExit) as ei:
            cli.cmd_eval_grant(_ns(action))
        assert ei.value.code == 2 and "disagree on the seam base" in capsys.readouterr().err
    cli.cmd_eval_grant(_ns("revoke"))
    out = capsys.readouterr()
    assert "WARNING" in out.err and "Published to 2 seams" in out.out
    assert sum(1 for r in store.iter_records() if (r.payload or {}).get("state") == "revoked") == 1
    assert _revoked_on(_units_seam(home)) and _revoked_on(str(other))


@pytest.mark.parametrize("fails", ["first", "other"])
def test_a_revoke_is_tried_on_every_seam_when_one_fails(home, monkeypatch, tmp_path, capsys, fails):
    """One seam failing never stops the revoke reaching the others: the failure raises the close alarm (`vigil
    doctor`) and the command fails (exit 1 / the first seam's error) — never a silent success."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.seam_publish import read_close_alarm
    _install(home, _COCKPIT, _SETTLE)
    other = home / "elsewhere"
    env = home / ".config" / "vigil" / "settle-drain.env"
    env.parent.mkdir(parents=True)
    env.write_text(f"VIGIL_BASE_DIR={other}\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    _store(monkeypatch, tmp_path)
    if fails == "first":
        real_revoke = EvalCapabilityGrant.revoke

        def _revoke(self, **kw):
            real_revoke(self, **kw)
            raise RuntimeError("the first seam's publish failed")
        monkeypatch.setattr(EvalCapabilityGrant, "revoke", _revoke)
        with pytest.raises(RuntimeError):
            cli.cmd_eval_grant(_ns("revoke"))
        assert _revoked_on(str(other))
    else:
        real_retract = EvalCapabilityGrant._retract

        def _retract(self, slug, **kw):
            if self._seam_override == str(other):
                raise RuntimeError("unreachable seam")
            return real_retract(self, slug, **kw)
        monkeypatch.setattr(EvalCapabilityGrant, "_retract", _retract)
        with pytest.raises(SystemExit) as ei:
            cli.cmd_eval_grant(_ns("revoke"))
        assert ei.value.code == 1 and str(other) in capsys.readouterr().err
        assert _revoked_on(_units_seam(home)) and read_close_alarm() is not None


def test_a_backup_units_seam_never_blocks_a_writer(home, monkeypatch, tmp_path, capsys):
    """A backup unit still on an older env file resolves another tree: `vigil doctor` reports that, but it only
    captures the seam — a revoke, an arm's seam check and a reconcile run on the writer units' seam."""
    from vigil_integration.seam_base_units import seam_base_agreement
    _install(home, _COCKPIT, _SETTLE, _BACKUP)
    env = home / ".config" / "vigil" / "backup.env"
    env.parent.mkdir(parents=True)
    env.write_text("VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR=.vigil-live\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    assert any("disagree on the seam base" in i for i in seam_base_agreement()[1])     # doctor still reports it
    _store(monkeypatch, tmp_path)
    assert cli._writer_seam_base("eval-grant arm") == _units_seam(home)
    cli.cmd_eval_grant(_ns("revoke"))
    assert "WARNING" not in capsys.readouterr().err and _revoked_on(_units_seam(home))
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["ok"] is True


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
