"""An operator-run sovereign command that WRITES the cross-plane seam writes the tree the configured units use.

`sigil eval-grant arm|revoke|reconcile` publish the eval grant / attestation (and raise its rollback floor) under
the seam base this process resolves; the keyless offense plane reads the one the shipped units set
(VIGIL_BASE_DIR=%h/.sigil/credit-lease). An arm publishes to ONE tree, the one the configured seam WRITER units agree
on (the cockpit, the settle drain, the console; the backup units only capture the seam): run from a shell that
resolves another tree, or while those units disagree, it refuses — before anything is appended or published — and
`sigil ops-sweep reservations` without --base-dir does too, against the cockpit's and settle drain's seam. A REVOKE
or a RECONCILE (the safe directions) is never refused for that: it runs on every writer unit's seam, so it reaches
whichever tree an offense plane reads, and a reconcile clears the close alarm only once every one is confirmed. With
nothing configured on the host every verb behaves exactly as before.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the "not the units' seam" refusal in ``_writer_seam_base``   -> test_*_refuses_*_the_units_seam
  * the "units disagree" refusal                                 -> test_units_that_disagree_refuse_every_writer
  * the backup units compared as writers                         -> test_a_backup_units_seam_never_blocks_a_writer
  * the eval-grant wiring                                        -> test_eval_grant_*_refuses_*
  * a revoke refused, or published to one seam only             -> test_a_revoke_reaches_every_writer_units_seam
  * a reconcile refused, or run on the shell's tree              -> test_eval_grant_reconcile_never_clears_the_alarm_from_the_wrong_tree
  * a reconcile settling the alarm per seam                      -> test_a_reconcile_failing_on_one_seam_keeps_the_alarm
  * a seam the alarm names left out of a reconcile              -> test_a_reconcile_runs_on_a_seam_the_alarm_names
  * a close over two seams appending a revoke per seam          -> test_a_close_over_two_seams_appends_one_revoke
  * a seam not floored again after the revoke lands             -> test_a_close_over_two_seams_floors_every_seam_above_a_concurrent_append
  * a tree holding a publication left out of a reconcile         -> test_a_reconcile_reaches_another_tree_that_holds_a_publication
  * the close alarm's seams not merged / kept / dropped          -> test_the_alarm_keeps_the_seams_a_reconcile_did_not_confirm
  * a one-seam close clearing names another seam still holds    -> test_an_offense_close_never_clears_the_alarm_for_a_seam_it_did_not_run_on
  * one failing seam stops the others / reports success          -> test_a_revoke_is_tried_on_every_seam_when_one_fails
  * a seam published from a spine without the revoke            -> test_a_revoke_whose_append_fails_publishes_nothing_and_ungrants_every_seam
  * another seam retracted only after the append                 -> test_every_seam_is_ungranted_before_the_revoke_is_appended
  * a tree holding a publication left out of the revoke          -> test_a_revoke_reaches_another_tree_that_holds_a_publication
  * the ops-sweep wiring (only without an explicit --base-dir)   -> test_ops_sweep_*
  * the eval publishers' ``_base_dir`` through the shared resolver -> test_the_eval_publishers_write_the_tree_*
"""
from __future__ import annotations

import json
import os
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


def test_eval_grant_arm_refuses_away_from_the_units_seam(home, monkeypatch, tmp_path, capsys):
    _install(home, _COCKPIT)
    store = _store(monkeypatch, tmp_path)
    before = sum(1 for _ in store.iter_records())
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns("arm"))
    assert ei.value.code == 2 and "eval-grant arm: refusing" in capsys.readouterr().err
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
    """While the cockpit and the settle drain disagree, an arm still refuses (it publishes to one seam), a revoke is
    published to both seams (one spine record), and a reconcile runs on both."""
    _install(home, _COCKPIT, _SETTLE)
    other = home / "elsewhere"
    env = home / ".config" / "vigil" / "settle-drain.env"
    env.parent.mkdir(parents=True)
    env.write_text(f"VIGIL_BASE_DIR={other}\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    store = _store(monkeypatch, tmp_path)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns("arm"))
    assert ei.value.code == 2 and "disagree on the seam base" in capsys.readouterr().err
    cli.cmd_eval_grant(_ns("revoke"))
    out = capsys.readouterr()
    assert "WARNING" in out.err and "Published to 2 seams" in out.out
    assert sum(1 for r in store.iter_records() if (r.payload or {}).get("state") == "revoked") == 1
    assert _revoked_on(_units_seam(home)) and _revoked_on(str(other))
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = json.loads(capsys.readouterr().out)
    assert got["ok"] is True and got["seams"] == [_units_seam(home), str(other)]
    assert got["republished"] == ["eng-x"]


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
        real_publish = EvalCapabilityGrant._publish

        def _publish(self, slug):
            if self._seam_override == _units_seam(home):
                raise RuntimeError("the first seam's publish failed")
            return real_publish(self, slug)
        monkeypatch.setattr(EvalCapabilityGrant, "_publish", _publish)
        with pytest.raises(SystemExit) as ei:
            cli.cmd_eval_grant(_ns("revoke"))
        assert ei.value.code == 1 and _units_seam(home) in capsys.readouterr().err
        assert _revoked_on(str(other)) and read_close_alarm() is not None
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


def _two_seams(home, monkeypatch):
    """The cockpit on the units' seam, the settle drain's env file naming another tree: ``(seam_a, seam_b)``."""
    _install(home, _COCKPIT, _SETTLE)
    other = home / "elsewhere"
    env = home / ".config" / "vigil" / "settle-drain.env"
    env.parent.mkdir(parents=True)
    env.write_text(f"VIGIL_BASE_DIR={other}\n", encoding="utf-8")
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    for k in ("VIGIL_EVAL_GRANT_HIGHWATER_DIR", "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR", "VIGIL_SEAM_MIGRATION_GUARD"):
        monkeypatch.delenv(k, raising=False)
    return _units_seam(home), str(other)


def _granted_on(rig):
    from tests.test_eval_publish_fail_closed import SLUG, TGT  # type: ignore
    from vigil_integration.live import eval_capability_grant as live
    pinned = [rig.owner.public_key_b64]
    return lambda b: live.verify_eval_capability_grant(str(b), engagement_slug=SLUG, target=TGT,
                                                       trusted_owner_pubkeys=pinned).granted


@pytest.mark.parametrize("retract", ["confirmed", "unconfirmed"])
def test_a_revoke_whose_append_fails_publishes_nothing_and_ungrants_every_seam(home, monkeypatch, tmp_path, retract):
    """The revoke record never lands (a full disk): no seam receives a publication read from a spine without the
    revoke, and every seam — the one that honoured the grant included — reads default-ungranted; the error stands. A
    seam whose retraction cannot be confirmed raises the close alarm (`vigil doctor`)."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.seam_publish import read_close_alarm
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    seam_a, seam_b = _two_seams(home, monkeypatch)
    rig = _Rig("grant")                                                  # armed on the units' seam A only
    ok = _granted_on(rig)
    assert ok(seam_a) and not ok(seam_b)
    if retract == "unconfirmed":
        real_retract = EvalCapabilityGrant._retract

        def _retract(self, slug, **kw):
            done = real_retract(self, slug, **kw)
            return done and self._seam_override != seam_b
        monkeypatch.setattr(EvalCapabilityGrant, "_retract", _retract)
    store = rig.store
    real_append = store.append

    def _append(*a, **kw):
        if (kw.get("payload") or {}).get("state") == "revoked":
            raise OSError(28, "No space left on device")
        return real_append(*a, **kw)
    monkeypatch.setattr(store, "append", _append)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    with pytest.raises(OSError):
        cli.cmd_eval_grant(_ns("revoke", engagement=SLUG))
    assert not ok(seam_a) and not ok(seam_b)
    from vigil_integration.live.eval_capability_grant import eval_capability_grant_path
    assert not eval_capability_grant_path(seam_b, SLUG).exists()       # nothing published from that spine
    alarm = read_close_alarm()
    assert (alarm is not None and seam_b in alarm.get("reason", "") + json.dumps(alarm)) == (retract == "unconfirmed")


def test_every_seam_is_ungranted_before_the_revoke_is_appended(home, monkeypatch, tmp_path):
    """Each seam's publication of the grant is retracted before the one spine append, so a revoke stopped right after
    it (the cockpit ceremony stops a CLI after 60 s) has already un-granted every seam."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    seam_a, seam_b = _two_seams(home, monkeypatch)
    rig = _Rig("grant")
    EvalCapabilityGrant(rig.store, owner_key=rig.owner, base_dir=seam_b)._publish(SLUG)   # B honours it too
    ok = _granted_on(rig)
    assert ok(seam_a) and ok(seam_b)
    store = rig.store
    real_append, at_append = store.append, []

    def _append(*a, **kw):
        if (kw.get("payload") or {}).get("state") == "revoked":
            at_append.append((ok(seam_a), ok(seam_b)))
        return real_append(*a, **kw)
    monkeypatch.setattr(store, "append", _append)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    cli.cmd_eval_grant(_ns("revoke", engagement=SLUG))
    assert at_append == [(False, False)]
    assert _revoked_on(seam_a, SLUG) and _revoked_on(seam_b, SLUG)


@pytest.mark.parametrize("where", ["shell", "vigil_up"])
def test_a_revoke_reaches_another_tree_that_holds_a_publication(home, monkeypatch, tmp_path, capsys, where):
    """The grant was published, before the upgrade, in this shell's tree or a running `vigil up`'s base: the revoke
    reaches that tree too (it only un-grants) — never a REVOKED report while a tree still honours the grant."""
    import os

    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    for k in ("VIGIL_EVAL_GRANT_HIGHWATER_DIR", "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR", "VIGIL_SEAM_MIGRATION_GUARD"):
        monkeypatch.delenv(k, raising=False)
    old_tree = tmp_path / ".vigil-live" if where == "shell" else tmp_path / "console-base"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(old_tree))
    rig = _Rig("grant")                                                  # published in the old tree
    if where == "shell":
        monkeypatch.delenv("VIGIL_BASE_DIR")                             # the shell resolves ./.vigil-live
    else:
        monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
        state = tmp_path / "state"
        (state / "vigil").mkdir(parents=True)
        (state / "vigil" / "vigil-up.json").write_text(json.dumps(
            {"schema": "vigil-up-pointer-v1", "base": str(old_tree), "pid": os.getpid()}))
        monkeypatch.setenv("XDG_STATE_HOME", str(state))
    _install(home, _COCKPIT)                                             # the units: %h/.sigil/credit-lease
    ok = _granted_on(rig)
    assert ok(old_tree)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    cli.cmd_eval_grant(_ns("revoke", engagement=SLUG))
    assert str(old_tree) in capsys.readouterr().err
    assert not ok(old_tree) and _revoked_on(str(old_tree), SLUG) and _revoked_on(_units_seam(home), SLUG)


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


def test_eval_grant_reconcile_never_clears_the_alarm_from_the_wrong_tree(home, monkeypatch, tmp_path, capsys):
    """A shell without the export resolves ./.vigil-live: a reconcile runs on the units' seam (a WARNING names it),
    never on the shell's tree, and the alarm is cleared only once the units' seam is confirmed."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.seam_publish import raise_close_alarm, read_close_alarm
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    assert raise_close_alarm("a revoke was not confirmed", cause="seam_unreconciled", failed=["grant:eng-x"])
    real_publish = EvalCapabilityGrant._publish

    def _unreachable(self, slug):
        raise RuntimeError("the units' seam cannot be written")
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", _unreachable)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = capsys.readouterr()
    assert ei.value.code == 1 and json.loads(got.out)["ok"] is False and "WARNING" in got.err
    alarm = read_close_alarm()
    assert alarm is not None and "grant:eng-x" in alarm["failed"]       # the doctor alarm still stands
    assert alarm.get("seams") == [_units_seam(home)]
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", real_publish)
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = json.loads(capsys.readouterr().out)
    assert got["ok"] is True and got["seams"] == [_units_seam(home)] and read_close_alarm() is None
    assert not (tmp_path / ".vigil-live").exists()                      # the shell's tree was never written


def test_eval_grant_reconcile_runs_on_the_units_seam(home, monkeypatch, tmp_path, capsys):
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["ok"] is True


@pytest.mark.parametrize("fails", ["first", "second"])
def test_a_reconcile_failing_on_one_seam_keeps_the_alarm(home, monkeypatch, tmp_path, capsys, fails):
    """Two seams (the cockpit's and the settle drain's disagree) and an alarm naming a grant: confirmed on one seam and
    not on the other, the alarm still names it, with the seam it was not confirmed on, and the command fails —
    whichever seam comes first. Once that seam is reachable, a reconcile clears it."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.seam_publish import raise_close_alarm, read_close_alarm
    seam_a, seam_b = _two_seams(home, monkeypatch)
    _store(monkeypatch, tmp_path)
    assert raise_close_alarm("a revoke was not confirmed", cause="seam_unreconciled", failed=["grant:eng-x"],
                             seams=[seam_a, seam_b])
    bad = seam_a if fails == "first" else seam_b
    real_publish = EvalCapabilityGrant._publish

    def _publish(self, slug):
        if self._seam_override == bad:
            raise RuntimeError("this seam cannot be written")
        return real_publish(self, slug)
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", _publish)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = json.loads(capsys.readouterr().out)
    assert ei.value.code == 1 and got["unconfirmed"] == ["grant:eng-x"] and got["seams"] == [seam_a, seam_b]
    alarm = read_close_alarm()
    assert alarm is not None and alarm["failed"] == ["grant:eng-x"] and alarm.get("seams") == [bad]
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", real_publish)
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["ok"] is True and read_close_alarm() is None


def test_a_reconcile_runs_on_a_seam_the_alarm_names(home, monkeypatch, tmp_path, capsys):
    """A revoke could not be confirmed on a tree a later shell no longer resolves (an earlier shell's, a stopped `vigil
    up`'s): the alarm names that seam and the reconcile runs there too — it never clears the alarm while a tree it
    did not confirm still honours the grant."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant
    from sigil.governor.seam_publish import read_close_alarm
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    for k in ("VIGIL_EVAL_GRANT_HIGHWATER_DIR", "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR", "VIGIL_SEAM_MIGRATION_GUARD"):
        monkeypatch.delenv(k, raising=False)
    old_tree = tmp_path / "old-tree"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(old_tree))
    rig = _Rig("grant")                                                  # published in the old tree
    _install(home, _COCKPIT)                                             # the units: %h/.sigil/credit-lease
    ok = _granted_on(rig)
    assert ok(old_tree)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    real_publish, real_retract = EvalCapabilityGrant._publish, EvalCapabilityGrant._retract

    def _publish(self, slug):
        if self._seam_override == str(old_tree):
            raise RuntimeError("unreachable")
        return real_publish(self, slug)

    def _retract(self, slug, **kw):
        if self._seam_override == str(old_tree):
            raise RuntimeError("unreachable")
        return real_retract(self, slug, **kw)
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", _publish)
    monkeypatch.setattr(EvalCapabilityGrant, "_retract", _retract)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_eval_grant(_ns("revoke", engagement=SLUG))           # this shell resolves the old tree
    assert ei.value.code == 1 and "eval-grant reconcile" in capsys.readouterr().err
    assert read_close_alarm().get("seams") == [str(old_tree)] and ok(old_tree)
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", real_publish)
    monkeypatch.setattr(EvalCapabilityGrant, "_retract", real_retract)
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))              # a later shell, with the runbook's export
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = capsys.readouterr()
    assert json.loads(got.out)["seams"] == [_units_seam(home), str(old_tree)] and "eval seam alarm" in got.err
    assert not ok(old_tree) and _revoked_on(str(old_tree), SLUG) and read_close_alarm() is None


@pytest.mark.parametrize("where", ["shell", "vigil_up", "shell_attestation_only"])
def test_a_reconcile_reaches_another_tree_that_holds_a_publication(home, monkeypatch, tmp_path, capsys, where):
    """A grant (or only its covering attestation) published, before the upgrade, in this shell's tree or a running
    `vigil up`'s base: the reconcile runs there too (the tree an offense plane may read), as a revoke does."""
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    from vigil_integration.live.eval_capability_grant import eval_capability_grants_root
    for k in ("VIGIL_EVAL_GRANT_HIGHWATER_DIR", "VIGIL_EVAL_OFFENSE_HIGHWATER_DIR", "VIGIL_SEAM_MIGRATION_GUARD"):
        monkeypatch.delenv(k, raising=False)
    old_tree = tmp_path / "console-base" if where == "vigil_up" else tmp_path / ".vigil-live"
    monkeypatch.setenv("VIGIL_BASE_DIR", str(old_tree))
    rig = _Rig("attestation" if where == "shell_attestation_only" else "grant")   # published in the old tree
    assert eval_capability_grants_root(old_tree).exists() == (where != "shell_attestation_only")
    if where != "vigil_up":
        monkeypatch.delenv("VIGIL_BASE_DIR")                             # the shell resolves ./.vigil-live
    else:
        monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
        state = tmp_path / "state"
        (state / "vigil").mkdir(parents=True)
        (state / "vigil" / "vigil-up.json").write_text(json.dumps(
            {"schema": "vigil-up-pointer-v1", "base": str(old_tree), "pid": os.getpid()}))
        monkeypatch.setenv("XDG_STATE_HOME", str(state))
    _install(home, _COCKPIT)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    got = capsys.readouterr()
    assert json.loads(got.out)["seams"] == [_units_seam(home), str(old_tree)] and str(old_tree) in got.err
    assert json.loads(got.out)["republished"] == ([] if where == "shell_attestation_only" else [SLUG])


def test_a_reconcile_targets_no_alarm_seam_that_is_relative_or_gone(home, monkeypatch, tmp_path, capsys):
    """Only an absolute, existing directory the alarm names is reconciled: nothing is created for one that is gone,
    and a relative entry is never resolved against this shell's directory."""
    from sigil.governor.seam_publish import raise_close_alarm, read_close_alarm
    _install(home, _COCKPIT)
    _store(monkeypatch, tmp_path)
    monkeypatch.setenv("VIGIL_BASE_DIR", _units_seam(home))
    (tmp_path / "rel-tree").mkdir()
    gone = tmp_path / "gone-tree"
    assert raise_close_alarm("x", cause="seam_unreconciled", failed=["grant:eng-x"], seams=["rel-tree", str(gone)])
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["seams"] == [_units_seam(home)] and read_close_alarm() is None
    assert not gone.exists() and list((tmp_path / "rel-tree").iterdir()) == []


def test_a_close_over_two_seams_appends_one_revoke(home, monkeypatch, tmp_path):
    """``reconcile_eval_seam(revoke_live_grants=True)`` over two seams: the live grant is retracted on both before the
    one revoke is appended, and both seams then publish the revoke."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant, reconcile_eval_seam
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    seam_a, seam_b = _two_seams(home, monkeypatch)
    rig = _Rig("grant")
    EvalCapabilityGrant(rig.store, owner_key=rig.owner, base_dir=seam_b)._publish(SLUG)   # B honours it too
    ok = _granted_on(rig)
    assert ok(seam_a) and ok(seam_b)
    store = rig.store
    real_append, at_append = store.append, []

    def _append(*a, **kw):
        if (kw.get("payload") or {}).get("state") == "revoked":
            at_append.append((ok(seam_a), ok(seam_b)))
        return real_append(*a, **kw)
    monkeypatch.setattr(store, "append", _append)
    out = reconcile_eval_seam(store, owner_key=rig.owner, revoke_live_grants=True, seams=[seam_a, seam_b])
    assert out["revoked"] == [SLUG] and at_append == [(False, False)]
    assert _revoked_on(seam_a, SLUG) and _revoked_on(seam_b, SLUG)


def test_a_close_over_two_seams_floors_every_seam_above_a_concurrent_append(home, monkeypatch, tmp_path):
    """Another process appends while the close revokes: once the revoke lands, every seam's rollback floor is raised to
    the spine's next seq again (above a publication sealed from the newer spine), before any publish — a close killed
    right then leaves every seam floored above the revoke, not only the first."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant, reconcile_eval_seam
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    from vigil_core.highwater import load_highwater
    from vigil_integration.live.eval_capability_grant import _shared_floor_path
    seam_a, seam_b = _two_seams(home, monkeypatch)
    rig = _Rig("grant")
    EvalCapabilityGrant(rig.store, owner_key=rig.owner, base_dir=seam_b)._publish(SLUG)
    store = rig.store
    real_append = store.append

    def _append(*a, **kw):
        if (kw.get("payload") or {}).get("state") == "revoked":
            real_append(**{**kw, "payload": {"signal": "unrelated.concurrent"}})
        return real_append(*a, **kw)
    monkeypatch.setattr(store, "append", _append)

    def _killed(self, slug):
        raise KeyboardInterrupt("the close is stopped right after the revokes landed")
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", _killed)
    with pytest.raises(KeyboardInterrupt):
        reconcile_eval_seam(store, owner_key=rig.owner, revoke_live_grants=True, seams=[seam_a, seam_b])
    floors = [load_highwater(_shared_floor_path(s, SLUG))["last_seq"] for s in (seam_a, seam_b)]
    assert floors == [store.next_seq, store.next_seq]


def test_the_alarm_keeps_the_seams_a_reconcile_did_not_confirm(home, tmp_path):
    """The close alarm's seams: merged by every revoke; a reconcile keeps those it did not run on — and, while one is
    left, every name the alarm held — and those it could not confirm, and drops those it confirmed; cleared with the
    last name. A seam directory that is gone (nothing left to authorize there) or a relative entry holds nothing."""
    from sigil.governor.seam_publish import raise_close_alarm, read_close_alarm, settle_close_alarm
    s1, s2, s3 = (str(tmp_path / n) for n in ("s1", "s2", "s3"))
    for s in (s1, s2, s3, "rel"):
        Path(s).mkdir()                                                  # "rel": relative to this shell's directory
    assert raise_close_alarm("a", cause="seam_unreconciled", failed=["grant:a"], seams=[s1])
    assert raise_close_alarm("b", cause="seam_unreconciled", failed=["grant:b"], seams=[s2])
    assert read_close_alarm().get("seams") == [s1, s2]
    settle_close_alarm({"grant:a": "x"}, checked={"grant:a", "grant:b"}, detail="d", seams_checked=[s1],
                       seams_failed=[s1])
    assert read_close_alarm().get("seams") == [s1, s2] and read_close_alarm()["failed"] == ["grant:a", "grant:b"]
    settle_close_alarm({"grant:b": "x"}, checked={"grant:a", "grant:b"}, detail="d", seams_checked=[s1, s2],
                       seams_failed=[s2])
    assert read_close_alarm().get("seams") == [s2] and read_close_alarm()["failed"] == ["grant:b"]
    settle_close_alarm({}, checked={"grant:b"}, detail="d", seams_checked=[s2])
    assert read_close_alarm() is None
    assert raise_close_alarm("c", cause="seam_unreconciled", failed=["grant:c"],
                             seams=[s3, str(tmp_path / "gone"), "rel"])
    settle_close_alarm({}, checked={"grant:c"}, detail="d", seams_checked=[s1])     # s3 not run on: kept
    assert read_close_alarm()["failed"] == ["grant:c"] and read_close_alarm().get("seams") == [s3]
    settle_close_alarm({}, checked={"grant:c"}, detail="d", seams_checked=[s3])
    assert read_close_alarm() is None


def test_an_offense_close_never_clears_the_alarm_for_a_seam_it_did_not_run_on(home, monkeypatch, tmp_path, capsys):
    """A revoke could not be confirmed on the settle drain's seam; an offense close (one seam: the cockpit's) then
    confirms its own seam, but the alarm keeps naming the grant and the other seam until a reconcile
    runs on it — `sigil eval-grant reconcile` does, and clears it."""
    from sigil.governor.eval_capability_grant import EvalCapabilityGrant, revoke_grants_on_close
    from sigil.governor.seam_publish import read_close_alarm
    from tests.test_eval_publish_fail_closed import SLUG, _Rig  # type: ignore
    seam_a, seam_b = _two_seams(home, monkeypatch)
    rig = _Rig("grant")
    EvalCapabilityGrant(rig.store, owner_key=rig.owner, base_dir=seam_b)._publish(SLUG)
    real_publish = EvalCapabilityGrant._publish

    def _publish(self, slug):
        if self._seam_override == seam_b:
            raise RuntimeError("the drain's seam is not reachable")
        return real_publish(self, slug)
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", _publish)
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: rig.store)
    with pytest.raises(SystemExit):
        cli.cmd_eval_grant(_ns("revoke", engagement=SLUG))
    assert read_close_alarm()["failed"] == [f"grant:{SLUG}"] and read_close_alarm().get("seams") == [seam_b]
    monkeypatch.setattr(EvalCapabilityGrant, "_publish", real_publish)
    revoke_grants_on_close(rig.store, owner_key=rig.owner)                # the cockpit's close: its own seam only
    alarm = read_close_alarm()
    assert alarm is not None and alarm["failed"] == [f"grant:{SLUG}"] and alarm.get("seams") == [seam_b]
    capsys.readouterr()
    cli.cmd_eval_grant(_ns("reconcile", engagement=None))
    assert json.loads(capsys.readouterr().out)["ok"] is True and read_close_alarm() is None
    assert _revoked_on(seam_b, SLUG)


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
