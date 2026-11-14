"""VIGIL_SEAM_MIGRATION_GUARD — nothing serves, settles, sweeps with --apply, arms an eval grant or provisions a
monitoring secret on the seam while a former seam directory still holds launch-seam records the seam lacks.

DEFAULT OFF in code (every verb behaves exactly as before); the shipped sigil-cockpit and vigil-settle-drain units set
it to 1. With it on, each listed verb exits 2 BEFORE anything is written — no token minted, no port bound, nothing
claimed from the completion spool, no spine record — until `sigil seam migrate --apply` commits the former tree at its
current digest. The safe direction (eval-grant revoke) and the fix itself (`seam migrate`) are never refused.
`sigil upgrade --check` reports an unmigrated former tree (exit 3) whatever the flag says, and changes nothing.

Sovereign leg: PYTHONPATH=apps/sigil:integration:packages/core/vigil_core.

Mutation-verify targets (each neuter reds a NAMED test here):
  * the serve wiring removed                          -> test_serve_is_refused_before_a_token_or_a_bind
  * the drain refusal moved after the watcher is built -> test_the_drain_is_refused_before_it_claims_anything
  * the guard predicate always returns []             -> every refusal test
  * the guard default ON                              -> test_with_the_guard_off_every_verb_is_unchanged
  * revoke wired to the guard                         -> test_eval_grant_revoke_is_never_refused
  * an operator shell not following the units' guard   -> test_an_operator_shell_follows_the_units_guard
  * an explicit value in the shell not honoured        -> test_an_explicit_shell_value_is_deliberate
  * a unit without the guard line turning it on        -> test_units_without_the_guard_leave_it_off
  * a sweep --apply aimed at a former seam directory   -> test_a_sweep_apply_never_targets_a_former_seam_directory
  * an unreadable unit model letting that sweep run    -> test_a_sweep_apply_with_a_base_dir_is_refused_when_the_units_cannot_be_read
  * an unreadable guard state lets a verb run          -> test_an_unreadable_migration_state_refuses
  * an unreadable journal hides a former tree          -> test_an_unreadable_journal_never_hides_a_former_tree
  * upgrade --check / migrate without units use the cwd -> test_with_no_seam_unit_nothing_is_compared_or_guessed
  * the flag's code default ON                         -> test_the_flag_is_off_unless_set
  * the console unit taken as a migration destination -> test_the_upgrade_procedure_on_a_console_host
  * a tree carried into the units' seam still guarding the console's own seam
                                                      -> test_the_upgrade_procedure_on_a_console_host
  * `seam migrate --to` the console's seam accepted    -> test_seam_migrate_never_carries_into_the_consoles_seam
  * the console's journal trusted for the money seam   -> test_a_tree_committed_into_the_consoles_seam_still_guards_the_money_seam
  * upgrade --check skipping a console host            -> test_upgrade_check_on_a_console_host_reports_the_former_tree
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from sigil import cli
from sigil.governor.identity import ensure_owner_keypair
from sigil.spine.store import SpineStore
from vigil_integration import seam_migration as sm
from vigil_integration.live.credit_lease_broker import record_lease_settlement


@pytest.fixture
def host(monkeypatch, tmp_path):
    """A host whose former seam directory ($SIGIL_HOME/.vigil-live) holds a settlement marker; the seam is empty."""
    home = tmp_path / "home"
    sigil_home = home / ".sigil"
    legacy, seam = sigil_home / ".vigil-live", sigil_home / "credit-lease"
    legacy.mkdir(parents=True)
    seam.mkdir()
    (legacy / "webauthn-credentials.json").write_text("{}")             # owner state: never counted
    record_lease_settlement(str(legacy), "cust_a", "n1")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SIGIL_HOME", str(sigil_home))
    monkeypatch.setenv("VIGIL_BASE_DIR", str(seam))
    for k in ("XDG_STATE_HOME", sm.LEGACY_DIRS_ENV, "VIGIL_SETTLE_BASE_DIR", "VIGIL_SETTLE_SPOOL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VIGIL_SEAM_MIGRATION_GUARD", "1")
    store = SpineStore(tmp_path / "spine.jsonl")
    monkeypatch.setattr(cli, "SpineStore", lambda *a, **k: store)
    # cli.main()'s startup gate checks the store at config.SPINE_PATH: point it at this test's own fresh home, never
    # the process-wide default an earlier test may have left in another layout
    from sigil import config
    monkeypatch.setattr(config, "SPINE_PATH", tmp_path / "default-spine" / "spine.jsonl")
    return {"legacy": legacy, "seam": seam, "store": store, "tmp": tmp_path}


def _exit(argv) -> int:
    with pytest.raises(SystemExit) as ex:
        cli.main(argv)
    return int(ex.value.code or 0)


def _migrated(h) -> None:
    j = sm.new_journal(h["seam"])
    j["sources"][os.path.realpath(h["legacy"])] = {"state": "complete",
                                                   "inventory": {"digest": sm.inventory(h["legacy"])["digest"]}}
    sm.write_journal(h["seam"], j)


@pytest.fixture
def serve_spy(monkeypatch):
    calls = {"serve": 0, "token": 0}
    import sigil.ui.bootstrap_token as bt
    import sigil.ui.server as srv

    def _serve(**kw):
        calls["serve"] += 1

    def _token(**kw):
        calls["token"] += 1
        return "t"
    monkeypatch.setattr(srv, "serve", _serve)
    monkeypatch.setattr(bt, "resolve_bootstrap_token", _token)
    return calls


def test_serve_is_refused_before_a_token_or_a_bind(host, serve_spy, capsys):
    assert _exit(["serve"]) == 2
    assert serve_spy == {"serve": 0, "token": 0}
    err = capsys.readouterr().err
    assert str(host["legacy"]) in err and "no_journal" in err and "sigil seam migrate" in err


def test_serve_proceeds_once_the_former_tree_is_migrated(host, serve_spy):
    _migrated(host)
    cli.main(["serve"])
    assert serve_spy["serve"] == 1


def test_a_former_tree_that_changed_since_is_refused_again(host, serve_spy, capsys):
    _migrated(host)
    record_lease_settlement(str(host["legacy"]), "cust_b", "n2")          # written after the migration
    assert _exit(["serve"]) == 2 and "changed_since" in capsys.readouterr().err


def test_owner_state_alone_never_blocks(host, serve_spy):
    for f in (host["legacy"] / "credit-lease-settlements").iterdir():
        f.unlink()
    cli.main(["serve"])
    assert serve_spy["serve"] == 1


def test_an_unreadable_migration_state_refuses(host, serve_spy, monkeypatch, capsys):
    def _boom(seam):
        raise RuntimeError("the unit model cannot be read")
    monkeypatch.setattr(cli, "_unmigrated_seam", _boom)
    assert _exit(["serve"]) == 2 and serve_spy == {"serve": 0, "token": 0}
    assert "migration state cannot be read" in capsys.readouterr().err


def test_an_unreadable_journal_never_hides_a_former_tree(host, serve_spy, capsys):
    """A journal that committed the former tree, then damaged: the tree counts as not migrated (refused)."""
    _migrated(host)
    cli.main(["serve"])
    assert serve_spy["serve"] == 1
    sm.journal_path(host["seam"]).write_text("{truncated")
    assert _exit(["serve"]) == 2 and serve_spy["serve"] == 1
    assert "no_journal" in capsys.readouterr().err


@pytest.mark.parametrize("value,on", [(None, False), ("", False), ("0", False), ("1", True), ("true", True)])
def test_the_flag_is_off_unless_set(monkeypatch, value, on):
    from sigil import config
    if value is None:
        monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD", raising=False)
    else:
        monkeypatch.setenv("VIGIL_SEAM_MIGRATION_GUARD", value)
    assert config.seam_migration_guard_enabled() is on


def test_with_the_guard_off_every_verb_is_unchanged(host, serve_spy, monkeypatch):
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    cli.main(["serve"])
    assert serve_spy["serve"] == 1


def _listing(d: Path) -> list:
    return sorted(str(p.relative_to(d)) for p in d.rglob("*")) if d.exists() else []


def test_the_drain_is_refused_before_it_claims_anything(host, capsys):
    spool = host["tmp"] / "spool"
    (spool / "incoming").mkdir(parents=True)
    (spool / "incoming" / "c.json").write_text("{}")
    before = _listing(spool)
    from tests.test_seam_migrate_requeue import _deleg  # type: ignore
    deleg = host["tmp"] / "deleg.json"
    deleg.write_text(_deleg()[1].model_dump_json())                        # a valid owner + delegation: only the
    scope = json.loads(deleg.read_text())["scope"]                         # guard stands between the drain and
    argv = ["settle-drain", "drain", "--spool", str(spool), "--delegation", str(deleg), "--scope", scope]
    assert _exit(argv) == 2                                                # its watcher
    assert _listing(spool) == before                                       # no working/, processed/, nothing claimed
    assert "settle-drain: refused" in capsys.readouterr().err
    _migrated(host)                                                        # negative control: the drain then runs
    assert _exit(argv) == 1                                                # (and quarantines the junk envelope)
    assert (spool / "rejected" / "c.json").is_file()


def test_sweep_apply_is_refused_and_the_report_warns(host, monkeypatch, capsys):
    ensure_owner_keypair()
    spool = host["tmp"] / "spool"
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True)
    monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
    tip = host["store"].next_seq
    assert _exit(["ops-sweep", "reservations", "--apply", "--completion-spool", str(spool)]) == 2
    assert host["store"].next_seq == tip
    capsys.readouterr()
    cli.main(["ops-sweep", "reservations"])                                # report-only still runs
    out = capsys.readouterr()
    assert json.loads(out.out)["items"] == [] and "WARNING" in out.err and "seam migrate" in out.err


def test_eval_grant_arm_is_refused_with_nothing_appended(host, capsys):
    ensure_owner_keypair()
    tip = host["store"].next_seq
    assert _exit(["eval-grant", "arm", "--engagement", "eng-x", "--target", "https://x.example"]) == 2
    assert host["store"].next_seq == tip and "eval-grant arm: refused" in capsys.readouterr().err


def test_eval_grant_revoke_is_never_refused(host, capsys):
    ensure_owner_keypair()
    try:
        cli.main(["eval-grant", "revoke", "--engagement", "eng-x"])
    except SystemExit as e:
        assert e.code in (0, None), capsys.readouterr().err
    assert "refused" not in capsys.readouterr().err


def test_monitoring_secret_provisioning_is_refused(host, monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
    secrets = host["tmp"] / "secrets"
    assert _exit(["monitoring-secret", "--org", "org_a", "--host", "apme.cm", "--secrets-dir", str(secrets)]) == 2
    assert not secrets.exists() and "monitoring-secret: refused" in capsys.readouterr().err


def test_seam_migrate_itself_is_never_refused(host, capsys):
    ensure_owner_keypair()
    code = _exit(["seam", "migrate", "--from", str(host["legacy"]), "--to", str(host["seam"]), "--apply"])
    assert code == 0, capsys.readouterr().err
    cli_out = capsys.readouterr().out
    assert "migrated" in cli_out


def test_upgrade_check_reports_an_unmigrated_former_tree_whatever_the_flag(host, monkeypatch, capsys):
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home", guard=False)                      # the units name the seam
    seam_before, tip = _listing(host["seam"]), host["store"].next_seq
    assert _exit(["upgrade", "--check"]) == 3
    out = capsys.readouterr().out
    assert "seam migration REQUIRED" in out and str(host["legacy"]) in out
    assert _listing(host["seam"]) == seam_before and host["store"].next_seq == tip    # read-only
    _migrated(host)
    cli.main(["upgrade", "--check"])                                       # up to date: returns normally
    assert "up to date" in capsys.readouterr().out


# ── the guard follows the configured units (a verb run from an operator's shell) ─────────────────────────────────

_REPO = Path(__file__).resolve().parents[3]
_UNITS = ("apps/sigil/deploy/systemd/sigil-cockpit.service", "infra/systemd/vigil-settle-drain.service")


def _install_units(home: Path, *, guard: bool = True) -> None:
    """The shipped cockpit and settle-drain units, re-copied (``guard=False``: a copy without the guard line)."""
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    for u in _UNITS:
        shutil.copy(_REPO / u, d / Path(u).name)
        if not guard:
            t = (d / Path(u).name).read_text()
            (d / Path(u).name).write_text(t.replace("Environment=VIGIL_SEAM_MIGRATION_GUARD=1\n", ""))


def _spool(h) -> Path:
    spool = h["tmp"] / "spool"
    for sub in ("incoming", "working", "processed", "rejected"):
        (spool / sub).mkdir(parents=True, exist_ok=True)
    return spool


@pytest.mark.parametrize("verb", ["sweep_apply", "sweep_report", "eval_grant_arm", "monitoring_secret"])
def test_an_operator_shell_follows_the_units_guard(host, monkeypatch, capsys, verb):
    """The units carry the guard; the operator's shell does not export it: every guarded verb is still refused (the
    report-only sweep still runs, with the warning) and nothing is written."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home")
    ensure_owner_keypair()
    tip = host["store"].next_seq
    if verb == "sweep_apply":
        monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
        assert _exit(["ops-sweep", "reservations", "--apply", "--completion-spool", str(_spool(host))]) == 2
        assert "ops-sweep reservations --apply: refused" in capsys.readouterr().err
    elif verb == "sweep_report":
        cli.main(["ops-sweep", "reservations"])
        assert "WARNING" in capsys.readouterr().err
    elif verb == "eval_grant_arm":
        assert _exit(["eval-grant", "arm", "--engagement", "eng-x", "--target", "https://x.example"]) == 2
        assert "eval-grant arm: refused" in capsys.readouterr().err
    else:
        monkeypatch.setenv("VIGIL_CUSTOMER_MONITORING_ENABLED", "1")
        secrets = host["tmp"] / "secrets"
        assert _exit(["monitoring-secret", "--org", "org_a", "--host", "apme.cm", "--secrets-dir", str(secrets)]) == 2
        assert not secrets.exists() and "monitoring-secret: refused" in capsys.readouterr().err
    assert host["store"].next_seq == tip


def test_an_explicit_shell_value_is_deliberate(host, monkeypatch, capsys):
    """An explicit VIGIL_SEAM_MIGRATION_GUARD in this environment decides (the override the env examples document)."""
    _install_units(host["tmp"] / "home")
    ensure_owner_keypair()
    monkeypatch.setenv("VIGIL_SEAM_MIGRATION_GUARD", "0")
    cli.main(["ops-sweep", "reservations"])
    assert "WARNING" not in capsys.readouterr().err


def test_units_without_the_guard_leave_it_off(host, monkeypatch, capsys):
    """Units configured without the guard line and nothing exported: the code default (off) is unchanged."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home", guard=False)
    ensure_owner_keypair()
    cli.main(["ops-sweep", "reservations"])
    assert "WARNING" not in capsys.readouterr().err


@pytest.mark.parametrize("target", ["former", "seam", "former_guard_off"])
def test_a_sweep_apply_never_targets_a_former_seam_directory(host, monkeypatch, capsys, target):
    """`ops-sweep reservations --apply --base-dir <former seam directory>` is refused, before and after the migration
    (its launches settle on the units' seam); the units' own seam named explicitly is the operator's choice. With
    the guard off (units without it, nothing exported) the explicit tree is used as given, as before."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home", guard=target != "former_guard_off")
    ensure_owner_keypair()
    _migrated(host)
    monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
    base = host["seam"] if target == "seam" else host["legacy"]
    before, tip = _listing(host["legacy"]), host["store"].next_seq
    argv = ["ops-sweep", "reservations", "--apply", "--base-dir", str(base), "--completion-spool", str(_spool(host))]
    if target == "former":
        assert _exit(argv) == 2 and "former seam directory" in capsys.readouterr().err
        assert _listing(host["legacy"]) == before and host["store"].next_seq == tip
    else:
        cli.main(argv)
        assert json.loads(capsys.readouterr().out)["applied"] is True


def test_a_sweep_apply_with_a_base_dir_is_refused_when_the_units_cannot_be_read(host, monkeypatch, capsys):
    """With the guard on, `ops-sweep reservations --apply --base-dir DIR` is refused (exit 2, nothing appended) when the
    configured seam units cannot be read: DIR cannot be shown not to be a former seam directory."""
    import vigil_integration.seam_base_units as sbu
    ensure_owner_keypair()
    monkeypatch.setenv("VIGIL_OPS_SWEEP_APPLY_ENABLED", "1")
    monkeypatch.setattr(cli, "_unmigrated_seam", lambda seam: [])         # the seam itself is fully migrated

    def _boom(*a, **k):
        raise RuntimeError("the unit model cannot be read")
    monkeypatch.setattr(sbu, "unit_details", _boom)
    tip = host["store"].next_seq
    argv = ["ops-sweep", "reservations", "--apply", "--base-dir", str(host["seam"]), "--completion-spool",
            str(_spool(host))]
    assert _exit(argv) == 2 and "configured seam units cannot be read" in capsys.readouterr().err
    assert host["store"].next_seq == tip


def test_with_no_seam_unit_nothing_is_compared_or_guessed(host, monkeypatch, capsys):
    """No seam unit configured: `upgrade --check` reports no seam migration (as `vigil doctor`), and `seam migrate`
    without --to refuses instead of migrating into a working-directory default; with the units it uses theirs."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    ensure_owner_keypair()
    cli.main(["upgrade", "--check"])
    assert "seam migration" not in capsys.readouterr().out
    monkeypatch.chdir(host["tmp"])
    monkeypatch.delenv("VIGIL_BASE_DIR")
    assert _exit(["seam", "migrate", "--from", str(host["legacy"])]) == 2
    assert "--to" in capsys.readouterr().err and not (host["tmp"] / ".vigil-live").exists()
    _install_units(host["tmp"] / "home")
    monkeypatch.setenv("VIGIL_BASE_DIR", str(host["seam"]))
    assert _exit(["seam", "migrate", "--from", str(host["legacy"]), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["to"] == os.path.realpath(host["seam"])


# ── a host with the operator console unit (its engine home stays in <repo>/.vigil-live) ──────────────────────────────

def _install_console(h) -> Path:
    """vigil-command.service installed beside the re-copied cockpit and settle-drain units; returns its seam."""
    repo = h["tmp"] / "vigil"
    (repo / ".vigil-live").mkdir(parents=True)
    d = h["tmp"] / "home" / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    (d / "vigil-command.service").write_text(
        (_REPO / "infra/systemd/vigil-command.service").read_text().replace("/home/kali/vigil", str(repo)))
    return repo / ".vigil-live"


def test_the_upgrade_procedure_on_a_console_host(host, serve_spy, monkeypatch, capsys):
    """The runbook's upgrade on a host where the operator console unit keeps its engine home: `sigil seam migrate`
    carries the former cockpit tree into the cockpit's and settle drain's seam (the console's seam is never the
    destination), after which the cockpit serves; the cockpit the console spawns on its own seam is refused while the
    former tree is not carried anywhere and serves once it is."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")                       # the operator's shell: units carry it
    _install_units(host["tmp"] / "home")
    console = _install_console(host)
    ensure_owner_keypair()
    monkeypatch.setenv("VIGIL_BASE_DIR", str(console))                     # `vigil up` hands its base to the cockpit
    assert _exit(["serve"]) == 2 and serve_spy["serve"] == 0               # nothing carried yet: refused
    monkeypatch.setenv("VIGIL_BASE_DIR", str(host["seam"]))                # the runbook's export
    assert _exit(["seam", "migrate", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["to"] == os.path.realpath(host["seam"])
    assert _exit(["seam", "migrate", "--apply"]) == 0, capsys.readouterr().err
    assert sm.read_journal(host["seam"])["sources"][os.path.realpath(host["legacy"])]["state"] == "complete"
    assert not sm.journal_path(console).exists()                           # the console's engine home is untouched
    cli.main(["serve"])                                                    # the units' cockpit
    monkeypatch.setenv("VIGIL_BASE_DIR", str(console))
    cli.main(["serve"])                                                    # the console's cockpit
    assert serve_spy["serve"] == 2


@pytest.mark.parametrize("apply", [False, True])
def test_seam_migrate_never_carries_into_the_consoles_seam(host, monkeypatch, capsys, apply):
    """`sigil seam migrate --to <the console's seam>` is refused (exit 2, nothing written): a former tree is carried
    only into the seam the cockpit and the settle drain use."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home")
    console = _install_console(host)
    ensure_owner_keypair()
    before, tip = _listing(console), host["store"].next_seq
    argv = ["seam", "migrate", "--to", str(console), "--from", str(host["legacy"])] + (["--apply"] if apply else [])
    assert _exit(argv) == 2
    err = capsys.readouterr().err
    assert "vigil-command.service" in err and str(host["seam"]) in err and "without --to" in err
    assert _listing(console) == before and not sm.journal_path(console).exists() and host["store"].next_seq == tip
    # a backup unit sharing the cockpit's and drain's seam never makes that seam a refused destination
    shutil.copy(_REPO / "infra/systemd/vigil-backup.service",
                host["tmp"] / "home" / ".config" / "systemd" / "user" / "vigil-backup.service")
    assert _exit(["seam", "migrate", "--to", str(host["seam"]), "--from", str(host["legacy"]), "--json"]) == 0


def test_a_tree_committed_into_the_consoles_seam_still_guards_the_money_seam(host, serve_spy, monkeypatch, capsys):
    """A journal in the console's seam (an earlier build let `--to` name it) that says the former tree is complete:
    the cockpit's and drain's seam never received its records, so the tree stays its candidate — the cockpit there is
    refused and `seam migrate` lists the tree — until it is migrated into that seam."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home")
    console = _install_console(host)
    ensure_owner_keypair()
    j = sm.new_journal(console)
    j["sources"][os.path.realpath(host["legacy"])] = {"state": "complete",
                                                      "inventory": {"digest": sm.inventory(host["legacy"])["digest"]}}
    sm.write_journal(console, j)
    monkeypatch.setenv("VIGIL_BASE_DIR", str(host["seam"]))
    left = cli._unmigrated_seam(str(host["seam"]))
    assert [x["path"] for x in left] == [os.path.realpath(host["legacy"])]
    assert _exit(["serve"]) == 2 and serve_spy["serve"] == 0
    capsys.readouterr()
    assert _exit(["seam", "migrate", "--json"]) == 0
    assert [x["from"] for x in json.loads(capsys.readouterr().out)["sources"]] == [os.path.realpath(host["legacy"])]
    assert _exit(["seam", "migrate", "--apply"]) == 0, capsys.readouterr().err
    cli.main(["serve"])
    assert serve_spy["serve"] == 1


def test_upgrade_check_on_a_console_host_reports_the_former_tree(host, monkeypatch, capsys):
    """`sigil upgrade --check` on the console host compares the seam the cockpit and the settle drain agree on (the
    console's engine home elsewhere does not hide it): exit 3 naming the former tree until it is migrated there."""
    monkeypatch.delenv("VIGIL_SEAM_MIGRATION_GUARD")
    _install_units(host["tmp"] / "home")
    _install_console(host)
    assert _exit(["upgrade", "--check"]) == 3
    out = capsys.readouterr().out
    assert "seam migration REQUIRED" in out and str(host["legacy"]) in out and str(host["seam"]) in out
    _migrated(host)
    cli.main(["upgrade", "--check"])
    assert "up to date" in capsys.readouterr().out
