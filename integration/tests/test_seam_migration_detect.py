"""Seam migration — detection: which former seam directories still hold launch-seam records the seam lacks.

``vigil_integration.seam_migration`` inventories ONLY the seam-class paths of a tree (never following a symlink,
skipping lock files and atomic-write temporaries), digests them, lists this host's former seam directories and
reads the migration journal ``<seam>/.seam-migration/journal.json``. A former directory is reported until a
migration committed it at its current digest. Owner state that shares the former directory (the passkey store, the
cockpit bootstrap token, ``hostcmd/``) is never counted.

Integration leg (stdlib + vigil_core + the import-clean seam modules; no framework).

Mutation-verify targets (each neuter reds a NAMED test here):
  * count every entry instead of the class paths        -> test_owner_state_alone_is_not_seam_content
  * drop the *.lock / .tmp skip                          -> test_lock_files_and_temporaries_do_not_change_the_digest
  * compare the file count instead of the digest         -> test_a_new_nonce_after_the_migration_is_changed_since
  * drop the current-seam exclusion                      -> test_a_configured_units_current_seam_is_not_a_candidate
  * accept a source whose state is not complete          -> test_an_uncommitted_migration_is_incomplete
  * follow symlinks                                      -> test_a_symlink_in_a_class_path_is_unsafe
  * doctor wiring ``_issue`` (-> ``_note``)               -> test_doctor_reports_an_unmigrated_tree_as_a_hard_issue
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from vigil_integration import doctor as _doc
from vigil_integration import seam_migration as sm
from vigil_integration.live.credit_lease_broker import record_lease_settlement
from vigil_integration.seam_base_units import SEAM_UNITS, unit_details

_REPO = Path(_doc.__file__).resolve().parents[2]
_SHIPPED = {u: _REPO / d / u for u, d in SEAM_UNITS}


def _install(home: Path, *units: str) -> None:
    d = home / ".config" / "systemd" / "user"
    d.mkdir(parents=True, exist_ok=True)
    for u in units:
        shutil.copy(_SHIPPED[u], d / u)


def _owner_state(tree: Path) -> None:
    """What the cockpit's former directory also holds: never seam content."""
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "webauthn-credentials.json").write_text('{"credentials": []}')
    (tree / "cockpit-bootstrap-token").write_text("tok")
    (tree / "hostcmd").mkdir(exist_ok=True)
    (tree / "hostcmd" / "req.json").write_text("{}")


def _committed(seam: Path, legacy: Path, *, state: str = "complete") -> None:
    j = sm.new_journal(seam)
    j["sources"][os.path.realpath(legacy)] = {"state": state, "inventory": {"digest": sm.inventory(legacy)["digest"]}}
    sm.write_journal(seam, j)


def test_no_former_directory_reports_nothing(tmp_path):
    seam = tmp_path / "seam"
    seam.mkdir()
    assert sm.unmigrated_legacy(seam, [str(tmp_path / "absent")]) == []
    assert sm.legacy_candidates(seam, units={}, sigil_home=tmp_path / "home", env={}) == []


def test_owner_state_alone_is_not_seam_content(tmp_path):
    legacy = tmp_path / "home" / ".vigil-live"
    _owner_state(legacy)
    inv = sm.inventory(legacy)
    assert inv["files"] == 0 and inv["status"] == "ok"
    assert sm.unmigrated_legacy(tmp_path / "seam", [str(legacy)]) == []


def test_a_settlement_marker_without_a_journal_is_no_journal(tmp_path):
    legacy = tmp_path / "legacy"
    _owner_state(legacy)
    record_lease_settlement(str(legacy), "cust_a", "n1")
    got = sm.unmigrated_legacy(tmp_path / "seam", [str(legacy)])
    assert got == [{"path": str(legacy), "reason": "no_journal", "files": 1}]


def test_a_committed_migration_at_the_same_digest_reports_nothing(tmp_path):
    seam, legacy = tmp_path / "seam", tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    _committed(seam, legacy)
    assert sm.unmigrated_legacy(seam, [str(legacy)]) == []
    assert oct(sm.journal_path(seam).stat().st_mode & 0o777) == "0o600"
    assert oct(sm.journal_path(seam).parent.stat().st_mode & 0o777) == "0o700"


def test_a_new_nonce_after_the_migration_is_changed_since(tmp_path):
    seam, legacy = tmp_path / "seam", tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    _committed(seam, legacy)
    record_lease_settlement(str(legacy), "cust_a", "n2")          # the same file count, a different content
    assert sm.inventory(legacy)["files"] == 1
    assert sm.unmigrated_legacy(seam, [str(legacy)])[0]["reason"] == "changed_since"


def test_an_uncommitted_migration_is_incomplete(tmp_path):
    seam, legacy = tmp_path / "seam", tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    _committed(seam, legacy, state="applying")
    assert sm.unmigrated_legacy(seam, [str(legacy)])[0]["reason"] == "incomplete"


def test_an_unreadable_journal_never_hides_a_former_tree(tmp_path):
    """The journal committed the tree, then cannot be read: the tree is reported again (never treated as migrated)."""
    seam, legacy = tmp_path / "seam", tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    _committed(seam, legacy)
    assert sm.unmigrated_legacy(seam, [str(legacy)]) == []
    sm.journal_path(seam).write_text("{truncated")
    assert sm.unmigrated_legacy(seam, [str(legacy)]) == [{"path": str(legacy), "reason": "no_journal", "files": 1}]


def test_lock_files_and_temporaries_do_not_change_the_digest(tmp_path):
    legacy = tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    nonces = legacy / "approval-nonces"                       # a class whose leaves are any file name
    nonces.mkdir()
    (nonces / ("ab" * 32)).write_text("n\n")
    before = sm.inventory(legacy)
    assert before["files"] == 2
    for d in (legacy / "credit-lease-settlements", nonces):
        (d / "cust_b.json.lock").write_text("")
        (d / ".tmp-abc").write_text("partial")
        (d / "cust_c.json.tmp-0123").write_text("partial")
    (legacy / "credit-lease-settlements" / "notes.txt").write_text("not a marker")   # outside the class pattern
    after = sm.inventory(legacy)
    assert after["digest"] == before["digest"] and after["files"] == 2


def test_a_symlink_in_a_class_path_is_unsafe(tmp_path):
    legacy = tmp_path / "legacy"
    record_lease_settlement(str(legacy), "cust_a", "n1")
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (legacy / "credit-lease-settlements" / "cust_b.json").symlink_to(outside)
    assert sm.inventory(legacy)["status"] == "unsafe"
    assert sm.unmigrated_legacy(tmp_path / "seam", [str(legacy)])[0]["reason"] == "unsafe"


def test_a_fifo_in_a_class_path_is_unsafe_and_never_opened(tmp_path):
    """A non-regular leaf (here a FIFO, which would block a reader) is refused from its lstat, never opened."""
    import threading
    legacy = tmp_path / "legacy"
    d = legacy / "credit-lease-settlements"
    d.mkdir(parents=True)
    fifo = d / "cust_x.json"
    os.mkfifo(fifo)
    out: dict = {}
    t = threading.Thread(target=lambda: out.update(sm.inventory(legacy)), daemon=True)
    t.start()
    t.join(10)
    blocked = t.is_alive()
    if blocked:                                                  # release the blocked reader before failing
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        t.join(10)
    assert not blocked and out["status"] == "unsafe", out


def test_a_symlinked_class_directory_is_unsafe(tmp_path):
    legacy, real = tmp_path / "legacy", tmp_path / "real"
    record_lease_settlement(str(real), "cust_a", "n1")
    legacy.mkdir()
    (legacy / "credit-lease-settlements").symlink_to(real / "credit-lease-settlements")
    assert sm.inventory(legacy)["status"] == "unsafe"


def test_a_symlinked_spelling_of_the_seam_is_not_a_candidate(tmp_path):
    seam = tmp_path / "seam"
    record_lease_settlement(str(seam), "cust_a", "n1")
    alias = tmp_path / "alias"
    alias.symlink_to(seam)
    got = sm.legacy_candidates(seam, units={}, sigil_home=tmp_path / "home", env={sm.LEGACY_DIRS_ENV: str(alias)})
    assert got == []


def test_legacy_dirs_env_adds_a_candidate(tmp_path):
    seam, extra = tmp_path / "seam", tmp_path / "old-tree"
    seam.mkdir()
    extra.mkdir()
    env = {sm.LEGACY_DIRS_ENV: f"relative/ignored:{extra}"}
    assert sm.legacy_candidates(seam, units={}, sigil_home=tmp_path / "home", env=env) == [str(extra)]


def test_sigil_home_dot_vigil_live_is_a_candidate(tmp_path):
    seam, home = tmp_path / "seam", tmp_path / "home"
    (home / ".vigil-live").mkdir(parents=True)
    assert sm.legacy_candidates(seam, units={}, sigil_home=home, env={}) == [str(home / ".vigil-live")]


def test_the_shipped_units_report_their_working_directories(tmp_path):
    _install(tmp_path, "sigil-cockpit.service", "vigil-settle-drain.service", "vigil-command.service")
    units = unit_details(_REPO, tmp_path)
    assert units["sigil-cockpit.service"]["workdir"] == str(tmp_path / ".sigil")
    assert units["vigil-settle-drain.service"]["workdir"] == str(tmp_path / ".sigil")
    assert units["vigil-command.service"]["workdir"] == "/home/kali/vigil"


def test_writer_units_working_directory_default_is_a_candidate(tmp_path):
    home = tmp_path / "home"
    _install(home, "sigil-cockpit.service", "vigil-settle-drain.service")
    seam = home / ".sigil" / "credit-lease"
    (home / ".sigil" / ".vigil-live").mkdir(parents=True)
    units = unit_details(_REPO, home)
    got = sm.legacy_candidates(seam, units=units, sigil_home=tmp_path / "elsewhere", env={})
    assert got == [str(home / ".sigil" / ".vigil-live")]


def test_a_retired_settle_base_naming_another_tree_is_a_candidate(tmp_path):
    home = tmp_path / "home"
    _install(home, "sigil-cockpit.service", "vigil-settle-drain.service")
    old = tmp_path / "old-settle-tree"
    old.mkdir()
    env_file = home / ".config" / "vigil" / "settle-drain.env"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text(f"VIGIL_SETTLE_BASE_DIR={old}\n")
    seam = home / ".sigil" / "credit-lease"
    got = sm.legacy_candidates(seam, units=unit_details(_REPO, home), sigil_home=tmp_path / "x", env={})
    assert str(old) in got


def test_a_configured_units_current_seam_is_not_a_candidate(tmp_path):
    home = tmp_path / "home"
    _install(home, "sigil-cockpit.service", "vigil-settle-drain.service", "vigil-backup.service")
    other = tmp_path / "other"
    record_lease_settlement(str(other), "cust_a", "n1")
    backup_env = home / ".config" / "vigil" / "backup.env"
    backup_env.parent.mkdir(parents=True, exist_ok=True)
    backup_env.write_text(f"VIGIL_BACKUP_PASSPHRASE=x\nVIGIL_BASE_DIR={other}\n")
    seam = home / ".sigil" / "credit-lease"
    units = unit_details(_REPO, home)
    got = sm.legacy_candidates(seam, units=units, sigil_home=tmp_path / "x", env={sm.LEGACY_DIRS_ENV: str(other)})
    assert str(other) not in got                       # a unit still uses it: not a FORMER seam
    from vigil_integration.seam_base_units import seam_base_agreement
    assert any("disagree on the seam base" in i for i in seam_base_agreement(_REPO, home)[1])


def test_a_running_vigil_up_base_is_not_a_candidate_but_a_stale_pointer_is_ignored(tmp_path):
    base = tmp_path / "up-base"
    base.mkdir()
    state = tmp_path / "state"
    ptr = state / "vigil" / "vigil-up.json"
    ptr.parent.mkdir(parents=True)
    env = {"XDG_STATE_HOME": str(state), sm.LEGACY_DIRS_ENV: str(base)}
    ptr.write_text(json.dumps({"schema": sm.UP_POINTER_SCHEMA, "base": str(base), "pid": os.getpid()}))
    assert sm.legacy_candidates(tmp_path / "seam", units={}, sigil_home=tmp_path / "x", env=env) == []
    dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True,
                          text=True).stdout.strip()
    ptr.write_text(json.dumps({"schema": sm.UP_POINTER_SCHEMA, "base": str(base), "pid": int(dead)}))
    assert sm.legacy_candidates(tmp_path / "seam", units={}, sigil_home=tmp_path / "x", env=env) == [str(base)]


def test_a_class_with_its_override_set_is_not_part_of_the_seam(tmp_path):
    legacy = tmp_path / "legacy"
    (legacy / "aegis" / "monitoring_authority").mkdir(parents=True)
    (legacy / "aegis" / "monitoring_authority" / "org_a__h.json").write_text("{}")
    assert sm.inventory(legacy, env={})["files"] == 1
    assert sm.inventory(legacy, env={"VIGIL_MONITORING_PUBLISH_DIR": "/srv/x"})["files"] == 0


def test_every_seam_dirname_constant_is_classified():
    """A new seam artifact must be classified (carried, or documented as left in place)."""
    paths = {part for c in sm.SEAM_CLASSES for part in c.path.split("/") if part}
    paths |= {c.pattern.split("/")[0] for c in sm.SEAM_CLASSES}
    names = set()
    sources = list((_REPO / "integration" / "vigil_integration" / "live").glob("*.py"))
    sources += [_REPO / "engine" / "crucible" / "framework" / "v2" / "launch_lease.py",
                _REPO / "integration" / "vigil_integration" / "jobs" / "engage_worker.py"]
    for f in sources:
        names |= set(re.findall(r'^_[A-Z_]*DIRNAME\s*=\s*"([^"]+)"', f.read_text(encoding="utf-8"), re.M))
    assert names, "no *_DIRNAME constants found"
    unclassified = {n for n in names if n not in paths and n not in sm.LEFT_IN_PLACE}
    assert unclassified == set(), unclassified


def test_doctor_reports_an_unmigrated_tree_as_a_hard_issue(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("SIGIL_HOME", str(home / ".sigil"))
    monkeypatch.setenv("VIGIL_SETTLE_SPOOL", str(tmp_path / "no-spool"))
    monkeypatch.delenv("VIGIL_BASE_DIR", raising=False)
    monkeypatch.delenv(sm.LEGACY_DIRS_ENV, raising=False)
    legacy = home / ".sigil" / ".vigil-live"
    _owner_state(legacy)
    record_lease_settlement(str(legacy), "cust_a", "n1")
    baseline = _doc.collect(_REPO)
    assert "seam_migration" not in baseline                      # nothing configured: byte-identical
    _install(home, "sigil-cockpit.service", "vigil-settle-drain.service")
    report = _doc.collect(_REPO)
    sec = report["seam_migration"]
    assert sec["legacy"][0]["reason"] == "no_journal" and sec["legacy"][0]["files"] == 1
    hits = [i for i in report["issues"] if i.startswith("seam migration:")]
    assert len(hits) == 1 and "sigil seam migrate" in hits[0] and report["ok"] is False
    assert not any(n.startswith("seam migration:") for n in report["notes"])
    _committed(home / ".sigil" / "credit-lease", legacy)
    report = _doc.collect(_REPO)
    assert report["seam_migration"]["legacy"] == []
    assert not any(i.startswith("seam migration:") for i in report["issues"])


def test_the_offense_backup_of_the_seam_carries_the_journal(tmp_path):
    """A restore of the seam from a backup brings the migration journal back with it (its lock file never)."""
    from vigil_integration.backup import _iter_base_files
    seam = tmp_path / "seam"
    sm.write_journal(seam, sm.new_journal(seam))
    with sm.journal_lock(seam):
        rels = {rel for _p, rel in _iter_base_files(seam)}
    assert ".seam-migration/journal.json" in rels and ".seam-migration/journal.json.lock" not in rels
