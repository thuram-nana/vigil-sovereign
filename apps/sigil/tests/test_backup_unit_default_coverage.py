"""#70 (backups-everywhere) — the SaaS money + delivery state the SHIPPED systemd units place under SIGIL_HOME by
default is captured by `sigil backup`, and the coverage gate can no longer miss a unit-default path.

THE GAP THIS CLOSES. The coverage contract (`CAPTURED_TOP_LEVEL` / `EXCLUDED_TOP_LEVEL`) was grounded only in a
static scan of the sigil PACKAGE for ``home / "<name>"`` writes. The settle / finding / billing spools and the
credit-lease launch seam are not created that way — their paths come from the shipped units' DEFAULTS
(``vigil-settle-drain``: ``VIGIL_SETTLE_BASE_DIR=%h/.sigil/credit-lease``, spools under ``%h/.sigil/spool``) — so
they were silently UNCLASSIFIED: on a default install the leases, the SETTLEMENT markers (the exactly-once guard
for charge/refund), the pause markers and every undrained money/delivery signal were in NEITHER backup (the
offense leg captures only ``--base-dir``). Same for the per-unit ``*.env`` files.

Pinned here:
  * the gate is grounded in the UNIT FILES too: every ``~/.sigil/<name>`` a shipped unit references classifies as
    captured-or-excluded (a new unit default that is neither turns this red);
  * a real round-trip restores ``credit-lease/`` + ``spool/`` + the unit env files byte-identically, 0600, with
    lockfiles skipped and symlinks never followed.
"""
from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest
from test_backup_recovery_functional import PW, _make_full_source, _restore

from sigil import backup
from sigil.backup import create_backup

_REPO = Path(backup.__file__).resolve().parents[3]
_UNIT_DIRS = (_REPO / "infra" / "systemd", _REPO / "apps" / "sigil" / "deploy" / "systemd")
_HOME_REF = re.compile(r"(?:%h|\$HOME|~|/home/[A-Za-z0-9_-]+)/\.sigil/([A-Za-z0-9_.-]+)")


def _unit_default_home_names(texts=None) -> set:
    """Every top-level ``~/.sigil/<name>`` referenced by a shipped unit / env example (an INDEPENDENT source of
    truth from the classifier's own sets)."""
    names: set = set()
    if texts is None:
        texts = [p.read_text(encoding="utf-8", errors="ignore")
                 for d in _UNIT_DIRS if d.is_dir() for p in sorted(d.iterdir()) if p.is_file()]
    for t in texts:
        names.update(_HOME_REF.findall(t))
    return names


def test_every_unit_default_home_path_is_classified():
    names = _unit_default_home_names()
    assert {"spool", "credit-lease", "venv"} <= names, names          # the scan really reads the units
    unclassified = sorted(n for n in names if backup.classify_top_level(n) == "unclassified")
    assert not unclassified, (f"shipped units place these SIGIL_HOME entries that are neither CAPTURED nor a "
                              f"documented exclusion (a silent drop from disaster recovery): {unclassified}")


def test_the_unit_scan_flags_a_new_unclassified_default():
    names = _unit_default_home_names(["Environment=X=%h/.sigil/brand-new-state", "ExecStart=~/.sigil/spool"])
    assert names == {"brand-new-state", "spool"}
    assert backup.classify_top_level("brand-new-state") == "unclassified"


@pytest.mark.parametrize("name", ["credit-lease", "spool", "bridge.env", "cockpit.env", "customer.env",
                                  "public.env"])
def test_money_and_unit_config_state_is_captured(name):
    assert backup.classify_top_level(name) == "captured"


def _populate_saas_state(src: Path) -> dict:
    files = {
        "credit-lease/leases/cust_a.json": b'{"slug":"cust_a","nonce":"n1","signed":"owner"}',
        "credit-lease/settlements/cust_a/n0.json": b'{"settled":true}',
        "credit-lease/pauses/cust_b.json": b'{"holds":["n7"]}',
        "spool/settle/incoming/c1.json": b'{"completion":"pending-money"}',
        "spool/billing/incoming/flw-991.json": b'{"tx":"991","customer":"a@example.com"}',
        "spool/billing/processed/flw-990": b"",
        "spool/findings/working/f1.json": b'{"finding":"in-flight"}',
        "bridge.env": b"SIGIL_BRIDGE_PORT=8771\n",
        "customer.env": b"SIGIL_CUSTOMER_SESSION_KEY=s3cr3t\n",
    }
    for rel, data in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    (src / "spool" / "settle" / "spool.lock").write_text("")                  # lockfiles are never captured
    outside = src.parent / "outside-secret.txt"
    outside.write_text("must never be followed")
    (src / "spool" / "billing" / "incoming" / "link.json").symlink_to(outside)  # symlinks are never followed
    return files


def test_saas_money_state_round_trips_byte_identically_and_owner_only(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    files = _populate_saas_state(src)
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    new, _rv, _out = _restore(tmp_path, dest)
    for rel, data in files.items():
        got = new / rel
        assert got.read_bytes() == data, rel
        assert stat.S_IMODE(got.stat().st_mode) == 0o600, f"{rel} must be owner-only on restore"
    assert not (new / "spool" / "settle" / "spool.lock").exists()
    assert not (new / "spool" / "billing" / "incoming" / "link.json").exists()


def test_a_home_without_saas_state_still_round_trips(tmp_path):
    import shutil
    src, v, owner, _w = _make_full_source(tmp_path)
    shutil.rmtree(src / "spool")
    shutil.rmtree(src / "credit-lease")                                    # an install without the SaaS pipeline
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    new, _rv, _out = _restore(tmp_path, dest)
    assert not (new / "spool").exists() and not (new / "credit-lease").exists()
    assert (new / "spine" / "spine.jsonl").exists() or (new / "spine").is_dir()
