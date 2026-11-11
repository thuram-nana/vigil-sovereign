"""#70 (backups-everywhere) — every SIGIL_HOME entry the PRODUCT references (not only the sigil package's own
``home / "<name>"`` writes) has a recorded capture-or-exclude decision, and the decisions for the SaaS money state
are the SAFE ones.

THE GAP THIS CLOSES. The coverage contract was grounded only in a static scan of the sigil PACKAGE. Paths that come
from the shipped units' DEFAULTS (``%h/.sigil/credit-lease``, ``%h/.sigil/spool``, the per-unit ``*.env`` files) or
from other planes (``$SIGIL_HOME/vigil-tool-state.tsv``) were silently UNCLASSIFIED — no decision at all.

The decisions (red-penned):
  * the unit ``*.env`` files are CAPTURED (operator config a functional recovery needs; restored 0600);
  * ``credit-lease`` is EXCLUDED from THIS leg: it is the cross-plane seam = the shared ``VIGIL_BASE_DIR`` (it also
    holds the offense engine's own keys / floor / job queue), so it is the OFFENSE leg's to capture — the sovereign
    process packaging it would carry offense private keys (FATAL-2) and two legs restoring one tree from different
    instants would clobber newer settlement markers;
  * ``spool`` is EXCLUDED: a capture not point-in-time consistent with the spine can tear exactly-once (lost refund /
    double grant), while losing pending signals fails SAFE (credits stay held, recoverable).
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
_HOME_REF = re.compile(
    r"(?:(?:%h|\$HOME|~|/home/[A-Za-z0-9_-]+)/\.sigil|\$\{?SIGIL_HOME\}?)/([A-Za-z0-9_-][A-Za-z0-9_.-]*[A-Za-z0-9_-])")
_SCAN_SUFFIXES = {".py", ".service", ".timer", ".example", ".sh", ".env"}
_SKIP_PARTS = {".git", "node_modules", "tests", "__pycache__"}


def _product_home_refs(texts=None) -> set:
    """Every top-level ``~/.sigil/<name>`` / ``$SIGIL_HOME/<name>`` the PRODUCT references — code, shipped units,
    env examples, scripts — tests excluded. An INDEPENDENT source of truth from the classifier's own sets."""
    names: set = set()
    if texts is None:
        texts = []
        for p in _REPO.rglob("*"):
            if p.suffix not in _SCAN_SUFFIXES or not p.is_file():
                continue
            rel = p.relative_to(_REPO).parts
            if any(part in _SKIP_PARTS or part.startswith(".venv") for part in rel):
                continue
            texts.append(p.read_text(encoding="utf-8", errors="ignore"))
    for t in texts:
        names.update(_HOME_REF.findall(t))
    return names


def test_every_product_reference_to_a_home_entry_has_a_decision():
    names = _product_home_refs()
    assert {"spool", "credit-lease", "venv", "vigil-tool-state.tsv", "sigil.env"} <= names, names   # real scan
    unclassified = sorted(n for n in names if backup.classify_top_level(n) == "unclassified")
    assert not unclassified, (f"the product references these SIGIL_HOME entries with NO capture-or-exclude "
                              f"decision (a silent drop from disaster recovery): {unclassified}")


@pytest.mark.parametrize("text,expected", [
    ("Environment=X=%h/.sigil/brand-new-state", {"brand-new-state"}),
    ("path = '$SIGIL_HOME/other.db'", {"other.db"}),
    ("x=${SIGIL_HOME}/third", {"third"}),
    ("~/.sigil/spool/settle", {"spool"}),
])
def test_the_scan_sees_every_reference_form(text, expected):
    assert _product_home_refs([text]) == expected


def test_a_new_unclassified_name_is_flagged():
    assert backup.classify_top_level("brand-new-state") == "unclassified"


@pytest.mark.parametrize("name", ["bridge.env", "cockpit.env", "customer.env", "public.env"])
def test_unit_env_files_are_captured(name):
    assert backup.classify_top_level(name) == "captured"


@pytest.mark.parametrize("name", ["credit-lease", "spool", "billing-spool", "venv", "checkpoint.witnessed.json",
                                  "vigil-tool-state.tsv"])
def test_money_state_and_rederivable_entries_are_documented_exclusions(name):
    assert backup.classify_top_level(name) == "excluded"
    assert backup._EXCLUSION_REASONS[name]


def test_the_sovereign_leg_never_packages_the_cross_plane_seam_or_the_spools(tmp_path):
    """FATAL-2 + exactly-once: even when they exist under SIGIL_HOME, neither the seam (which on a SaaS install
    also holds offense private keys) nor the spools ride in the sovereign backup."""
    import json

    from vigil_core.sealing import unseal
    src, v, owner, _w = _make_full_source(tmp_path)
    seam = src / "credit-lease"
    (seam / "credit-launch-leases").mkdir(parents=True)
    (seam / "credit-launch-leases" / "cust_a.json").write_text('{"lease":1}')
    (seam / "offense-governance.key").write_text("OFFENSE-PRIVATE-KEY")      # what a real seam dir also holds
    (src / "spool" / "settle" / "incoming").mkdir(parents=True)
    (src / "spool" / "settle" / "incoming" / "c1.json").write_text('{"completion":1}')
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    salt, sealed = backup._read_header(dest)
    body = json.loads(unseal(backup._derive_key(PW, salt), sealed, context=backup._BODY_CONTEXT))
    rels = set(body["files"])
    assert not any(r.startswith(("credit-lease/", "spool/")) for r in rels), sorted(rels)
    assert "OFFENSE-PRIVATE-KEY" not in json.dumps(body)


def test_unit_env_files_round_trip_owner_only(tmp_path):
    src, v, owner, _w = _make_full_source(tmp_path)
    (src / "customer.env").write_text("SIGIL_CUSTOMER_SESSION_KEY=s3cr3t\n")
    dest = tmp_path / "bk.sglbk"
    create_backup(dest, PW, home=src, vault=v, owner_key=owner)
    new, _rv, _out = _restore(tmp_path, dest)
    for env in ("bridge.env", "cockpit.env", "customer.env", "public.env"):
        got = new / env
        assert got.read_bytes() == (src / env).read_bytes(), env
        assert stat.S_IMODE(got.stat().st_mode) == 0o600, f"{env} must be owner-only on restore"
