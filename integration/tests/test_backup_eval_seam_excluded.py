"""An offense backup never carries the eval-capability-grant / eval-offense-attestation PUBLICATIONS, and restore
skips them in an archive made before that rule: restoring one would bring back a grant or attestation the sovereign
spine has since revoked (with its older, lower floor beside it). The floors themselves are still restored.

Runs where ``framework`` is importable (the restore re-verifies the offense spine), like test_backup_roundtrip:
    PYTHONPATH="integration:engine/crucible:apps/sigil:gateway:packages/core/vigil_core:." \\
        .venv/bin/python -m pytest integration/tests/test_backup_eval_seam_excluded.py -q
"""
from __future__ import annotations

import pytest

pytest.importorskip("framework.v2.evidence.cli")

from test_backup_roundtrip import PW, _seed_offense_home

from vigil_integration import backup as ob

_PUBS = ("eval-capability-grants/eng-x.json", "eval-offense-attestations/eng-x.json")
_FLOORS = (".eval-grant-highwater/eng-x.json", ".eval-offense-highwater/eng-x.json")


def _seed_eval_seam(base):
    for rel in _PUBS + _FLOORS:
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text('{"entry_count": 1, "last_seq": 1}')


def test_a_new_backup_leaves_the_publications_out(tmp_path):
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed_eval_seam(base)
    ob.create_offense_backup(tmp_path / "o.vglbk", PW, base_dir=str(base))
    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "o.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _PUBS)
    assert all((new_base / rel).is_file() for rel in _FLOORS)


def test_restore_skips_the_publications_in_an_older_archive(tmp_path, monkeypatch):
    base = tmp_path / "base"
    _seed_offense_home(base)
    _seed_eval_seam(base)
    with monkeypatch.context() as m:
        m.setattr(ob, "_EVAL_SEAM_PUBLICATION_DIRS", ())          # an archive made before the exclusion
        ob.create_offense_backup(tmp_path / "old.vglbk", PW, base_dir=str(base))
    new_base = tmp_path / "nb"
    ob.restore_offense_backup(tmp_path / "old.vglbk", str(new_base), PW)
    assert not any((new_base / rel).exists() for rel in _PUBS)
    assert all((new_base / rel).is_file() for rel in _FLOORS)
