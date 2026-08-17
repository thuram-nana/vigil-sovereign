"""SUB-PART 3 — TRUE off-HOST transport: `vigil backup --push <dest>` replicates the ENCRYPTED parts.

The systemd local backup is a PORTABLE, passphrase-encrypted LOCAL copy on the same disk (air-gapped). This
adds an opt-in, pluggable, gated off-HOST push that copies the encrypted ``*.vglbk`` / ``*.sglbk`` +
MANIFEST to a transport backend AFTER a successful backup — ciphertext only, never plaintext:
  * the pluggable transport: the local-directory backend copies the parts into ``<root>/<timestamp>/``; the
    factory resolves bare paths / ``local:`` to it and errors clearly on unbuilt schemes (rsync/scp/s3);
  * end-to-end: ``vigil backup --offense-only --push <dir>`` copies the encrypted part + MANIFEST, and the
    PUSHED copy restores identically (a real second, restorable copy off the host).

Run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core:. .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_push_transport.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

# put the repo root on sys.path so ``tools.backup.transport`` imports (as the CLI does via _ensure_tools_on_path)
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.backup.transport import (  # noqa: E402
    LocalDirectoryTransport,
    TransportError,
    get_transport,
)

from vigil_integration.cli import main  # noqa: E402
from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore  # noqa: E402


# --- the pluggable transport backend -------------------------------------------------------------------

def test_local_directory_transport_copies_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    a = src / "offense.vglbk"
    a.write_bytes(b"ciphertext-a")
    m = src / "MANIFEST.json"
    m.write_text("{}")
    root = tmp_path / "remote"
    res = LocalDirectoryTransport(root).push([a, m], "20260101-000000")
    assert res["backend"] == "local"
    assert set(res["files"]) == {"offense.vglbk", "MANIFEST.json"}
    assert (root / "20260101-000000" / "offense.vglbk").read_bytes() == b"ciphertext-a"
    assert (root / "20260101-000000" / "MANIFEST.json").read_text() == "{}"


def test_get_transport_factory_resolves_local_and_errors_on_unbuilt(tmp_path):
    assert isinstance(get_transport(str(tmp_path)), LocalDirectoryTransport)
    assert isinstance(get_transport("local:" + str(tmp_path)), LocalDirectoryTransport)
    for remote in ("rsync://host/path", "scp://host/path", "s3://bucket/key"):
        with pytest.raises(TransportError, match="not built yet"):
            get_transport(remote)
    with pytest.raises(TransportError, match="empty"):
        get_transport("")


def test_transport_rejects_unsafe_subdir(tmp_path):
    t = LocalDirectoryTransport(tmp_path / "r")
    for bad in ("../escape", "a/b", "..", "."):
        with pytest.raises(TransportError, match="unsafe remote subdir"):
            t.push([], bad)


# --- end-to-end: `vigil backup --push` then restore FROM the pushed copy -------------------------------

def test_backup_push_replicates_and_the_pushed_copy_restores(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    empty_croot = tmp_path / "empty-crucible"
    empty_croot.mkdir()
    out_root = tmp_path / "vigil-backups"
    remote = tmp_path / "off-host"

    rc = main(["backup", "--offense-only", "--out", str(out_root), "--base-dir", str(base),
               "--crucible-root", str(empty_croot), "--push", str(remote)])
    assert rc == 0

    # the pushed copy mirrors the local timestamped-dir layout: MANIFEST + the encrypted offense part.
    pushed_dirs = [p for p in remote.iterdir() if p.is_dir()]
    assert len(pushed_dirs) == 1, pushed_dirs
    pushed = pushed_dirs[0]
    assert (pushed / "MANIFEST.json").is_file()
    assert (pushed / "offense.vglbk").is_file()

    # the pushed encrypted part is byte-identical to the local one (ciphertext copied verbatim).
    local_dir = next(p for p in out_root.iterdir() if p.is_dir())
    assert (pushed / "offense.vglbk").read_bytes() == (local_dir / "offense.vglbk").read_bytes()
    # and it is NOT the plaintext spine key (transport moved ciphertext, not secrets).
    spine_key = json.loads((base / "offense-spine.key").read_text())["private_key_b64"]
    assert spine_key.encode() not in (pushed / "offense.vglbk").read_bytes()

    # restore FROM the pushed copy into fresh dirs → verified round-trip (a real, restorable off-host copy).
    new_base = tmp_path / "restored-base"
    rc2 = main(["restore", str(pushed), "--offense-only", "--base-dir", str(new_base)])
    assert rc2 == 0
    assert (new_base / f"{SLUG}.spine").is_file()
