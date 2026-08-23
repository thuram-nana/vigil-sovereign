"""SUB-PART 3 — TRUE off-HOST transport: `vigil backup --push <dest>` replicates the ENCRYPTED parts and
VERIFIES them AT THE DESTINATION (W7-4, #462).

The systemd local backup is a PORTABLE, passphrase-encrypted LOCAL copy on the same disk (air-gapped). This
adds an opt-in, pluggable, gated off-HOST push that copies the encrypted ``*.vglbk`` / ``*.sglbk`` +
MANIFEST to a transport backend AFTER a successful backup — ciphertext only, never plaintext — and then
re-reads the copy AT THE DESTINATION and refuses it if the bytes do not match what was sent:
  * the pluggable transport: the local-directory backend copies the parts into ``<root>/<timestamp>/``; the
    factory resolves bare paths / ``local:`` to it and ``rsync://`` / ``rsync:`` to the real rsync backend,
    and errors clearly on still-unbuilt schemes (scp/s3);
  * DESTINATION-side integrity (W7-4): ``Transport.verify`` hashes the bytes that actually landed at the
    destination and FAILS CLOSED on a truncated / corrupted / tampered / missing copy — negative controls
    below prove it is not a no-op, for BOTH the local-directory and the rsync backends;
  * a REAL transport round-trips: ``RsyncTransport`` shells out to the real ``rsync`` binary and its
    destination-side verify (an ssh ``sha256sum`` on the remote, or a byte-for-byte ``rsync`` read-back)
    catches tamper;
  * end-to-end: ``vigil backup --offense-only --push <dir>`` copies the encrypted part + MANIFEST, VERIFIES
    the destination (a corrupted destination makes the verb exit non-zero — the "fails without this change"
    guard), and the PUSHED copy restores identically (a real second, restorable copy off the host).

Run in the offense leg:
    PYTHONPATH=integration:engine/crucible:gateway:packages/core/vigil_core:. .venv-offense/bin/python \
        -m pytest integration/tests/test_backup_push_transport.py -q
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest

pytest.importorskip("framework.v2.evidence.cli")

# put the repo root on sys.path so ``tools.backup.transport`` imports (as the CLI does via _ensure_tools_on_path)
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools.backup import transport as _transport_mod  # noqa: E402
from tools.backup.transport import (  # noqa: E402
    LocalDirectoryTransport,
    RsyncTransport,
    TransportError,
    get_transport,
)

from vigil_integration.cli import main  # noqa: E402
from test_backup_roundtrip import PW, SLUG, _seed_offense_home  # type: ignore  # noqa: E402


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_HAVE_RSYNC = shutil.which("rsync") is not None
_requires_rsync = pytest.mark.skipif(not _HAVE_RSYNC, reason="the real `rsync` binary is not installed")


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
    # scp/s3 are still honest residuals — a clear error, never a silent no-op.
    for remote in ("scp://host/path", "s3://bucket/key"):
        with pytest.raises(TransportError, match="not built yet"):
            get_transport(remote)
    with pytest.raises(TransportError, match="empty"):
        get_transport("")


def test_get_transport_resolves_rsync(tmp_path):
    # rsync now SHIPS as a real remote transport (daemon URL, ssh host:path, and local/mounted paths).
    t_daemon = get_transport("rsync://host/module/path")
    assert isinstance(t_daemon, RsyncTransport) and t_daemon.dest == "rsync://host/module/path"
    t_ssh = get_transport("rsync:user@host:/srv/vigil-backups")
    assert isinstance(t_ssh, RsyncTransport) and t_ssh._ssh_split() == ("user@host", "/srv/vigil-backups")
    t_local = get_transport("rsync:" + str(tmp_path))
    assert isinstance(t_local, RsyncTransport) and t_local._ssh_split() is None
    with pytest.raises(TransportError, match="empty rsync destination"):
        get_transport("rsync:")


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


# --- W7-4: DESTINATION-side integrity verification (local-directory backend, always runs) ---------------

def _push_two(root: Path, subdir: str = "20260101-000000") -> tuple[LocalDirectoryTransport, dict]:
    """Push two files into a local-directory destination; return the transport + the sent-sha256 map."""
    src = root / "src"
    src.mkdir(parents=True, exist_ok=True)
    a = src / "offense.vglbk"
    a.write_bytes(b"ciphertext-a" * 100)
    m = src / "MANIFEST.json"
    m.write_text(json.dumps({"schema": 1}))
    t = LocalDirectoryTransport(root / "remote")
    t.push([a, m], subdir)
    expected = {"offense.vglbk": _sha256(a.read_bytes()), "MANIFEST.json": _sha256(m.read_bytes())}
    return t, expected


def test_local_verify_passes_on_an_intact_copy(tmp_path):
    t, expected = _push_two(tmp_path)
    res = t.verify("20260101-000000", expected)
    assert set(res["verified"]) == {"offense.vglbk", "MANIFEST.json"}
    assert res["verified"]["offense.vglbk"] == expected["offense.vglbk"]


def test_local_verify_catches_a_TRUNCATED_destination_copy(tmp_path):
    # NEGATIVE CONTROL: a truncated remote copy must be detected and refused (never silently accepted).
    t, expected = _push_two(tmp_path)
    landed = tmp_path / "remote" / "20260101-000000" / "offense.vglbk"
    landed.write_bytes(landed.read_bytes()[:-10])          # truncate at the destination
    with pytest.raises(TransportError, match="destination integrity verification FAILED"):
        t.verify("20260101-000000", expected)


def test_local_verify_catches_a_TAMPERED_destination_copy(tmp_path):
    # NEGATIVE CONTROL: a same-length byte flip (a checksum that only counted bytes would miss this).
    t, expected = _push_two(tmp_path)
    landed = tmp_path / "remote" / "20260101-000000" / "offense.vglbk"
    b = bytearray(landed.read_bytes())
    b[0] ^= 0xFF                                            # flip a bit, SAME length
    landed.write_bytes(bytes(b))
    with pytest.raises(TransportError, match="destination sha256"):
        t.verify("20260101-000000", expected)


def test_local_verify_catches_a_MISSING_destination_copy(tmp_path):
    # NEGATIVE CONTROL: the remote copy never landed (or was deleted) → refused, not passed as "no news".
    t, expected = _push_two(tmp_path)
    (tmp_path / "remote" / "20260101-000000" / "MANIFEST.json").unlink()
    with pytest.raises(TransportError, match="unreadable|missing"):
        t.verify("20260101-000000", expected)


# --- W7-4: a REAL transport round-trips + is destination-verified (rsync binary) ------------------------

def test_rsync_available_when_running_in_ci():
    # A skipped proof is the same colour as a passing one on a dashboard. rsync ships on the CI runner, so
    # the rsync round-trip tests below MUST actually run there; if rsync were missing under CI the
    # real-transport proof would silently go dark. Fail loudly in that case, skip only in local dev.
    if os.environ.get("CI"):
        assert _HAVE_RSYNC, ("rsync is missing under CI — the real-transport round-trip proof would skip; "
                             "install rsync in the job rather than let the proof go dark")
    else:
        pytest.skip("not CI; the real `rsync` binary is optional for local dev")


@_requires_rsync
def test_rsync_transport_roundtrips_via_the_real_binary(tmp_path):
    # A REAL transport (the rsync binary) round-trips: push copies the bytes, and the DESTINATION-side
    # verify (a byte-for-byte rsync read-back) confirms they landed intact.
    src = tmp_path / "src"
    src.mkdir()
    a = src / "offense.vglbk"
    a.write_bytes(os.urandom(4096))
    m = src / "MANIFEST.json"
    m.write_text(json.dumps({"schema": 1, "host": "x"}))
    dest = tmp_path / "rsync-dest"
    t = RsyncTransport(str(dest))                           # a local path exercises the real rsync binary
    res = t.push([a, m], "20260101-000000")
    assert res["backend"] == "rsync"
    landed = dest / "20260101-000000" / "offense.vglbk"
    assert landed.is_file() and landed.read_bytes() == a.read_bytes()   # a real, byte-identical copy
    expected = {"offense.vglbk": _sha256(a.read_bytes()), "MANIFEST.json": _sha256(m.read_bytes())}
    verified = t.verify("20260101-000000", expected)        # destination-side read-back matches
    assert set(verified["verified"]) == {"offense.vglbk", "MANIFEST.json"}


@_requires_rsync
def test_rsync_verify_catches_a_tampered_destination_copy(tmp_path):
    # NEGATIVE CONTROL over the real rsync backend: tamper the landed copy → verify fails closed.
    src = tmp_path / "src"
    src.mkdir()
    a = src / "offense.vglbk"
    a.write_bytes(os.urandom(2048))
    dest = tmp_path / "rsync-dest"
    t = RsyncTransport(str(dest))
    t.push([a], "20260101-000000")
    expected = {"offense.vglbk": _sha256(a.read_bytes())}
    assert t.verify("20260101-000000", expected)            # intact first
    landed = dest / "20260101-000000" / "offense.vglbk"
    bad = bytearray(landed.read_bytes())
    bad[5] ^= 0x01
    landed.write_bytes(bytes(bad))
    with pytest.raises(TransportError, match="destination integrity verification FAILED"):
        t.verify("20260101-000000", expected)


def _fake_ssh(tmp_path: Path) -> str:
    """A real executable that emulates ``ssh <host> <cmd...>`` by dropping the host and running the command
    locally. Lets the rsync-over-ssh remote-hash path (``ssh host sha256sum``) be exercised for real —
    a real subprocess computing a real hash — without a live remote host."""
    p = tmp_path / "fake-ssh"
    p.write_text("#!/bin/sh\nshift\nexec \"$@\"\n")         # drop the host arg, run the rest locally
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(p)


@pytest.mark.skipif(shutil.which("sha256sum") is None, reason="sha256sum not available")
def test_rsync_over_ssh_remote_sha256_and_negative_control(tmp_path):
    # The strongest destination-side check: the REMOTE runs sha256sum on its OWN bytes. Exercised for real
    # via a fake-ssh wrapper that runs sha256sum locally, so the ssh command construction + hex parsing +
    # mismatch detection are all real.
    remote_root = tmp_path / "remote-root"
    landed_dir = remote_root / "20260101-000000"
    landed_dir.mkdir(parents=True)
    payload = os.urandom(1000)
    (landed_dir / "offense.vglbk").write_bytes(payload)
    t = RsyncTransport(f"backuphost:{remote_root}", ssh_bin=_fake_ssh(tmp_path))
    assert t._ssh_split() == ("backuphost", str(remote_root))
    # positive: the remote-computed hash matches the bytes we sent.
    assert t.remote_sha256("20260101-000000", "offense.vglbk") == _sha256(payload)
    assert t.verify("20260101-000000", {"offense.vglbk": _sha256(payload)})
    # NEGATIVE CONTROL: tamper the remote bytes → the remote sha256sum no longer matches → verify fails.
    (landed_dir / "offense.vglbk").write_bytes(payload + b"x")
    with pytest.raises(TransportError, match="destination integrity verification FAILED"):
        t.verify("20260101-000000", {"offense.vglbk": _sha256(payload)})


# --- W7-4: end-to-end CLI fail-closed — the "fails WITHOUT this change" guard ---------------------------

class _CorruptingTransport(LocalDirectoryTransport):
    """A transport that TRUNCATES every file as it lands — a stand-in for a lossy/hostile wire. Push
    'succeeds', so a build WITHOUT the destination-verify step would report the backup as good. The W7-4
    destination check is what turns this into a non-zero exit."""

    def push(self, files, remote_subdir):
        res = super().push(files, remote_subdir)
        for name in res["files"]:
            landed = self.root / remote_subdir / name
            landed.write_bytes(landed.read_bytes()[:1])    # corrupt at the destination
        return res


def test_cli_push_FAILS_CLOSED_when_the_destination_is_corrupted(tmp_path, monkeypatch):
    # THE "fails without this change" TEST. With the W7-4 verify in place, a corrupted destination makes
    # `vigil backup --push` exit non-zero. On a tree WITHOUT the CLI verify step this returns 0 (the copy
    # is silently accepted) — observed RED on the pre-fix cli.py, GREEN with the fix.
    monkeypatch.setenv("VIGIL_BACKUP_PASSPHRASE", PW)
    monkeypatch.setattr(_transport_mod, "get_transport",
                        lambda spec: _CorruptingTransport(spec), raising=True)
    base = tmp_path / "src-base"
    _seed_offense_home(base)
    empty_croot = tmp_path / "empty-crucible"
    empty_croot.mkdir()
    out_root = tmp_path / "vigil-backups"
    remote = tmp_path / "off-host"

    rc = main(["backup", "--offense-only", "--out", str(out_root), "--base-dir", str(base),
               "--crucible-root", str(empty_croot), "--push", str(remote)])
    assert rc == 1, "a corrupted destination copy must make the backup verb fail closed"
    # the LOCAL backup is untouched (fail-closed refuses the off-host copy, not the good local one).
    local_dir = next(p for p in out_root.iterdir() if p.is_dir())
    assert (local_dir / "offense.vglbk").is_file()


def test_cli_push_reports_destination_verified_on_a_clean_push(tmp_path, monkeypatch, capsys):
    # The positive companion: a clean push verifies the destination and says so.
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
    out = capsys.readouterr().out
    assert "verified →" in out and "destination" in out
