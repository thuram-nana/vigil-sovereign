"""SUB-PART 3 — pluggable off-HOST transport for the two-plane backup (pure stdlib).

The systemd LOCAL backup writes to ``~/vigil-backups`` on the SAME disk and runs air-gapped
(``PrivateNetwork=yes``): it is a PORTABLE, passphrase-encrypted LOCAL backup, NOT off-HOST replication — a
dead host takes both the engine and its local backups. ``vigil backup --push <dest>`` closes that gap: AFTER a
successful local backup it copies the ENCRYPTED plane files (``*.vglbk`` / ``*.sglbk``) + ``MANIFEST.json`` to
a transport backend, so a genuine second copy lives off the host.

Confidentiality across the wire: every plane file is passphrase-encrypted (scrypt-derived AEAD) BEFORE it is
written locally, so transport moves CIPHERTEXT only — the remote never sees plaintext, and the remote's own
security is the operator's responsibility. The MANIFEST carries only file names, sizes, and sha256 hashes (no
secrets). Push transports exactly the bytes the local backup produced; it does not re-encrypt or decrypt.

Only a LOCAL-DIRECTORY backend ships here — copy to a local path, used in tests to simulate a remote host and
usable in production against a mounted remote filesystem (NFS / sshfs / a removable disk). The factory +
registry are structured so rsync / scp / object-store backends slot in behind the SAME ``Transport.push``
contract without touching callers: implement ``push`` and register the scheme.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Iterable

# A ``scheme://`` prefix (e.g. ``rsync://``, ``s3://``) marks a remote backend spec; a bare path or ``local:``
# is the shipped local-directory backend.
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*)://")


class TransportError(Exception):
    """A push could not be completed (unknown/unbuilt backend, or a copy failure). Fail-closed: the local
    backup already succeeded and is untouched — only the off-host replication step failed."""


class Transport:
    """The transport contract. A backend copies a fixed set of already-encrypted local files into a
    ``remote_subdir`` on the destination, mirroring the local timestamped-dir layout so the pushed copy is
    itself a valid ``vigil restore`` source. Subclasses implement :meth:`push`."""

    scheme = ""

    def push(self, files: Iterable[Path], remote_subdir: str) -> dict:
        raise NotImplementedError


class LocalDirectoryTransport(Transport):
    """Copy the encrypted parts + MANIFEST into ``<root>/<remote_subdir>/`` on the local filesystem. Used in
    tests to simulate a remote host, and in production against a mounted remote FS / removable disk. The copy
    preserves bytes exactly (``shutil.copy2``), so the pushed dir restores byte-identically to the local one."""

    scheme = "local"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def push(self, files: Iterable[Path], remote_subdir: str) -> dict:
        if not remote_subdir or "/" in remote_subdir or remote_subdir in (".", ".."):
            raise TransportError(f"unsafe remote subdir name {remote_subdir!r}")
        target = self.root / remote_subdir
        try:
            target.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise TransportError(f"cannot create push target {target}: {e}") from e
        copied: list[str] = []
        for f in files:
            f = Path(f)
            if not f.is_file():
                raise TransportError(f"push source {f} is not a file")
            try:
                shutil.copy2(str(f), str(target / f.name))    # copy2 preserves bytes + mtime
            except OSError as e:
                raise TransportError(f"failed to copy {f} → {target / f.name}: {e}") from e
            copied.append(f.name)
        return {"backend": self.scheme, "target": str(target), "files": copied}


# The pluggable registry: scheme → backend factory taking the destination string. Add rsync/scp/s3 here.
_REGISTRY: dict[str, "callable[[str], Transport]"] = {   # type: ignore[valid-type]
    "local": lambda dest: LocalDirectoryTransport(dest),
}


def get_transport(spec: str) -> Transport:
    """Resolve a ``--push`` destination spec to a Transport backend.

      * a bare path (``/mnt/remote/backups`` or ``~/off-host``) → the local-directory backend;
      * ``local:<path>`` → the local-directory backend, explicitly;
      * ``<scheme>://…`` for a scheme NOT in the registry → a clear TransportError naming the contract to
        implement (rsync/scp/object-store are structured to slot in, not silently no-op).
    """
    if not spec:
        raise TransportError("empty --push destination")
    m = _SCHEME_RE.match(spec)
    if m:
        scheme = m.group(1)
        factory = _REGISTRY.get(scheme)
        if factory is None:
            raise TransportError(
                f"transport backend {scheme!r} is not built yet — only the local-directory backend ships. "
                f"Implement Transport.push and register {scheme!r} in tools/backup/transport._REGISTRY, or "
                f"push to a local path / mounted remote filesystem (a bare path or local:<path>).")
        return factory(spec[len(scheme) + len("://"):])
    if spec.startswith("local:"):
        return LocalDirectoryTransport(spec[len("local:"):])
    return LocalDirectoryTransport(spec)                    # a bare path is the local-directory backend
