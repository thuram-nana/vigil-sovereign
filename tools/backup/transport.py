"""SUB-PART 3 — pluggable off-HOST transport for the two-plane backup, with DESTINATION-side integrity
verification (W7-4, #462). Pure stdlib.

The systemd LOCAL backup writes to ``~/vigil-backups`` on the SAME disk and runs air-gapped
(``PrivateNetwork=yes``): it is a PORTABLE, passphrase-encrypted LOCAL backup, NOT off-HOST replication — a
dead host takes both the engine and its local backups. ``vigil backup --push <dest>`` closes that gap: AFTER a
successful local backup it copies the ENCRYPTED plane files (``*.vglbk`` / ``*.sglbk``) + ``MANIFEST.json`` +
its governance signature ``MANIFEST.sig.json`` (W7-6) to a transport backend, so a genuine second copy lives
off the host — and, carrying the signature, the pushed copy is itself a signature-verifying ``vigil restore``
source.

Confidentiality across the wire: every plane file is passphrase-encrypted (scrypt-derived AEAD) BEFORE it is
written locally, so transport moves CIPHERTEXT only — the remote never sees plaintext, and the remote's own
security is the operator's responsibility. The MANIFEST carries only file names, sizes, and sha256 hashes (no
secrets). Push transports exactly the bytes the local backup produced; it does not re-encrypt or decrypt.

DESTINATION-side integrity — the W7-4 gate. A push is NOT trusted until the bytes AT THE DESTINATION are
re-hashed and matched against the sha256 of exactly what was sent — this is deliberately NOT a second local
checksum of the source (which would only re-confirm what we already know). :meth:`Transport.verify` reads the
remote copy back THROUGH the backend's own read path and FAILS CLOSED (raises :class:`TransportError`) on any
missing, truncated, corrupted, or tampered file, so a bad off-host copy is DETECTED and refused, never
silently accepted. A backend cannot opt out: :meth:`Transport.verify` is written once on the base class over a
single :meth:`Transport.remote_sha256` readback each backend must provide. (Signing the top-level MANIFEST is
the separate W7-6/#464 step; it hardens verification against an attacker who rewrites the copy AND its
recorded hashes together — this gate already catches corruption/truncation/tamper relative to what was sent.)

Two REAL backends ship (neither is a stub):
  * ``local`` — the local-directory backend (a bare path, or ``local:<path>``): copy the parts into
    ``<root>/<subdir>/`` on the local filesystem. Used against a MOUNTED remote FS (NFS / sshfs), a removable
    disk, and in tests to simulate a remote host. Verification re-reads the landed bytes.
  * ``rsync`` — a REAL remote transport over the ``rsync`` binary (``rsync://…`` daemon URL, an
    ``[user@]host:path`` ssh spec, or a local / mounted path), selected by ``rsync://…`` or ``rsync:<spec>``.
    Push shells out to real ``rsync`` (requires rsync >= 3.2.3 for ``--mkpath``). Verification is
    DESTINATION-side in the strongest sense over ssh: it runs ``sha256sum`` ON the remote host, so the remote
    hashes its OWN stored bytes; for a daemon / local target it reads the landed copy back (via ``rsync``) and
    hashes the bytes it actually receives.

The factory + registry are structured so further backends (scp / object-store / S3) slot in behind the SAME
``Transport.push`` + ``Transport.remote_sha256`` contract without touching callers.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Mapping

# A ``scheme://`` prefix (e.g. ``rsync://``, ``s3://``) marks a remote backend spec; a bare path or ``local:``
# is the shipped local-directory backend.
_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]*)://")

_CHUNK = 1 << 16
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


class TransportError(Exception):
    """A push could not be completed, or its DESTINATION-side integrity check failed (unknown/unbuilt backend,
    a copy failure, or a remote copy that is missing / truncated / corrupted / tampered). Fail-closed: the
    local backup already succeeded and is untouched — only the off-host replication step is refused."""


def _sha256_path(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_subdir(remote_subdir: str) -> None:
    if not remote_subdir or "/" in remote_subdir or remote_subdir in (".", ".."):
        raise TransportError(f"unsafe remote subdir name {remote_subdir!r}")


def _safe_name(name: str) -> None:
    if not name or "/" in name or name in (".", ".."):
        raise TransportError(f"unsafe remote file name {name!r}")


class Transport:
    """The transport contract. A backend copies a fixed set of already-encrypted local files into a
    ``remote_subdir`` on the destination, mirroring the local timestamped-dir layout so the pushed copy is
    itself a valid ``vigil restore`` source. Subclasses implement :meth:`push` and :meth:`remote_sha256`;
    :meth:`verify` (the W7-4 destination-side integrity gate) is provided once, over ``remote_sha256``."""

    scheme = ""

    def push(self, files: Iterable[Path], remote_subdir: str) -> dict:
        raise NotImplementedError

    def remote_sha256(self, remote_subdir: str, name: str) -> str:
        """The sha256 the DESTINATION currently holds for ``name`` under ``remote_subdir``, computed from the
        destination's OWN bytes (a remote hash, or a byte-for-byte re-read of the landed copy). Fail-closed:
        a missing / unreadable remote copy raises :class:`TransportError`."""
        raise NotImplementedError

    def verify(self, remote_subdir: str, expected_sha256: Mapping[str, str]) -> dict:
        """DESTINATION-side integrity gate (W7-4). For each ``name -> sent-sha256`` pair, re-read the copy AT
        THE DESTINATION (:meth:`remote_sha256`) and confirm it equals what was sent. Raises
        :class:`TransportError` naming every file that is missing, truncated, corrupted, or altered — the push
        MUST then be treated as FAILED, never silently accepted (a corrupt off-host copy is worse than a
        known-absent one). Returns the per-file destination hashes on success. This is not a local checksum:
        it hashes the bytes that actually landed on the destination."""
        failures: list[str] = []
        checked: dict[str, str] = {}
        for name, sent in expected_sha256.items():
            try:
                got = self.remote_sha256(remote_subdir, name)
            except TransportError as e:
                failures.append(f"{name}: destination copy unreadable ({e})")
                continue
            checked[name] = got
            if got != sent:
                failures.append(f"{name}: destination sha256 {got[:12]}… != sent {sent[:12]}…")
        if failures:
            raise TransportError(
                "destination integrity verification FAILED — refusing to trust the off-host copy "
                "(fail-closed): " + "; ".join(sorted(failures)))
        return {"backend": self.scheme, "subdir": remote_subdir, "verified": checked}


class LocalDirectoryTransport(Transport):
    """Copy the encrypted parts + MANIFEST into ``<root>/<remote_subdir>/`` on the local filesystem. Used in
    tests to simulate a remote host, and in production against a mounted remote FS / removable disk. The copy
    preserves bytes exactly (``shutil.copy2``), so the pushed dir restores byte-identically to the local one.
    Destination verification re-reads the landed bytes and hashes them."""

    scheme = "local"

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def push(self, files: Iterable[Path], remote_subdir: str) -> dict:
        _safe_subdir(remote_subdir)
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

    def remote_sha256(self, remote_subdir: str, name: str) -> str:
        _safe_subdir(remote_subdir)
        _safe_name(name)
        p = self.root / remote_subdir / name
        if not p.is_file():
            raise TransportError(f"destination copy missing: {p}")
        try:
            return _sha256_path(p)
        except OSError as e:
            raise TransportError(f"cannot read destination copy {p}: {e}") from e


class RsyncTransport(Transport):
    """A REAL remote transport over the ``rsync`` binary (not a stub). ``dest`` is the rsync destination ROOT:
    an ``[user@]host:path`` ssh spec, an ``rsync://[user@]host[:port]/module/path`` daemon URL, or a local /
    mounted path. ``push`` shells out to real ``rsync`` (``-a --mkpath``; requires rsync >= 3.2.3 on both
    ends). Destination verification is genuinely destination-side: over ssh it runs ``sha256sum`` ON THE
    REMOTE host (the remote hashes its own stored bytes); for a daemon / local-or-mounted target it reads the
    landed copy back with ``rsync`` and hashes the bytes it actually receives.

    Residual: a real off-host ssh / daemon target needs the operator's endpoint + credentials (an ssh key or
    an rsyncd secret) and a Linux remote that provides ``sha256sum`` — see the honest note in
    ``infra/systemd/vigil-backup-push.env.example``. The push and verification logic below is real and tested
    end to end against a real ``rsync`` binary; only the network endpoint is operator-supplied."""

    scheme = "rsync"

    def __init__(self, dest: str, *, rsync_bin: str = "rsync", ssh_bin: str = "ssh", timeout: float = 300.0):
        self.dest = str(dest).rstrip("/")
        if not self.dest:
            raise TransportError("empty rsync destination")
        self.rsync_bin = rsync_bin
        self.ssh_bin = ssh_bin
        self.timeout = timeout

    def _is_daemon(self) -> bool:
        return self.dest.startswith("rsync://")

    def _ssh_split(self) -> "tuple[str, str] | None":
        """``(host, path)`` if ``dest`` is an ssh ``[user@]host:path`` spec, else ``None``. rsync's own rule:
        a ``:`` that appears before the first ``/`` marks a remote-host spec (and it is not a daemon URL)."""
        if self._is_daemon():
            return None
        colon = self.dest.find(":")
        slash = self.dest.find("/")
        if colon > 0 and (slash == -1 or colon < slash):
            return self.dest[:colon], self.dest[colon + 1:]
        return None

    def _target(self, remote_subdir: str) -> str:
        _safe_subdir(remote_subdir)
        return f"{self.dest}/{remote_subdir}/"

    def _run(self, argv: list[str]) -> "subprocess.CompletedProcess[str]":
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout)
        except FileNotFoundError as e:
            raise TransportError(f"{argv[0]!r} not found — install rsync (>=3.2.3) / ssh: {e}") from e
        except subprocess.TimeoutExpired as e:
            raise TransportError(f"{argv[0]!r} timed out after {self.timeout}s") from e

    def push(self, files: Iterable[Path], remote_subdir: str) -> dict:
        paths = [Path(f) for f in files]
        for f in paths:
            if not f.is_file():
                raise TransportError(f"push source {f} is not a file")
        target = self._target(remote_subdir)
        # -a archive; --mkpath creates the destination path (rsync >= 3.2.3); '--' ends option parsing so a
        # filename can never be read as a flag. Copy exactly the given files into <dest>/<subdir>/.
        argv = [self.rsync_bin, "-a", "--mkpath", "--"] + [str(f) for f in paths] + [target]
        proc = self._run(argv)
        if proc.returncode != 0:
            raise TransportError(f"rsync push to {target} failed (exit {proc.returncode}): "
                                 f"{(proc.stderr or '').strip()}")
        return {"backend": self.scheme, "target": target, "files": [f.name for f in paths]}

    def remote_sha256(self, remote_subdir: str, name: str) -> str:
        _safe_subdir(remote_subdir)
        _safe_name(name)
        ssh = self._ssh_split()
        if ssh is not None:
            host, path = ssh
            remote_file = f"{path}/{remote_subdir}/{name}"
            # DESTINATION-side hash in the strongest form: the REMOTE host hashes its OWN stored bytes.
            proc = self._run([self.ssh_bin, host, "sha256sum", "--", remote_file])
            if proc.returncode != 0:
                raise TransportError(f"remote sha256sum of {host}:{remote_file} failed "
                                     f"(exit {proc.returncode}): {(proc.stderr or '').strip()}")
            tokens = (proc.stdout or "").split()
            if not tokens or not _HEX64_RE.fullmatch(tokens[0]):
                raise TransportError(
                    f"unparseable remote sha256sum output for {remote_file!r}: {proc.stdout!r}")
            return tokens[0]
        # daemon or local/mounted path -> pull the landed copy back and hash the bytes we actually receive.
        return self._pullback_sha256(remote_subdir, name)

    def _pullback_sha256(self, remote_subdir: str, name: str) -> str:
        src = f"{self.dest}/{remote_subdir}/{name}"
        with tempfile.TemporaryDirectory() as td:
            local = Path(td) / name
            proc = self._run([self.rsync_bin, "-a", "--", src, str(local)])
            if proc.returncode != 0 or not local.is_file():
                raise TransportError(f"cannot read destination copy {src} (exit {proc.returncode}): "
                                     f"{(proc.stderr or '').strip()}")
            return _sha256_path(local)


# The pluggable registry: scheme -> backend factory taking the destination string. rsync is routed
# explicitly in get_transport (its spec must reach rsync verbatim); add scp/object-store here.
_REGISTRY: dict[str, "callable[[str], Transport]"] = {   # type: ignore[valid-type]
    "local": lambda dest: LocalDirectoryTransport(dest),
}


def get_transport(spec: str) -> Transport:
    """Resolve a ``--push`` destination spec to a Transport backend.

      * a bare path (``/mnt/remote/backups`` or ``~/off-host``) -> the local-directory backend;
      * ``local:<path>`` -> the local-directory backend, explicitly;
      * ``rsync://[user@]host[:port]/module/path`` -> the rsync backend (daemon URL, passed to rsync verbatim);
      * ``rsync:<spec>`` where ``<spec>`` is ``[user@]host:path`` (ssh) or a local/mounted path -> the rsync
        backend;
      * ``<scheme>://…`` for a scheme NOT in the registry (``scp``, ``s3``) -> a clear TransportError naming
        the contract to implement (structured to slot in, not silently no-op).
    """
    if not spec:
        raise TransportError("empty --push destination")
    if spec.startswith("rsync://"):
        return RsyncTransport(spec)                        # full daemon URL, passed to rsync verbatim
    if spec.startswith("rsync:"):
        return RsyncTransport(spec[len("rsync:"):])        # rsync:[user@]host:path | rsync:/local/path
    m = _SCHEME_RE.match(spec)
    if m:
        scheme = m.group(1)
        factory = _REGISTRY.get(scheme)
        if factory is None:
            raise TransportError(
                f"transport backend {scheme!r} is not built yet — the local-directory and rsync backends "
                f"ship. Implement Transport.push + Transport.remote_sha256 and register {scheme!r} in "
                f"tools/backup/transport._REGISTRY, or push over rsync (rsync://… or "
                f"rsync:[user@]host:path) or to a local path / mounted remote filesystem "
                f"(a bare path or local:<path>).")
        return factory(spec[len(scheme) + len("://"):])
    if spec.startswith("local:"):
        return LocalDirectoryTransport(spec[len("local:"):])
    return LocalDirectoryTransport(spec)                    # a bare path is the local-directory backend
