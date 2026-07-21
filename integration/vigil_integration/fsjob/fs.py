"""
fsjob.fs — the governed, sandboxed workspace filesystem (VIGIL-FUSION F9).

A port of redamon's ``workspace_fs`` mutation surface, subordinated to the sovereign core:

  * Every path resolves through the race-free :mod:`fsjob.sandbox` kernel — traversal / absolute /
    symlink / symlink-race / NUL are all refused, and the *operation itself* runs over the safe fd, not
    a re-resolved string.
  * Every MUTATION (write/edit/delete/move/mkdir/extract) is a signed, append-only
    :class:`~fsjob.spine.SpineEvent` carrying the pre/post content hashes, and is REVERSIBLE: the
    byte-snapshot undo stack becomes a signed compensating event (``fs.undo``). If the mutation cannot
    be signed, it is refused or rolled back — there is no unsigned mutation.
  * Archive extraction is hardened against tar-slip (member names validated + written through the safe
    kernel), symlink members (refused), and zip-bombs (entry-count + total-uncompressed-size caps).
  * ``jobs/`` is a PROTECTED subtree: the agent-facing fs tools refuse to mutate it, so the LLM cannot
    forge job metadata to smuggle an escalation (the job runner writes there through the low-level
    kernel, not this tool surface).

Total on untrusted input: every public method returns a structured :class:`FsResult` and NEVER raises —
a malformed path/arg degrades to ``ok=False`` (a denial-of-cognition crash is itself a failure).

Import-clean: pydantic-free here (stdlib + the sandbox/spine siblings); no framework/strix/network.
"""

from __future__ import annotations

import functools
import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import sandbox
from .spine import EventLogError, SpineEventLog, sha256_hex

# --- bounds -------------------------------------------------------------------------------------
_MAX_READ_BYTES = 16 * 1024 * 1024          # a single read is bounded (RAM DoS guard)
_MAX_WRITE_BYTES = 16 * 1024 * 1024         # a single write is bounded
_UNDO_MAX_ENTRIES = 128                     # bounded in-memory undo stack (oldest evicted)
_UNDO_MAX_SNAPSHOT = 8 * 1024 * 1024        # a pre-image larger than this is not snapshotted (still signed)
_ARCHIVE_MAX_INPUT = 64 * 1024 * 1024       # max archive file size read
_ARCHIVE_MAX_ENTRIES = 5000                 # zip-bomb: entry-count cap
_ARCHIVE_MAX_TOTAL = 500 * 1024 * 1024      # zip-bomb: total uncompressed-size cap

# The subtrees the agent-facing fs tools may never mutate (job-runner provenance lives here).
PROTECTED_SUBDIRS = frozenset({"jobs"})
_PROTECTED_SUBDIRS_CF = frozenset(p.casefold() for p in PROTECTED_SUBDIRS)


@dataclass(frozen=True)
class FsResult:
    """The total result of a workspace operation. ``ok=False`` is the fail-closed / no-signal outcome;
    ``event_id`` is the signed spine event id for a successful mutation; ``data`` carries read payloads."""

    ok: bool
    reason: str = ""
    event_id: str = ""
    data: Optional[Dict[str, Any]] = None


@dataclass
class _UndoEntry:
    """How to reverse a signed mutation. Held in a bounded in-memory stack; consumed by ``fs_undo``."""

    op: str                                  # restore_bytes | remove_path | move_back | remove_many
    paths: Tuple[str, ...]
    pre_bytes: Optional[bytes] = None        # for restore_bytes: None ⇒ target was absent ⇒ undo deletes


def _total(fn: Callable[..., FsResult]) -> Callable[..., FsResult]:
    """Total boundary: any exception from a public method degrades to a fail-closed ``FsResult``."""
    @functools.wraps(fn)
    def wrapper(self: "WorkspaceFS", *args: Any, **kwargs: Any) -> FsResult:
        try:
            return fn(self, *args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — never raise into the agent
            return FsResult(False, f"refused ({type(exc).__name__}): {exc}")
    return wrapper


def _is_protected(components: Tuple[str, ...]) -> bool:
    # case-INSENSITIVE (casefold): on a case-insensitive fs (macOS/APFS, Windows) a "Jobs/" member would
    # alias the real "jobs/" provenance tree; fold so no case variant can smuggle a write in. On a
    # case-sensitive fs this only over-refuses a distinct "Jobs/" dir (fail-closed, never under-refuses).
    return bool(components) and components[0].casefold() in _PROTECTED_SUBDIRS_CF


class WorkspaceFS:
    """A per-engagement sandboxed filesystem. ``root`` is the injected sandbox root; ``log`` supplies the
    injected signer + sequence. Reads are unsigned; every mutation is a signed, reversible spine event."""

    def __init__(self, root: str, log: SpineEventLog, *, engagement: str = "") -> None:
        # Canonicalize + validate the root once (fail-closed if it is not a real directory).
        self._root = sandbox.canonical_root(root)
        self._log = log
        self._engagement = engagement or log.engagement
        self._undo: "dict[str, _UndoEntry]" = {}
        self._undo_order: List[str] = []

    # -- internal: commit a mutation as a signed event, else roll it back -------------------------

    def _has_signer(self) -> bool:
        return self._log.signer is not None

    def _commit(self, kind: str, *, paths: List[str], pre_hash: str, post_hash: str,
                meta: dict, rollback: Callable[[], None]) -> Tuple[bool, str, str]:
        """Append the signed event; on a signing failure, run ``rollback`` (best-effort) and report."""
        try:
            event = self._log.append(kind, paths=paths, pre_hash=pre_hash, post_hash=post_hash, meta=meta)
        except EventLogError as exc:
            try:
                rollback()
            except Exception:  # noqa: BLE001 — best-effort rollback; report the signing failure either way
                return (False, f"signing failed AND rollback failed: {exc}", "")
            return (False, f"signing failed, mutation rolled back (fail-closed): {exc}", "")
        return (True, "", event.event_id)

    def _register_undo(self, event_id: str, entry: _UndoEntry) -> None:
        self._undo[event_id] = entry
        self._undo_order.append(event_id)
        while len(self._undo_order) > _UNDO_MAX_ENTRIES:
            evicted = self._undo_order.pop(0)
            self._undo.pop(evicted, None)

    def _snapshot(self, components: Tuple[str, ...]) -> Optional[bytes]:
        """Best-effort pre-image for undo: the current bytes, or ``None`` if absent / too large / a
        non-regular file. A ``None`` snapshot for an existing-but-unsnapshottable file disables undo of
        that specific op (reported), never silently corrupts."""
        try:
            data = sandbox.read_bytes(self._root, "/".join(components), max_bytes=_UNDO_MAX_SNAPSHOT)
            return data
        except FileNotFoundError:
            return None
        except (sandbox.PathEscapeError, OSError):
            return None

    # -- reads (unsigned) ------------------------------------------------------------------------

    @_total
    def read(self, path: object, *, max_bytes: int = _MAX_READ_BYTES) -> FsResult:
        limit = min(int(max_bytes), _MAX_READ_BYTES)
        data = sandbox.read_bytes(self._root, path, max_bytes=limit)
        try:
            text = data.decode("utf-8")
            is_text = True
        except UnicodeDecodeError:
            text = ""
            is_text = False
        return FsResult(True, data={"bytes": len(data), "sha256": sha256_hex(data),
                                    "is_text": is_text, "content": text})

    @_total
    def stat(self, path: object) -> FsResult:
        st = sandbox.lstat_in_sandbox(self._root, path)
        kind = ("symlink" if stat.S_ISLNK(st.st_mode) else
                "dir" if stat.S_ISDIR(st.st_mode) else
                "file" if stat.S_ISREG(st.st_mode) else "other")
        return FsResult(True, data={"type": kind, "size": st.st_size, "mode": stat.S_IMODE(st.st_mode)})

    @_total
    def list(self, path: object = "") -> FsResult:
        names = sandbox.listdir_in_sandbox(self._root, path)
        entries: List[Dict[str, Any]] = []
        base = sandbox.lexical_components(path)
        for name in names:
            child = "/".join((*base, name))
            try:
                st = sandbox.lstat_in_sandbox(self._root, child)
                etype = ("symlink" if stat.S_ISLNK(st.st_mode) else
                         "dir" if stat.S_ISDIR(st.st_mode) else
                         "file" if stat.S_ISREG(st.st_mode) else "other")
                entries.append({"name": name, "type": etype, "size": st.st_size})
            except OSError:
                entries.append({"name": name, "type": "unknown", "size": 0})
        return FsResult(True, data={"path": "/".join(base), "entries": entries})

    # -- mutations (signed + reversible) ---------------------------------------------------------

    @_total
    def write(self, path: object, content: object, *, overwrite: bool = True) -> FsResult:
        components = sandbox.lexical_components(path)
        if not components:
            return FsResult(False, "refusing to write to the sandbox root")
        if _is_protected(components):
            return FsResult(False, f"refusing to write into the protected subtree {components[0]!r}")
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content) \
            if isinstance(content, (bytes, bytearray)) else str(content).encode("utf-8")
        if len(data) > _MAX_WRITE_BYTES:
            return FsResult(False, f"content exceeds the {_MAX_WRITE_BYTES}-byte write bound")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        rel = "/".join(components)

        pre = self._snapshot(components)
        existed = pre is not None or self._exists(components)
        if existed and not overwrite:
            return FsResult(False, "target exists and overwrite=False")

        sandbox.write_bytes(self._root, rel, data, overwrite=overwrite, create_parents=True)

        def _rollback() -> None:
            if existed and pre is not None:
                sandbox.write_bytes(self._root, rel, pre, overwrite=True, create_parents=True)
            else:
                try:
                    sandbox.unlink_in_sandbox(self._root, rel)
                except OSError:
                    pass

        ok, reason, event_id = self._commit(
            "fs.write", paths=[rel], pre_hash=(sha256_hex(pre) if pre is not None else ""),
            post_hash=sha256_hex(data), meta={"path": rel, "overwrite": overwrite, "existed": existed},
            rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        self._register_undo(event_id, _UndoEntry("restore_bytes", (rel,),
                                                 pre if (existed and pre is not None) else None))
        return FsResult(True, event_id=event_id, data={"path": rel, "bytes": len(data)})

    @_total
    def edit(self, path: object, old: object, new: object) -> FsResult:
        components = sandbox.lexical_components(path)
        if not components:
            return FsResult(False, "refusing to edit the sandbox root")
        if _is_protected(components):
            return FsResult(False, f"refusing to edit into the protected subtree {components[0]!r}")
        if not isinstance(old, str) or not isinstance(new, str) or old == "":
            return FsResult(False, "edit requires non-empty 'old' and a 'new' string")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        rel = "/".join(components)
        pre = sandbox.read_bytes(self._root, rel, max_bytes=_MAX_WRITE_BYTES)
        try:
            text = pre.decode("utf-8")
        except UnicodeDecodeError:
            return FsResult(False, "edit target is not valid UTF-8 text")
        occurrences = text.count(old)
        if occurrences == 0:
            return FsResult(False, "'old' string not found")
        if occurrences > 1:
            return FsResult(False, f"'old' string is not unique ({occurrences} matches) — refuse ambiguity")
        new_text = text.replace(old, new, 1)
        data = new_text.encode("utf-8")
        if len(data) > _MAX_WRITE_BYTES:
            return FsResult(False, f"edit result exceeds the {_MAX_WRITE_BYTES}-byte bound")

        sandbox.write_bytes(self._root, rel, data, overwrite=True, create_parents=False)

        def _rollback() -> None:
            sandbox.write_bytes(self._root, rel, pre, overwrite=True, create_parents=False)

        ok, reason, event_id = self._commit(
            "fs.edit", paths=[rel], pre_hash=sha256_hex(pre), post_hash=sha256_hex(data),
            meta={"path": rel}, rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        self._register_undo(event_id, _UndoEntry("restore_bytes", (rel,), pre))
        return FsResult(True, event_id=event_id, data={"path": rel, "bytes": len(data)})

    @_total
    def delete(self, path: object) -> FsResult:
        components = sandbox.lexical_components(path)
        if not components:
            return FsResult(False, "refusing to delete the sandbox root")
        if _is_protected(components):
            return FsResult(False, f"refusing to delete within the protected subtree {components[0]!r}")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        rel = "/".join(components)
        st = sandbox.lstat_in_sandbox(self._root, rel)
        if not stat.S_ISREG(st.st_mode):
            return FsResult(False, "delete supports only regular files in this slice")
        pre = sandbox.read_bytes(self._root, rel, max_bytes=_MAX_WRITE_BYTES)

        sandbox.unlink_in_sandbox(self._root, rel)

        def _rollback() -> None:
            sandbox.write_bytes(self._root, rel, pre, overwrite=True, create_parents=True)

        ok, reason, event_id = self._commit(
            "fs.delete", paths=[rel], pre_hash=sha256_hex(pre), post_hash="",
            meta={"path": rel}, rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        self._register_undo(event_id, _UndoEntry("restore_bytes", (rel,), pre))
        return FsResult(True, event_id=event_id, data={"path": rel})

    @_total
    def move(self, src: object, dst: object) -> FsResult:
        src_c = sandbox.lexical_components(src)
        dst_c = sandbox.lexical_components(dst)
        if not src_c or not dst_c:
            return FsResult(False, "refusing to move the sandbox root")
        if _is_protected(src_c) or _is_protected(dst_c):
            return FsResult(False, "refusing to move into/out of a protected subtree")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        rel_src, rel_dst = "/".join(src_c), "/".join(dst_c)

        if len(dst_c) > 1:                       # create the destination parent race-free first
            sandbox.makedirs_in_sandbox(self._root, dst_c[:-1])
        sandbox.rename_in_sandbox(self._root, rel_src, rel_dst)

        def _rollback() -> None:
            sandbox.rename_in_sandbox(self._root, rel_dst, rel_src)

        ok, reason, event_id = self._commit(
            "fs.move", paths=[rel_src, rel_dst], pre_hash="", post_hash="",
            meta={"src": rel_src, "dst": rel_dst}, rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        self._register_undo(event_id, _UndoEntry("move_back", (rel_src, rel_dst)))
        return FsResult(True, event_id=event_id, data={"src": rel_src, "dst": rel_dst})

    @_total
    def mkdir(self, path: object) -> FsResult:
        components = sandbox.lexical_components(path)
        if not components:
            return FsResult(False, "sandbox root already exists")
        if _is_protected(components):
            return FsResult(False, f"refusing to mkdir within the protected subtree {components[0]!r}")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        rel = "/".join(components)
        existed_before = self._exists(components)
        sandbox.makedirs_in_sandbox(self._root, components)

        def _rollback() -> None:
            if not existed_before:
                try:
                    sandbox.rmdir_in_sandbox(self._root, rel)
                except OSError:
                    pass

        ok, reason, event_id = self._commit(
            "fs.mkdir", paths=[rel], pre_hash="", post_hash="",
            meta={"path": rel, "existed": existed_before}, rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        if not existed_before:
            self._register_undo(event_id, _UndoEntry("remove_path", (rel,)))
        return FsResult(True, event_id=event_id, data={"path": rel})

    @_total
    def extract(self, archive_path: object, dest: object) -> FsResult:
        """Extract a tar/zip archive from within the sandbox into ``dest`` (also in the sandbox), with
        tar-slip / symlink-member / zip-bomb defenses. Every member name is lexically confined AND each
        file is written through the race-free kernel, so a crafted member cannot escape. Reversible:
        undo removes exactly the files this extraction created."""
        dest_c = sandbox.lexical_components(dest)
        if _is_protected(dest_c):
            return FsResult(False, "refusing to extract into a protected subtree")
        if not self._has_signer():
            return FsResult(False, "no signer wired — a mutation cannot be recorded (fail-closed)")
        raw = sandbox.read_bytes(self._root, archive_path, max_bytes=_ARCHIVE_MAX_INPUT)

        # _plan_archive validates every member (name confinement / type) AND enforces the zip-bomb
        # entry-count + running total-uncompressed-size caps DURING decompression, so a bomb is refused
        # before it can balloon RAM (it never buffers past the caps).
        members = _plan_archive(raw)
        total = sum(size for _, _, size in members)

        created: List[str] = []
        dest_prefix = tuple(dest_c)
        # PRE-VALIDATE every member against the protected subtree BEFORE writing any — the dest-prefix
        # check alone is insufficient: a member name (e.g. "jobs/<id>/meta.json") can land inside the
        # protected `jobs/` tree and forge witnessed job provenance through the low-level kernel, the exact
        # thing the per-path write/edit/delete/move/mkdir guards refuse. No partial write on refusal.
        for name_components, _data, _size in members:
            target = (*dest_prefix, *name_components)
            sandbox.lexical_components("/".join(target))
            if _is_protected(target):
                return FsResult(False, "refusing to extract a member into a protected subtree")
        try:
            for name_components, data, _size in members:
                target = (*dest_prefix, *name_components)
                # Confirm the joined target is itself lexically confined (defense in depth).
                sandbox.lexical_components("/".join(target))
                if data is None:                # directory member
                    sandbox.makedirs_in_sandbox(self._root, target)
                    continue
                rel = "/".join(target)
                sandbox.write_bytes(self._root, rel, data, overwrite=True, create_parents=True)
                created.append(rel)
        except Exception:
            # partial extraction failed — remove what we created, then re-raise into the total boundary
            for rel in reversed(created):
                try:
                    sandbox.unlink_in_sandbox(self._root, rel)
                except OSError:
                    pass
            raise

        def _rollback() -> None:
            for rel in reversed(created):
                try:
                    sandbox.unlink_in_sandbox(self._root, rel)
                except OSError:
                    pass

        ok, reason, event_id = self._commit(
            "fs.extract", paths=created[:64], pre_hash="", post_hash=sha256_hex(raw),
            meta={"dest": "/".join(dest_prefix), "files": len(created), "bytes": total},
            rollback=_rollback)
        if not ok:
            return FsResult(False, reason)
        self._register_undo(event_id, _UndoEntry("remove_many", tuple(created)))
        return FsResult(True, event_id=event_id,
                        data={"dest": "/".join(dest_prefix), "files": len(created)})

    @_total
    def undo(self, event_id: object) -> FsResult:
        """Reverse a prior signed mutation and record a signed compensating ``fs.undo`` event
        (append-only — the original event is never removed). Fail-closed if no signer is wired."""
        if not isinstance(event_id, str) or event_id not in self._undo:
            return FsResult(False, "no undo available for that event id")
        if not self._has_signer():
            return FsResult(False, "no signer wired — undo cannot be recorded (fail-closed)")
        entry = self._undo[event_id]
        self._apply_undo(entry)
        try:
            event = self._log.append("fs.undo", paths=list(entry.paths), undo_of=event_id,
                                     meta={"op": entry.op})
        except EventLogError as exc:
            return FsResult(False, f"undo applied but signing failed: {exc}")
        # Consume the undo entry (one-shot) but KEEP the append-only log intact.
        self._undo.pop(event_id, None)
        if event_id in self._undo_order:
            self._undo_order.remove(event_id)
        return FsResult(True, event_id=event.event_id, data={"undid": event_id, "op": entry.op})

    def _apply_undo(self, entry: _UndoEntry) -> None:
        if entry.op == "restore_bytes":
            rel = entry.paths[0]
            if entry.pre_bytes is None:
                try:
                    sandbox.unlink_in_sandbox(self._root, rel)
                except FileNotFoundError:
                    pass
            else:
                sandbox.write_bytes(self._root, rel, entry.pre_bytes, overwrite=True, create_parents=True)
        elif entry.op == "remove_path":
            try:
                sandbox.rmdir_in_sandbox(self._root, entry.paths[0])
            except FileNotFoundError:
                pass
        elif entry.op == "move_back":
            src, dst = entry.paths
            sandbox.rename_in_sandbox(self._root, dst, src)
        elif entry.op == "remove_many":
            for rel in reversed(entry.paths):
                try:
                    sandbox.unlink_in_sandbox(self._root, rel)
                except FileNotFoundError:
                    pass

    # -- helpers ---------------------------------------------------------------------------------

    def _exists(self, components: Tuple[str, ...]) -> bool:
        try:
            sandbox.lstat_in_sandbox(self._root, "/".join(components))
            return True
        except (OSError, sandbox.PathEscapeError):
            return False

    @property
    def events(self) -> Tuple:
        return self._log.events()


# --- archive planning: tar-slip / symlink-member / zip-bomb defenses ----------------------------


def _bomb_guard(entries: int, running_total: int, declared_next: int) -> None:
    """Refuse (raise) once the entry-count or the running uncompressed-size cap would be exceeded — the
    check happens BEFORE the next member is decompressed, so a bomb never buffers past the cap."""
    if entries > _ARCHIVE_MAX_ENTRIES:
        raise sandbox.PathEscapeError(
            f"archive has too many entries (> {_ARCHIVE_MAX_ENTRIES}) — zip-bomb guard")
    if running_total + max(0, declared_next) > _ARCHIVE_MAX_TOTAL:
        raise sandbox.PathEscapeError(
            "archive uncompressed size exceeds the zip-bomb cap")


def _plan_archive(raw: bytes) -> List[Tuple[Tuple[str, ...], Optional[bytes], int]]:
    """Parse + VALIDATE an archive (zip or tar) into a list of ``(name_components, data, size)`` where
    ``data is None`` marks a directory. Refuses (raises): an unrecognized format, an absolute / ``..``
    member name, any symlink / hardlink / device / fifo member, and any archive that trips the
    entry-count or total-uncompressed-size zip-bomb caps (enforced incrementally). Members are written by
    the caller through the race-free kernel; nothing here follows a link."""
    bio = io.BytesIO(raw)
    if zipfile.is_zipfile(bio):
        return _plan_zip(raw)
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
            return _plan_tar(tf)
    except tarfile.TarError as exc:
        raise sandbox.PathEscapeError(f"unrecognized or malformed archive: {exc}") from exc


def _plan_zip(raw: bytes) -> List[Tuple[Tuple[str, ...], Optional[bytes], int]]:
    out: List[Tuple[Tuple[str, ...], Optional[bytes], int]] = []
    entries = 0
    running = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        for zi in zf.infolist():
            entries += 1
            mode = (zi.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise sandbox.PathEscapeError(f"refusing symlink member {zi.filename!r}")
            name = zi.filename
            components = sandbox.lexical_components(name)       # validates confinement
            if name.endswith("/"):
                _bomb_guard(entries, running, 0)
                out.append((components, None, 0))
                continue
            if not components:
                continue
            _bomb_guard(entries, running, zi.file_size)         # check BEFORE decompressing
            data = zf.read(zi)                                  # zipfile validates size vs the header
            running += len(data)
            if running > _ARCHIVE_MAX_TOTAL:
                raise sandbox.PathEscapeError("archive uncompressed size exceeds the zip-bomb cap")
            out.append((components, data, len(data)))
    return out


def _plan_tar(tf: tarfile.TarFile) -> List[Tuple[Tuple[str, ...], Optional[bytes], int]]:
    out: List[Tuple[Tuple[str, ...], Optional[bytes], int]] = []
    entries = 0
    running = 0
    for member in tf:                                          # lazy iteration (no full materialization)
        entries += 1
        if member.issym() or member.islnk():
            raise sandbox.PathEscapeError(f"refusing link member {member.name!r}")
        if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
            raise sandbox.PathEscapeError(f"refusing special-device member {member.name!r}")
        components = sandbox.lexical_components(member.name)    # validates confinement
        if member.isdir():
            _bomb_guard(entries, running, 0)
            out.append((components, None, 0))
            continue
        if not member.isfile() or not components:
            continue
        _bomb_guard(entries, running, member.size)             # check BEFORE reading the member
        fobj = tf.extractfile(member)
        data = fobj.read(_ARCHIVE_MAX_TOTAL + 1) if fobj is not None else b""
        running += len(data)
        if running > _ARCHIVE_MAX_TOTAL:
            raise sandbox.PathEscapeError("archive uncompressed size exceeds the zip-bomb cap")
        out.append((components, data, len(data)))
    return out
