"""
fsjob.sandbox — the path-confinement kernel (VIGIL-FUSION F9).

This is the single load-bearing security primitive of the workspace filesystem and the exact surface
the red-pen attacks. redamon's ``workspace_fs._resolve_safe`` uses ``Path.resolve()`` (which FOLLOWS
symlinks) and then string-compares the result against the root — a design the SCOUT inventory flags as
TOCTOU/symlink-race-prone (ANALYSIS.md §228, SCOUT §361). VIGIL replaces the resolve-then-compare
pattern with a **race-free openat walk**:

  * The requested path is first validated LEXICALLY (no NUL, not absolute, no ``..`` that escapes the
    root, bounded component count/length) — an escape is refused before touching the disk.
  * The path is then walked ONE COMPONENT AT A TIME relative to an open directory file descriptor,
    each hop opened with ``O_NOFOLLOW | O_DIRECTORY`` via ``dir_fd=``. Because every hop is opened
    relative to a *pinned real directory fd* (never re-resolved from a string), an attacker who swaps a
    component for a symlink mid-walk cannot make us follow it — the swapped component simply fails
    ``ELOOP`` and the walk is refused. This closes the symlink-race the string approach cannot.
  * ANY symlink component (intermediate or final) is REFUSED. We do not attempt to validate a symlink's
    target "safely" — under a racing adversary that is unwinnable, so a symlink is never a safe
    primitive here. (redamon's explicit symlink tools are a later, separately-gated slice.)

Every fs mutation therefore resolves through :func:`resolve_within` and executes over the ``dir_fd``
returned by :func:`walk_to_parent`, so the *operation itself* — not just a prior check — is confined.

Deny-by-default / total: the low-level primitives raise :class:`PathEscapeError` on a policy violation
(a refusal IS the safe outcome); the tool layer (``fsjob.fs`` / ``fsjob.jobs``) catches everything and
degrades to a structured "no signal" result so no attacker-influenced path can crash the agent.

Import-clean: stdlib only (``os``/``stat``). No wallclock, no RNG, no network.
"""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple

# --- bounds (DoS-safe; a hostile path can't blow these up) --------------------------------------
_MAX_COMPONENT_LEN = 255        # NAME_MAX on typical filesystems
_MAX_PATH_COMPONENTS = 64       # a workspace path deeper than this is refused
_MAX_PATH_CHARS = 4096          # PATH_MAX-ish overall bound

# Directory-hop flags: read-only, must be a directory, MUST NOT follow a symlink, close-on-exec.
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_DIR_HOP_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC


class PathEscapeError(ValueError):
    """The requested path is not confinable to the sandbox root (traversal / absolute / symlink /
    malformed). Always fail closed — a refusal is the safe outcome."""


def lexical_components(user_path: object) -> Tuple[str, ...]:
    """Validate ``user_path`` lexically and return its normalized, root-relative components.

    Refuses (raises :class:`PathEscapeError`): a non-string, an embedded NUL, an absolute path, a path
    that exceeds the length/component bounds, and any ``..`` sequence that would climb above the root.
    A ``.`` or empty segment is dropped; a ``..`` that stays within the tree is collapsed. The result
    contains only real name components (never ``.`` / ``..`` / ``""``), so it is safe to join onto the
    root. Total: never returns a value that escapes; it either yields a confined tuple or raises."""
    if not isinstance(user_path, str):
        raise PathEscapeError(f"path must be a string, got {type(user_path).__name__}")
    if "\x00" in user_path:
        raise PathEscapeError("NUL byte in path")
    if len(user_path) > _MAX_PATH_CHARS:
        raise PathEscapeError("path is too long")
    # An absolute path (POSIX leading '/') is refused outright — the sandbox is relative-only.
    if user_path.startswith("/"):
        raise PathEscapeError("absolute path rejected")
    comps: list[str] = []
    for part in user_path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not comps:
                raise PathEscapeError("path escapes sandbox root via '..'")
            comps.pop()
            continue
        if len(part) > _MAX_COMPONENT_LEN:
            raise PathEscapeError("path component is too long")
        comps.append(part)
    if len(comps) > _MAX_PATH_COMPONENTS:
        raise PathEscapeError("path has too many components")
    return tuple(comps)


def canonical_root(root: object) -> str:
    """Canonicalize the (trusted, operator-supplied) sandbox root once. The root itself may legitimately
    contain symlinks (e.g. ``/tmp`` → ``/private/tmp``); ``realpath`` resolves them so subsequent
    ``O_NOFOLLOW`` walks start from a real directory. Raises if the root is missing or not a directory —
    a workspace without a real root cannot confine anything (fail-closed)."""
    if not isinstance(root, str) or not root:
        raise PathEscapeError("sandbox root must be a non-empty string")
    real = os.path.realpath(root)
    if not os.path.isdir(real):
        raise PathEscapeError(f"sandbox root is not a directory: {root!r}")
    return real


def _open_root(root_canonical: str) -> int:
    return os.open(root_canonical, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)


def _descend(parent_fd: int, name: str) -> int:
    """Open child directory ``name`` under ``parent_fd`` WITHOUT following a symlink.

    A genuinely-absent component surfaces as ``FileNotFoundError`` (a legitimate "not found"). ANY other
    traversal failure — ``ELOOP`` (``name`` is a symlink), ``ENOTDIR`` (a symlink-to-non-dir or a file
    used as a directory), permission errors, etc. — is a confinement REFUSAL and is raised as
    :class:`PathEscapeError`. This is what makes a mid-walk symlink swap a hard refusal, not a followed
    redirect: the openat hop cannot resolve the symlink, so the walk is denied."""
    try:
        return os.open(name, _DIR_HOP_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PathEscapeError(f"cannot safely traverse {name!r}: {exc.strerror or exc}") from exc


@contextmanager
def walk_to_parent(root: str, components: Tuple[str, ...]) -> Iterator[Tuple[int, Optional[str]]]:
    """Race-free openat walk. Yields ``(parent_fd, final_name)`` where ``parent_fd`` is an open fd for
    the directory that (would) contain the final component, reached without following any symlink, and
    ``final_name`` is the last component (``None`` when ``components`` is empty → the target IS the
    root). Every intermediate hop is opened ``O_NOFOLLOW`` relative to the previous *pinned* fd, so a
    mid-walk symlink swap fails ``ELOOP`` instead of being followed. All fds are closed on exit; the
    caller must perform its operation via ``dir_fd=parent_fd`` INSIDE the ``with`` block."""
    root_canonical = canonical_root(root)
    fds: list[int] = []
    try:
        cur = _open_root(root_canonical)
        fds.append(cur)
        if not components:
            yield cur, None
            return
        for name in components[:-1]:
            child = _descend(cur, name)   # raises on symlink / non-dir / missing
            fds.append(child)
            cur = child
        yield cur, components[-1]
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def resolve_within(root: str, user_path: object, *, must_exist: bool = False) -> str:
    """Resolve ``user_path`` to a canonical absolute path proven to be confined to ``root``.

    Proves (all via the race-free walk, not a string compare): the path is lexically confined, no
    component is a symlink, and the final component — if it exists — is not a symlink either. Returns
    the canonical absolute path (safe to report/log). Raises :class:`PathEscapeError` on any escape /
    symlink, and ``FileNotFoundError`` when ``must_exist`` is set and the target is absent. This is the
    predicate the adversarial test hammers; a raise is the correct (deny) behaviour."""
    components = lexical_components(user_path)
    root_canonical = canonical_root(root)
    with walk_to_parent(root_canonical, components) as (parent_fd, final_name):
        if final_name is None:
            return root_canonical
        try:
            st = os.lstat(final_name, dir_fd=parent_fd)
        except FileNotFoundError:
            if must_exist:
                raise
            return os.path.join(root_canonical, *components)
        if stat.S_ISLNK(st.st_mode):
            raise PathEscapeError("refusing a symlink target (symlink-out / race defense)")
        return os.path.join(root_canonical, *components)


def is_within_sandbox(root: object, user_path: object) -> bool:
    """Total boolean form of :func:`resolve_within`: ``True`` iff ``user_path`` confines to ``root``
    with no escape or symlink. Never raises — any violation or fs error yields ``False``."""
    try:
        if not isinstance(root, str):
            return False
        resolve_within(root, user_path, must_exist=False)
        return True
    except (PathEscapeError, OSError, ValueError):
        return False


# --- race-free operation primitives (used by fsjob.fs / fsjob.jobs) -----------------------------


def open_in_sandbox(root: str, user_path: object, flags: int, mode: int = 0o600) -> int:
    """Open the final component relative to a safe parent fd, ``O_NOFOLLOW`` so a symlink at the final
    position is refused. Returns an open fd (caller closes). The parent walk is race-free; the final
    open is atomic relative to the pinned parent. Refuses opening the sandbox root itself as a file."""
    components = lexical_components(user_path)
    with walk_to_parent(root, components) as (parent_fd, final_name):
        if final_name is None:
            raise PathEscapeError("refusing to open the sandbox root as a file")
        return os.open(final_name, flags | _O_NOFOLLOW | _O_CLOEXEC, mode, dir_fd=parent_fd)


def read_bytes(root: str, user_path: object, *, max_bytes: int) -> bytes:
    """Read a regular file's bytes (bounded). Refuses a symlink / escape (via ``open_in_sandbox``) and a
    non-regular file. Raises ``PathEscapeError`` past the size bound so a huge file cannot exhaust RAM."""
    fd = open_in_sandbox(root, user_path, os.O_RDONLY)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PathEscapeError("not a regular file")
        if st.st_size > max_bytes:
            raise PathEscapeError(f"file exceeds the {max_bytes}-byte read bound")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            block = os.read(fd, min(1 << 20, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise PathEscapeError(f"file exceeds the {max_bytes}-byte read bound")
        return data
    finally:
        os.close(fd)


def makedirs_in_sandbox(root: str, components: Tuple[str, ...]) -> None:
    """Create ``components`` as nested directories under ``root``, race-free. Each level is created with
    ``mkdir`` (which never follows a symlink for the new name) and then descended ``O_NOFOLLOW`` — so a
    pre-planted symlink named like a would-be directory fails ``ELOOP`` rather than being traversed."""
    root_canonical = canonical_root(root)
    fds: list[int] = []
    try:
        cur = _open_root(root_canonical)
        fds.append(cur)
        for name in components:
            try:
                os.mkdir(name, 0o700, dir_fd=cur)
            except FileExistsError:
                pass
            child = _descend(cur, name)   # O_NOFOLLOW: a symlink here is refused
            fds.append(child)
            cur = child
    finally:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass


def write_bytes(root: str, user_path: object, data: bytes, *, overwrite: bool,
                create_parents: bool = True) -> None:
    """Write ``data`` to a confined path. ``O_NOFOLLOW`` on the final open means an existing symlink at
    the target is refused (never written through). ``overwrite=False`` uses ``O_EXCL`` (create-new).
    Optionally creates parent directories race-free first."""
    components = lexical_components(user_path)
    if not components:
        raise PathEscapeError("refusing to write to the sandbox root")
    if create_parents and len(components) > 1:
        makedirs_in_sandbox(root, components[:-1])
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    fd = open_in_sandbox(root, user_path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def unlink_in_sandbox(root: str, user_path: object) -> None:
    """Remove a file (or a symlink itself — ``unlink`` never follows) under a safe parent fd, confined."""
    components = lexical_components(user_path)
    with walk_to_parent(root, components) as (parent_fd, final_name):
        if final_name is None:
            raise PathEscapeError("refusing to unlink the sandbox root")
        os.unlink(final_name, dir_fd=parent_fd)


def rmdir_in_sandbox(root: str, user_path: object) -> None:
    """Remove an (empty) directory under a safe parent fd, confined."""
    components = lexical_components(user_path)
    with walk_to_parent(root, components) as (parent_fd, final_name):
        if final_name is None:
            raise PathEscapeError("refusing to rmdir the sandbox root")
        os.rmdir(final_name, dir_fd=parent_fd)


def rename_in_sandbox(root: str, src: object, dst: object) -> None:
    """Rename/move confined→confined. Both endpoints resolve through race-free walks and the rename runs
    via ``src_dir_fd``/``dst_dir_fd`` so neither side can be redirected out of the sandbox by a symlink."""
    src_components = lexical_components(src)
    dst_components = lexical_components(dst)
    if not src_components or not dst_components:
        raise PathEscapeError("refusing to move the sandbox root")
    with walk_to_parent(root, src_components) as (src_fd, src_name), \
            walk_to_parent(root, dst_components) as (dst_fd, dst_name):
        if src_name is None or dst_name is None:
            raise PathEscapeError("refusing to move the sandbox root")
        os.rename(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)


def lstat_in_sandbox(root: str, user_path: object) -> os.stat_result:
    """``lstat`` (no symlink following) of a confined path, via a safe parent fd."""
    components = lexical_components(user_path)
    with walk_to_parent(root, components) as (parent_fd, final_name):
        if final_name is None:
            return os.fstat(parent_fd)
        return os.lstat(final_name, dir_fd=parent_fd)


def listdir_in_sandbox(root: str, user_path: object) -> list[str]:
    """List a confined directory's immediate entries (sorted, deterministic). The directory is opened
    ``O_NOFOLLOW`` so a symlinked directory is refused."""
    components = lexical_components(user_path)
    with walk_to_parent(root, components) as (parent_fd, final_name):
        if final_name is None:
            dir_fd = os.open(".", _DIR_HOP_FLAGS, dir_fd=parent_fd)
        else:
            dir_fd = os.open(final_name, _DIR_HOP_FLAGS, dir_fd=parent_fd)
        try:
            return sorted(os.listdir(dir_fd))
        finally:
            os.close(dir_fd)
