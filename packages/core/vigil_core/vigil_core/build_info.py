"""Deterministic build & version identity, shared by every VIGIL CLI (W4-2, #442).

``vigil --version``, ``vigil-gateway --version``, ``sigil --version`` and
``python3 -m framework.v2 --version`` all resolve the SAME three facts through this one
module — there is no per-CLI reimplementation of the version string:

  * **product version** — the repo-root ``VERSION`` file (the single source of truth
    W4-1 established), falling back to the installed ``vigil-core`` distribution metadata,
    then to ``0+unknown``;
  * **git sha** — the full commit the running tree is built from, or ``unknown`` when the
    code is not inside a git checkout (a non-editable wheel install);
  * **build id** — a PEP 440 local-version string that is HONEST about the tree: a clean
    checkout reads ``<version>+g<short>``, a tree with uncommitted changes reads
    ``<version>+g<short>.dirty``, and a tree with no reachable git at all reads
    ``<version>+unknown``.

FAIL-CLOSED HONESTY. The build id never claims a clean sha it cannot prove. If ``git
rev-parse`` succeeds but ``git status`` cannot be read, the tree is reported ``.dirty``,
not clean — an unknown cleanliness is treated as dirty, never as clean.

DETERMINISM. Given a tree state the output is fully determined — no wallclock, no RNG — so
two ``--version`` runs against the same committed tree print the same build id. The git
queries are read-only, time-bounded, and never mutate the repository.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_UNKNOWN = "unknown"
_GIT_TIMEOUT_S = 5
_SHORT = 12


@dataclass(frozen=True)
class BuildInfo:
    """The three facts ``--version`` reports, plus the composed build id."""

    program: str
    version: str
    git_sha: str  # full 40-hex sha, or "unknown"
    dirty: bool
    build_id: str

    def line(self) -> str:
        """The single, machine-greppable line a ``--version`` invocation prints."""
        return f"{self.program} {self.version} (build {self.build_id}; git {self.git_sha})"


def compose_build_id(version: str, git_sha: Optional[str], dirty: bool) -> str:
    """Pure: the honest local-version build id.

    No git sha (``None``/``"unknown"``) -> ``<version>+unknown``; a dirty tree ->
    ``<version>+g<short>.dirty``; a clean tree -> ``<version>+g<short>``. Kept free of I/O
    so the dirty/unknown negative controls run in-process, without a real repository.
    """
    if not git_sha or git_sha == _UNKNOWN:
        return f"{version}+{_UNKNOWN}"
    short = git_sha[:_SHORT]
    return f"{version}+g{short}.dirty" if dirty else f"{version}+g{short}"


def _read_version_file(root: Path) -> Optional[str]:
    vf = root / "VERSION"
    if not vf.is_file():
        return None
    lines = [ln.strip() for ln in vf.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return lines[0] if lines else None


def find_repo_root(start: Optional[Path] = None) -> Optional[Path]:
    """Walk up from ``start`` (default: this module) to the first directory holding BOTH a
    ``VERSION`` file and a ``.git`` entry. ``.git`` may be a directory (a normal clone) or a
    file (a git worktree), so ``.exists()`` is used, not ``.is_dir()``. ``None`` when the
    code is not inside a checkout (e.g. a wheel unpacked into site-packages)."""
    here = (start or Path(__file__)).resolve()
    for d in [here, *here.parents]:
        if (d / "VERSION").is_file() and (d / ".git").exists():
            return d
    return None


def product_version(root: Optional[Path] = None) -> str:
    """The single product version: the repo-root ``VERSION`` file, else the installed
    ``vigil-core`` distribution metadata, else ``0+unknown``."""
    if root is not None:
        v = _read_version_file(root)
        if v:
            return v
    found = find_repo_root()
    if found:
        v = _read_version_file(found)
        if v:
            return v
    try:
        from importlib.metadata import PackageNotFoundError
        from importlib.metadata import version as _dist_version

        try:
            return _dist_version("vigil-core")
        except PackageNotFoundError:
            return f"0+{_UNKNOWN}"
    except Exception:  # noqa: BLE001 — importlib.metadata is stdlib; degrade rather than crash --version
        return f"0+{_UNKNOWN}"


def _git(root: Path, *args: str) -> Optional[str]:
    """Run a read-only ``git`` query in ``root``; ``None`` on any failure (no git binary,
    not a repo, non-zero exit, timeout). Never raises."""
    try:
        out = subprocess.run(  # noqa: S603 — fixed argv, no shell; args are literal git subcommands
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def git_state(root: Optional[Path] = None) -> tuple[str, bool]:
    """Return ``(full_sha_or_"unknown", dirty)`` for ``root`` (default: the discovered repo
    root). When the sha is unknown, ``dirty`` is ``False`` (there is nothing to be dirty
    against). When the sha is known but cleanliness cannot be determined, ``dirty`` is
    ``True`` — the fail-closed choice, so ``--version`` never claims a clean tree it cannot
    prove."""
    base = root or find_repo_root()
    if base is None:
        return _UNKNOWN, False
    sha = _git(base, "rev-parse", "HEAD")
    if not sha:
        return _UNKNOWN, False
    porcelain = _git(base, "status", "--porcelain")
    dirty = True if porcelain is None else bool(porcelain.strip())
    return sha, dirty


def resolve(program: str, root: Optional[Path] = None) -> BuildInfo:
    """Resolve the full :class:`BuildInfo` for ``program`` (the CLI name to print)."""
    ver = product_version(root)
    sha, dirty = git_state(root)
    return BuildInfo(
        program=program,
        version=ver,
        git_sha=sha,
        dirty=dirty,
        build_id=compose_build_id(ver, sha, dirty),
    )


def version_line(program: str, root: Optional[Path] = None) -> str:
    """The one line every VIGIL CLI's ``--version`` prints for ``program``."""
    return resolve(program, root).line()
