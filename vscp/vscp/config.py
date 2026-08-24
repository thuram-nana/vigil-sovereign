"""VSCP runtime configuration with FAIL-CLOSED isolation guards (W13-7 / #500).

VSCP keeps its OWN database and its OWN signing material, in its OWN data directory,
disjoint from every product data plane. This module both resolves those paths and
REFUSES (at construction) any configuration that would place VSCP state inside — or
overlapping with — a known product data root. That refusal is the enforcement behind
the "separate DB + credentials, isolated signing" half of the isolation claim: it is
not a convention a deployment can forget, it is a constructor that raises.

Stdlib only. No import of the product; no import of ``vigil_core`` (the paths are pure
data). Both the VSCP-own suite and the required integration proof exercise the guards.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "VscpIsolationError",
    "VscpConfig",
    "product_data_roots",
    "DEFAULT_DATA_DIR_ENV",
]

# Environment override for the VSCP data directory. Default: ``~/.vscp`` — a sibling of,
# and disjoint from, the product's ``~/.sigil`` (sovereign) and ``~/.vigil`` (host state)
# and the repo-local ``.vigil-live`` (offense/live plane).
DEFAULT_DATA_DIR_ENV = "VSCP_HOME"
_DEFAULT_DATA_DIR = "~/.vscp"

_DB_BASENAME = "vscp.sqlite"
_SIGNING_KEY_BASENAME = "vscp-signing.key"


class VscpIsolationError(RuntimeError):
    """Raised when a VSCP path would collide with a product data root. Fail-closed:
    VSCP refuses to run against shared storage or shared signing material."""


def product_data_roots() -> set[Path]:
    """The resolved set of data roots owned by the ASSESSMENT PRODUCT / its trust planes,
    which VSCP state must never fall inside. Env-aware so it tracks a non-default
    deployment (the same env conventions the product itself reads):

      * ``VIGIL_BASE_DIR`` (default ``.vigil-live``) — the offense / live plane; holds the
        offense blackboard ``.blackboard/store.sqlite`` where assessment findings persist;
      * ``VIGIL_LIVE_DIR`` — an explicit override for the same plane, when set;
      * ``SIGIL_HOME`` (default ``~/.sigil``) — the sovereign personal core: keystore,
        vault, and the owner signing material;
      * ``SIGIL_WARDEN_HOME`` — the WARDEN kernel home, when set;
      * ``~/.vigil`` — the host-state dir (attestation / backup trust anchors).
    """
    roots: set[Path] = set()
    roots.add(Path(os.environ.get("VIGIL_BASE_DIR", ".vigil-live")).expanduser().resolve())
    live = os.environ.get("VIGIL_LIVE_DIR")
    if live:
        roots.add(Path(live).expanduser().resolve())
    roots.add(Path(os.path.expanduser(os.environ.get("SIGIL_HOME", "~/.sigil"))).resolve())
    warden = os.environ.get("SIGIL_WARDEN_HOME")
    if warden:
        roots.add(Path(warden).expanduser().resolve())
    roots.add(Path(os.path.expanduser("~/.vigil")).resolve())
    return roots


def _paths_conflict(a: Path, b: Path) -> bool:
    """True if ``a`` and ``b`` are the same path or one contains the other. Overlap in
    EITHER direction is a conflict: VSCP state inside a product root, OR a product root
    inside the VSCP dir, both defeat isolation."""
    a = a.resolve()
    b = b.resolve()
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


@dataclass(frozen=True)
class VscpConfig:
    """Resolved VSCP configuration. Construct via :meth:`resolve` (which applies defaults
    and env overrides) or directly with explicit paths. Either way, :meth:`_validate`
    runs at construction and REFUSES a configuration that overlaps any product data root.

    Invariant (pinned by the isolation proof): ``db_path`` and ``signing_key_path`` both
    resolve strictly OUTSIDE every path in :func:`product_data_roots`.
    """

    data_dir: Path
    db_path: Path
    signing_key_path: Path

    def __post_init__(self) -> None:
        # dataclass is frozen; normalise the fields to resolved Paths in place.
        object.__setattr__(self, "data_dir", Path(self.data_dir).expanduser().resolve())
        object.__setattr__(self, "db_path", Path(self.db_path).expanduser().resolve())
        object.__setattr__(
            self, "signing_key_path", Path(self.signing_key_path).expanduser().resolve()
        )
        self._validate()

    @classmethod
    def resolve(
        cls,
        *,
        data_dir: str | os.PathLike | None = None,
        db_path: str | os.PathLike | None = None,
        signing_key_path: str | os.PathLike | None = None,
    ) -> "VscpConfig":
        """Build a config from the environment and defaults, allowing explicit overrides.
        The signing key and database default to living INSIDE the VSCP data dir, so a
        deployment gets an isolated layout with no further configuration."""
        base = Path(
            data_dir
            if data_dir is not None
            else os.environ.get(DEFAULT_DATA_DIR_ENV, _DEFAULT_DATA_DIR)
        ).expanduser()
        db = Path(db_path).expanduser() if db_path is not None else base / _DB_BASENAME
        key = (
            Path(signing_key_path).expanduser()
            if signing_key_path is not None
            else base / _SIGNING_KEY_BASENAME
        )
        return cls(data_dir=base, db_path=db, signing_key_path=key)

    def _validate(self) -> None:
        roots = product_data_roots()
        for label, path in (
            ("data_dir", self.data_dir),
            ("db_path", self.db_path),
            ("signing_key_path", self.signing_key_path),
        ):
            for root in roots:
                if _paths_conflict(path, root):
                    raise VscpIsolationError(
                        f"VSCP {label} {str(path)!r} overlaps product data root {str(root)!r}: "
                        "VSCP must use a SEPARATE database and SEPARATE signing material, disjoint "
                        "from every product data plane (W13-7 isolation, fail-closed)."
                    )

    def ensure_data_dir(self) -> Path:
        """Create the VSCP data dir (0700) if absent and return it. Never touched during
        validation — this is the deployment-time side effect, kept out of construction."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.data_dir, 0o700)
        return self.data_dir
