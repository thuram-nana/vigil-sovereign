"""
evidence.manifest — bind raw on-disk artifacts into a certificate by digest.

The executors write raw proof (`request.http`, `response.http`, `response.body`) under
`targets/<slug>/evidence/<action_id>/`. Those bytes are the ground truth a finding rests
on, but nothing linked them to the certificate. `manifest_dir` hashes each file so the
certificate can carry a per-file sha256; `verify_manifest` recomputes and flags any file
that was altered, truncated, or is missing — the certificate then proves not just the
oracle's verdict but the exact raw bytes it saw.

Deterministic: files are listed in sorted relative-path order, so the manifest is stable.
"""

from __future__ import annotations

from pathlib import Path

from ..common.paths import is_within
from .models import ArtifactRef

_READ_CHUNK = 1 << 16
# Cap on a single artifact read during verification. manifest_dir hashes the operator's
# own evidence (trusted), but verify_manifest may be pointed at an UNTRUSTED bundle's
# paths — cap the read so a hostile manifest cannot force an unbounded hash.
_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


class _TooLarge(Exception):
    pass


def _sha256_file(path: Path) -> tuple[str, int]:
    import hashlib
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(_READ_CHUNK)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_ARTIFACT_BYTES:
                raise _TooLarge(f"artifact exceeds {_MAX_ARTIFACT_BYTES} bytes")
            h.update(chunk)
    return h.hexdigest(), size


def _confined(root: Path, rel: str) -> Path | None:
    """Join ``rel`` under ``root`` iff it stays inside root: reject absolute paths, any
    ``..`` component, and (via resolution) symlink escapes. Returns None on any escape —
    the verifier must never stat/read a file outside the engagement evidence tree."""
    p = Path(rel)
    if p.is_absolute() or any(part == ".." for part in p.parts):
        return None
    fp = root / p
    return fp if is_within(fp, root) else None


def manifest_dir(evidence_dir: Path, *, root: Path | None = None) -> list[ArtifactRef]:
    """Per-file sha256 manifest of ``evidence_dir`` (recursive). Paths are recorded
    relative to ``root`` (defaults to ``evidence_dir``), sorted for determinism. A
    missing/empty dir yields an empty manifest — never raises."""
    base = Path(evidence_dir)
    if not base.is_dir():
        return []
    root = Path(root) if root is not None else base
    out: list[ArtifactRef] = []
    for fp in sorted(p for p in base.rglob("*") if p.is_file()):
        try:
            digest, size = _sha256_file(fp)
        except (OSError, _TooLarge):
            continue
        try:
            rel = str(fp.relative_to(root))
        except ValueError:
            rel = fp.name
        out.append(ArtifactRef(path=rel, sha256=digest, size=size))
    return out


def verify_manifest(artifacts: list[ArtifactRef], *, root: Path) -> list[tuple[str, bool, str]]:
    """Recompute each artifact's digest under ``root``. Returns (path, ok, note) per
    entry — ok is False if the file is missing, unreadable, or its bytes changed."""
    root = Path(root)
    results: list[tuple[str, bool, str]] = []
    for a in artifacts:
        fp = _confined(root, a.path)
        if fp is None:
            results.append((a.path, False, "path escapes the evidence root (refused)"))
            continue
        if not fp.is_file():
            results.append((a.path, False, "missing"))
            continue
        try:
            digest, size = _sha256_file(fp)
        except _TooLarge as e:
            results.append((a.path, False, str(e)))
            continue
        except OSError as e:
            results.append((a.path, False, f"unreadable: {e}"))
            continue
        if digest != a.sha256:
            results.append((a.path, False, "sha256 mismatch (bytes altered)"))
        elif size != a.size:
            results.append((a.path, False, "size mismatch"))
        else:
            results.append((a.path, True, "ok"))
    return results
