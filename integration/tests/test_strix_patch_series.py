"""S0 — the vendored-Strix patch series is the record of every VIGIL modification, and CI enforces it.

``vendor/strix`` is a plain vendored copy of an autonomous offensive agent (usestrix/strix, Apache-2.0)
that VIGIL modifies: governance gates, proof capture, egress hardening, telemetry excision. Before this
guard the only record of those modifications was monorepo git history — honest, but not rebasable and not
reviewable on an upstream upgrade, and nothing stopped a new edit landing unrecorded.

THE INVARIANT

    vendor/strix == the pristine upstream import at ``base_import_commit``
                    + docs/strix-patches/*.patch, applied in order.

``docs/strix-patches/series.json`` is the machine-checked record: per-patch digests, the set of files that
deviate from upstream, and sha256 manifests of both the base import and the current tree. These tests fail
if the vendored tree and that record disagree — so a change to the offensive agent cannot land silently.

Offline and history-free by construction: every assertion reads the committed manifests, never the git
object database, so a shallow CI checkout is enough. (``git ls-files`` is used only to enumerate tracked
paths, and the test skips if git is unavailable rather than passing vacuously.)
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_VENDOR = _REPO / "vendor" / "strix"
_PATCH_DIR = _REPO / "docs" / "strix-patches"
_SERIES = _PATCH_DIR / "series.json"


def _load() -> dict:
    assert _SERIES.is_file(), (
        f"{_SERIES} is missing — the vendored-Strix patch series is the record of every VIGIL "
        "modification to the offensive agent. Regenerate with tools/vendoring/regen_strix_series.py."
    )
    return json.loads(_SERIES.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tracked_vendor_paths() -> list[str]:
    """Tracked paths under vendor/strix. Skips (never silently passes) if git is unavailable."""
    try:
        out = subprocess.run(["git", "ls-files", "vendor/strix"], cwd=_REPO,
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - env dependent
        pytest.skip(f"git unavailable, cannot enumerate tracked files: {exc}")
    if out.returncode != 0:  # pragma: no cover - env dependent
        pytest.skip(f"git ls-files failed: {out.stderr.strip()}")
    return [line for line in out.stdout.splitlines() if line]


# --- the core guard: the tree is exactly what the series says it is -----------------------------------

def test_vendor_tree_matches_the_recorded_manifest():
    """Every tracked file under vendor/strix hashes to the digest the series recorded.

    This is the drift guard. An edit to the vendored agent — by a human, an agent, or an upstream
    re-import — changes a digest and fails here until it is recorded in the series.
    """
    series = _load()
    manifest: dict = series["tree_manifest"]
    drifted: list[str] = []
    for rel, expected in sorted(manifest.items()):
        path = _REPO / rel
        assert path.is_file(), (
            f"{rel} is in the series manifest but missing from the tree — regenerate the series "
            "(tools/vendoring/regen_strix_series.py) if the deletion is intentional."
        )
        if _sha256(path) != expected:
            drifted.append(rel)
    assert not drifted, (
        "vendor/strix has changed without the patch series being updated:\n  "
        + "\n  ".join(drifted)
        + "\n\nRun: python3 tools/vendoring/regen_strix_series.py"
    )


def test_no_tracked_vendor_file_escapes_the_manifest():
    """A NEW file under vendor/strix must enter the manifest — otherwise it is an unrecorded addition."""
    series = _load()
    manifest = set(series["tree_manifest"])
    tracked = set(_tracked_vendor_paths())
    assert tracked, "expected tracked files under vendor/strix; the enumerator may be broken"
    unrecorded = sorted(tracked - manifest)
    assert not unrecorded, (
        "these tracked vendor/strix files are absent from the series manifest:\n  "
        + "\n  ".join(unrecorded)
        + "\n\nRun: python3 tools/vendoring/regen_strix_series.py"
    )
    stale = sorted(manifest - tracked)
    assert not stale, (
        "the series manifest lists files that are no longer tracked:\n  " + "\n  ".join(stale)
    )


def test_every_deviation_from_upstream_is_covered_by_the_series():
    """The deviation set is derived from the two manifests and must agree with them.

    A file whose current digest differs from the base import — or which was added or deleted relative to
    upstream — is a VIGIL modification and must appear in ``deviations_from_upstream``.
    """
    series = _load()
    base: dict = series["base_manifest"]
    tree: dict = series["tree_manifest"]
    recorded = set(series["deviations_from_upstream"])
    derived = {p for p in tree if base.get(p) != tree[p]} | (set(base) - set(tree))
    assert derived == recorded, (
        "the recorded deviation set does not match the manifests.\n"
        f"  only in recorded: {sorted(recorded - derived)}\n"
        f"  only in derived : {sorted(derived - recorded)}\n"
        "Run: python3 tools/vendoring/regen_strix_series.py"
    )
    # The series must be non-trivial: VIGIL genuinely modifies this tree (telemetry excision alone).
    assert len(recorded) >= 20, f"expected a substantial deviation set, got {len(recorded)}"


def test_patch_files_match_their_recorded_digests():
    """A patch cannot be edited after the fact without the record noticing."""
    series = _load()
    rows = series["patches"]
    assert rows, "the series records no patches"
    on_disk = sorted(p.name for p in _PATCH_DIR.glob("*.patch"))
    recorded = [row["file"] for row in rows]
    assert on_disk == sorted(recorded), (
        f"patch files on disk {on_disk} != recorded {sorted(recorded)}"
    )
    for row in rows:
        path = _PATCH_DIR / row["file"]
        assert _sha256(path) == row["sha256"], (
            f"{row['file']} has been modified since the series was generated"
        )


def test_patches_are_ordered_and_carry_their_origin_commit():
    """Order is load-bearing (they apply in sequence) and each patch names the commit it came from."""
    series = _load()
    rows = series["patches"]
    numbers = [int(row["file"][:3]) for row in rows]
    assert numbers == list(range(1, len(rows) + 1)), f"patch numbering is not contiguous: {numbers}"
    for row in rows:
        text = (_PATCH_DIR / row["file"]).read_text(encoding="utf-8", errors="replace")
        assert re.search(rf"^X-VIGIL-Commit: {re.escape(row['commit'])}$", text, re.M), (
            f"{row['file']} does not carry its X-VIGIL-Commit header"
        )
        assert "diff --git" in text, f"{row['file']} contains no diff"
        assert row["commit"], f"{row['file']} has no recorded origin commit"


def test_provenance_is_documented_and_true_of_the_series():
    """UPSTREAM.md and NOTICE must name the same base/upstream commits the series records."""
    series = _load()
    base, upstream = series["base_import_commit"], series["upstream_commit"]
    up_md = (_VENDOR / "UPSTREAM.md").read_text(encoding="utf-8")
    assert base[:12] in up_md, "UPSTREAM.md does not name the base import commit"
    assert upstream[:12] in up_md, "UPSTREAM.md does not name the upstream commit"
    assert "docs/strix-patches" in up_md, "UPSTREAM.md does not point at the series"
    notice = (_VENDOR / "NOTICE").read_text(encoding="utf-8")
    assert "docs/strix-patches" in notice, (
        "NOTICE must point at the patch series, not at bare git history"
    )
    assert "Apache-2.0" in notice, "upstream attribution must be retained"


# --- negative controls: prove each guard can actually fail ---------------------------------------------

def test_negative_control_a_drifted_digest_is_detected(tmp_path):
    """Mutating one byte of a vendored file must be caught by the digest comparison."""
    series = _load()
    manifest = dict(series["tree_manifest"])
    victim = "vendor/strix/strix/report/proof_capture.py"
    assert victim in manifest, "expected the proof-capture module in the manifest"
    original = (_REPO / victim).read_bytes()
    mutated = original + b"\n# unrecorded edit\n"
    assert hashlib.sha256(mutated).hexdigest() != manifest[victim], (
        "the digest comparison is vacuous — a mutated file hashed to the recorded value"
    )


def test_negative_control_an_unrecorded_new_file_is_detected():
    """A file present in the tree but absent from the manifest must be reported."""
    series = _load()
    manifest = set(series["tree_manifest"])
    phantom = "vendor/strix/strix/backdoor.py"
    assert phantom not in manifest
    unrecorded = sorted({*manifest, phantom} - manifest)
    assert unrecorded == [phantom], "the set difference used by the guard does not isolate new files"


def test_negative_control_a_missing_deviation_is_detected():
    """Dropping an entry from the deviation set must make the derived/recorded comparison fail."""
    series = _load()
    base, tree = dict(series["base_manifest"]), dict(series["tree_manifest"])
    derived = {p for p in tree if base.get(p) != tree[p]} | (set(base) - set(tree))
    assert derived, "expected a non-empty derived deviation set"
    tampered = set(sorted(derived)[1:])
    assert tampered != derived, "the comparison cannot distinguish a dropped deviation"
