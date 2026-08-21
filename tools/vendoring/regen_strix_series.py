#!/usr/bin/env python3
"""Regenerate the vendored-Strix patch series and its machine-checked record.

The invariant this maintains (see ``vendor/strix/UPSTREAM.md``):

    vendor/strix == the pristine upstream import at ``base_import_commit``
                    + docs/strix-patches/*.patch, applied in order.

Run this after changing anything under ``vendor/strix`` (or after an upstream re-import), then re-run
``pytest integration/tests/test_strix_patch_series.py``. The guard fails CI when the tree and the series
disagree, so an unrecorded modification to the vendored offensive agent cannot land silently.

Usage:  python3 tools/vendoring/regen_strix_series.py [--check]

``--check`` regenerates into a temp dir and exits non-zero if the committed series is stale, printing what
differs. It writes nothing — safe for CI and for a pre-commit hook.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VENDOR = "vendor/strix"
PATCH_DIR = os.path.join(REPO, "docs", "strix-patches")
SERIES_JSON = os.path.join(PATCH_DIR, "series.json")


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=REPO, check=False).stdout


def _git_bytes(*args: str) -> bytes:
    return subprocess.run(["git", *args], capture_output=True, cwd=REPO, check=False).stdout


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _slug(subject: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", subject.lower()).strip("-")
    return s[:48].strip("-")


def read_series() -> dict:
    """The committed record. Raises FileNotFoundError if the series was never generated."""
    with open(SERIES_JSON, encoding="utf-8") as fh:
        return json.load(fh)


def build(base: str, upstream: str) -> tuple[dict, list[tuple[str, str]]]:
    """Compute the series document and the (filename, content) patches, without writing."""
    commits = [c for c in _git("log", "--no-merges", "--format=%H", "--reverse",
                               f"{base}..HEAD", "--", VENDOR).split() if c]
    patches_out: list[tuple[str, str]] = []
    patch_rows: list[dict] = []
    for i, commit in enumerate(commits, start=1):
        subject = _git("log", "-1", "--format=%s", commit).strip()
        name = f"{i:03d}-{_slug(subject)}.patch"
        body = _git("diff", f"{commit}^", commit, "--", VENDOR)
        text = (
            f"From {commit} Mon Sep 17 00:00:00 2001\n"
            f"Subject: [strix-patch {i:03d}] {subject}\n"
            f"X-VIGIL-Commit: {commit}\n"
            f"X-VIGIL-Date: {_git('log', '-1', '--format=%aI', commit).strip()}\n\n"
            f"{body}"
        )
        patches_out.append((name, text))
        patch_rows.append({
            "file": name,
            "sha256": _sha256_bytes(text.encode("utf-8")),
            "commit": commit,
            "subject": subject,
        })

    tracked = [p for p in _git("ls-files", VENDOR).splitlines() if p]
    tree = {p: _sha256_file(os.path.join(REPO, p)) for p in tracked}
    base_files = [p for p in _git("ls-tree", "-r", "--name-only", base, VENDOR).splitlines() if p]
    base_manifest = {p: _sha256_bytes(_git_bytes("show", f"{base}:{p}")) for p in base_files}
    deviations = sorted(set(p for p in tree if base_manifest.get(p) != tree[p])
                        | (set(base_manifest) - set(tree)))

    doc = {
        "schema": 1,
        "upstream_repo": "https://github.com/usestrix/strix",
        "upstream_license": "Apache-2.0",
        "upstream_commit": upstream,
        "base_import_commit": base,
        "note": ("vendor/strix == the pristine upstream import at base_import_commit, plus the patches "
                 "below, in order. Verified byte-for-byte."),
        "patches": patch_rows,
        "deviations_from_upstream": deviations,
        "base_manifest": base_manifest,
        "tree_manifest": tree,
    }
    return doc, patches_out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit non-zero if the committed series is stale")
    args = ap.parse_args()

    try:
        committed = read_series()
        base, upstream = committed["base_import_commit"], committed["upstream_commit"]
    except FileNotFoundError:
        print(f"error: {SERIES_JSON} not found; bootstrap it once with an explicit base commit",
              file=sys.stderr)
        return 2

    doc, patches = build(base, upstream)

    if args.check:
        stale: list[str] = []
        if committed.get("tree_manifest") != doc["tree_manifest"]:
            stale.append("tree_manifest (vendor/strix content changed)")
        if committed.get("deviations_from_upstream") != doc["deviations_from_upstream"]:
            stale.append("deviations_from_upstream")
        if [p["sha256"] for p in committed.get("patches", [])] != [p["sha256"] for p in doc["patches"]]:
            stale.append("patch set")
        if stale:
            print("STALE: " + "; ".join(stale), file=sys.stderr)
            print("run: python3 tools/vendoring/regen_strix_series.py", file=sys.stderr)
            return 1
        print("series is current")
        return 0

    os.makedirs(PATCH_DIR, exist_ok=True)
    for old in os.listdir(PATCH_DIR):
        if old.endswith(".patch"):
            os.remove(os.path.join(PATCH_DIR, old))
    for name, text in patches:
        with open(os.path.join(PATCH_DIR, name), "w", encoding="utf-8") as fh:
            fh.write(text)
    with open(SERIES_JSON, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(patches)} patches + series.json "
          f"({len(doc['deviations_from_upstream'])} deviations, {len(doc['tree_manifest'])} tracked files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
