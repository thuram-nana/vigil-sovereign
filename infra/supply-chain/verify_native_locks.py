#!/usr/bin/env python3
"""A14 — verify the NON-PYTHON dependency locks still match their manifests (W3-10, issue #433).

THE GAP THIS CLOSES. The Python locks are regenerated and diffed on every run; the non-Python locks
were only ever *scanned* by trivy, never checked for currency, so one could silently stop matching its
manifest — a dependency added to `Cargo.toml` or strix's `pyproject.toml` with the lock never
regenerated leaves that dependency resolved by whatever the toolchain picks, not by the committed lock.

This module verifies two committed non-Python locks against their manifests:

  * ``vendor/strix/uv.lock``            ↔ ``vendor/strix/pyproject.toml``   (uv)
  * ``apps/sigil/kernel/Cargo.lock``    ↔ ``apps/sigil/kernel/Cargo.toml``  (cargo)

There is deliberately NO ``package-lock.json`` pair: the only ``package.json`` in the tree is a
DELIBERATELY-VULNERABLE CVE test fixture (``engine/crucible/.../corpus_apps/_cve/...``) with no lock,
which must NOT be locked or regenerated. Stating that honestly is the point — the acceptance criterion
names package-lock.json, and the honest answer is that this repo ships no first-party one.

TWO CHECKS, two audiences:

  * ``--check`` (default) — OFFLINE, stdlib-only (``tomllib``): every direct dependency named in each
    manifest resolves to a ``[[package]]`` in its lock. Catches "a dep was added but the lock never
    regenerated". Runs in the REQUIRED integration + A14 jobs with no network and no toolchain, and is
    what ``integration/tests/test_supply_chain.py`` exercises with negative controls.
  * ``--regenerate-check`` — LIVE (needs uv / cargo + network), the AUTHORITATIVE regenerate-and-diff:
    ``uv lock --check`` (run on a copy OUTSIDE the uv workspace, mirroring gen-strix-lock.sh) and
    ``cargo metadata --locked`` both exit non-zero if regenerating the lock would change it. Run by the
    "A14 supply-chain gate" job.

Fail-closed everywhere: a missing manifest, a missing/empty lock, or an unparseable file is a FAILURE,
never a pass.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _canon(name: str) -> str:
    """PEP 503 / crates.io-ish normalisation so `serde_json`, `serde-json` and `Serde.JSON` are one."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


# --------------------------------------------------------------------------------------
# The committed non-Python locks under audit.
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class NativeLock:
    ecosystem: str        # "uv" | "cargo"
    manifest: str         # repo-relative path to the manifest (pyproject.toml / Cargo.toml)
    lock: str             # repo-relative path to the lock (uv.lock / Cargo.lock)
    regen_hint: str       # the exact command that regenerates/updates it


NATIVE_LOCKS: tuple[NativeLock, ...] = (
    NativeLock(
        ecosystem="uv",
        manifest="vendor/strix/pyproject.toml",
        lock="vendor/strix/uv.lock",
        # strix is a uv WORKSPACE member; regenerate on a copy outside the workspace (gen-strix-lock.sh
        # uses the same trick), then re-export infra/supply-chain/strix.lock from it.
        regen_hint="(cd vendor/strix && uv lock) && bash infra/supply-chain/gen-strix-lock.sh",
    ),
    NativeLock(
        ecosystem="cargo",
        manifest="apps/sigil/kernel/Cargo.toml",
        lock="apps/sigil/kernel/Cargo.lock",
        regen_hint="cargo update --manifest-path apps/sigil/kernel/Cargo.toml",
    ),
)


# --------------------------------------------------------------------------------------
# Pure extractors (take TEXT, so tests can feed fixtures without touching the filesystem).
# --------------------------------------------------------------------------------------
def uv_manifest_direct_deps(pyproject_text: str) -> list[str]:
    """The direct runtime dependency NAMES declared in a PEP 621 ``[project.dependencies]``."""
    data = tomllib.loads(pyproject_text)
    specs = data.get("project", {}).get("dependencies", []) or []
    out = []
    for spec in specs:
        # "openai-agents[litellm]==0.14.6" -> "openai-agents"; strip extras / version / markers.
        name = re.split(r"[<>=!~;\[\s]", spec, maxsplit=1)[0]
        if name:
            out.append(name)
    return out


def cargo_manifest_direct_deps(cargo_toml_text: str) -> list[str]:
    """The direct dependency NAMES declared in a Cargo.toml (`[dependencies]` + `[build-dependencies]`)."""
    data = tomllib.loads(cargo_toml_text)
    out: list[str] = []
    for table in ("dependencies", "build-dependencies"):
        out.extend((data.get(table) or {}).keys())
    return out


def lock_package_names(lock_text: str) -> set[str]:
    """The canonicalised set of every package named in a uv.lock or Cargo.lock (both TOML with a
    top-level ``[[package]]`` array)."""
    data = tomllib.loads(lock_text)
    return {_canon(p["name"]) for p in data.get("package", []) if isinstance(p, dict) and p.get("name")}


def missing_from_lock(ecosystem: str, manifest_text: str, lock_text: str) -> list[str]:
    """Direct deps declared in the manifest that are NOT pinned in the lock — i.e. the lock is stale.
    Raises ValueError on an empty/packageless lock (fail-closed: a lock that pins nothing is not a pass)."""
    if ecosystem == "uv":
        direct = uv_manifest_direct_deps(manifest_text)
    elif ecosystem == "cargo":
        direct = cargo_manifest_direct_deps(manifest_text)
    else:  # pragma: no cover - guarded by NATIVE_LOCKS
        raise ValueError(f"unknown ecosystem {ecosystem!r}")
    locked = lock_package_names(lock_text)
    if not locked:
        raise ValueError("lock contains no [[package]] entries — it is a placeholder, not a lock")
    return sorted({d for d in direct if _canon(d) not in locked})


# --------------------------------------------------------------------------------------
# Offline consistency check (the required-job guard).
# --------------------------------------------------------------------------------------
def check_lock_matches_manifest(nl: NativeLock, root: Path = REPO_ROOT) -> list[str]:
    """Return a list of human-readable errors (empty == consistent). Fail-closed on missing files."""
    manifest = root / nl.manifest
    lock = root / nl.lock
    errs: list[str] = []
    if not manifest.is_file():
        errs.append(f"{nl.manifest} is missing — cannot verify {nl.lock}")
    if not lock.is_file():
        errs.append(f"{nl.lock} is missing — the {nl.ecosystem} lock is not committed")
    if errs:
        return errs
    try:
        missing = missing_from_lock(nl.ecosystem, manifest.read_text("utf-8"), lock.read_text("utf-8"))
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return [f"{nl.lock}: {exc}"]
    if missing:
        errs.append(
            f"{nl.lock} does not pin these direct dependencies from {nl.manifest}: {missing}. "
            f"The lock has drifted from its manifest — regenerate it: {nl.regen_hint}"
        )
    return errs


def run_offline_check(root: Path = REPO_ROOT) -> int:
    print("A14 non-Python lock consistency (W3-10) — every direct dep must be pinned in its lock\n")
    total = 0
    for nl in NATIVE_LOCKS:
        errs = check_lock_matches_manifest(nl, root)
        if errs:
            total += len(errs)
            for e in errs:
                print(f"  FAIL  {e}")
        else:
            print(f"  ok    {nl.lock} matches {nl.manifest}")
    if total:
        print(f"\n{total} lock/manifest inconsistency(ies).")
        return 1
    print("\nAll non-Python locks are consistent with their manifests.")
    return 0


# --------------------------------------------------------------------------------------
# Live regenerate-and-diff (the authoritative A14-gate check; needs uv / cargo + network).
# --------------------------------------------------------------------------------------
def _uv_lock_check(nl: NativeLock, root: Path) -> tuple[bool, str]:
    """`uv lock --check` on a COPY of the project OUTSIDE the uv workspace (vendor/strix is a workspace
    member, so an in-tree `uv lock` resolves the whole workspace, not strix). Non-zero == the committed
    lock would change if regenerated."""
    uv = shutil.which("uv")
    if not uv:
        return False, "uv not found on PATH (needed for the live uv.lock regenerate-check)"
    src = root / Path(nl.manifest).parent
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for fn in ("pyproject.toml", "uv.lock", "README.md"):
            f = src / fn
            if f.is_file():
                shutil.copy(f, tmp / fn)
        proc = subprocess.run([uv, "lock", "--check"], cwd=tmp, capture_output=True, text=True)
        ok = proc.returncode == 0
        return ok, (proc.stderr or proc.stdout).strip()


def _cargo_locked_check(nl: NativeLock, root: Path) -> tuple[bool, str]:
    """`cargo metadata --locked` — resolves the graph and exits non-zero if Cargo.lock is out of date
    relative to Cargo.toml, without compiling."""
    cargo = shutil.which("cargo")
    if not cargo:
        return False, "cargo not found on PATH (needed for the live Cargo.lock regenerate-check)"
    proc = subprocess.run(
        [cargo, "metadata", "--locked", "--format-version", "1",
         "--manifest-path", str(root / nl.manifest)],
        capture_output=True, text=True,
    )
    ok = proc.returncode == 0
    return ok, (proc.stderr or proc.stdout).strip()


def run_regenerate_check(root: Path = REPO_ROOT) -> int:
    print("A14 non-Python lock regenerate-and-diff (W3-10) — a lock that would change if regenerated FAILS\n")
    failed = 0
    for nl in NATIVE_LOCKS:
        if nl.ecosystem == "uv":
            ok, detail = _uv_lock_check(nl, root)
        elif nl.ecosystem == "cargo":
            ok, detail = _cargo_locked_check(nl, root)
        else:  # pragma: no cover
            ok, detail = False, "unknown ecosystem"
        if ok:
            print(f"  ok    {nl.lock} is up-to-date with {nl.manifest}")
        else:
            failed += 1
            print(f"  FAIL  {nl.lock} is STALE or unverifiable: {detail}")
            print(f"        regenerate: {nl.regen_hint}")
    if failed:
        print(f"\n{failed} non-Python lock(s) are stale or could not be verified.")
        return 1
    print("\nAll non-Python locks regenerate byte-for-byte identical (nothing to update).")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=None, help="repo root (default: two levels up from this file)")
    ap.add_argument("--check", action="store_true",
                    help="OFFLINE: every direct dep in each manifest is pinned in its lock (default)")
    ap.add_argument("--regenerate-check", action="store_true",
                    help="LIVE (uv/cargo): fail if regenerating a lock would change it")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else REPO_ROOT
    if args.regenerate_check:
        return run_regenerate_check(root)
    return run_offline_check(root)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
